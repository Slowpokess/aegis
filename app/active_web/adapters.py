import asyncio
import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.discovery.errors import ToolExecutionError
from app.domain.discovery import ToolDescriptor, ToolErrorCode


@dataclass(frozen=True)
class ActiveProcessResult:
    stdout: bytes
    stderr: str
    argv: tuple[str, ...]
    exit_code: int


@dataclass(frozen=True)
class FfufProfile:
    profile_id: str
    version: str
    wordlist_id: str
    wordlist_path: Path
    concurrency: int
    request_timeout_seconds: int
    max_duration_seconds: int
    max_results: int

    @property
    def wordlist_bytes(self) -> bytes:
        return self.wordlist_path.read_bytes()

    @property
    def wordlist_sha256(self) -> str:
        return hashlib.sha256(self.wordlist_bytes).hexdigest()

    @property
    def word_count(self) -> int:
        return len([line for line in self.wordlist_bytes.splitlines() if line.strip()])


@dataclass(frozen=True)
class NucleiProfile:
    profile_id: str
    version: str
    template_ids: tuple[str, ...]
    template_paths: tuple[Path, ...]
    concurrency: int
    rate_limit: int
    request_timeout_seconds: int
    max_duration_seconds: int
    max_results: int

    @property
    def inventory_sha256(self) -> str:
        digest = hashlib.sha256()
        for path in self.template_paths:
            digest.update(path.name.encode())
            digest.update(b"\x00")
            digest.update(path.read_bytes())
            digest.update(b"\x00")
        return digest.hexdigest()


class FfufAdapter:
    tool_id = "ffuf"

    def __init__(self, descriptor: ToolDescriptor, *, output_max_bytes: int) -> None:
        self.descriptor = descriptor
        self.output_max_bytes = output_max_bytes

    def argv(self, *, target: str, profile: FfufProfile, output_path: str = "-") -> tuple[str, ...]:
        executable = _executable(self.descriptor)
        _approved_file(profile.wordlist_path)
        return (
            executable,
            "-u",
            target,
            "-w",
            str(profile.wordlist_path.resolve()),
            "-of",
            "json",
            "-o",
            output_path,
            "-t",
            str(profile.concurrency),
            "-timeout",
            str(profile.request_timeout_seconds),
            "-maxtime",
            str(profile.max_duration_seconds),
            "-noninteractive",
            "-s",
        )

    async def execute(self, *, target: str, profile: FfufProfile) -> ActiveProcessResult:
        with tempfile.TemporaryDirectory(prefix="aegis-ffuf-") as directory:
            output_file = Path(directory) / "ffuf.json"
            result = await _execute(
                self.argv(target=target, profile=profile, output_path=str(output_file)),
                timeout_seconds=profile.max_duration_seconds,
                output_max_bytes=self.output_max_bytes,
                cwd=Path(directory),
            )
            artifact = output_file.read_bytes() if output_file.exists() else result.stdout
            return ActiveProcessResult(
                stdout=artifact,
                stderr=result.stderr,
                argv=result.argv,
                exit_code=result.exit_code,
            )


class NucleiAdapter:
    tool_id = "nuclei"

    def __init__(self, descriptor: ToolDescriptor, *, output_max_bytes: int) -> None:
        self.descriptor = descriptor
        self.output_max_bytes = output_max_bytes

    def argv(self, *, targets_file: Path, profile: NucleiProfile) -> tuple[str, ...]:
        executable = _executable(self.descriptor)
        for path in profile.template_paths:
            _approved_file(path)
        values = [
            executable,
            "-list",
            str(targets_file),
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-concurrency",
            str(profile.concurrency),
            "-rate-limit",
            str(profile.rate_limit),
            "-timeout",
            str(profile.request_timeout_seconds),
        ]
        for template in profile.template_paths:
            values.extend(("-templates", str(template.resolve())))
        return tuple(values)

    async def execute(self, *, targets: tuple[str, ...], profile: NucleiProfile) -> ActiveProcessResult:
        with tempfile.TemporaryDirectory(prefix="aegis-nuclei-") as directory:
            target_file = Path(directory) / "targets.txt"
            target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
            return await _execute(
                self.argv(targets_file=target_file, profile=profile),
                timeout_seconds=profile.max_duration_seconds,
                output_max_bytes=self.output_max_bytes,
                cwd=Path(directory),
            )


def _approved_file(path: Path) -> None:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or path.is_symlink():
        raise ToolExecutionError(
            ToolErrorCode.PROFILE_NOT_ALLOWED,
            "approved inventory entry is not a regular file",
        )


def _executable(descriptor: ToolDescriptor) -> str:
    if not descriptor.available or not descriptor.executable_path:
        raise ToolExecutionError(ToolErrorCode.TOOL_NOT_AVAILABLE, "tool binary is unavailable")
    return descriptor.executable_path


async def _execute(
    argv: tuple[str, ...],
    *,
    timeout_seconds: float,
    output_max_bytes: int,
    cwd: Path | None = None,
) -> ActiveProcessResult:
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=_controlled_env(argv[0]),
        )
    except FileNotFoundError as error:
        raise ToolExecutionError(ToolErrorCode.TOOL_NOT_AVAILABLE, "fixed tool executable was not found") from error

    async def read(stream: asyncio.StreamReader | None, limit: int) -> bytes:
        if stream is None:
            return b""
        data = await stream.read(limit + 1)
        if len(data) > limit:
            process.kill()
            raise ToolExecutionError(ToolErrorCode.OUTPUT_TOO_LARGE, "tool output exceeded configured bound")
        return data

    try:
        stdout, stderr = await asyncio.wait_for(
            asyncio.gather(read(process.stdout, output_max_bytes), read(process.stderr, 32_000)),
            timeout=timeout_seconds,
        )
        await asyncio.wait_for(process.wait(), timeout=2)
    except ToolExecutionError:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    except TimeoutError as error:
        process.kill()
        await process.wait()
        raise ToolExecutionError(ToolErrorCode.PROCESS_TIMEOUT, "tool process exceeded configured timeout") from error
    return ActiveProcessResult(
        stdout=stdout,
        stderr=stderr.decode(errors="replace")[:2000],
        argv=argv,
        exit_code=process.returncode or 0,
    )


def _controlled_env(executable: str) -> dict[str, str]:
    tool_name = Path(executable).name
    root = Path(tempfile.gettempdir()) / "aegis-active-tools" / tool_name
    home = root / "home"
    config_root = home / "Library" / "Application Support"
    cache_root = home / "Library" / "Caches"
    (root / "xdg_config").mkdir(parents=True, exist_ok=True)
    (root / "xdg_cache").mkdir(parents=True, exist_ok=True)
    cache_root.mkdir(parents=True, exist_ok=True)
    if tool_name == "ffuf":
        (config_root / "ffuf" / "scraper").mkdir(parents=True, exist_ok=True)
    if tool_name == "nuclei":
        (config_root / "nuclei").mkdir(parents=True, exist_ok=True)
        (cache_root / "nuclei").mkdir(parents=True, exist_ok=True)
        (home / ".pdcp").mkdir(parents=True, exist_ok=True)
    return {
        "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": str(home),
        "TMPDIR": tempfile.gettempdir(),
        "XDG_CONFIG_HOME": str(root / "xdg_config"),
        "XDG_CACHE_HOME": str(root / "xdg_cache"),
    }
