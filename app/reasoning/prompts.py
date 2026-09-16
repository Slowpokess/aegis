from pathlib import Path

from pydantic import BaseModel, ConfigDict

PROMPT_VERSION = "hypothesis-v1"
_PROMPT_ROOT = Path(__file__).resolve().parents[1] / "prompts" / "hypothesis"
EXPERIMENT_PROMPT_VERSION = "experiment-v2"
_EXPERIMENT_PROMPT_ROOT = Path(__file__).resolve().parents[1] / "prompts" / "experiment"


class PromptBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str
    system: str
    task: str


def load_hypothesis_prompt(version: str = PROMPT_VERSION) -> PromptBundle:
    if version != PROMPT_VERSION:
        raise ValueError(f"unsupported hypothesis prompt version: {version}")
    system = (_PROMPT_ROOT / "v1_system.md").read_text(encoding="utf-8").strip()
    task = (_PROMPT_ROOT / "v1_task.md").read_text(encoding="utf-8").strip()
    if not system or not task:
        raise ValueError("hypothesis prompt assets cannot be empty")
    return PromptBundle(version=version, system=system, task=task)


def load_experiment_prompt(version: str = EXPERIMENT_PROMPT_VERSION) -> PromptBundle:
    supported = {"experiment-v1": "v1", "experiment-v2": "v2"}
    if version not in supported:
        raise ValueError(f"unsupported experiment prompt version: {version}")
    asset_version = supported[version]
    system = (_EXPERIMENT_PROMPT_ROOT / f"{asset_version}_system.md").read_text(
        encoding="utf-8"
    ).strip()
    task = (_EXPERIMENT_PROMPT_ROOT / f"{asset_version}_task.md").read_text(
        encoding="utf-8"
    ).strip()
    if not system or not task:
        raise ValueError("experiment prompt assets cannot be empty")
    return PromptBundle(version=version, system=system, task=task)
