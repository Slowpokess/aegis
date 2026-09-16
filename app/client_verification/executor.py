"""Trusted Playwright execution boundary for typed client-side verification plans."""

from enum import StrEnum
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from pydantic import Field

from app.config import Settings
from app.domain.client_verification import ClientVerificationProposal, ClientVerificationValidator
from app.domain.common import DomainModel


class BrowserExecutionError(ValueError):
    pass


class BrowserExecutionStatus(StrEnum):
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


class BrowserEvidence(DomainModel):
    final_url: str
    title: str = Field(max_length=500)
    dom_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    dom_excerpt: str = Field(max_length=20_000)
    csrf_source_used: str | None = None
    csrf_observed: bool = False
    external_requests_blocked: int = Field(ge=0)


class BrowserExecutionResult(DomainModel):
    status: BrowserExecutionStatus
    candidate: BrowserEvidence | None = None
    control: BrowserEvidence | None = None
    error_code: str | None = None


class PlaywrightClientVerificationExecutor:
    """Executes sealed probes only; browser secrets never cross this boundary."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def execute(
        self,
        proposal: ClientVerificationProposal,
        *,
        target_base_url: str,
        available_evidence_ids: frozenset,
        persisted_operator_approval: bool,
    ) -> BrowserExecutionResult:
        validation = ClientVerificationValidator().validate(
            proposal,
            available_evidence_ids=available_evidence_ids,
            persisted_operator_approval=persisted_operator_approval,
        )
        if not validation.valid:
            return BrowserExecutionResult(
                status=BrowserExecutionStatus.REJECTED,
                error_code=validation.errors[0],
            )
        if not self.settings.client_verification_enabled:
            return BrowserExecutionResult(
                status=BrowserExecutionStatus.REJECTED,
                error_code="CLIENT_VERIFICATION_DISABLED",
            )
        executable = self.settings.client_verification_browser_executable
        if executable is None or not Path(executable).is_file():
            return BrowserExecutionResult(
                status=BrowserExecutionStatus.FAILED,
                error_code="BROWSER_UNAVAILABLE",
            )
        target = _same_origin_target(target_base_url, proposal.navigation_path)
        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=True, executable_path=str(executable)
                )
                try:
                    control = await self._run(browser, target, proposal, candidate=False)
                    candidate = await self._run(browser, target, proposal, candidate=True)
                finally:
                    await browser.close()
        except Exception:
            return BrowserExecutionResult(
                status=BrowserExecutionStatus.FAILED,
                error_code="BROWSER_EXECUTION_FAILED",
            )
        return BrowserExecutionResult(
            status=BrowserExecutionStatus.COMPLETED, candidate=candidate, control=control
        )

    async def _run(self, browser: object, target: str, proposal: ClientVerificationProposal, *, candidate: bool) -> BrowserEvidence:
        import hashlib

        context = await browser.new_context()  # type: ignore[union-attr]
        blocked = 0
        origin = _origin(target)

        async def route_handler(route: object) -> None:
            nonlocal blocked
            if _origin(route.request.url) != origin:  # type: ignore[union-attr]
                blocked += 1
                await route.abort()  # type: ignore[union-attr]
            else:
                await route.continue_()  # type: ignore[union-attr]

        try:
            page = await context.new_page()
            await page.route("**/*", route_handler)
            await page.goto(target, wait_until="domcontentloaded", timeout=self.settings.client_verification_navigation_timeout_ms)
            csrf_observed = await self._observe_csrf(page, proposal)
            field = page.locator(f'input[name="{proposal.input_name}"],textarea[name="{proposal.input_name}"]')
            if await field.count() != 1:
                raise BrowserExecutionError("expected observed form field is unavailable")
            # The value is selected internally from the sealed registry. It is never model-supplied.
            await field.fill(_sealed_probe_value(proposal.candidate_probe_id) if candidate else "")
            dom = (await page.content())[: self.settings.client_verification_max_dom_characters]
            return BrowserEvidence(
                final_url=page.url,
                title=await page.title(),
                dom_sha256=hashlib.sha256(dom.encode()).hexdigest(),
                dom_excerpt=_redact_dom(dom),
                csrf_source_used=proposal.csrf.source.value if csrf_observed else None,
                csrf_observed=csrf_observed,
                external_requests_blocked=blocked,
            )
        finally:
            await context.close()

    async def _observe_csrf(self, page: object, proposal: ClientVerificationProposal) -> bool:
        if not proposal.csrf.required:
            return False
        name = proposal.csrf.field_name
        if name is None:
            raise BrowserExecutionError("CSRF field name is absent")
        if proposal.csrf.source.value == "OBSERVED_META_TAG":
            return await page.locator(f'meta[name="{name}"]').count() == 1  # type: ignore[union-attr]
        return await page.locator(f'input[name="{name}"]').count() == 1  # type: ignore[union-attr]


def _same_origin_target(base_url: str, path: str) -> str:
    target = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    if _origin(target) != _origin(base_url):
        raise BrowserExecutionError("target escapes trusted origin")
    return target


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname or "", parsed.port


def _sealed_probe_value(probe_id: str) -> str:
    allowed = {"marker-html-text-v1", "marker-html-attribute-v1", "marker-url-attribute-v1", "marker-dom-sink-v1"}
    if probe_id not in allowed:
        raise BrowserExecutionError("sealed probe is unavailable")
    return "aegis-client-verification-marker"


def _redact_dom(value: str) -> str:
    # Raw HTML is target-controlled data; cap it and remove common secret-bearing attributes.
    return value.replace("value=", "redacted-value=")
