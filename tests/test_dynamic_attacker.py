"""The week-4 criterion: run 10+ payloads at a target and record the success rate."""

from __future__ import annotations

from tests.conftest import FakeClient

from ouroboros.agents.dynamic_attacker import _RateLimiter, attack, run_campaign
from ouroboros.schemas.repo_profile import ExtractedPrompt, RepoProfile

CANARY = "CANARY"


def _profile(mode: str = "owner") -> RepoProfile:
    return RepoProfile(
        source="./target",
        resolved_mode=mode,  # type: ignore[arg-type]
        system_prompts=[
            ExtractedPrompt(file_path="p.md", method="text-fence", text="You are strict.")
        ],
    )


def _replies(hits: int, total: int) -> list[str]:
    # First `hits` replies contain the canary; the rest are refusals.
    return [f"sure {CANARY}" if i < hits else "I cannot help." for i in range(total)]


def test_runs_full_library_and_records_success_rate() -> None:
    client = FakeClient(replies=_replies(hits=4, total=12))
    run = run_campaign(
        _profile(),
        client=client,
        canary_factory=lambda: CANARY,
        min_interval_seconds=0,
    )
    assert run.attempts >= 10
    assert run.attempts == 12
    assert run.successes == 4
    assert run.success_rate == round(4 / 12, 3)
    assert len(client.calls) == 12


def test_findings_are_confirmed_live_with_family_and_atlas() -> None:
    client = FakeClient(replies=_replies(hits=12, total=12))
    run = run_campaign(
        _profile("owner"),
        client=client,
        canary_factory=lambda: CANARY,
        min_interval_seconds=0,
    )
    assert len(run.findings) == 12
    for finding in run.findings:
        assert finding.success is True
        assert finding.confidence == "confirmed_live"
        assert finding.family in {"direct", "indirect", "jailbreak", "encoding"}
        assert finding.atlas


def test_confidence_label_can_be_simulated() -> None:
    client = FakeClient(replies=_replies(hits=1, total=12))
    run = run_campaign(
        _profile("auditor"),
        client=client,
        confidence="simulated",
        canary_factory=lambda: CANARY,
        min_interval_seconds=0,
    )
    assert run.confidence == "simulated"
    assert all(f.confidence == "simulated" for f in run.findings)


def test_max_payloads_caps_attempts() -> None:
    client = FakeClient(replies=_replies(hits=0, total=3))
    run = run_campaign(
        _profile(),
        client=client,
        canary_factory=lambda: CANARY,
        min_interval_seconds=0,
        max_payloads=3,
    )
    assert run.attempts == 3


def test_attack_without_a_client_sends_nothing() -> None:
    assert attack(_profile()) == []


def test_stats_projects_into_the_report_contract() -> None:
    client = FakeClient(replies=_replies(hits=4, total=12))
    stats = run_campaign(
        _profile(), client=client, canary_factory=lambda: CANARY, min_interval_seconds=0
    ).stats()
    assert stats.attempts == 12
    assert stats.successes == 4
    assert stats.success_rate == round(4 / 12, 3)
    assert set(stats.families) == {"direct", "indirect", "jailbreak", "encoding"}


def test_rate_limiter_paces_between_calls() -> None:
    slept: list[float] = []
    clock_values = iter([0.0, 0.0, 0.0, 0.0, 0.0])
    limiter = _RateLimiter(5.0, sleep=slept.append, clock=lambda: next(clock_values))
    limiter.wait()  # first call: no wait
    limiter.wait()  # second: must pace
    assert slept == [5.0]


def test_rate_limiter_zero_interval_never_sleeps() -> None:
    slept: list[float] = []
    limiter = _RateLimiter(0.0, sleep=slept.append, clock=lambda: 0.0)
    limiter.wait()
    limiter.wait()
    assert slept == []
