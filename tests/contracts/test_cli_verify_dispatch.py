"""CLI dispatch selection for the trusted root verification lane."""
from __future__ import annotations

from pathlib import Path

from hermes_installer import cli
from hermes_installer.results import OutcomeState
from hermes_installer.verification import runtime_workflows


def test_root_verify_uses_protected_runtime_lane_without_caller_target(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    captured = {}

    def run_root(**kwargs):
        captured.update(kwargs)
        from hermes_installer.results import CommandResult
        return CommandResult("verify", OutcomeState.PENDING, "root fixture dispatch")

    monkeypatch.setattr(runtime_workflows, "run_root_verify_cli", run_root)
    args = cli.build_parser().parse_args([
        "verify", "--output", str(tmp_path / "evidence"), "--acceptance", "AC16",
    ])
    result = cli.run(args)

    assert result.message == "root fixture dispatch"
    assert captured == {
        "output_path": Path(tmp_path / "evidence"),
        "requested_acceptance": ("AC16",),
        "request_path": None,
        "result_path": None,
    }


def test_root_verify_rejects_caller_target_lease(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    args = cli.build_parser().parse_args([
        "verify", "--target", str(tmp_path / "lease.json"),
        "--output", str(tmp_path / "evidence"),
    ])

    result = cli.run(args)

    assert result.state is OutcomeState.FAILED
    assert "derives target identity from protected enrollment" in result.message


def test_root_verify_without_protected_runtime_stays_pending(tmp_path, monkeypatch):
    from hermes_installer.authority import daemon

    monkeypatch.setattr(runtime_workflows.os, "geteuid", lambda: 0)
    monkeypatch.setattr(daemon, "build_enrolled_authority_service",
                        lambda: (type("Service", (), {"root_authority_runtime": None})(), object()))

    result = runtime_workflows.run_root_verify_cli(output_path=Path("evidence"),
                                                    requested_acceptance=("AC16",))

    assert result.state is OutcomeState.PENDING
    assert "no acceptance workflow ran" in result.message
    assert result.findings[0].details["runtime_composed"] is False
