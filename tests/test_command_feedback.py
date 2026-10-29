"""Long native tracebacks must retain their final error within the feedback budget."""

import pytest

from daedalus.infrastructure.git_sandbox import CommandResult
from daedalus.infrastructure.sandbox.base import CommandOutcome


@pytest.mark.parametrize("result_type", [CommandResult, CommandOutcome])
def test_bounded_feedback_keeps_test_identity_and_exception_without_changing_failure(result_type):
    result = result_type(
        command=("python3","verify_public.py"),exit_code=2,
        stdout="Testing the frozen upstream contract\n" + "traceback frame\n"*400,
        stderr="sqlite3.OperationalError: invalid SQL alias from candidate",duration_ms=1,
    )
    feedback = result.combined(1500)
    assert feedback.startswith("Testing the frozen upstream contract")
    assert "sqlite3.OperationalError: invalid SQL alias from candidate" in feedback
    assert len(feedback) <= 1500
    assert result.exit_code == 2 and not result.ok


@pytest.mark.parametrize("result_type", [CommandResult, CommandOutcome])
def test_short_command_feedback_keeps_both_streams(result_type):
    result = result_type(command=("python3",),exit_code=0,
                         stdout="public checks passed",stderr="diagnostic",duration_ms=1)
    assert result.combined(1500) == "public checks passed\ndiagnostic"
    assert result.ok
