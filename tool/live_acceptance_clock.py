"""Parent-local timing bounds for one acceptance run; no clock or process IO.

Record L immediately before spawning the guard and R when its matching arm ACK
is received, using the same parent's monotonic clock. Arm is only known to lie
in [L, R]. Child timestamps must never be passed here. A caller must correlate
the ACK with a fresh run ID and must not reuse a clock for another launch.
"""
import math
from typing import Optional, Tuple


class ClockError(ValueError):
    """A fixed validation code, without timestamps or run IDs in the message."""


def _finite(value, code):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ClockError(code)
    try:
        number = float(value)
    except (OverflowError, ValueError):
        raise ClockError(code) from None
    if not math.isfinite(number):
        raise ClockError(code)
    return number


class LiveAcceptanceClock:
    """Single-use ACK window with fixed launch-relative cutoffs.

    Supply observations in nondecreasing order. A remaining budget of zero is
    expired. These bounds do not prove guard health, native Stop or device OFF;
    the caller owns ACK authenticity and all timestamp provenance.
    """
    __slots__ = ("_run_id", "_launch_before", "_ack_received", "_last_observed")

    def __init__(self, run_id: str, launch_before: float):
        if not isinstance(run_id, str) or not run_id:
            raise ClockError("invalid_run_id")
        self._run_id = run_id
        self._launch_before = _finite(launch_before, "invalid_time")
        self._ack_received: Optional[float] = None
        self._last_observed = self._launch_before

    def _check_now(self, value):
        now = _finite(value, "invalid_time")
        if now < self._last_observed:
            raise ClockError("clock_regression")
        return now

    def acknowledge(self, ack_run_id: str, received_at: float) -> None:
        """Accept one matching ACK observed by this parent, never a child time."""
        if ack_run_id != self._run_id:
            raise ClockError("stale_ack")
        if self._ack_received is not None:
            raise ClockError("already_acknowledged")
        received = self._check_now(received_at)
        _finite(received - self._launch_before, "invalid_window")
        self._ack_received = received
        self._last_observed = received

    def deadline(self, budget: float) -> float:
        """Return L + budget; a delayed or repeated ACK cannot extend it."""
        duration = _finite(budget, "invalid_budget")
        if duration < 0:
            raise ClockError("invalid_budget")
        return _finite(self._launch_before + duration, "invalid_budget")

    def remaining(self, budget: float, now: float) -> float:
        """Return the conservative wait budget, including before arm ACK."""
        deadline = self.deadline(budget)
        observed = self._check_now(now)
        self._last_observed = observed
        return max(0.0, deadline - observed)

    def elapsed_bounds(self, now: float) -> Tuple[float, float]:
        """Return [now - R, now - L], not an estimated exact arm elapsed."""
        if self._ack_received is None:
            raise ClockError("not_acknowledged")
        observed = self._check_now(now)
        lower = _finite(observed - self._ack_received, "invalid_time")
        upper = _finite(observed - self._launch_before, "invalid_time")
        self._last_observed = observed
        return lower, upper
