"""Real temporary financial owners for physical-transport qualification tests."""

from __future__ import annotations

from uuid import uuid4

from lyrashield.artifacts.state import ReportState, get_global_report_state
from lyrashield.lifecycle import hooks as hooks_module


def owned_hooks(base, root):
    class OwnedHooks(base):
        def __init__(self, **kwargs):
            state = get_global_report_state()
            if not isinstance(state, ReportState):
                state = ReportState(f"physical-{uuid4().hex}")
                state._run_dir = root / state.run_name
            super().__init__(**{**kwargs, "report_state": state})
            hooks_module.set_active_hooks(self)

    return OwnedHooks
