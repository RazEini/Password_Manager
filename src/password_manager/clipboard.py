"""Clipboard helper that clears a copied secret after a delay.

A password left on the clipboard can be read by any other program, pasted into
the wrong window, or captured by clipboard-history tools. ClipboardGuard
copies the secret and clears it after `seconds`, but only if the clipboard
still holds that same value, so it never wipes something the user copied
afterwards.
"""
from __future__ import annotations

import threading
from typing import Optional

try:
    import pyperclip
except Exception:  # pragma: no cover - depends on the environment
    pyperclip = None

DEFAULT_CLEAR_SECONDS = 30


def available() -> bool:
    return pyperclip is not None


class ClipboardGuard:
    def __init__(self, backend=None, seconds: int = DEFAULT_CLEAR_SECONDS):
        self.backend = backend if backend is not None else pyperclip
        self.seconds = seconds
        self._last: Optional[str] = None
        self._timer: Optional[threading.Timer] = None

    def copy(self, text: str) -> None:
        """Copy `text`; schedule an automatic clear (non-blocking, for the TUI)."""
        self.backend.copy(text)
        self._last = text
        self._cancel_timer()
        if self.seconds and self.seconds > 0:
            self._timer = threading.Timer(self.seconds, self.clear_if_unchanged)
            self._timer.daemon = True
            self._timer.start()

    def clear_if_unchanged(self) -> bool:
        """Clear the clipboard only if it still holds what we copied."""
        if self._last is None:
            return False
        try:
            current = self.backend.paste()
        except Exception:
            return False
        cleared = False
        if current == self._last:
            try:
                self.backend.copy("")
                cleared = True
            except Exception:
                pass
        self._last = None
        return cleared

    def _cancel_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def close(self) -> None:
        """Cancel the pending timer and clear now (call on exit)."""
        self._cancel_timer()
        self.clear_if_unchanged()
