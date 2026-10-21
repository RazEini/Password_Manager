import time

from password_manager.clipboard import ClipboardGuard


class FakeClipboard:
    def __init__(self):
        self.value = ""
        self.fail_paste = False

    def copy(self, text):
        self.value = text

    def paste(self):
        if self.fail_paste:
            raise RuntimeError("no clipboard")
        return self.value


def test_copy_then_clear_removes_the_secret():
    cb = FakeClipboard()
    guard = ClipboardGuard(backend=cb, seconds=0)
    guard.copy("s3cret")
    assert cb.value == "s3cret"
    assert guard.clear_if_unchanged() is True
    assert cb.value == ""


def test_does_not_wipe_something_the_user_copied_afterwards():
    cb = FakeClipboard()
    guard = ClipboardGuard(backend=cb, seconds=0)
    guard.copy("s3cret")
    cb.value = "my shopping list"
    assert guard.clear_if_unchanged() is False
    assert cb.value == "my shopping list"


def test_seconds_zero_disables_the_timer():
    guard = ClipboardGuard(backend=FakeClipboard(), seconds=0)
    guard.copy("x")
    assert guard._timer is None


def test_timer_clears_the_clipboard_automatically():
    cb = FakeClipboard()
    guard = ClipboardGuard(backend=cb, seconds=0.05)
    guard.copy("s3cret")
    time.sleep(0.4)
    assert cb.value == ""


def test_close_cancels_the_timer_and_clears_now():
    cb = FakeClipboard()
    guard = ClipboardGuard(backend=cb, seconds=60)
    guard.copy("s3cret")
    guard.close()
    assert cb.value == "" and guard._timer is None


def test_a_second_copy_replaces_the_pending_timer():
    cb = FakeClipboard()
    guard = ClipboardGuard(backend=cb, seconds=60)
    guard.copy("first")
    first_timer = guard._timer
    guard.copy("second")
    assert guard._timer is not first_timer
    guard.close()


def test_clear_without_a_prior_copy_is_a_noop():
    cb = FakeClipboard()
    cb.value = "unrelated"
    assert ClipboardGuard(backend=cb, seconds=0).clear_if_unchanged() is False
    assert cb.value == "unrelated"


def test_clipboard_errors_are_swallowed_not_raised():
    cb = FakeClipboard()
    guard = ClipboardGuard(backend=cb, seconds=0)
    guard.copy("s3cret")
    cb.fail_paste = True
    assert guard.clear_if_unchanged() is False
