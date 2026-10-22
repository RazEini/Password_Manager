import csv
import sys
from pathlib import Path

import pytest

import password_manager.cli.main as cli
from password_manager.core.crypto import DEFAULT_ITERATIONS

MASTER = "MasterPass123"
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


@pytest.fixture
def run(tmp_path, monkeypatch):
    """Run the CLI against a temp vault; every getpass prompt answers from `answers`."""
    vault = str(tmp_path / "vault.json")

    def _run(*argv, answers=None):
        queue = list(answers or [])
        monkeypatch.setattr("getpass.getpass", lambda prompt="": queue.pop(0) if queue else MASTER)
        cli.main(["--vault", vault, *argv])

    _run.vault = vault
    _run.dir = tmp_path
    return _run


def test_parser_uses_the_current_default_work_factor():
    assert cli.build_parser().parse_args(["init"]).iterations == DEFAULT_ITERATIONS


def test_full_lifecycle(run, capsys):
    run("init", "--iterations", "1000")
    run("add", "--service", "github", "--user", "alice", "--generate", "--length", "24")
    run("add", "--service", "gitlab", "--user", "bob", "--notes", "work")  # typed password prompt
    run("list")
    out = capsys.readouterr().out
    assert "github" in out and "gitlab" in out

    run("get", "--service", "gitlab")
    assert '"username": "bob"' in capsys.readouterr().out

    run("delete", "--service", "github")
    run("list")
    out = capsys.readouterr().out.splitlines()
    assert "github" not in out and "gitlab" in out


def test_wrong_master_password_exits_with_an_error(run, capsys):
    run("init", "--iterations", "1000")
    with pytest.raises(SystemExit) as e:
        run("list", answers=["WrongPassword1"])
    assert e.value.code == 1
    assert "Invalid master password" in capsys.readouterr().err


def test_short_master_password_is_rejected(run):
    with pytest.raises(SystemExit) as e:
        run("init", "--iterations", "1000", answers=["short", "short"])
    assert e.value.code == 2


def test_mismatched_confirmation_is_rejected(run):
    with pytest.raises(SystemExit) as e:
        run("init", "--iterations", "1000", answers=[MASTER, "Different123"])
    assert e.value.code == 2


def test_change_master_via_cli(run, capsys):
    run("init", "--iterations", "1000")
    run("add", "--service", "github", "--user", "a", "--generate")
    run("change-master", "--iterations", "1000", answers=[MASTER, "NewMaster456", "NewMaster456"])
    run("list", answers=["NewMaster456"])
    assert "github" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        run("list", answers=[MASTER])


def test_change_master_mismatch_exits(run):
    run("init", "--iterations", "1000")
    with pytest.raises(SystemExit) as e:
        run("change-master", answers=[MASTER, "NewMaster456", "Different789"])
    assert e.value.code == 2


def test_old_vaults_get_an_upgrade_hint(run, capsys):
    run("init", "--iterations", "1000")
    run("list")
    err = capsys.readouterr().err
    assert "change-master" in err and "1,000" in err


def test_very_low_iteration_count_triggers_a_warning(run, capsys):
    run("init", "--iterations", "1000")
    err = capsys.readouterr().err
    assert "VERY weak" in err and "1,000" in err


def test_mid_range_iteration_count_gets_a_softer_note(run, capsys):
    run("init", "--iterations", "300000")
    err = capsys.readouterr().err
    assert "below the recommended" in err and "VERY weak" not in err


def test_default_iteration_count_is_silent(run, capsys):
    run("init")  # real default work factor
    assert "weak" not in capsys.readouterr().err.lower()
    assert "below the recommended" not in capsys.readouterr().err


def test_change_master_warns_on_an_explicit_weak_value(run, capsys):
    run("init", "--iterations", "1000")
    capsys.readouterr()
    run("change-master", "--iterations", "2000", answers=[MASTER, "NewMaster456", "NewMaster456"])
    assert "VERY weak" in capsys.readouterr().err


def test_change_master_without_a_value_does_not_warn(run, capsys):
    run("init", "--iterations", "1000")
    capsys.readouterr()
    run("change-master", answers=[MASTER, "NewMaster456", "NewMaster456"])
    assert "weak" not in capsys.readouterr().err.lower()


def test_generate_command(run, capsys):
    run("generate", "--length", "30", "--no-symbols")
    pwd = capsys.readouterr().out.strip()
    assert len(pwd) == 30 and pwd.isalnum()


# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------
class FakeClipboard:
    def __init__(self):
        self.value = ""

    def copy(self, t):
        self.value = t

    def paste(self):
        return self.value


@pytest.fixture
def fake_clipboard(monkeypatch):
    cb = FakeClipboard()
    monkeypatch.setattr("password_manager.clipboard.pyperclip", cb)
    monkeypatch.setattr(cli, "HAS_PYPERCLIP", True)
    sleeps = []
    monkeypatch.setattr(cli.time, "sleep", lambda s: sleeps.append(s))
    cb.sleeps = sleeps
    return cb


def test_get_copy_clears_the_clipboard_after_the_default_delay(run, fake_clipboard):
    run("init", "--iterations", "1000")
    run("add", "--service", "github", "--user", "a", "--generate")
    run("get", "--service", "github", "--copy")
    assert fake_clipboard.sleeps == [cli.DEFAULT_CLEAR_SECONDS]
    assert fake_clipboard.value == ""  # cleared after the wait


def test_clear_after_zero_leaves_the_password_on_the_clipboard(run, fake_clipboard, capsys):
    run("init", "--iterations", "1000")
    run("add", "--service", "github", "--user", "a", "--generate", "--length", "22")
    run("get", "--service", "github", "--copy", "--clear-after", "0")
    assert fake_clipboard.sleeps == [] and len(fake_clipboard.value) == 22
    assert "disabled" in capsys.readouterr().err


def test_ctrl_c_during_the_wait_still_clears(run, fake_clipboard, monkeypatch):
    run("init", "--iterations", "1000")
    run("add", "--service", "github", "--user", "a", "--generate")

    def interrupt(_):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", interrupt)
    run("get", "--service", "github", "--copy")
    assert fake_clipboard.value == ""


# ---------------------------------------------------------------------------
# CSV import / export
# ---------------------------------------------------------------------------
def test_export_warns_and_is_owner_only(run, capsys):
    run("init", "--iterations", "1000")
    run("add", "--service", "github", "--user", "alice", "--generate")
    out_csv = run.dir / "export.csv"
    capsys.readouterr()
    run("export-csv", "--path", str(out_csv))
    assert "PLAINTEXT" in capsys.readouterr().err
    rows = list(csv.DictReader(out_csv.open()))
    assert rows[0]["service"] == "github" and rows[0]["username"] == "alice"
    if sys.platform != "win32":
        assert out_csv.stat().st_mode & 0o777 == 0o600


def test_import_round_trip_and_skips_bad_rows(run, capsys):
    src = run.dir / "in.csv"
    src.write_text("service,username,password,notes\ngithub,alice,pw1,n1\n,nobody,pw2,\ngitlab,bob,pw3,\n")
    run("init", "--iterations", "1000")
    capsys.readouterr()
    run("import-csv", "--path", str(src))
    out = capsys.readouterr().out
    assert "Skipping row 3" in out and "Imported/updated 2" in out
    run("get", "--service", "gitlab")
    assert '"username": "bob"' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Accuracy of what the UI claims
# ---------------------------------------------------------------------------
def test_ui_does_not_claim_the_wrong_cipher():
    """Regression: the banner said AES-128-GCM; Fernet is AES-128-CBC + HMAC-SHA256."""
    source = Path(cli.__file__).read_text(encoding="utf-8")
    assert "GCM" not in source and "CBC" in source
