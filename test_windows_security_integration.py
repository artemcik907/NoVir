import hashlib
import json
import os
import shutil
import subprocess
import ctypes
import re
import uuid

import pytest


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows ACL integration test")


def test_manifest_directory_acl_is_hardened(tmp_path, monkeypatch, request):
    if not ctypes.windll.shell32.IsUserAnAdmin():
        if os.environ.get("CI"):
            pytest.fail("Windows ACL integration test requires an elevated CI runner")
        pytest.skip("Windows ACL integration test requires an elevated process")

    import virus_recovery

    backup_dir = tmp_path / "NoVir_Backups"
    security_dir = tmp_path / "Security"
    backup_dir.mkdir()
    security_dir.mkdir()
    request.addfinalizer(
        lambda: _cleanup_test_directory(security_dir)
    )
    backup_path = backup_dir / "hosts_backup_20260916_120000.txt"
    backup_path.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    manifest_path = security_dir / "backup_manifest.json"
    monkeypatch.setattr(virus_recovery, "BACKUP_DIR", str(backup_dir))
    monkeypatch.setattr(virus_recovery, "BACKUP_SECURITY_DIR", str(security_dir))
    monkeypatch.setattr(virus_recovery, "BACKUP_MANIFEST", str(manifest_path))

    acl_diagnostics = []
    assert virus_recovery._harden_backup_security_dir(acl_diagnostics), acl_diagnostics
    register_diagnostics = []
    assert virus_recovery._register_backup(str(backup_path), register_diagnostics), register_diagnostics
    assert json.loads(manifest_path.read_text(encoding="utf-8"))[backup_path.name]

    acl_sddl = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$acl = Get-Acl -LiteralPath $args[0]; $acl.Sddl",
            str(security_dir),
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    owner_match = re.search(r"(?:^|;)O:(S-[^GDS]+)(?=G|D|S|$)", acl_sddl.strip())
    assert owner_match and owner_match.group(1) == "S-1-5-18"
    assert "A;" in acl_sddl
    assert "S-1-5-32-544" in acl_sddl
    assert "S-1-1-0" not in acl_sddl
    assert "S-1-5-11" not in acl_sddl
    assert "S-1-5-32-545" not in acl_sddl

    username = f"NoVirAcl{uuid.uuid4().hex[:12]}"
    password = f"NoVir-{uuid.uuid4().hex}-Aa9!"
    target = security_dir / "standard-user-write-test.txt"
    subprocess.run(
        ["net", "user", username, password, "/add", "/expires:never"],
        capture_output=True,
        text=True,
        check=True,
    )
    try:
        child_script = (
            "$target = $env:NOVIR_ACL_TARGET; "
            "try { [IO.File]::WriteAllText($target, 'tampered'); exit 0 } "
            "catch [UnauthorizedAccessException] { exit 5 } "
            "catch { exit 7 }"
        )
        env = os.environ.copy()
        env["NOVIR_ACL_TARGET"] = str(target)
        env["NOVIR_ACL_PASSWORD"] = password
        env["NOVIR_ACL_USERNAME"] = username
        access_attempt = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$secure = ConvertTo-SecureString $env:NOVIR_ACL_PASSWORD -AsPlainText -Force; "
                "$credential = [PSCredential]::new($env:NOVIR_ACL_USERNAME, $secure); "
                "$p = Start-Process powershell.exe -Credential $credential -WindowStyle Hidden "
                "-ArgumentList '-NoProfile','-NonInteractive','-Command', $args[0] -Wait -PassThru; "
                "exit $p.ExitCode",
                child_script,
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        assert access_attempt.returncode == 5, access_attempt.stderr
        assert not target.exists()
    finally:
        subprocess.run(
            ["net", "user", username, "/delete"],
            capture_output=True,
            text=True,
            check=False,
        )

    assert hashlib.sha256(backup_path.read_bytes()).hexdigest() in manifest_path.read_text(encoding="utf-8")


def _cleanup_test_directory(security_dir):
    """Restore temporary ACLs and fail teardown if cleanup was incomplete."""
    if not security_dir.exists():
        return
    take_ownership = subprocess.run(
        ["takeown", "/f", str(security_dir), "/a"],
        capture_output=True,
        text=True,
        check=False,
    )
    if take_ownership.returncode != 0:
        pytest.fail(
            "takeown failed during teardown: "
            f"{take_ownership.stdout}\n{take_ownership.stderr}"
        )
    grant_admin = subprocess.run(
        ["icacls", str(security_dir), "/grant:r", "Administrators:(OI)(CI)(F)"],
        capture_output=True,
        text=True,
        check=False,
    )
    grant_output = f"{grant_admin.stdout}\n{grant_admin.stderr}".lower()
    grant_failed = re.search(r"failed processing\s+([1-9]\d*)", grant_output)
    if grant_admin.returncode != 0 or grant_failed or "access is denied" in grant_output:
        pytest.fail(
            "icacls administrator grant failed during teardown: "
            f"{grant_admin.stdout}\n{grant_admin.stderr}"
        )
    reset = subprocess.run(
        ["icacls", str(security_dir), "/reset"],
        capture_output=True,
        text=True,
        check=False,
    )
    reset_output = f"{reset.stdout}\n{reset.stderr}".lower()
    reset_failed = re.search(r"failed processing\s+([1-9]\d*)", reset_output)
    if reset.returncode != 0 or reset_failed or "access is denied" in reset_output:
        pytest.fail(
            "icacls reset failed during teardown: "
            f"{reset.stdout}\n{reset.stderr}"
        )
    try:
        shutil.rmtree(security_dir)
    except OSError as error:
        pytest.fail(f"temporary ACL directory removal failed: {error}")
    if security_dir.exists():
        pytest.fail(f"temporary ACL directory still exists: {security_dir}")
