"""Real process CLI tests (no network — probe is mocked via KEYTRUTH test hook)."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
CLI = ROOT / "keytruth.py"


def _run(args, env=None, input_text=None):
    e = os.environ.copy()
    e["PYTHONPATH"] = str(ROOT)
    if env:
        e.update(env)
    return subprocess.run(
        [PY, str(CLI), *args],
        cwd=str(ROOT),
        env=e,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )


def test_cli_scan_json(tmp_path, monkeypatch):
    openai = "sk-proj-" + ("A" * 48)
    stripe = "sk_live_" + ("B" * 24)
    (tmp_path / ".env").write_text(
        f"OPENAI_API_KEY={openai}\nSTRIPE_SECRET_KEY={stripe}\n"
    )
    (tmp_path / ".env.2").write_text(f"OPENAI_API_KEY={openai}\n")

    cache = tmp_path / "cache.json"
    # Monkeypatch via env is unavailable; patch module file location by
    # running through python -c wrapper that sets CACHE_FILE.
    script = f"""
import keytruth
from pathlib import Path
keytruth.CACHE_FILE = Path({str(cache)!r})
import sys
sys.argv = ["keytruth", "scan", {str(tmp_path)!r}, "--json", "--no-color"]
keytruth.main()
"""
    r = subprocess.run([PY, "-c", script], cwd=str(ROOT), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert isinstance(data, list)
    assert any(d["provider"] == "OPENAI" and d["risk"] == "CRITICAL" for d in data)
    assert cache.exists()
    assert openai not in cache.read_text()


def test_cli_help():
    r = _run(["--help"])
    assert r.returncode == 0
    assert "scan" in r.stdout
    assert "probe" in r.stdout
    assert "show" in r.stdout


def test_cli_scan_then_probe_debug(tmp_path):
    openai = "sk-proj-" + ("A" * 48)
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={openai}\n")
    cache = tmp_path / "cache.json"

    scan = f"""
import keytruth
from pathlib import Path
keytruth.CACHE_FILE = Path({str(cache)!r})
import sys
sys.argv = ["keytruth", "scan", {str(tmp_path)!r}, "--no-color"]
keytruth.main()
"""
    r = subprocess.run([PY, "-c", scan], cwd=str(ROOT), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "PROVIDER" in r.stdout
    assert "OPENAI" in r.stdout

    probe = f"""
import keytruth
from pathlib import Path
keytruth.CACHE_FILE = Path({str(cache)!r})

def mock_request(url, method="GET", headers=None, data=None):
    if "moderations" in url:
        return 200, "{{}}", 3
    if "openai.com" in url:
        return 200, '{{"data":[]}}', 3
    return 401, "{{}}", 3

keytruth.make_request = mock_request
import sys
sys.argv = ["keytruth", "probe", "--yes", "--debug", "--no-color"]
keytruth.main()
"""
    r = subprocess.run([PY, "-c", probe], cwd=str(ROOT), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + r.stdout
    assert "=== OPENAI" in r.stdout
    assert "[/v1/models]" in r.stdout
    assert "auth=Valid" in r.stdout
    assert "--- facts ---" in r.stdout

    show_id = json.loads(cache.read_text())["probe"]["results"][0]["hash"][:8]
    show = f"""
import keytruth
from pathlib import Path
keytruth.CACHE_FILE = Path({str(cache)!r})
import sys
sys.argv = ["keytruth", "show", {show_id!r}, "--no-color"]
keytruth.main()
"""
    r = subprocess.run([PY, "-c", show], cwd=str(ROOT), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert show_id in r.stdout
    assert "action:" in r.stdout
