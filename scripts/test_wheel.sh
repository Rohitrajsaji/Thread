#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
scratch="$(mktemp -d /tmp/thread-wheel.XXXXXXXX)"
trap 'rm -rf -- "$scratch"' EXIT

if [[ -x "$root/.venv/bin/python" ]]; then
    default_python="$root/.venv/bin/python"
else
    default_python=python3
fi
python_bin="${THREAD_PYTHON:-$default_python}"
export TMPDIR=/tmp PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
unset PYTHONHOME PYTHONPATH

"$python_bin" - "$root" "$scratch/source" <<'PY'
from pathlib import Path
import shutil
import sys

source, target = map(Path, sys.argv[1:])
target.mkdir()
for name in ("pyproject.toml", "README.md"):
    shutil.copy2(source / name, target / name)
shutil.copytree(
    source / "src", target / "src",
    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
)
PY

"$python_bin" -m build --wheel --outdir "$scratch/dist" "$scratch/source"
"$python_bin" -m venv "$scratch/venv"
installed_python="$scratch/venv/bin/python"
thread="$scratch/venv/bin/thread"
wheel=("$scratch/dist"/thread_sdlc-*.whl)
[[ "${#wheel[@]}" -eq 1 && -f "${wheel[0]}" ]]
"$installed_python" -m pip install "${wheel[0]}"
"$installed_python" -m pip check

fixture="$scratch/fixture"
git init -q -b main "$fixture"
"$thread" --help
"$thread" init --repo "$fixture"
"$thread" compile --check --repo "$fixture"

"$installed_python" -I - "$thread" "$fixture" <<'PY'
import importlib.metadata
import json
from html.parser import HTMLParser
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, ProxyHandler, build_opener

import thread_sdlc


class AssetLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = set()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "script":
            url = attributes.get("src")
        elif tag == "link" and attributes.get("rel") == "stylesheet":
            url = attributes.get("href")
        else:
            return
        if url and url.startswith("/assets/"):
            self.urls.add(url)


dist = importlib.metadata.distribution("thread-sdlc")
source = json.loads(dist.read_text("direct_url.json"))
assert source["url"].endswith(".whl") and not source.get("dir_info", {}).get("editable")
assert Path(thread_sdlc.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())

thread, fixture = sys.argv[1:]
with subprocess.Popen(
    [thread, "ui", "--repo", fixture, "--port", "0"],
    cwd=fixture, stdout=subprocess.PIPE, text=True,
) as server:
    try:
        with selectors.DefaultSelector() as readiness:
            readiness.register(server.stdout, selectors.EVENT_READ)
            assert readiness.select(timeout=15), "Thread UI did not print its launch URL"
        launch = re.fullmatch(r"Open (http://127\.0\.0\.1:\d+/\?token=\S+)\s*", server.stdout.readline())
        assert launch, "Thread UI did not report its tokenized loopback URL"
        url = launch[1]
        origin = f"http://{urlsplit(url).netloc}"
        opener = build_opener(ProxyHandler({}), HTTPCookieProcessor())
        deadline = time.monotonic() + 10
        while True:
            try:
                with opener.open(url, timeout=2) as response:
                    assert response.status == 200 and response.url == f"{origin}/"
                    assets = AssetLinks()
                    assets.feed(response.read().decode())
                break
            except URLError as error:
                if not isinstance(error.reason, ConnectionRefusedError) or time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        assert {Path(url).suffix for url in assets.urls} >= {".js", ".css"}, assets.urls
        for url in sorted(assets.urls):
            with opener.open(origin + url, timeout=5) as response:
                assert response.status == 200 and response.read(), url
        print("PASS installed wheel: authenticated UI HTML, JavaScript and CSS returned HTTP 200.")
    finally:
        server.terminate()
        try:
            server.wait(timeout=8)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
PY
