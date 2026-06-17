"""Enforcement coverage matrix — verification harness.

Proves *interception*, not just regex matching, for every supported manager
across multiple invocation paths.

Layers exercised:
  * registry      — classification of commands / argv vectors (all managers).
  * PATH shim     — fake manager binaries on PATH; assert bad blocked + real
                    binary never ran, good proceeds + scanner called once.
  * execve (LD_PRELOAD, Linux+cc) — absolute-path invocations blocked.
  * proxy         — decide() block/allow/fail-closed + request path parsing.

The shim/execve tests use *fake* manager binaries that record their argv, and a
*fake* ``agentshield`` that blocks a sentinel package — so nothing real is
installed and no network is touched.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from agentshield.enforce import registry, shim

# ── registry coverage matrix ──────────────────────────────────────────────────

# (command, expected manager, expected ecosystem value or None, expected packages)
_MATRIX = [
    ("pip install requests", "pip", "pypi", ["requests"]),
    ("pip3 install requests", "pip", "pypi", ["requests"]),
    ("python -m pip install requests", "python-m-pip", "pypi", ["requests"]),
    ("python3.11 -m pip install requests", "python-m-pip", "pypi", ["requests"]),
    ("uv pip install requests", "uv-pip", "pypi", ["requests"]),
    ("uv add requests", "uv-add", "pypi", ["requests"]),
    ("npm install lodash", "npm", "npm", ["lodash"]),
    ("npm i lodash", "npm", "npm", ["lodash"]),
    ("yarn add react", "yarn", "npm", ["react"]),
    ("pnpm add vue", "pnpm", "npm", ["vue"]),
    ("pnpm install vue", "pnpm", "npm", ["vue"]),
    ("bun add hono", "bun", "npm", ["hono"]),
    ("bun install hono", "bun", "npm", ["hono"]),
    ("cargo add serde", "cargo", "cargo", ["serde"]),
    ("cargo install ripgrep", "cargo", "cargo", ["ripgrep"]),
    ("poetry add flask", "poetry", "pypi", ["flask"]),
    ("pipx install black", "pipx", "pypi", ["black"]),
    ("conda install numpy", "conda", "pypi", ["numpy"]),
    ("gem install rails", "gem", None, ["rails"]),
    ("go install example.com/cmd@latest", "go", None, ["example.com/cmd"]),
]


@pytest.mark.parametrize("command,manager,eco,packages", _MATRIX)
def test_registry_parse_command_matrix(command, manager, eco, packages):
    installs = registry.parse_command(command)
    assert len(installs) == 1, f"{command!r} -> {installs}"
    inst = installs[0]
    assert inst.manager == manager
    assert (inst.ecosystem.value if inst.ecosystem else None) == eco
    assert inst.packages == packages


def test_no_install_command_is_ignored():
    assert registry.parse_command("ls -la /tmp") == []
    assert registry.parse_command("python app.py") == []
    assert registry.parse_command("pip list") == []


def test_pnpm_is_not_an_npm_substring_accident():
    # `pnpm add` must be classified as pnpm, never npm; bare `npm` substring must
    # not produce a spurious npm match.
    installs = registry.parse_command("pnpm add vue")
    assert [i.manager for i in installs] == ["pnpm"]


def test_uv_pip_not_double_counted_as_pip():
    installs = registry.parse_command("uv pip install requests")
    assert [i.manager for i in installs] == ["uv-pip"]


# ── invocation-path coverage (argv) ───────────────────────────────────────────

_ARGV = [
    (["pip", "install", "x"], "pip"),
    (["/usr/bin/pip", "install", "x"], "pip"),  # absolute path
    (["python", "-m", "pip", "install", "x"], "python-m-pip"),
    (["/opt/py/bin/python3", "-m", "pip", "install", "x"], "python-m-pip"),
    (["uv", "add", "x"], "uv-add"),
    (["go", "install", "y"], "go"),
    (["npm", "i", "z"], "npm"),
]


@pytest.mark.parametrize("argv,manager", _ARGV)
def test_registry_parse_argv(argv, manager):
    inst = registry.parse_argv(argv)
    assert inst is not None and inst.manager == manager


@pytest.mark.parametrize("argv", [["ls", "-la"], ["python", "app.py"], ["pip", "list"]])
def test_registry_parse_argv_negatives(argv):
    assert registry.parse_argv(argv) is None


# ── boolean install flags must not swallow the package name ───────────────────
# Regression for the audit finding: a boolean flag wrongly listed in VALUE_FLAGS
# makes the tokenizer skip the *following* token (the package), so the install is
# parsed as zero packages and silently bypasses scanning.

# (command, manager, ecosystem value, expected packages)
_BOOLEAN_FLAG_MATRIX = [
    # npm boolean flags (long + short) — the package must survive in every spot.
    ("npm install --save-exact lodash", "npm", "npm", ["lodash"]),
    ("npm install -E lodash", "npm", "npm", ["lodash"]),
    ("npm install --save-dev typescript", "npm", "npm", ["typescript"]),
    ("npm install -D typescript", "npm", "npm", ["typescript"]),
    ("npm install --save-optional left-pad", "npm", "npm", ["left-pad"]),
    ("npm install -O left-pad", "npm", "npm", ["left-pad"]),
    ("npm install --save-prod express", "npm", "npm", ["express"]),
    ("npm install -P express", "npm", "npm", ["express"]),
    ("npm install --global typescript", "npm", "npm", ["typescript"]),
    ("npm install -g typescript", "npm", "npm", ["typescript"]),
    ("npm install --no-save lodash", "npm", "npm", ["lodash"]),
    ("npm install --save-exact --save-dev lodash", "npm", "npm", ["lodash"]),
    # yarn / pnpm / bun equivalents.
    ("yarn add --exact react", "yarn", "npm", ["react"]),
    ("yarn add --dev react", "yarn", "npm", ["react"]),
    ("pnpm add --save-exact vue", "pnpm", "npm", ["vue"]),
    ("pnpm add --save-dev vue", "pnpm", "npm", ["vue"]),
    ("pnpm add -D vue", "pnpm", "npm", ["vue"]),
    ("bun add --exact hono", "bun", "npm", ["hono"]),
    ("bun add --dev hono", "bun", "npm", ["hono"]),
    # pip boolean flags must likewise not eat the package.
    ("pip install --user requests", "pip", "pypi", ["requests"]),
    ("pip install --upgrade requests", "pip", "pypi", ["requests"]),
    ("pip install --no-deps requests", "pip", "pypi", ["requests"]),
]


@pytest.mark.parametrize("command,manager,eco,packages", _BOOLEAN_FLAG_MATRIX)
def test_boolean_flags_do_not_swallow_package_parse_command(command, manager, eco, packages):
    installs = registry.parse_command(command)
    assert len(installs) == 1, f"{command!r} -> {installs}"
    inst = installs[0]
    assert inst.manager == manager
    assert (inst.ecosystem.value if inst.ecosystem else None) == eco
    assert inst.packages == packages, f"{command!r} dropped the package -> bypass"


@pytest.mark.parametrize("command,manager,eco,packages", _BOOLEAN_FLAG_MATRIX)
def test_boolean_flags_do_not_swallow_package_parse_argv(command, manager, eco, packages):
    inst = registry.parse_argv(command.split())
    assert inst is not None, f"{command!r} not recognised as an install"
    assert inst.manager == manager
    assert inst.packages == packages, f"{command!r} dropped the package -> bypass"


def test_value_flags_still_consume_their_value():
    # The fix must not over-correct: genuine value flags must keep consuming the
    # following token, so a registry URL is never mistaken for a package.
    installs = registry.parse_command("npm install --registry https://r.example lodash")
    assert len(installs) == 1
    assert installs[0].packages == ["lodash"]
    installs = registry.parse_command("pip install -i https://pypi.example/simple requests")
    assert installs[0].packages == ["requests"]


# ── shim / execve fixtures ────────────────────────────────────────────────────

_SENTINEL = "evil-pkg"


def _write_exec(path: Path, content: str) -> Path:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture
def fake_env(tmp_path: Path):
    """A realistic enough environment: real (fake) manager binaries that record
    their argv, plus a fake `agentshield` that blocks the sentinel package."""
    realbin = tmp_path / "realbin"
    realbin.mkdir()
    marker = tmp_path / "ran.log"
    scanlog = tmp_path / "scan.log"

    for binary in registry.shadow_binaries():
        _write_exec(
            realbin / binary,
            f'#!/usr/bin/env bash\necho "RAN {binary} $*" >> "{marker}"\nexit 0\n',
        )

    fake_as_dir = tmp_path / "asbin"
    fake_as_dir.mkdir()
    fake_as = _write_exec(
        fake_as_dir / "agentshield",
        f'''#!/usr/bin/env bash
echo "SCAN $*" >> "{scanlog}"
if [ "$1" = "guard-scan-cmd" ]; then
    shift
    for a in "$@"; do
        if [ "$a" = "{_SENTINEL}" ]; then exit 1; fi
    done
fi
exit 0
''',
    )
    return {
        "tmp": tmp_path,
        "realbin": realbin,
        "marker": marker,
        "scanlog": scanlog,
        "agentshield": fake_as,
    }


# ── PATH shim enforcement ─────────────────────────────────────────────────────


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
class TestShimEnforcement:
    def _run(self, fake_env, shim_dir, command: str):
        env = {
            **os.environ,
            "PATH": f"{shim_dir}:{fake_env['realbin']}:{os.environ.get('PATH', '')}",
            "AGENTSHIELD_BIN": str(fake_env["agentshield"]),
        }
        return subprocess.run(["bash", "-c", command], env=env, capture_output=True, text=True)

    def test_shim_blocks_bad_and_real_never_runs(self, fake_env, tmp_path):
        shim_dir, installed = shim.install(tmp_path / "shim")
        assert "pip" in installed
        res = self._run(fake_env, shim_dir, f"pip install {_SENTINEL}")
        assert res.returncode != 0
        assert not fake_env["marker"].exists(), "real pip must NOT have run"

    def test_shim_allows_good_and_scanner_called_once(self, fake_env, tmp_path):
        shim_dir, _ = shim.install(tmp_path / "shim")
        res = self._run(fake_env, shim_dir, "pip install requests")
        assert res.returncode == 0, res.stderr
        assert fake_env["marker"].read_text().count("RAN pip") == 1
        assert fake_env["scanlog"].read_text().count("SCAN") == 1

    def test_shim_covers_command_builtin(self, fake_env, tmp_path):
        shim_dir, _ = shim.install(tmp_path / "shim")
        res = self._run(fake_env, shim_dir, f"command pip install {_SENTINEL}")
        assert res.returncode != 0
        assert not fake_env["marker"].exists()

    @pytest.mark.parametrize("mgr,sub", [("npm", "install"), ("cargo", "add"), ("pipx", "install")])
    def test_shim_blocks_across_managers(self, fake_env, tmp_path, mgr, sub):
        shim_dir, _ = shim.install(tmp_path / "shim")
        res = self._run(fake_env, shim_dir, f"{mgr} {sub} {_SENTINEL}")
        assert res.returncode != 0
        assert not fake_env["marker"].exists()


# ── execve (LD_PRELOAD) enforcement — absolute path ───────────────────────────


@pytest.mark.skipif(
    platform.system() != "Linux"
    or shutil.which("bash") is None
    or not (shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")),
    reason="Linux + bash + C compiler required for execve interception",
)
class TestExecveEnforcement:
    def _build(self, tmp_path: Path) -> Path:
        from agentshield.enforce import execve

        return execve.build(tmp_path / "libas.so")

    def _run_abs(self, fake_env, so: Path, pip_path: Path, pkg: str):
        env = {
            **os.environ,
            "LD_PRELOAD": str(so),
            "AGENTSHIELD_BIN": str(fake_env["agentshield"]),
        }
        # Absolute path bypasses PATH/shim; only execve hook can catch it.
        return subprocess.run(
            ["bash", "-c", f'"{pip_path}" install {pkg}'],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_execve_blocks_absolute_path_bad(self, fake_env, tmp_path):
        so = self._build(tmp_path)
        pip_path = fake_env["realbin"] / "pip"
        res = self._run_abs(fake_env, so, pip_path, _SENTINEL)
        assert res.returncode != 0
        assert not fake_env["marker"].exists(), "absolute-path pip must be blocked"

    def test_execve_allows_absolute_path_good(self, fake_env, tmp_path):
        so = self._build(tmp_path)
        pip_path = fake_env["realbin"] / "pip"
        res = self._run_abs(fake_env, so, pip_path, "requests")
        assert res.returncode == 0, res.stderr
        assert fake_env["marker"].read_text().count("RAN pip") == 1

    def _run_abs_env(self, fake_env, so: Path, pip_path: Path, pkg: str, extra_env: dict):
        env = {**os.environ, "LD_PRELOAD": str(so), **extra_env}
        return subprocess.run(
            ["bash", "-c", f'"{pip_path}" install {pkg}'],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_execve_fails_closed_when_scanner_missing(self, fake_env, tmp_path):
        # Scanner unavailable (AGENTSHIELD_BIN points nowhere) must BLOCK a managed
        # binary by default — the fail-closed promise for the absolute-path layer.
        so = self._build(tmp_path)
        pip_path = fake_env["realbin"] / "pip"
        res = self._run_abs_env(
            fake_env, so, pip_path, "requests", {"AGENTSHIELD_BIN": str(tmp_path / "nope")}
        )
        assert res.returncode != 0
        assert not fake_env["marker"].exists(), "managed install ran despite missing scanner"
        assert "fail-closed" in res.stderr.lower()

    def test_execve_emergency_fail_open_env_allows(self, fake_env, tmp_path):
        # The documented emergency override re-opens the gate, loudly.
        so = self._build(tmp_path)
        pip_path = fake_env["realbin"] / "pip"
        res = self._run_abs_env(
            fake_env,
            so,
            pip_path,
            "requests",
            {"AGENTSHIELD_BIN": str(tmp_path / "nope"), "AGENTSHIELD_EXEC_FAIL_OPEN": "1"},
        )
        assert res.returncode == 0, res.stderr
        assert fake_env["marker"].read_text().count("RAN pip") == 1
        assert "emergency mode" in res.stderr.lower()

    def test_execve_unmanaged_binary_unaffected_when_scanner_missing(self, fake_env, tmp_path):
        # Only managed entrypoints fail closed; an unrelated binary still runs.
        so = self._build(tmp_path)
        env = {**os.environ, "LD_PRELOAD": str(so), "AGENTSHIELD_BIN": str(tmp_path / "nope")}
        res = subprocess.run(
            ["bash", "-c", "/bin/echo hello-unmanaged"],
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0 and "hello-unmanaged" in res.stdout


# ── proxy ─────────────────────────────────────────────────────────────────────


class TestProxy:
    def test_parse_request_path(self):
        from agentshield.core.models import Ecosystem
        from agentshield.enforce.proxy import parse_request_path

        assert parse_request_path("/simple/requests/") == (Ecosystem.PYPI, "requests")
        assert parse_request_path("/pypi/simple/flask/") == (Ecosystem.PYPI, "flask")
        assert parse_request_path("/npm/lodash") == (Ecosystem.NPM, "lodash")
        assert parse_request_path("/@scope/pkg") == (Ecosystem.NPM, "@scope/pkg")
        assert parse_request_path("/") is None

    def test_decide_allow_block_and_fail_closed(self, monkeypatch):
        from agentshield.core.models import (
            Decision,
            DecisionAction,
            Ecosystem,
            ScanResult,
            Severity,
        )
        from agentshield.enforce.proxy import ProxyScreen

        screen = ProxyScreen()

        async def _allow(req):
            return ScanResult(
                request=req,
                findings=[],
                max_severity=Severity.NONE,
                decision=Decision(action=DecisionAction.ALLOW, reason="clean"),
            )

        async def _block(req):
            return ScanResult(
                request=req,
                findings=[],
                max_severity=Severity.CRITICAL,
                decision=Decision(action=DecisionAction.BLOCK, reason="malicious"),
            )

        async def _boom(req):
            raise RuntimeError("network down")

        monkeypatch.setattr(screen.shield, "ascan", _allow)
        ok, _ = screen.decide("requests", Ecosystem.PYPI)
        assert ok is True

        monkeypatch.setattr(screen.shield, "ascan", _block)
        ok, reason = screen.decide("evil", Ecosystem.PYPI)
        assert ok is False and "malicious" in reason

        monkeypatch.setattr(screen.shield, "ascan", _boom)
        ok, reason = screen.decide("whatever", Ecosystem.PYPI)
        assert ok is False and "fail closed" in reason

    def test_proxy_env_injection(self):
        from agentshield.enforce.proxy import proxy_env, proxy_export_lines

        env = proxy_env("127.0.0.1", 8799)
        assert env["PIP_INDEX_URL"] == "http://127.0.0.1:8799/simple/"
        assert env["UV_INDEX_URL"] == "http://127.0.0.1:8799/simple/"
        assert env["npm_config_registry"] == "http://127.0.0.1:8799/npm/"
        lines = proxy_export_lines("h", 1234)
        assert any(ln == 'export PIP_INDEX_URL="http://h:1234/simple/"' for ln in lines)

    def test_decide_blocks_on_malicious_transitive_dep(self, monkeypatch):
        from agentshield.core.models import (
            Decision,
            DecisionAction,
            Ecosystem,
            ScanRequest,
            ScanResult,
            Severity,
        )
        from agentshield.enforce.proxy import ProxyScreen

        screen = ProxyScreen(transitive=True)

        async def _clean_pkg_dirty_dep(req):
            dep = ScanResult(
                request=ScanRequest(package="evil-dep", ecosystem=Ecosystem.PYPI),
                findings=[],
                max_severity=Severity.CRITICAL,
                decision=Decision(action=DecisionAction.BLOCK, reason="malicious dep"),
            )
            return ScanResult(
                request=req,
                findings=[],
                max_severity=Severity.NONE,
                decision=Decision(action=DecisionAction.ALLOW, reason="pkg clean"),
                transitive_results=[dep],
            )

        monkeypatch.setattr(screen.shield, "ascan", _clean_pkg_dirty_dep)
        ok, reason = screen.decide("toppkg", Ecosystem.PYPI)
        assert ok is False
        assert "transitive dependency" in reason and "evil-dep" in reason


# ── conda channel handling ────────────────────────────────────────────────────


class TestCondaChannels:
    def test_default_channel_is_pypi_best_effort(self):
        installs = registry.parse_command("conda install numpy")
        assert len(installs) == 1
        assert installs[0].ecosystem is not None and installs[0].ecosystem.value == "pypi"
        assert installs[0].packages == ["numpy"]

    def test_trusted_channel_flag_is_pypi(self):
        installs = registry.parse_command("conda install -c conda-forge numpy")
        assert [i.ecosystem.value if i.ecosystem else None for i in installs] == ["pypi"]
        assert installs[0].packages == ["numpy"]

    def test_untrusted_channel_flag_fails_closed(self):
        installs = registry.parse_command("conda install --channel sketchy evilpkg")
        assert len(installs) == 1
        inst = installs[0]
        assert inst.ecosystem is None
        assert inst.packages == ["evilpkg"]
        assert inst.unverifiable_reason and "sketchy" in inst.unverifiable_reason

    def test_untrusted_channel_spec_syntax_fails_closed(self):
        installs = registry.parse_command("conda install sketchy::trojan")
        assert installs[0].ecosystem is None
        assert installs[0].packages == ["trojan"]

    def test_trusted_channel_spec_syntax_is_pypi(self):
        installs = registry.parse_command("conda install conda-forge::numpy")
        assert installs[0].ecosystem is not None
        assert installs[0].packages == ["numpy"]

    def test_version_spec_stripped(self):
        installs = registry.parse_command("conda install numpy=1.24 scipy")
        assert installs[0].packages == ["numpy", "scipy"]

    def test_conda_parser_unit(self):
        from agentshield.enforce import conda

        pkgs = conda.parse_conda_install(["-c", "conda-forge", "numpy", "badchan::x"])
        by_name = {p.name: p for p in pkgs}
        assert by_name["numpy"].trusted is True
        assert by_name["x"].trusted is False and by_name["x"].channel == "badchan"


# ── execve macOS source generation ────────────────────────────────────────────


class TestExecveMacOS:
    def test_macos_source_uses_interpose_not_dlsym(self):
        from agentshield.enforce import execve

        src = execve.c_source("Darwin")
        assert "__DATA,__interpose" in src
        assert "dlsym" not in src
        # managed binaries embedded
        assert '"pip"' in src and '"conda"' in src

    def test_linux_source_uses_dlsym_not_interpose(self):
        from agentshield.enforce import execve

        src = execve.c_source("Linux")
        assert "dlsym" in src
        assert "__interpose" not in src

    def test_library_name_and_env_var_per_platform(self):
        from pathlib import Path

        from agentshield.enforce import execve

        assert execve.library_name("Darwin") == "libagentshield_exec.dylib"
        assert execve.library_name("Linux") == "libagentshield_exec.so"
        assert execve.preload_env_var(Path("/x/lib.dylib")) == "DYLD_INSERT_LIBRARIES"
        assert execve.preload_env_var(Path("/x/lib.so")) == "LD_PRELOAD"

    def test_preload_line_macos(self):
        from pathlib import Path

        from agentshield.enforce import execve

        line = execve.preload_env_line(Path("/opt/libagentshield_exec.dylib"))
        assert line.startswith("export DYLD_INSERT_LIBRARIES=")


# ── execve fail-closed source generation (platform-independent) ───────────────


class TestExecveFailClosedSource:
    @pytest.mark.parametrize("target", ["Linux", "Darwin"])
    def test_error_paths_route_through_fail_verdict(self, target):
        from agentshield.enforce import execve

        src = execve.c_source(target)
        # The helper exists and is keyed on the emergency env var.
        assert "as_fail_verdict" in src
        assert "AGENTSHIELD_EXEC_FAIL_OPEN" in src
        # Each unverifiable condition for a managed binary must fail closed via the
        # helper rather than the old bare `return 1` (allow).
        assert "calloc failure" in src  # allocation failure
        assert 'as_fail_verdict("fork failure")' in src  # fork failure
        assert "agentshield not found" in src  # scanner missing (rc 127)
        assert "terminated abnormally" in src  # child killed / no WIFEXITED
        # Regression guard: the old fail-open rationale must be gone.
        assert "fail open so we don't brick" not in src
        assert "scanner not found -> allow" not in src

    def test_default_is_fail_closed_not_open(self):
        from agentshield.enforce import execve

        src = execve.c_source("Linux")
        # Fail-open must be gated behind getenv(AGENTSHIELD_EXEC_FAIL_OPEN); the
        # default branch returns 0 (block).
        assert 'getenv("AGENTSHIELD_EXEC_FAIL_OPEN")' in src
        assert "return 0; /* fail closed: block */" in src
