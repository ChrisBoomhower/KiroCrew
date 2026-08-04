"""Tests for the per-app third-party trust-grant REST API.

Covers the 4 endpoints in ``dashboard/handlers/security.py`` that write
``agent.apps_trusted`` / ``agent.apps_allow_third_party`` in ``config.json``,
plus the end-to-end property that actually matters: a grant flips
``apps.execution.app_execution_denied`` for THAT app and leaves every other
third-party app denied.

The aiohttp handlers are exercised through an in-test ``TestClient`` opened with
``async with`` (matching ``test_denied_commands_api.py``) rather than an
async-gen fixture: the CI-pinned ``pytest-asyncio==0.20.3`` is incompatible with
the pinned ``pytest==8.4.1`` for async fixtures, so the whole suite avoids
``@pytest_asyncio.fixture`` by convention.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from kiro_crew.apps.manager import (
    APP_MANIFEST_FILENAME,
    _read_installed,
    _write_installed,
    install_app,
)
from kiro_crew.dashboard.handlers import security
from kiro_crew.dashboard.handlers.security import (
    api_trusted_app_grant,
    api_trusted_app_revoke,
    api_trusted_apps_allow_all,
    api_trusted_apps_list,
    build_trusted_apps_snapshot,
)

_APP = "trust-test-app"
_OTHER = "other-test-app"

# A real builtin: its name is declared by a SHIPPED app.json, so it is exempt at
# the gate and must never be granted or torn down by this surface.
_BUILTIN = "file-explorer"

# A POPULATED config.json with a syntax error (trailing comma after
# max_subagents). Every distinctive value below is one ``KiroCrewConfig.load()``
# would silently replace with a default — so a mutation that loaded this file and
# saved it back would erase the model, the subagent cap, the external registry
# and the dashboard settings. The regression assertion is byte-identity, not the
# presence of the 409.
_CORRUPT_CONFIG = """{
  "agent": {
    "model": "distinctive-sentinel-model",
    "max_subagents": 7,
  },
  "registries": [
    {"name": "distinctive-registry", "repo": "acme/apps", "branch": "release"}
  ],
  "dashboard": {"port": 41999, "host": "127.0.0.101"}
}"""

# Values that must survive a refused mutation verbatim.
_CORRUPT_SENTINELS = (
    "distinctive-sentinel-model",
    '"max_subagents": 7',
    "distinctive-registry",
    "acme/apps",
    '"port": 41999',
    "127.0.0.101",
)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect KIROCREW_HOME so config.json + installed apps land in tmp."""
    h = tmp_path / "kirocrew-home"
    h.mkdir()
    monkeypatch.setenv("KIROCREW_HOME", str(h))
    return h


@pytest.fixture
def mock_sel():
    """Patch the late-bound ``_sel()`` so SEL audit calls are observable."""
    with patch("kiro_crew.dashboard.handlers.security._sel") as m:
        instance = MagicMock()
        m.return_value = instance
        yield instance


def _install(
    tmp_path: Path,
    name: str,
    *,
    enabled: bool = False,
    builtin: bool = False,
    entry_point: str | None = None,
    body: str = "",
) -> None:
    """Install a minimal app record under the tmp KIROCREW_HOME.

    ``builtin=True`` marks the install builtin-OWNED (``source``/``origin`` ==
    ``builtin``), which is what ``manager.builtin_owns_installed`` checks. Combined
    with a *name* a shipped ``app.json`` declares (``_BUILTIN``), that is the only
    way a name enters ``execution.builtin_app_names()``.

    ``entry_point`` declares a gateway-spawned backend so the app has real code to
    stop; *body* is written to that file.
    """
    source = tmp_path / "source" / name
    source.mkdir(parents=True)
    manifest: dict[str, Any] = {
        "name": name,
        "version": "1.0.0",
        "displayName": name,
        "description": "trust grant fixture",
        "author": "tester",
    }
    if entry_point:
        manifest["backend"] = {"entryPoint": entry_point, "runtime": "python"}
        (source / entry_point).write_text(body, encoding="utf-8")
    (source / APP_MANIFEST_FILENAME).write_text(json.dumps(manifest), encoding="utf-8")
    assert install_app(source).ok
    meta = _read_installed(name)
    assert meta is not None
    meta.enabled = enabled
    meta.origin = "builtin" if builtin else "registry"
    if builtin:
        meta.source = "builtin"
    meta.resources = "gateway"
    _write_installed(name, meta)


def _make_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/api/security/trusted-apps", api_trusted_apps_list)
    app.router.add_put("/api/security/trusted-apps/allow-all", api_trusted_apps_allow_all)
    app.router.add_post("/api/security/trusted-apps/{name}", api_trusted_app_grant)
    app.router.add_delete("/api/security/trusted-apps/{name}", api_trusted_app_revoke)
    return app


def _client() -> TestClient:
    """Build an aiohttp TestClient — open with ``async with`` inside each test."""
    return TestClient(TestServer(_make_app()))


def _stored(home: Path) -> dict[str, Any]:
    """The persisted ``agent`` section of config.json (``{}`` before first save)."""
    path = home / "config.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    agent = data.get("agent")
    return agent if isinstance(agent, dict) else {}


# ── snapshot ──


def test_snapshot_defaults_to_empty_and_denied(home: Path):
    assert build_trusted_apps_snapshot() == {"apps": [], "ineffective": [], "allowAll": False}


def test_snapshot_sorts_and_dedupes_and_drops_junk(home: Path):
    (home / "config.json").write_text(
        json.dumps({"agent": {"apps_trusted": ["zebra", "apple", "apple", "", 5, {}]}}),
        encoding="utf-8",
    )
    assert build_trusted_apps_snapshot()["apps"] == ["apple", "zebra"]


def test_snapshot_allow_all_string_true_is_not_truthy(home: Path):
    # Mirrors the gate's strict identity check: "true" must render (and enforce)
    # as False, never coerced.
    (home / "config.json").write_text(
        json.dumps({"agent": {"apps_allow_third_party": "true"}}), encoding="utf-8"
    )
    assert build_trusted_apps_snapshot()["allowAll"] is False


# ── GET ──


@pytest.mark.asyncio
async def test_get_returns_snapshot_shape(home: Path, mock_sel):
    async with _client() as client:
        resp = await client.get("/api/security/trusted-apps")
        assert resp.status == 200
        body = await resp.json()
        assert body == {"apps": [], "ineffective": [], "allowAll": False}
    # reads do not audit
    mock_sel.log_api_access.assert_not_called()


# ── grant ──


@pytest.mark.asyncio
async def test_grant_persists_and_is_idempotent(home: Path, tmp_path: Path, mock_sel):
    _install(tmp_path, _APP)
    async with _client() as client:
        first = await client.post(f"/api/security/trusted-apps/{_APP}")
        assert first.status == 200
        assert (await first.json()) == {"apps": [_APP], "ineffective": [], "allowAll": False}

        second = await client.post(f"/api/security/trusted-apps/{_APP}")
        assert second.status == 200
        # Idempotent: no duplicate entry in the response or on disk.
        assert (await second.json())["apps"] == [_APP]

    assert _stored(home)["apps_trusted"] == [_APP]
    ops = [c.kwargs["operation"] for c in mock_sel.log_api_access.call_args_list]
    assert ops == ["security.trusted_apps.grant"] * 2
    assert all(c.kwargs["outcome"] == "ok" for c in mock_sel.log_api_access.call_args_list)


@pytest.mark.asyncio
async def test_grant_of_uninstalled_app_404s_with_code(home: Path, mock_sel):
    async with _client() as client:
        resp = await client.post("/api/security/trusted-apps/ghost-app")
        assert resp.status == 404
        body = await resp.json()
        assert body["code"] == "app_not_installed"
        assert body["error"]
    assert build_trusted_apps_snapshot()["apps"] == []
    assert mock_sel.log_api_access.call_args.kwargs["outcome"] == "denied"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["-leading", "Upper", "has.dot", "has%20space"])
async def test_grant_invalid_name_400s_with_code(home: Path, mock_sel, name: str):
    async with _client() as client:
        resp = await client.post(f"/api/security/trusted-apps/{name}")
        assert resp.status == 400
        body = await resp.json()
        assert body["code"] == "invalid_app_name"
    assert build_trusted_apps_snapshot()["apps"] == []


@pytest.mark.asyncio
async def test_grant_preserves_existing_grants(home: Path, tmp_path: Path, mock_sel):
    _install(tmp_path, _APP)
    _install(tmp_path, _OTHER)
    async with _client() as client:
        await client.post(f"/api/security/trusted-apps/{_APP}")
        resp = await client.post(f"/api/security/trusted-apps/{_OTHER}")
        assert (await resp.json())["apps"] == sorted([_APP, _OTHER])


# ── revoke ──


@pytest.mark.asyncio
async def test_revoke_removes_grant_and_is_idempotent(home: Path, tmp_path: Path, mock_sel):
    _install(tmp_path, _APP)
    async with _client() as client:
        await client.post(f"/api/security/trusted-apps/{_APP}")

        first = await client.delete(f"/api/security/trusted-apps/{_APP}")
        assert first.status == 200
        assert (await first.json()) == {"apps": [], "ineffective": [], "allowAll": False, "disabled": False}

        # Revoking a name that holds no grant is a 200, not a 404.
        second = await client.delete(f"/api/security/trusted-apps/{_APP}")
        assert second.status == 200
        assert (await second.json())["apps"] == []

        never = await client.delete("/api/security/trusted-apps/never-granted")
        assert never.status == 200
        assert (await never.json())["disabled"] is False

    assert _stored(home)["apps_trusted"] == []


@pytest.mark.asyncio
async def test_revoke_disables_a_currently_enabled_app(home: Path, tmp_path: Path, mock_sel):
    _install(tmp_path, _APP, enabled=True)
    async with _client() as client:
        await client.post(f"/api/security/trusted-apps/{_APP}")
        resp = await client.delete(f"/api/security/trusted-apps/{_APP}")
        assert resp.status == 200
        body = await resp.json()

    # Revocation is EFFECTIVE, not merely declarative: the app's code stops.
    assert body["disabled"] is True
    meta = _read_installed(_APP)
    assert meta is not None and meta.enabled is False

    revokes = [
        c
        for c in mock_sel.log_api_access.call_args_list
        if c.kwargs["operation"] == "security.trusted_apps.revoke"
    ]
    assert revokes and "disabled=True" in revokes[-1].kwargs["resources"]


@pytest.mark.asyncio
async def test_revoke_of_disabled_app_reports_not_disabled(home: Path, tmp_path: Path, mock_sel):
    _install(tmp_path, _APP, enabled=False)
    async with _client() as client:
        await client.post(f"/api/security/trusted-apps/{_APP}")
        resp = await client.delete(f"/api/security/trusted-apps/{_APP}")
        assert (await resp.json())["disabled"] is False


# ── allow-all ──


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [True, False])
async def test_allow_all_sets_the_blanket_flag(home: Path, mock_sel, value: bool):
    async with _client() as client:
        resp = await client.put("/api/security/trusted-apps/allow-all", json={"value": value})
        assert resp.status == 200
        assert (await resp.json())["allowAll"] is value
    assert _stored(home)["apps_allow_third_party"] is value


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{"value": "true"}, {"value": 1}, {}, [], "nope"])
async def test_allow_all_rejects_non_bool_with_code(home: Path, mock_sel, body: Any):
    async with _client() as client:
        resp = await client.put("/api/security/trusted-apps/allow-all", json=body)
        assert resp.status == 400
        payload = await resp.json()
        assert payload["code"] == "invalid_value"
        assert payload["error"]
    assert build_trusted_apps_snapshot()["allowAll"] is False


@pytest.mark.asyncio
async def test_allow_all_rejects_unparseable_body_with_code(home: Path, mock_sel):
    async with _client() as client:
        resp = await client.put(
            "/api/security/trusted-apps/allow-all",
            data="{not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status == 400
        assert (await resp.json())["code"] == "invalid_value"


# ── the property that matters: a grant changes enforcement ──


@pytest.mark.asyncio
async def test_grant_admits_only_that_app(home: Path, tmp_path: Path, mock_sel):
    from kiro_crew.apps.execution import app_execution_denied

    _install(tmp_path, _APP)
    _install(tmp_path, _OTHER)

    # Baseline: both third-party apps are denied.
    assert app_execution_denied(_APP, action="enable") is not None
    assert app_execution_denied(_OTHER, action="enable") is not None

    async with _client() as client:
        assert (await client.post(f"/api/security/trusted-apps/{_APP}")).status == 200

    # The grant is narrow: it admits exactly the app named, nothing else.
    assert app_execution_denied(_APP, action="enable") is None
    assert app_execution_denied(_OTHER, action="enable") is not None

    async with _client() as client:
        assert (await client.delete(f"/api/security/trusted-apps/{_APP}")).status == 200

    # And revoking it takes effect immediately — no restart.
    assert app_execution_denied(_APP, action="enable") is not None


# ══════════════════════════════════════════════════════════════════════════
# Regression tests — five defects an adversarial review proved, each of which
# the suite above did NOT catch. Every test below asserts a POSTCONDITION
# (bytes on disk, a process's liveness, what the gate admits), not that a write
# happened, because "the metadata was written" is exactly what let these
# through.
# ══════════════════════════════════════════════════════════════════════════


# ── 1. a corrupt config.json is never clobbered ──


def _drive(client: TestClient, op: str, name: str):
    """Issue one of the three MUTATING trusted-apps requests."""
    if op == "grant":
        return client.post(f"/api/security/trusted-apps/{name}")
    if op == "revoke":
        return client.delete(f"/api/security/trusted-apps/{name}")
    return client.put("/api/security/trusted-apps/allow-all", json={"value": True})


@pytest.mark.asyncio
@pytest.mark.parametrize("op", ["grant", "revoke", "allow_all"])
async def test_mutation_on_corrupt_config_409s_without_clobbering(
    home: Path, tmp_path: Path, mock_sel, op: str
):
    # REGRESSION: ``KiroCrewConfig.load()`` degrades an unparseable config.json to
    # DEFAULTS. A blind load→mutate→save would therefore write those defaults over
    # a populated file and silently erase the model, the subagent cap, the external
    # registry and the dashboard settings — total config loss from a trailing
    # comma. ``_mutate_agent_config`` pre-flight-parses inside the config lock and
    # raises ConfigCorruptError instead. Byte-identity is the assertion that
    # matters; the 409 is only how the refusal is reported.
    _install(tmp_path, _APP)  # so grant fails on corruption, not on existence
    path = home / "config.json"
    path.write_text(_CORRUPT_CONFIG, encoding="utf-8")

    async with _client() as client:
        resp = await _drive(client, op, _APP)
        body = await resp.json()

    # POSTCONDITION FIRST: the file is untouched, byte-for-byte — not merely
    # "still parses". Asserted before the status code so a regression reports the
    # data loss it caused rather than a status mismatch.
    after = path.read_text(encoding="utf-8")
    # Spelled out per value so a partial rewrite names what it destroyed.
    for sentinel in _CORRUPT_SENTINELS:
        assert sentinel in after, f"mutation destroyed {sentinel!r} in config.json"
    assert after == _CORRUPT_CONFIG, "config.json was rewritten"

    # Only then: the refusal is reported as a coded 409 and audited.
    assert resp.status == 409
    assert body["code"] == "config_corrupt"
    assert body["error"]
    assert mock_sel.log_api_access.call_args.kwargs["outcome"] == "denied"


@pytest.mark.asyncio
async def test_corrupt_config_refusal_does_not_create_the_file(home: Path, mock_sel):
    # The pre-flight only guards an EXISTING file: with no config.json at all a
    # mutation must still succeed (first-ever write), so the guard cannot be
    # implemented as "refuse whenever the parse fails".
    async with _client() as client:
        resp = await client.put("/api/security/trusted-apps/allow-all", json={"value": True})
        assert resp.status == 200
    assert (home / "config.json").is_file()
    assert _stored(home)["apps_allow_third_party"] is True


# ── 2. revoke actually stops the running code ──

_LOOP_APP = "trust-loop-app"
_BEACON = "beacon.txt"


def _beacon_body(beacon: Path) -> str:
    """A backend that proves it is still executing by advancing a counter."""
    return (
        "import pathlib\n"
        "import time\n"
        f"p = pathlib.Path({str(beacon)!r})\n"
        "i = 0\n"
        "while True:\n"
        "    i += 1\n"
        "    p.write_text(str(i))\n"
        "    time.sleep(0.05)\n"
    )


def _await_beacon(beacon: Path, timeout: float = 5.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if beacon.exists():
            text = beacon.read_text(encoding="utf-8")
            if text:
                return text
        time.sleep(0.05)
    raise AssertionError(f"backend never wrote {beacon}")


@pytest.mark.asyncio
async def test_revoke_stops_the_backend_process_and_the_beacon(
    home: Path, tmp_path: Path, mock_sel
):
    # REGRESSION: revoke used to be a METADATA write (``disable_app`` only). The
    # enabled flag flipped and the endpoint reported success while the app's
    # backend process kept running with its app secret, its routes stayed proxied
    # and its crons stayed armed — i.e. third-party code the operator had just
    # un-trusted was still executing. The assertion is the PROCESS, not the flag.
    from kiro_crew.apps import backend as appbackend

    # This test spawns a REAL backend, and spawning goes through the sandbox. CI
    # runners have no backend for it (Linux ``unshare`` is EPERM in the container,
    # Windows has none at all), so without this the test only passes on a macOS
    # dev box. The subject here is teardown, not isolation, so the isolated home
    # opts out explicitly rather than the test silently skipping in CI — a skipped
    # regression test for a shipped exploit is not a regression test.
    (home / "config.json").write_text(
        json.dumps({"agent": {"sandbox_allow_unsandboxed_exec": True}}),
        encoding="utf-8",
    )

    beacon = home / _BEACON
    _install(
        tmp_path,
        _LOOP_APP,
        enabled=True,
        entry_point="server.py",
        body=_beacon_body(beacon),
    )

    async with _client() as client:
        assert (await client.post(f"/api/security/trusted-apps/{_LOOP_APP}")).status == 200

    loop = asyncio.get_running_loop()
    proc = await loop.run_in_executor(None, appbackend.start_app_backend, _LOOP_APP)
    if proc is None:  # pragma: no cover - environment could not spawn a backend
        pytest.skip("backend process could not be started in this environment")

    try:
        # Precondition: the third-party code is alive and demonstrably running.
        assert proc.proc.poll() is None
        assert _LOOP_APP in appbackend._processes
        before = _await_beacon(beacon)

        async with _client() as client:
            resp = await client.delete(f"/api/security/trusted-apps/{_LOOP_APP}")
            assert resp.status == 200
            assert (await resp.json())["disabled"] is True

        # POSTCONDITION: the process is gone, the registry entry with it, and the
        # beacon has stopped advancing (no orphan still writing).
        assert proc.proc.poll() is not None, "backend survived the revoke"
        assert _LOOP_APP not in appbackend._processes
        after_revoke = beacon.read_text(encoding="utf-8")
        time.sleep(0.5)
        assert beacon.read_text(encoding="utf-8") == after_revoke, (
            "beacon advanced after revoke — third-party code is still executing"
        )
        assert before is not None
    finally:
        await loop.run_in_executor(None, appbackend.stop_app_backend, _LOOP_APP)


@pytest.mark.asyncio
async def test_revoke_runs_the_full_teardown_in_order(home: Path, tmp_path: Path, mock_sel):
    # Companion to the process test: pins the ORDER of the teardown so a refactor
    # cannot reintroduce a metadata-only revoke, or reorder it so the flag flips
    # before the code stops (a window in which the app is disabled-but-running).
    # Patch on apps.teardown, the module that LOOKS THESE UP: it binds them at
    # import so patching their defining modules would not affect the sequence
    # under test ("patch where it's used, not where it's defined").
    import kiro_crew.apps.teardown as appteardown
    from kiro_crew.apps.manager import AppResult

    calls: list[str] = []

    async def _on_app_disable(name: str, record: dict) -> dict:
        calls.append(f"on_app_disable:{name}")
        return {}

    with (
        patch.object(appteardown, "on_app_disable", _on_app_disable),
        patch.object(
            appteardown,
            "stop_app_backend",
            lambda name: calls.append(f"stop_app_backend:{name}") or True,
        ),
        patch.object(
            appteardown,
            "deregister_app",
            lambda name: calls.append(f"deregister_app:{name}"),
        ),
        patch.object(
            security,
            "disable_app",
            lambda name: (
                calls.append(f"disable_app:{name}"),
                AppResult(ok=True, name=name),
            )[1],
        ),
    ):
        _install(tmp_path, _APP, enabled=True)
        async with _client() as client:
            await client.post(f"/api/security/trusted-apps/{_APP}")
            resp = await client.delete(f"/api/security/trusted-apps/{_APP}")
            assert (await resp.json())["disabled"] is True

    # Shutdown hooks → backend process → bridge deregistration → enabled flag.
    # ``disable_app`` LAST: the flag is the cheapest step and the least
    # security-relevant, so it must not gate the ones that stop real code.
    assert calls == [
        f"on_app_disable:{_APP}",
        f"stop_app_backend:{_APP}",
        f"deregister_app:{_APP}",
        f"disable_app:{_APP}",
    ]


# ── 3. revoke does not over-disable ──


@pytest.mark.asyncio
async def test_revoke_without_a_grant_leaves_an_enabled_app_running(
    home: Path, tmp_path: Path, mock_sel
):
    # REGRESSION: the teardown used to fire on ANY revoke. Revoke is deliberately
    # NOT name-validated (the user must be able to delete junk config entries the
    # snapshot shows them), so an unconditional teardown turned this endpoint into
    # "disable any installed app" for a caller holding no grant at all.
    _install(tmp_path, _APP, enabled=True)
    assert build_trusted_apps_snapshot()["apps"] == []  # never granted

    async with _client() as client:
        resp = await client.delete(f"/api/security/trusted-apps/{_APP}")
        assert resp.status == 200
        body = await resp.json()

    # POSTCONDITION FIRST: the app is untouched. A caller holding no grant over
    # this app must not be able to disable it through the revoke endpoint.
    meta = _read_installed(_APP)
    assert meta is not None and meta.enabled is True, "revoke disabled an app it never granted"
    assert body["disabled"] is False, "revoke reported a teardown it had no grant to perform"
    revokes = [
        c
        for c in mock_sel.log_api_access.call_args_list
        if c.kwargs["operation"] == "security.trusted_apps.revoke"
    ]
    assert revokes and "was_granted=False" in revokes[-1].kwargs["resources"]


@pytest.mark.asyncio
async def test_revoke_of_a_builtin_name_leaves_the_builtin_enabled(
    home: Path, tmp_path: Path, mock_sel
):
    # A builtin is exempt at the gate, so no grant governs it and revoking one
    # must not disable it. The grant list is force-seeded (the POST endpoint
    # refuses builtins — see test 4), which is exactly the hand-edited-config
    # shape the un-validated revoke path exists to clean up.
    _install(tmp_path, _BUILTIN, enabled=True, builtin=True)
    from kiro_crew.apps.execution import builtin_app_names

    assert _BUILTIN in builtin_app_names(), "fixture failed to make a real builtin"
    (home / "config.json").write_text(
        json.dumps({"agent": {"apps_trusted": [_BUILTIN]}}), encoding="utf-8"
    )

    async with _client() as client:
        resp = await client.delete(f"/api/security/trusted-apps/{_BUILTIN}")
        assert resp.status == 200
        body = await resp.json()

    # POSTCONDITION FIRST: the builtin's code is left alone. Shipped code is
    # exempt at the gate, so no grant governs it and revoking one cannot disable it.
    meta = _read_installed(_BUILTIN)
    assert meta is not None and meta.enabled is True, "revoke disabled a builtin"
    # The stale entry is still removed — that is what the un-validated name is for.
    assert body["apps"] == [] and body["ineffective"] == []
    assert body["disabled"] is False, "revoke claimed to tear down a builtin"


# ── 4. a builtin name can never hold a grant ──


@pytest.mark.asyncio
async def test_grant_of_a_builtin_name_409s_and_persists_nothing(
    home: Path, tmp_path: Path, mock_sel
):
    # REGRESSION: a builtin passed the "is this a real app?" existence check
    # (builtins have an installed.json too), so a grant persisted for it. It sat
    # inert while the builtin owned the slot — and went LIVE the moment a
    # third-party app claimed that name, inheriting a grant nobody made for it.
    _install(tmp_path, _BUILTIN, enabled=True, builtin=True)
    from kiro_crew.apps.execution import builtin_app_names

    assert _BUILTIN in builtin_app_names()

    async with _client() as client:
        resp = await client.post(f"/api/security/trusted-apps/{_BUILTIN}")
        body = await resp.json()

    # POSTCONDITION FIRST: nothing was written — not to the effective set and not
    # to the raw file. The persisted entry is the defect; the status is the report.
    assert _stored(home).get("apps_trusted", []) == [], "a grant persisted for a builtin"
    snapshot = build_trusted_apps_snapshot()
    assert snapshot["apps"] == [] and snapshot["ineffective"] == []

    assert resp.status == 409
    assert body["code"] == "app_is_builtin"
    assert body["error"]
    assert mock_sel.log_api_access.call_args.kwargs["outcome"] == "denied"


@pytest.mark.asyncio
async def test_refused_builtin_grant_is_not_inherited_by_a_later_takeover(
    home: Path, tmp_path: Path, mock_sel
):
    # WHY the refusal matters: after the builtin stops owning the name, a
    # third-party app claiming it must still be denied. Had the grant persisted,
    # this app would execute on a grant the operator never made for it.
    # The POST's status is deliberately not asserted here — the load-bearing
    # assertion is the gate's verdict AFTER the takeover.
    from kiro_crew.apps.execution import app_execution_denied, builtin_app_names

    _install(tmp_path, _BUILTIN, enabled=True, builtin=True)
    async with _client() as client:
        await client.post(f"/api/security/trusted-apps/{_BUILTIN}")

    # The name is now occupied by a USER-installed app (registry-owned install,
    # so builtin_owns_installed is False and the gate treats it as third party).
    meta = _read_installed(_BUILTIN)
    assert meta is not None
    meta.source = "registry:takeover"
    meta.origin = "registry"
    _write_installed(_BUILTIN, meta)
    assert _BUILTIN not in builtin_app_names(), "takeover fixture did not take effect"

    assert app_execution_denied(_BUILTIN, action="enable") is not None, (
        "a third-party app inherited a grant made against the builtin's name"
    )


# ── 5. a registry name that is not installed yet is grantable ──

_REG_ONLY = "registry-only-app"


@pytest.fixture
def seeded_registry(monkeypatch: pytest.MonkeyPatch):
    """Seed the BUNDLED registry index in-process (never touches the network)."""
    import kiro_crew.apps.registry as registry

    monkeypatch.setattr(
        registry,
        "_load_registry_file",
        lambda: [{"name": _REG_ONLY, "repo": "acme/registry-only-app", "branch": "main"}],
    )
    return _REG_ONLY


@pytest.mark.asyncio
async def test_grant_accepts_a_registry_name_that_is_not_installed(
    home: Path, mock_sel, seeded_registry: str
):
    # REGRESSION: requiring an INSTALL deadlocked the feature. ``install_from_
    # registry`` checks the execution gate BEFORE cloning (clone/build/onInstall
    # are themselves third-party code), so "no grant without an install, no
    # install without a grant" left the operator only the blanket
    # ``apps_allow_third_party`` this endpoint exists to avoid.
    from kiro_crew.apps.manager import get_app

    assert get_app(_REG_ONLY) is None, "fixture must NOT install the app"

    async with _client() as client:
        resp = await client.post(f"/api/security/trusted-apps/{_REG_ONLY}")
        assert resp.status == 200
        assert (await resp.json())["apps"] == [_REG_ONLY]

    # Persisted AND effective, so the install that follows is admitted.
    assert _stored(home)["apps_trusted"] == [_REG_ONLY]
    from kiro_crew.apps.execution import app_execution_denied

    assert app_execution_denied(_REG_ONLY, action="install") is None


@pytest.mark.asyncio
async def test_grant_of_a_name_in_neither_registry_nor_installs_404s(
    home: Path, mock_sel, seeded_registry: str
):
    # The registry leg widens WHICH names are acceptable, not whether the check
    # runs: a name in neither the index nor the installs is still a 404, so an
    # arbitrary name cannot sit in config waiting for an app to claim it.
    async with _client() as client:
        resp = await client.post("/api/security/trusted-apps/not-in-any-registry")
        assert resp.status == 404
        assert (await resp.json())["code"] == "app_not_installed"

    assert _stored(home).get("apps_trusted", []) == []
    assert build_trusted_apps_snapshot()["apps"] == []


# ── 6. the snapshot tells the truth about what is enforced ──

# Stored entries the ENFORCEMENT reader (``trusted_app_names``) drops: wrong case,
# a trailing space, a fullwidth homoglyph that is not ASCII at all, traversal, and
# a glob. Every one of these renders as a grant unless the snapshot splits them
# out — a security panel claiming trust that admits nothing, with no way for the
# user to see why their app is still blocked.
_INEFFECTIVE_ENTRIES = ["LD-App", "ld-app ", "ｌd-app", "..", "*"]


@pytest.mark.asyncio
async def test_snapshot_reports_unenforceable_entries_as_ineffective(
    home: Path, tmp_path: Path, mock_sel
):
    from kiro_crew.apps.execution import app_execution_denied, trusted_app_names

    _install(tmp_path, _APP)
    (home / "config.json").write_text(
        json.dumps({"agent": {"apps_trusted": [_APP, *_INEFFECTIVE_ENTRIES]}}),
        encoding="utf-8",
    )

    snapshot = build_trusted_apps_snapshot()

    # NONE of the junk is reported as an enforced grant; ALL of it is surfaced as
    # ineffective so the user can see the entry exists and does nothing.
    assert snapshot["apps"] == [_APP]
    for entry in _INEFFECTIVE_ENTRIES:
        assert entry not in snapshot["apps"], f"{entry!r} reported as enforced"
        assert entry in snapshot["ineffective"], f"{entry!r} silently dropped"
    assert sorted(_INEFFECTIVE_ENTRIES) == snapshot["ineffective"]

    # The invariant behind the split: ``apps`` is EXACTLY what the gate enforces.
    stored = set(json.loads((home / "config.json").read_text())["agent"]["apps_trusted"])
    assert set(snapshot["apps"]) == stored & set(trusted_app_names())
    # And the gate agrees with the report, entry by entry.
    assert app_execution_denied(_APP, action="enable") is None
    assert app_execution_denied("LD-App", action="enable") is not None


@pytest.mark.asyncio
async def test_snapshot_reflected_over_the_api_matches_the_gate(
    home: Path, tmp_path: Path, mock_sel
):
    # The split must survive the wire, not just the helper: the GET is what the
    # Security panel actually renders.
    _install(tmp_path, _APP)
    (home / "config.json").write_text(
        json.dumps({"agent": {"apps_trusted": [_APP, *_INEFFECTIVE_ENTRIES]}}),
        encoding="utf-8",
    )
    async with _client() as client:
        body = await (await client.get("/api/security/trusted-apps")).json()
    assert body["apps"] == [_APP]
    assert body["ineffective"] == sorted(_INEFFECTIVE_ENTRIES)


@pytest.mark.asyncio
async def test_failed_cron_cleanup_does_not_report_a_successful_revoke(
    home: Path, tmp_path: Path, mock_sel
):
    # REGRESSION: ``on_app_disable`` reports cron cleanup as PROSE in one field —
    # "removed N job(s)" on success, "failed: cron store busy — jobs may still be
    # enabled" when the store is contended. Treating both as an informational
    # warning let a contended store leave the app's scheduled commands ARMED while
    # the endpoint returned 200 and said the app was switched off: third-party code
    # still executing on a timer, with trust reported as revoked.
    import kiro_crew.apps.teardown as appteardown

    async def _busy_store(name: str, record: dict) -> dict:
        return {"cron_cleanup": "failed: cron store busy — jobs may still be enabled"}

    _install(tmp_path, _APP, enabled=True)
    with (
        patch.object(appteardown, "on_app_disable", _busy_store),
        patch.object(appteardown, "stop_app_backend", lambda name: True),
        patch.object(appteardown, "deregister_app", lambda name: None),
    ):
        async with _client() as client:
            assert (await client.post(f"/api/security/trusted-apps/{_APP}")).status == 200
            resp = await client.delete(f"/api/security/trusted-apps/{_APP}")
            assert resp.status == 409
            body = await resp.json()
            assert body["code"] == "teardown_incomplete"
            assert any("cron cleanup incomplete" in f for f in body["failures"])

    # RETRYABLE: the grant must still be there, otherwise a retry would skip the
    # teardown and the app would keep running with trust already gone. This is why
    # the teardown runs BEFORE the config write.
    assert _APP in _stored(home).get("apps_trusted", [])

    # And the retry succeeds once cleanup can complete.
    async def _clean(name: str, record: dict) -> dict:
        return {"cron_cleanup": "removed 2 job(s)"}

    with (
        patch.object(appteardown, "on_app_disable", _clean),
        patch.object(appteardown, "stop_app_backend", lambda name: True),
        patch.object(appteardown, "deregister_app", lambda name: None),
    ):
        async with _client() as client:
            resp = await client.delete(f"/api/security/trusted-apps/{_APP}")
            assert resp.status == 200
            assert (await resp.json())["disabled"] is True
    assert _APP not in _stored(home).get("apps_trusted", [])


@pytest.mark.asyncio
async def test_blanket_off_reports_apps_it_could_not_stop(home: Path, tmp_path: Path, mock_sel):
    # REGRESSION: turning the blanket flag OFF sweeps every enabled third-party app
    # that holds no grant. A failed teardown used to `continue` silently, so the
    # response carried only `stopped` — the operator could not tell that code they
    # had just un-trusted was STILL RUNNING. Same shape as the metadata-only revoke
    # this feature already had to fix, one layer up.
    import kiro_crew.apps.teardown as appteardown

    async def _busy_store(name: str, record: dict) -> dict:
        return {"cron_cleanup": "failed: cron store busy — jobs may still be enabled"}

    _install(tmp_path, _APP, enabled=True)
    with (
        patch.object(appteardown, "on_app_disable", _busy_store),
        patch.object(appteardown, "stop_app_backend", lambda name: True),
        patch.object(appteardown, "deregister_app", lambda name: None),
    ):
        async with _client() as client:
            on = await client.put(
                "/api/security/trusted-apps/allow-all", json={"value": True}
            )
            assert on.status == 200
            off = await client.put(
                "/api/security/trusted-apps/allow-all", json={"value": False}
            )
            # 409, not 200: the flag IS off (and the snapshot says so) but code the
            # flag was admitting survived, and the caller must be able to tell.
            assert off.status == 409
            body = await off.json()
            assert body["allowAll"] is False
            assert body["code"] == "blanket_trust_sweep_incomplete"
            # The app is NOT in `stopped`, and the response SAYS it is still running.
            assert _APP not in body["stopped"]
            assert _APP in body["stillRunning"]


def test_uninstall_reports_a_trust_grant_it_could_not_drop(home: Path, tmp_path: Path):
    # REGRESSION: uninstall drops the app's grant because a grant is keyed on NAME
    # alone — a leftover would admit a DIFFERENT app installed under that name with
    # no consent prompt. When the drop FAILED the old code logged and returned
    # ok=True, so the app vanished while its code-execution trust stayed on file and
    # reusable. The uninstall still succeeds (the files are gone either way) but it
    # must say so.
    from kiro_crew.apps import manager as appmanager

    _install(tmp_path, _APP, enabled=False)

    def _boom(name: str) -> None:
        raise RuntimeError("config.json is unreadable")

    with patch.object(appmanager, "_drop_trust_grant", _boom):
        result = appmanager.uninstall_app(_APP)

    # REFUSES rather than half-uninstalling. Deleting the files first and reporting
    # the surviving grant as a warning left a state the user could not recover from:
    # the app is gone, so nothing is left to uninstall and no retry clears the
    # grant, while the name stays armed for whatever is installed under it next.
    assert result.ok is False
    assert result.error_code == "trust_grant_not_removed"
    assert "not uninstalling" in result.error
    assert "code" in result.to_dict()
    # Nothing was destroyed, so the user can fix the cause and retry.
    assert appmanager.get_app(_APP) is not None


@pytest.mark.asyncio
async def test_mutations_refuse_when_config_local_owns_the_trust_setting(
    home: Path, tmp_path: Path, mock_sel
):
    # REGRESSION: KiroCrewConfig deep-merges config.local.json OVER config.json and
    # save() STRIPS overlay-owned values from what it writes. So when the overlay
    # owns a trust setting, mutating config.json is doubly ineffective — and the old
    # code returned 200, telling the operator a grant was revoked while the overlay
    # re-admitted the app's code on the very next load. Third variant of
    # "revocation that revokes nothing". Refusing is the honest answer: the overlay
    # is user-owned and Kiro Crew never writes it.
    (home / "config.local.json").write_text(
        json.dumps({"agent": {"apps_trusted": ["pinned-app"]}}), encoding="utf-8"
    )
    _install(tmp_path, _APP, enabled=False)
    async with _client() as client:
        for call in (
            client.post(f"/api/security/trusted-apps/{_APP}"),
            client.delete(f"/api/security/trusted-apps/{_APP}"),
            client.put("/api/security/trusted-apps/allow-all", json={"value": True}),
        ):
            resp = await call
            assert resp.status == 409
            body = await resp.json()
            assert body["code"] == "trust_setting_overlay_owned"
            assert body["overlaySettings"] == ["apps_trusted"]
            assert "config.local.json" in body["error"]


def test_uninstall_reports_an_overlay_owned_grant_it_cannot_drop(
    home: Path, tmp_path: Path
):
    # Same hazard on the uninstall path: the grant is name-keyed, so one left in the
    # overlay would admit a DIFFERENT app installed under this name later. The
    # uninstall still succeeds (files are gone) but must SAY the grant survived.
    from kiro_crew.apps import manager as appmanager

    (home / "config.local.json").write_text(
        json.dumps({"agent": {"apps_trusted": [_APP]}}), encoding="utf-8"
    )
    _install(tmp_path, _APP, enabled=False)
    result = appmanager.uninstall_app(_APP)

    assert result.ok is False
    assert result.error_code == "trust_grant_not_removed"
    assert "config.local.json" in result.error
    assert appmanager.get_app(_APP) is not None  # still installed, so retryable


def test_an_overlay_grant_for_another_app_does_not_block_this_uninstall(
    home: Path, tmp_path: Path
):
    # The overlay refusal used to fire on the mere PRESENCE of `apps_trusted`,
    # regardless of which apps it named — so any operator who set it at all could
    # never uninstall ANY app. Scoped to a grant this app actually holds.
    from kiro_crew.apps import manager as appmanager

    (home / "config.local.json").write_text(
        json.dumps({"agent": {"apps_trusted": ["some-other-app"]}}), encoding="utf-8"
    )
    _install(tmp_path, _APP, enabled=False)

    assert appmanager.trust_grant_removal_blocked(_APP) is None
    result = appmanager.uninstall_app(_APP)
    assert result.ok is True, result.error
    assert appmanager.get_app(_APP) is None


@pytest.mark.asyncio
async def test_uninstall_route_refuses_before_running_anything_destructive(
    home: Path, tmp_path: Path, mock_sel
):
    # The abort used to live inside uninstall_app, which the handler reaches only
    # at Step 5 — AFTER cron deregistration, the app's non-idempotent onUninstall
    # script, the backend stop and dependency cleanup. The refusal therefore
    # stranded a half-removed app and re-ran onUninstall on every retry. It is now
    # a precondition: nothing destructive may have run when it fires.
    from kiro_crew.apps import routes as approutes

    (home / "config.local.json").write_text(
        json.dumps({"agent": {"apps_trusted": [_APP]}}), encoding="utf-8"
    )
    _install(tmp_path, _APP, enabled=False)

    uninstall_app_router = web.Application()
    uninstall_app_router.router.add_delete(
        "/api/apps/{name}", approutes.handle_uninstall_app
    )

    destructive: list[str] = []
    with (
        patch.object(
            approutes,
            "deregister_app",
            lambda *a, **k: destructive.append("deregister_app"),
        ),
        patch.object(
            approutes,
            "uninstall_app",
            lambda *a, **k: destructive.append("uninstall_app"),
        ),
    ):
        async with TestClient(TestServer(uninstall_app_router)) as client:
            resp = await client.delete(f"/api/apps/{_APP}")
            assert resp.status == 409
            body = await resp.json()
            assert body["code"] == "trust_grant_not_removed"
            assert body["retryable"] is True
            assert "Nothing has been changed" in body["error"]

    assert destructive == []


@pytest.mark.asyncio
async def test_blanket_off_runs_shutdown_hooks_before_persisting_false(
    home: Path, tmp_path: Path, mock_sel
):
    # REGRESSION: the flag is what authorises loading an app's Python at all —
    # `load_app_module` consults `app_execution_denied`. Persisting `false` FIRST
    # therefore denied the app's own `on_shutdown` hook, so it was stopped without
    # ever being told to flush state or release resources. The sweep has to run
    # while trust still stands. Pinned by observing the config as the hook sees it.
    import kiro_crew.apps.teardown as appteardown

    observed: list[bool] = []

    async def _on_app_disable(name: str, record: dict) -> dict:
        # What a shutdown hook would see when the loader gates it.
        from kiro_crew.apps.execution import third_party_execution_allowed

        observed.append(third_party_execution_allowed())
        return {}

    _install(tmp_path, _APP, enabled=True)
    with (
        patch.object(appteardown, "on_app_disable", _on_app_disable),
        patch.object(appteardown, "stop_app_backend", lambda name: True),
        patch.object(appteardown, "deregister_app", lambda name: None),
    ):
        async with _client() as client:
            assert (
                await client.put(
                    "/api/security/trusted-apps/allow-all", json={"value": True}
                )
            ).status == 200
            off = await client.put(
                "/api/security/trusted-apps/allow-all", json={"value": False}
            )
            assert off.status == 200
            assert (await off.json())["allowAll"] is False

    # The hook ran, and it ran while the app was still permitted to execute.
    assert observed == [True], (
        "the shutdown hook must run BEFORE the flag is persisted; observed "
        f"allow-all={observed} at hook time"
    )


@pytest.mark.asyncio
async def test_blanket_off_catches_an_app_enabled_during_the_sweep(
    home: Path, tmp_path: Path, mock_sel
):
    # REGRESSION: the falling edge sweeps BEFORE persisting `false` so shutdown hooks
    # can still load. That opened a window — the sweep enumerates candidates and then
    # spends real time stopping backends, and an app enabled inside that window is
    # never in the enumeration, so it kept executing under trust the operator
    # believed they had withdrawn. Per-app locks cannot cover it: there is no name to
    # lock for an app that was not enumerated. A second sweep after the write closes
    # it. Simulated by enabling a second app from inside the first app's teardown.
    import kiro_crew.apps.teardown as appteardown
    from kiro_crew.apps.manager import enable_app

    late = "trust-late-app"
    _install(tmp_path, _APP, enabled=True)
    _install(tmp_path, late, enabled=False)

    async def _enable_the_other_app(name: str, record: dict) -> dict:
        # The racing enable: lands after `late` was already passed over.
        if name == _APP:
            enable_app(late)
        return {}

    with (
        patch.object(appteardown, "on_app_disable", _enable_the_other_app),
        patch.object(appteardown, "stop_app_backend", lambda name: True),
        patch.object(appteardown, "deregister_app", lambda name: None),
    ):
        async with _client() as client:
            assert (
                await client.put(
                    "/api/security/trusted-apps/allow-all", json={"value": True}
                )
            ).status == 200
            off = await client.put(
                "/api/security/trusted-apps/allow-all", json={"value": False}
            )
            body = await off.json()

    # The app that raced in must NOT be left enabled-and-running on withdrawn trust:
    # either it was stopped, or the response says it may still be executing.
    from kiro_crew.apps.manager import get_app

    record = get_app(late) or {}
    accounted = late in body.get("stopped", []) or late in body.get("stillRunning", [])
    assert accounted, (
        f"{late!r} was enabled during the sweep and is unaccounted for: "
        f"stopped={body.get('stopped')} stillRunning={body.get('stillRunning')}"
    )
    assert not (record.get("enabled") and not accounted)


def test_blanket_flag_is_not_editable_through_the_generic_config_patch():
    # REGRESSION: `agent.apps_allow_third_party` was PATCHable through
    # /api/config/kirocrew, and that path performs NO teardown — so flipping it off
    # there withdrew trust on paper while every app it had admitted kept executing,
    # crons included, until a gateway restart. A dashboard card shipped against that
    # endpoint (#1414), which is how the hole became reachable from the UI.
    #
    # The key is deliberately absent from the editable set so the ONLY writer is the
    # endpoint that runs the sweep, and the refusal names it rather than dead-ending
    # on "field not editable".
    from kiro_crew.dashboard.handlers.core import (
        _EDITABLE_CONFIG,
        _MOVED_CONFIG_FIELDS,
    )

    assert "agent.apps_allow_third_party" not in _EDITABLE_CONFIG
    hint = _MOVED_CONFIG_FIELDS["agent.apps_allow_third_party"]
    assert "/api/security/trusted-apps/allow-all" in hint
    # The sibling grant list is not editable there either, for the same reason.
    assert "agent.apps_trusted" not in _EDITABLE_CONFIG
