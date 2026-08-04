"""The one request-free way to stop an app's code.

Two callers need to make an app's code stop running: ``POST /api/apps/{name}/disable``
and revoking that app's third-party execution grant. Before this module the revoke
path carried a hand-maintained copy of the disable handler's sequence, and a copy is
a defect with a delay on it: any step added to the handler later would silently not
run on revoke, recreating the "revoke reported success while the backend kept
executing" bug that shipped in the first draft of the grant feature.

So the sequence lives here once, and it deliberately takes NO aiohttp request. The
disable handler's request-bound tail — notification-channel unregistration, the
builtin module's ``on_disable(app)`` hook, builtin service sync — stays in the
handler: those need ``request.app``, and none of them are what makes third-party
code stop. What does is here, in order:

1. ``on_app_disable`` — Python shutdown hooks, route deregistration, cron cleanup.
2. ``stop_app_backend`` — the backend PROCESS. Skipping this is what let a revoked
   app keep running with its app secret and its routes still proxied.
3. ``deregister_app`` — agents, skills, MCP servers.

Ordering matters: hooks first (the app gets to shut down cleanly), then the process,
then the registrations, so nothing re-registers behind us.

Both blocking steps are offloaded to the subprocess executor — ``stop_app_backend``
signals a process group and waits, ``deregister_app`` walks and rewrites registry
files — because this runs on the gateway's event loop, where a slow filesystem would
stall every other request and the heartbeat.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

# Module level, not deferred inside the function: these are the seams both callers'
# tests patch (`patch("kiro_crew.apps.teardown.on_app_disable")`), and a
# function-local import is invisible to `patch`. Safe to import eagerly because
# nothing in this dependency set imports this module back — only routes.py and the
# security handlers do, and both already depend on all of it.
from kiro_crew.apps.backend import stop_app_backend
from kiro_crew.apps.bridges import deregister_app
from kiro_crew.apps.hooks_integration import on_app_disable
from kiro_crew.executors import subprocess_executor

logger = logging.getLogger(__name__)


@dataclass
class TeardownResult:
    """Outcome of stopping an app's code.

    ``failures`` is the load-bearing field: a caller that must not claim success
    (revoking trust) checks it, while a caller that proceeds regardless (the
    disable handler, whose contract is "disable proceeds anyway with warnings")
    can surface everything and continue.

    The split exists because ``on_app_disable`` reports cron cleanup as PROSE in a
    single field — ``"removed 3 job(s)"`` on success and ``"failed: cron store busy
    — jobs may still be enabled"`` on failure. Treating both as a warning is how a
    contended cron store could leave an app's scheduled commands armed while the
    revoke endpoint returned 200 and reported the app switched off: the same
    "reported success while third-party code kept running" defect this module was
    extracted to kill, one layer up.
    """

    warnings: list[str]
    failures: list[str]

    @property
    def ok(self) -> bool:
        return not self.failures


async def teardown_app_runtime(name: str, record: dict[str, Any]) -> TeardownResult:
    """Stop *name*'s running code.

    Never raises for a failing step: a teardown that aborts halfway leaves the app
    in a worse state than one that pushes through and reports. Each failure is
    logged, collected into ``failures``, and the next step still runs — stopping the
    backend matters even when a shutdown hook threw.

    ``record`` is the app's installed metadata (``manager.get_app``); its
    ``resources`` field decides whether the gateway owns the app's resources
    (``"gateway"``) or the app manages its own (``"app"``). For a self-managed app
    the gateway still runs the hooks and still stops any backend it spawned — the
    field describes who REGISTERS resources, not whose code is allowed to keep
    running after trust is withdrawn.
    """
    warnings: list[str] = []
    failures: list[str] = []
    loop = asyncio.get_running_loop()

    try:
        hooks_result = await on_app_disable(name, record)
        # ``on_app_disable`` reports cron cleanup as prose the caller shows the
        # user, and the SAME field carries both outcomes. A "failed:" value means
        # the app's scheduled jobs may still fire, so it is a teardown FAILURE, not
        # a note — the marker is the contract in hooks_integration.py.
        if hooks_result:
            for key, value in hooks_result.items():
                if key == "cron_cleanup" and isinstance(value, str) and value:
                    if value.startswith("failed:"):
                        failures.append(f"cron cleanup incomplete: {value}")
                    else:
                        warnings.append(value)
    except Exception as exc:  # noqa: BLE001 - a failed hook must not skip the rest
        logger.warning("shutdown hooks failed for app %r: %s", name, exc, exc_info=True)
        failures.append(f"hooks disable failed: {exc}")

    # The backend process is stopped for EVERY app, self-managed included: it is the
    # thing actually executing third-party code.
    try:
        await loop.run_in_executor(subprocess_executor(), stop_app_backend, name)
    except Exception as exc:  # noqa: BLE001
        logger.warning("stopping backend failed for app %r: %s", name, exc, exc_info=True)
        failures.append(f"backend stop failed: {exc}")

    if record.get("resources", "gateway") == "gateway":
        try:
            # `deregister_app` reports most problems SOFTLY: it catches internally
            # and returns them on `RegistrationResult.errors` rather than raising.
            # Discarding that return made a registry write failure look like a clean
            # teardown, so revoke would drop the grant while the app's agents,
            # skills, crons or MCP servers were still registered — trust removed on
            # paper, stale execution surface left behind.
            dereg = await loop.run_in_executor(subprocess_executor(), deregister_app, name)
            for err in getattr(dereg, "errors", None) or ():
                logger.warning("deregistering app %r reported: %s", name, err)
                failures.append(f"deregister failed: {err}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("deregistering app %r failed: %s", name, exc, exc_info=True)
            failures.append(f"deregister failed: {exc}")

    return TeardownResult(warnings=warnings, failures=failures)
