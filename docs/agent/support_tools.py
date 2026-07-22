"""Support / troubleshooting tools (app-wide).

Diagnostics collection and support-bundle assembly. Two of these are pure reads;
`create_support_bundle` assembles an archive of read-only diagnostics (logs,
versions, health, recent errors) — it does NOT change any array/host/config. All
three MUST redact secrets: device credentials are plaintext in `devices` and job
payloads can carry credentials.

`description` text addresses the model. Adapt `get_db()` and `SERVICE_LOGS` to the
deployment; wire `TOOLS` into the AI-agent module.
"""
from __future__ import annotations

import io
import os
import re
import json
import zipfile
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field

# from app.db import get_db

# Service -> how to read its recent log. Configure per deployment. A value is either
# a file path or a shell command ("cmd:journalctl -u ... -n 500"). Keep this the ONE
# place that knows the log layout.
SERVICE_LOGS: dict[str, str] = {
    "gui": "API-Explorer_GUI/logs/gui.log",
    # "operating-systems": "cmd:docker logs --tail 500 os-module",
    # "remote-ops":        "cmd:docker logs --tail 500 remoteops-module",
    # "reporting":         "API-Explorer_Reporting/logs/reporting.log",
    # ...
}

# Where a finished bundle is written for the user to download.
BUNDLE_DIR = os.environ.get("SUPPORT_BUNDLE_DIR", "/tmp")

_SECRET_KEYS = re.compile(r"(pass|secret|token|credential|api[_-]?key)", re.I)
_SECRET_LINE = re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+")


def _redact_obj(o):
    """Recursively drop secret-looking fields from dict/list structures."""
    if isinstance(o, dict):
        return {k: ("<redacted>" if _SECRET_KEYS.search(str(k)) else _redact_obj(v))
                for k, v in o.items()}
    if isinstance(o, list):
        return [_redact_obj(x) for x in o]
    return o


def _redact_text(s: str) -> str:
    """Mask secret-looking assignments in a log/text blob."""
    return _SECRET_LINE.sub(lambda m: m.group(0).split(m.group(0)[-1])[0] + "<redacted>", s)


# ── recent errors ─────────────────────────────────────────────────────────────
class RecentErrorsArgs(BaseModel):
    limit: int = Field(20, description="Max failed jobs to return (newest first).")


RECENT_ERRORS_TOOL = {
    "name": "get_recent_errors",
    "description": (
        "Return the most recent FAILED background jobs (provisioning, deploy, "
        "onboarding) with their error and steps, plus any arrays currently failing "
        "collection. Use to start troubleshooting 'what went wrong recently' before "
        "building a bundle."
    ),
    "input_schema": RecentErrorsArgs.model_json_schema(),
}


def get_recent_errors(limit: int = 20) -> dict:
    db = get_db()
    jobs = list(db.jobs.find({"status": {"$in": ["failed", "error"]}},
                             {"_id": 0}).sort("created", -1).limit(limit))
    # Remote Ops arrays that collected nothing on their last poll.
    bad_polls = []
    seen = set()
    for h in db.remoteops_poll_health.find({}, {"_id": 0}).sort("timestamp", -1):
        s = h.get("serial")
        if s in seen:
            continue
        seen.add(s)
        if not h.get("collected", True):
            bad_polls.append(h)
    return {"failed_jobs": _redact_obj(jobs), "collection_failures": _redact_obj(bad_polls)}


# ── service / agent versions ──────────────────────────────────────────────────
class VersionsArgs(BaseModel):
    pass


VERSIONS_TOOL = {
    "name": "get_service_versions",
    "description": (
        "Return the versions of the running services and deployed agents (e.g. the OS "
        "agent version per host). Use when a support engineer needs to know exactly "
        "what's running, or to check a host is on a required agent version."
    ),
    "input_schema": VersionsArgs.model_json_schema(),
}


def get_service_versions() -> dict:
    db = get_db()
    os_hosts = list(db.os_hosts.find({}, {"_id": 0, "name": 1, "os_type": 1,
                                          "agent_version": 1, "status": 1}))
    return {"os_agents": os_hosts,
            "note": "add per-service versions from each service's /health or build info"}


# ── assemble a support bundle ─────────────────────────────────────────────────
class BundleArgs(BaseModel):
    services: Optional[list[str]] = Field(
        None, description="Which services' logs to include (keys of the log map). "
                          "Omit for all configured services.")
    reason: Optional[str] = Field(
        None, description="Short note on why the bundle is being made (goes in the "
                          "manifest, helps support).")


CREATE_BUNDLE_TOOL = {
    "name": "create_support_bundle",
    "description": (
        "Assemble a downloadable support bundle: recent service logs, versions, "
        "health, and recent errors, with all secrets redacted. Use when the user asks "
        "for a support bundle or logs to send to support. This only READS diagnostics "
        "and writes one archive; it changes no array/host/config. Returns the bundle "
        "path to give the user."
    ),
    "input_schema": BundleArgs.model_json_schema(),
}


def _read_log(spec: str, max_bytes: int = 512_000) -> str:
    try:
        if spec.startswith("cmd:"):
            import subprocess
            out = subprocess.run(spec[4:], shell=True, capture_output=True, text=True, timeout=30)
            return _redact_text(out.stdout[-max_bytes:])
        with open(spec, "r", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - max_bytes))
            return _redact_text(f.read())
    except Exception as e:  # noqa: BLE001
        return f"<could not read log: {e}>"


def create_support_bundle(services: list[str] | None = None,
                          reason: str | None = None) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(BUNDLE_DIR, f"api-explorer-support-{stamp}.zip")
    chosen = services or list(SERVICE_LOGS.keys())
    manifest = {
        "created_utc": stamp, "reason": reason, "services": chosen,
        "note": "Read-only diagnostics. Secrets redacted. No system state changed.",
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
        for svc in chosen:
            spec = SERVICE_LOGS.get(svc)
            if spec:
                z.writestr(f"logs/{svc}.log", _read_log(spec))
        z.writestr("versions.json", json.dumps(get_service_versions(), indent=2, default=str))
        z.writestr("recent_errors.json", json.dumps(get_recent_errors(), indent=2, default=str))
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return {"bundle_path": path, "services": chosen,
            "message": f"Support bundle created at {path} (secrets redacted). "
                       "Download it and attach to your support case."}


TOOLS = [
    (RECENT_ERRORS_TOOL, get_recent_errors),
    (VERSIONS_TOOL, get_service_versions),
    (CREATE_BUNDLE_TOOL, create_support_bundle),
]
