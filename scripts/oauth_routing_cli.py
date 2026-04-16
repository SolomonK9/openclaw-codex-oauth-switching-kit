#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import py_compile
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_WORKSPACE = Path.home() / ".openclaw" / "workspace"
REQUIRED_SCRIPT_NAMES = [
    "oauth_pool_router.py",
    "oauth_command_router.py",
    "oauth_lease_sync.py",
    "oauth_profile_capture.py",
    "onboard_oauth_account.py",
    "oauth_telegram_reauth.py",
    "oauth_telegram_bridge.py",
    "oauth_routing_cli.py",
]


def is_windows() -> bool:
    return os.name == "nt" or platform.system().lower().startswith("win")


def shell_path(path: Path) -> str:
    return str(path.expanduser().resolve())


def info(message: str) -> None:
    print(message)


def fail(message: str, code: int = 1) -> int:
    print(f"[error] {message}", file=sys.stderr)
    return code


def run(cmd: List[str], *, cwd: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True, timeout=timeout)

def detect_prereqs() -> List[Tuple[str, bool, str]]:
    python3_path = shutil.which("python3")
    openclaw_path = shutil.which("openclaw")
    return [
        ("python3", python3_path is not None, python3_path or "missing"),
        ("openclaw", openclaw_path is not None, openclaw_path or "missing"),
    ]


def ensure_unix_supported() -> None:
    if is_windows():
        raise RuntimeError("Windows is not implemented in this slice yet. Use Linux or macOS for install/init.")


def repo_script(name: str) -> Path:
    return REPO_ROOT / "scripts" / name


def workspace_paths(workspace: Path) -> dict[str, Path]:
    workspace = workspace.expanduser().resolve()
    ops_dir = workspace / "ops"
    return {
        "workspace": workspace,
        "ops": ops_dir,
        "scripts": ops_dir / "scripts",
        "bin": ops_dir / "bin",
        "state": ops_dir / "state",
        "logs": ops_dir / "state" / "logs",
        "backups": ops_dir / "state" / "backups",
        "config": ops_dir / "state" / "oauth-pool-config.json",
        "lease_map": ops_dir / "state" / "oauth-lease-project-map.json",
        "router": ops_dir / "scripts" / "oauth_pool_router.py",
        "shim": ops_dir / "bin" / "oauth-routing",
    }


def copy_if_changed(src: Path, dest: Path) -> str:
    existed = dest.exists()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if existed and src.read_bytes() == dest.read_bytes():
        return "kept"
    shutil.copy2(src, dest)
    return "updated" if existed else "created"


def ensure_template(path: Path, template_name: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return "kept"
    shutil.copy2(REPO_ROOT / "templates" / template_name, path)
    return "created"


def compile_scripts(paths: Iterable[Path]) -> None:
    for path in paths:
        py_compile.compile(str(path), doraise=True)

def render_help() -> str:
    return """oauth-routing — OpenClaw Codex OAuth routing wrapper

Commands:
  install      Stage scripts and starter state into an OpenClaw workspace
  init         Generate a standard starter config without hand-editing JSON
  add-account  Run the guided account onboarding helper
  enable       Enable scheduler jobs after explicit confirmation
  status       Show current router status
  doctor       Check install/config prerequisites and common problems

Examples:
  ./oauth-routing install --workspace ~/.openclaw/workspace
  ./oauth-routing init --workspace ~/.openclaw/workspace --managed-agent main
  ./oauth-routing add-account --workspace ~/.openclaw/workspace --name Demo
  ./oauth-routing enable --workspace ~/.openclaw/workspace
  ./oauth-routing status --workspace ~/.openclaw/workspace --json
  ./oauth-routing doctor --workspace ~/.openclaw/workspace
"""


def prompt_yes_no(message: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    answer = input(message + suffix).strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def save_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def standard_config(managed_agents: List[str]) -> dict:
    payload = load_json(REPO_ROOT / "templates" / "oauth-pool-config.template.json")
    agents = managed_agents or ["main"]
    payload["managedAgents"] = agents
    payload.setdefault("usageProbe", {})["agentId"] = agents[0]
    payload.setdefault("sessionRebind", {})["agents"] = agents
    payload.setdefault("accounts", [])
    payload.setdefault("alerts", {})
    for channel in ("telegram", "discord"):
        payload["alerts"].setdefault(channel, {})["enabled"] = False
    return payload


def validate_router_status(workspace: Path) -> Tuple[bool, str]:
    paths = workspace_paths(workspace)
    router = paths["router"]
    if not router.exists():
        return False, f"router missing: {router}"
    result = run(["python3", shell_path(router), "status", "--json"], cwd=paths["workspace"], timeout=60)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "router status failed"
        return False, detail
    try:
        json.loads(result.stdout)
    except Exception as exc:
        return False, f"router returned non-JSON output: {exc}"
    return True, "router status --json returned valid JSON"

def enable_scheduler(workspace: Path) -> int:
    ensure_unix_supported()
    paths = workspace_paths(workspace)
    setup_script = paths["scripts"] / "setup_oauth_crons.sh"
    setup_status = copy_if_changed(REPO_ROOT / "scripts" / "setup_oauth_crons.sh", setup_script)
    os.chmod(setup_script, 0o755)
    info(f"Scheduler setup script: {setup_status} -> {setup_script}")
    if not prompt_yes_no(f"Confirm scheduler changes in workspace {paths['workspace']}? This will add OpenClaw cron jobs.", default=False):
        info("Scheduler enable cancelled.")
        return 0
    result = run(["bash", shell_path(setup_script), shell_path(paths["workspace"])], cwd=paths["workspace"], timeout=120)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.returncode != 0:
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
        return fail("Failed to enable scheduler jobs.", result.returncode)
    return 0


def install_workspace(workspace: Path) -> int:
    ensure_unix_supported()
    paths = workspace_paths(workspace)
    prereqs = detect_prereqs()
    missing = [name for name, ok, _detail in prereqs if not ok]
    info("Checking prerequisites:")
    for name, ok, detail in prereqs:
        info(f"- {name}: {'ok' if ok else 'missing'} ({detail})")
    if missing:
        return fail("Missing required prerequisites: " + ", ".join(missing))

    for key in ("workspace", "ops", "scripts", "bin", "state", "logs", "backups"):
        paths[key].mkdir(parents=True, exist_ok=True)

    script_results = []
    installed_scripts: List[Path] = []
    for name in REQUIRED_SCRIPT_NAMES:
        dest = paths["scripts"] / name
        status = copy_if_changed(repo_script(name), dest)
        installed_scripts.append(dest)
        script_results.append((name, status, dest))

    config_status = ensure_template(paths["config"], "oauth-pool-config.template.json")
    lease_status = ensure_template(paths["lease_map"], "oauth-lease-project-map.template.json")
    setup_status = copy_if_changed(REPO_ROOT / "scripts" / "setup_oauth_crons.sh", paths["scripts"] / "setup_oauth_crons.sh")
    os.chmod(paths["scripts"] / "setup_oauth_crons.sh", 0o755)
    shim_status = copy_if_changed(REPO_ROOT / "oauth-routing", paths["shim"])
    os.chmod(paths["shim"], 0o755)
    compile_scripts(installed_scripts)

    info("\nInstalled/staged files:")
    for name, status, dest in script_results:
        info(f"- {name}: {status} -> {dest}")
    info(f"- setup_oauth_crons.sh: {setup_status} -> {paths['scripts'] / 'setup_oauth_crons.sh'}")
    info(f"- oauth-pool-config.json: {config_status} -> {paths['config']}")
    info(f"- oauth-lease-project-map.json: {lease_status} -> {paths['lease_map']}")
    info(f"- oauth-routing shim: {shim_status} -> {paths['shim']}")

    if prompt_yes_no("Install scheduler/cron jobs now via openclaw cron add?", default=False):
        rc = enable_scheduler(workspace)
        if rc != 0:
            return rc
    else:
        info("Skipped scheduler changes. You can enable them later with: oauth-routing enable")

    info("\nNext step:")
    info(f"  {paths['shim']} init --workspace {paths['workspace']}")
    return 0

def init_workspace(workspace: Path, managed_agents: List[str], force: bool) -> int:
    ensure_unix_supported()
    paths = workspace_paths(workspace)
    if not paths["router"].exists():
        return fail(f"Router is not installed in {paths['workspace']}. Run install first.")
    template_bytes = (REPO_ROOT / "templates" / "oauth-pool-config.template.json").read_bytes()
    config_exists = paths["config"].exists()
    config_is_unedited_template = config_exists and paths["config"].read_bytes() == template_bytes
    if config_exists and not force and not config_is_unedited_template:
        return fail(f"Config already exists: {paths['config']} (use --force to overwrite)")

    save_json(paths["config"], standard_config(managed_agents))
    if not paths["lease_map"].exists():
        shutil.copy2(REPO_ROOT / "templates" / "oauth-lease-project-map.template.json", paths["lease_map"])

    ok, detail = validate_router_status(paths["workspace"])
    if not ok:
        return fail(f"Config written but validation failed: {detail}")

    cfg = load_json(paths["config"])
    info(f"Created config: {paths['config']}")
    info(f"Managed agents: {', '.join(cfg['managedAgents'])}")
    info("Validation: router status --json succeeded")
    info("\nNext step:")
    info(f"  {paths['shim']} add-account --workspace {paths['workspace']} --name <Label>")
    return 0


def add_account(workspace: Path, name: str, reauth: bool, no_login: bool, source_profile: str | None, json_mode: bool) -> int:
    ensure_unix_supported()
    paths = workspace_paths(workspace)
    onboard_script = paths["scripts"] / "onboard_oauth_account.py"
    if not onboard_script.exists():
        return fail(f"Onboarding helper is not installed in {paths['workspace']}. Run install first.")
    cmd = ["python3", shell_path(onboard_script), "--name", name]
    if reauth:
        cmd.append("--reauth")
    if no_login:
        cmd.append("--no-login")
    if source_profile:
        cmd.extend(["--source-profile", source_profile])
    if json_mode:
        cmd.append("--json")
    return subprocess.run(cmd, cwd=str(paths["workspace"])).returncode


def status_cmd(workspace: Path, json_mode: bool) -> int:
    paths = workspace_paths(workspace)
    if not paths["router"].exists():
        return fail(f"Router is not installed in {paths['workspace']}. Run install first.")
    cmd = ["python3", shell_path(paths["router"]), "status"]
    if json_mode:
        cmd.append("--json")
    return subprocess.run(cmd, cwd=str(paths["workspace"])).returncode


def doctor_cmd(workspace: Path, json_mode: bool) -> int:
    ensure_unix_supported()
    paths = workspace_paths(workspace)
    checks = []
    for name, ok, detail in detect_prereqs():
        checks.append({"name": name, "ok": ok, "detail": detail})
    checks.extend([
        {"name": "workspace", "ok": paths["workspace"].exists(), "detail": shell_path(paths["workspace"])} ,
        {"name": "router", "ok": paths["router"].exists(), "detail": shell_path(paths["router"])} ,
        {"name": "config", "ok": paths["config"].exists(), "detail": shell_path(paths["config"])} ,
        {"name": "lease_map", "ok": paths["lease_map"].exists(), "detail": shell_path(paths["lease_map"])} ,
        {"name": "shim", "ok": paths["shim"].exists(), "detail": shell_path(paths["shim"])} ,
    ])
    router_ok = False
    router_detail = "router not installed"
    if paths["router"].exists() and paths["config"].exists():
        router_ok, router_detail = validate_router_status(paths["workspace"])
    checks.append({"name": "router_status_json", "ok": router_ok, "detail": router_detail})

    payload = {"ok": all(item["ok"] for item in checks), "workspace": shell_path(paths["workspace"]), "checks": checks}
    if json_mode:
        print(json.dumps(payload, indent=2))
    else:
        info(f"Doctor for {payload['workspace']}")
        for item in checks:
            info(f"- {item['name']}: {'ok' if item['ok'] else 'fail'} ({item['detail']})")
    return 0 if payload["ok"] else 1

def add_workspace_arg(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--workspace", default=str(DEFAULT_WORKSPACE), help="Target OpenClaw workspace (default: ~/.openclaw/workspace)")
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oauth-routing", description="Public wrapper for OpenClaw Codex OAuth routing")
    sub = parser.add_subparsers(dest="command")
    add_workspace_arg(sub.add_parser("install", help="Stage scripts and starter state into a workspace"))

    init_parser = add_workspace_arg(sub.add_parser("init", help="Generate a standard starter config"))
    init_parser.add_argument("--managed-agent", action="append", dest="managed_agents", help="Managed agent id (repeatable; default: main)")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing config")

    add_parser = add_workspace_arg(sub.add_parser("add-account", help="Run the guided onboarding helper"))
    add_parser.add_argument("--name", required=True, help="Display name for the account")
    add_parser.add_argument("--reauth", action="store_true", help="Reauthenticate an existing account")
    add_parser.add_argument("--no-login", action="store_true", help="Skip provider login step")
    add_parser.add_argument("--source-profile", default=None, help="Existing source profile id for copy-based flows")
    add_parser.add_argument("--json", action="store_true", help="Emit JSON from the wrapped onboarding helper")

    add_workspace_arg(sub.add_parser("enable", help="Enable scheduler jobs after confirmation"))
    status_parser = add_workspace_arg(sub.add_parser("status", help="Show router status"))
    status_parser.add_argument("--json", action="store_true", help="Emit JSON")
    doctor_parser = add_workspace_arg(sub.add_parser("doctor", help="Check install/config health"))
    doctor_parser.add_argument("--json", action="store_true", help="Emit JSON")
    return parser


def main(argv: List[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in {"-h", "--help", "help"}:
        print(render_help())
        return 0
    parser = build_parser()
    args = parser.parse_args(argv)
    workspace = Path(args.workspace)
    if args.command == "install":
        return install_workspace(workspace)
    if args.command == "init":
        return init_workspace(workspace, args.managed_agents or ["main"], args.force)
    if args.command == "add-account":
        return add_account(workspace, args.name, args.reauth, args.no_login, args.source_profile, args.json)
    if args.command == "enable":
        return enable_scheduler(workspace)
    if args.command == "status":
        return status_cmd(workspace, args.json)
    if args.command == "doctor":
        return doctor_cmd(workspace, args.json)
    print(render_help())
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
