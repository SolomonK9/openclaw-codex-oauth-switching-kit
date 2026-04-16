#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
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
PLUGIN_ID = "oauth-native-command"
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
        raise RuntimeError("Windows is not implemented in this slice yet. Use Linux or macOS for install/init/setup.")


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
        "plugins": workspace / "plugins",
        "oauth_plugin": workspace / "plugins" / PLUGIN_ID,
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


def install_plugin_package(workspace: Path) -> List[Tuple[str, str, Path]]:
    paths = workspace_paths(workspace)
    plugin_src = REPO_ROOT / "plugins" / PLUGIN_ID
    results: List[Tuple[str, str, Path]] = []
    if not plugin_src.exists():
        return results
    for name in ["index.js", "openclaw.plugin.json", "package.json"]:
        src = plugin_src / name
        dest = paths["oauth_plugin"] / name
        status = copy_if_changed(src, dest)
        results.append((f"{PLUGIN_ID}/{name}", status, dest))
    return results


def compile_scripts(paths: Iterable[Path]) -> None:
    for path in paths:
        py_compile.compile(str(path), doraise=True)


def render_help() -> str:
    return """oauth-routing — OpenClaw Codex OAuth routing wrapper

Commands:
  setup        Guided setup flow for install/init/plugin/scheduler wiring
  install      Stage scripts and starter state into an OpenClaw workspace
  init         Generate a standard starter config without hand-editing JSON
  add-account  Run the guided account onboarding helper
  enable       Enable scheduler jobs after explicit confirmation
  status       Show current router status
  doctor       Check install/config prerequisites and common problems

Examples:
  ./oauth-routing setup --workspace ~/.openclaw/workspace
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


def prompt_text(message: str, default: str = "") -> str:
    suffix = f" [{default}]: " if default else ": "
    answer = input(message + suffix).strip()
    return answer or default


def parse_csv_list(raw: str) -> List[str]:
    return [item.strip() for item in str(raw).split(",") if item.strip()]


def uniq(items: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        raw = str(item).strip()
        if not raw or raw in seen:
            continue
        seen.add(raw)
        out.append(raw)
    return out


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
    accounts = payload.get("accounts") if isinstance(payload.get("accounts"), list) else []
    if not accounts:
        payload["accounts"] = [{
            "profileId": "openai-codex:default",
            "name": "OAuth-Primary",
            "enabled": True,
            "priority": 1,
            "projects": ["mb", "autopit4", "temp"],
        }]
    payload.setdefault("alerts", {})
    for channel in ("telegram", "discord"):
        payload["alerts"].setdefault(channel, {})["enabled"] = False
    return payload


def update_config_channels(payload: dict, *, telegram_sender_ids: List[str], telegram_chat_ids: List[str], discord_channel_ids: List[str]) -> dict:
    alerts = payload.get("alerts") if isinstance(payload.get("alerts"), dict) else {}
    payload["alerts"] = alerts
    telegram = alerts.get("telegram") if isinstance(alerts.get("telegram"), dict) else {}
    discord = alerts.get("discord") if isinstance(alerts.get("discord"), dict) else {}
    alerts["telegram"] = telegram
    alerts["discord"] = discord
    telegram["channel"] = "telegram"
    telegram["target"] = telegram_chat_ids[0] if telegram_chat_ids else ""
    telegram["enabled"] = bool(telegram_chat_ids)
    discord["channel"] = "discord"
    discord["target"] = f"channel:{discord_channel_ids[0]}" if discord_channel_ids else ""
    discord["enabled"] = bool(discord_channel_ids)
    payload["sessionRebind"] = payload.get("sessionRebind") if isinstance(payload.get("sessionRebind"), dict) else {}
    payload["sessionRebind"]["agents"] = payload.get("managedAgents", ["main"])
    payload["usageProbe"] = payload.get("usageProbe") if isinstance(payload.get("usageProbe"), dict) else {}
    payload["usageProbe"]["agentId"] = payload.get("managedAgents", ["main"])[0]
    payload["meta"] = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    payload["meta"]["setup"] = {
        "telegramSenderIds": telegram_sender_ids,
        "telegramChatIds": telegram_chat_ids,
        "discordChannelIds": discord_channel_ids,
    }
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


def openclaw_cmd(profile: str | None = None) -> List[str]:
    cmd = ["openclaw"]
    if profile:
        cmd.extend(["--profile", profile])
    return cmd


def run_openclaw(args: List[str], *, profile: str | None = None, cwd: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return run(openclaw_cmd(profile) + args, cwd=cwd, timeout=timeout)


def get_active_openclaw_workspace(profile: str | None = None) -> Tuple[Path | None, str | None]:
    result = run_openclaw(["plugins", "list", "--json"], profile=profile, timeout=60)
    if result.returncode != 0:
        return None, result.stderr.strip() or result.stdout.strip() or "openclaw plugins list failed"
    try:
        payload = json.loads(result.stdout)
    except Exception as exc:
        return None, f"failed to parse openclaw plugins list json: {exc}"
    raw = payload.get("workspaceDir")
    if not raw:
        return None, "plugins list returned no workspaceDir"
    return Path(raw).expanduser().resolve(), None


def config_set_json(path: str, value, *, profile: str | None = None) -> Tuple[bool, str]:
    result = run_openclaw(["config", "set", path, json.dumps(value), "--strict-json"], profile=profile, timeout=60)
    ok = result.returncode == 0
    detail = result.stdout.strip() or result.stderr.strip() or ("ok" if ok else "config set failed")
    return ok, detail


def config_get_json(path: str, *, profile: str | None = None):
    result = run_openclaw(["config", "get", path], profile=profile, timeout=60)
    if result.returncode != 0:
        return None
    raw = (result.stdout or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return raw


def merge_plugins_allow(profile: str | None = None) -> Tuple[bool, str]:
    current = config_get_json("plugins.allow", profile=profile)
    values = [] if current in (None, "") else (current if isinstance(current, list) else [str(current)])
    merged = uniq([*values, PLUGIN_ID])
    return config_set_json("plugins.allow", merged, profile=profile)


def verify_plugin_loaded(profile: str | None = None) -> Tuple[bool, str]:
    result = run_openclaw(["plugins", "inspect", PLUGIN_ID, "--json"], profile=profile, timeout=60)
    if result.returncode != 0:
        return False, result.stderr.strip() or result.stdout.strip() or "plugins inspect failed"
    try:
        payload = json.loads(result.stdout)
    except Exception as exc:
        return False, f"plugins inspect returned invalid JSON: {exc}"
    plugin = payload.get("plugin") or {}
    commands = payload.get("commands") or []
    if plugin.get("enabled") and "oauth" in commands:
        return True, "plugin inspect reports enabled native /oauth command"
    return False, f"plugin inspect did not show enabled /oauth command: enabled={plugin.get('enabled')} commands={commands}"


def install_and_enable_plugin(workspace: Path, *, profile: str | None, telegram_sender_ids: List[str], telegram_chat_ids: List[str], discord_channel_ids: List[str]) -> Tuple[bool, List[str]]:
    paths = workspace_paths(workspace)
    plugin_path = paths["oauth_plugin"]
    if not plugin_path.exists():
        return False, [f"plugin staging path missing: {plugin_path}"]
    messages: List[str] = []
    install_result = run_openclaw(["plugins", "install", shell_path(plugin_path)], profile=profile, cwd=paths["workspace"], timeout=120)
    messages.append(install_result.stdout.strip() or install_result.stderr.strip() or f"plugins install exited {install_result.returncode}")
    if install_result.returncode != 0:
        return False, messages
    allow_ok, allow_detail = merge_plugins_allow(profile=profile)
    messages.append(allow_detail)
    if not allow_ok:
        return False, messages
    for config_path, value in [
        (f"plugins.entries.{PLUGIN_ID}.config.workspacePath", shell_path(paths["workspace"])),
        (f"plugins.entries.{PLUGIN_ID}.config.telegramSenderIds", telegram_sender_ids),
        (f"plugins.entries.{PLUGIN_ID}.config.telegramChatIds", telegram_chat_ids),
        (f"plugins.entries.{PLUGIN_ID}.config.discordChannelIds", discord_channel_ids),
    ]:
        ok, detail = config_set_json(config_path, value, profile=profile)
        messages.append(detail)
        if not ok:
            return False, messages
    enable_result = run_openclaw(["plugins", "enable", PLUGIN_ID], profile=profile, cwd=paths["workspace"], timeout=120)
    messages.append(enable_result.stdout.strip() or enable_result.stderr.strip() or f"plugins enable exited {enable_result.returncode}")
    if enable_result.returncode != 0:
        return False, messages
    verify_ok, verify_detail = verify_plugin_loaded(profile=profile)
    messages.append(verify_detail)
    return verify_ok, messages


def enable_scheduler(workspace: Path, confirm: bool = True) -> int:
    ensure_unix_supported()
    paths = workspace_paths(workspace)
    setup_script = paths["scripts"] / "setup_oauth_crons.sh"
    setup_status = copy_if_changed(REPO_ROOT / "scripts" / "setup_oauth_crons.sh", setup_script)
    os.chmod(setup_script, 0o755)
    info(f"Scheduler setup script: {setup_status} -> {setup_script}")
    if confirm and not prompt_yes_no(f"Confirm scheduler changes in workspace {paths['workspace']}? This will add OpenClaw cron jobs.", default=False):
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


def install_workspace(workspace: Path, prompt_scheduler: bool = True) -> int:
    ensure_unix_supported()
    paths = workspace_paths(workspace)
    prereqs = detect_prereqs()
    missing = [name for name, ok, _detail in prereqs if not ok]
    info("Checking prerequisites:")
    for name, ok, detail in prereqs:
        info(f"- {name}: {'ok' if ok else 'missing'} ({detail})")
    if missing:
        return fail("Missing required prerequisites: " + ", ".join(missing))

    for key in ("workspace", "ops", "scripts", "bin", "state", "logs", "backups", "plugins", "oauth_plugin"):
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
    plugin_results = install_plugin_package(paths["workspace"])
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
    for name, status, dest in plugin_results:
        info(f"- {name}: {status} -> {dest}")
    info(f"- oauth-routing shim: {shim_status} -> {paths['shim']}")

    if prompt_scheduler and sys.stdin.isatty() and prompt_yes_no("Install scheduler/cron jobs now via openclaw cron add?", default=False):
        rc = enable_scheduler(workspace)
        if rc != 0:
            return rc
    elif prompt_scheduler:
        info("Skipped scheduler changes. You can enable them later with: oauth-routing enable")

    info("\nNext step:")
    info(f"  {paths['shim']} init --workspace {paths['workspace']}")
    return 0


def init_workspace(workspace: Path, managed_agents: List[str], force: bool, telegram_sender_ids: List[str] | None = None, telegram_chat_ids: List[str] | None = None, discord_channel_ids: List[str] | None = None) -> int:
    ensure_unix_supported()
    paths = workspace_paths(workspace)
    if not paths["router"].exists():
        return fail(f"Router is not installed in {paths['workspace']}. Run install first.")
    template_bytes = (REPO_ROOT / "templates" / "oauth-pool-config.template.json").read_bytes()
    config_exists = paths["config"].exists()
    config_is_unedited_template = config_exists and paths["config"].read_bytes() == template_bytes
    if config_exists and not force and not config_is_unedited_template:
        return fail(f"Config already exists: {paths['config']} (use --force to overwrite)")

    payload = standard_config(managed_agents)
    payload = update_config_channels(
        payload,
        telegram_sender_ids=telegram_sender_ids or [],
        telegram_chat_ids=telegram_chat_ids or [],
        discord_channel_ids=discord_channel_ids or [],
    )
    save_json(paths["config"], payload)
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


def collect_setup_inputs(args) -> dict:
    interactive = sys.stdin.isatty() and not args.yes
    managed_agents = uniq(args.managed_agents or [])
    if not managed_agents:
        if interactive:
            managed_agents = uniq(parse_csv_list(prompt_text("Managed agent IDs (comma-separated)", "main")))
        else:
            managed_agents = ["main"]

    channel = args.channel
    if channel is None:
        if interactive:
            channel = (prompt_text("Which operator surfaces do you want to enable? (telegram/discord/both/none)", "both").lower() or "both")
        else:
            channel = "both"

    telegram_sender_ids = uniq(args.telegram_sender_ids or [])
    telegram_chat_ids = uniq(args.telegram_chat_ids or [])
    discord_channel_ids = uniq(args.discord_channel_ids or [])

    wants_telegram = channel in {"telegram", "both"}
    wants_discord = channel in {"discord", "both"}

    if wants_telegram and not telegram_sender_ids and interactive:
        telegram_sender_ids = uniq(parse_csv_list(prompt_text("Telegram sender IDs (comma-separated)")))
    if wants_telegram and not telegram_chat_ids and interactive:
        raw = prompt_text("Telegram chat IDs (comma-separated, blank = reuse sender IDs)", "")
        telegram_chat_ids = uniq(parse_csv_list(raw)) if raw else list(telegram_sender_ids)
    if wants_telegram and telegram_sender_ids and not telegram_chat_ids:
        telegram_chat_ids = list(telegram_sender_ids)
    if wants_discord and not discord_channel_ids and interactive:
        discord_channel_ids = uniq(parse_csv_list(prompt_text("Discord channel IDs (comma-separated)")))

    if wants_telegram and not telegram_sender_ids:
        raise RuntimeError("Telegram support selected, but no Telegram sender IDs were provided.")
    if wants_telegram and not telegram_chat_ids:
        raise RuntimeError("Telegram support selected, but no Telegram chat IDs were provided.")
    if wants_discord and not discord_channel_ids:
        raise RuntimeError("Discord support selected, but no Discord channel IDs were provided.")

    enable_plugin = args.enable_plugin
    if enable_plugin is None:
        enable_plugin = False if channel == "none" else True
        if interactive and channel != "none":
            enable_plugin = prompt_yes_no(
                "Stage and enable the native /oauth plugin now? This enables native /oauth handling and inline operator controls.",
                default=True,
            )

    enable_scheduler_flag = args.enable_scheduler
    if enable_scheduler_flag is None:
        enable_scheduler_flag = True
        if interactive:
            enable_scheduler_flag = prompt_yes_no(
                "Enable core background OAuth routing jobs now? This adds OpenClaw cron jobs for routing automation.",
                default=True,
            )

    return {
        "managed_agents": managed_agents,
        "channel": channel,
        "telegram_sender_ids": telegram_sender_ids,
        "telegram_chat_ids": telegram_chat_ids,
        "discord_channel_ids": discord_channel_ids,
        "enable_plugin": enable_plugin,
        "enable_scheduler": enable_scheduler_flag,
    }


def setup_cmd(args) -> int:
    ensure_unix_supported()
    quiet = bool(args.json)
    emit = (lambda *_args, **_kwargs: None) if quiet else info
    workspace = Path(args.workspace).expanduser().resolve()
    paths = workspace_paths(workspace)
    prereqs = detect_prereqs()
    missing = [name for name, ok, _detail in prereqs if not ok]
    if missing:
        return fail("Missing required prerequisites: " + ", ".join(missing))

    try:
        setup = collect_setup_inputs(args)
    except RuntimeError as exc:
        return fail(str(exc))

    emit("OAuth Routing setup\n")
    emit("Detected:")
    emit(f"- OS: {platform.system()}")
    for name, ok, detail in prereqs:
        emit(f"- {name}: {'ok' if ok else 'missing'} ({detail})")
    emit(f"- workspace: {paths['workspace']}")
    emit(f"- existing install: {'yes' if paths['router'].exists() else 'no'}")
    emit(f"- existing config: {'yes' if paths['config'].exists() else 'no'}")
    if args.openclaw_profile:
        emit(f"- openclaw profile: {args.openclaw_profile}")

    with contextlib.redirect_stdout(io.StringIO()) if quiet else contextlib.nullcontext():
        install_rc = install_workspace(paths["workspace"], prompt_scheduler=False)
    if install_rc != 0:
        return install_rc

    with contextlib.redirect_stdout(io.StringIO()) if quiet else contextlib.nullcontext():
        init_rc = init_workspace(
        paths["workspace"],
        setup["managed_agents"],
        args.force,
        telegram_sender_ids=setup["telegram_sender_ids"],
        telegram_chat_ids=setup["telegram_chat_ids"],
        discord_channel_ids=setup["discord_channel_ids"],
    )
    if init_rc != 0:
        return init_rc

    plugin_status = "skipped"
    plugin_notes: List[str] = []
    if setup["enable_plugin"]:
        plugin_ok, plugin_notes = install_and_enable_plugin(
            paths["workspace"],
            profile=args.openclaw_profile,
            telegram_sender_ids=setup["telegram_sender_ids"],
            telegram_chat_ids=setup["telegram_chat_ids"],
            discord_channel_ids=setup["discord_channel_ids"],
        )
        plugin_status = "enabled" if plugin_ok else "staged-only"
    else:
        plugin_status = "staged-only"
        plugin_notes.append("Native plugin was staged but not enabled by request.")

    scheduler_status = "skipped"
    if setup["enable_scheduler"]:
        with contextlib.redirect_stdout(io.StringIO()) if quiet else contextlib.nullcontext():
            scheduler_rc = enable_scheduler(paths["workspace"], confirm=False)
        if scheduler_rc != 0:
            return scheduler_rc
        scheduler_status = "enabled"

    with contextlib.redirect_stdout(io.StringIO()) if quiet else contextlib.nullcontext():
        doctor_rc = doctor_cmd(paths["workspace"], json_mode=False)
    doctor_ok = doctor_rc == 0
    router_ok, router_detail = validate_router_status(paths["workspace"])
    active_ws, active_ws_err = get_active_openclaw_workspace(profile=args.openclaw_profile)

    summary = {
        "workspace": shell_path(paths["workspace"]),
        "managedAgents": setup["managed_agents"],
        "channels": setup["channel"],
        "plugin": plugin_status,
        "scheduler": scheduler_status,
        "routerStatusJson": router_ok,
        "doctor": doctor_ok,
        "activeOpenClawWorkspace": shell_path(active_ws) if active_ws else None,
        "activeOpenClawWorkspaceError": active_ws_err,
        "next": f"{shell_path(paths['shim'])} add-account --workspace {shell_path(paths['workspace'])} --name <Label>",
    }

    emit("\nSetup summary")
    emit(f"- plugin: {plugin_status}")
    emit(f"- scheduler: {scheduler_status}")
    emit(f"- router status json: {'ok' if router_ok else 'fail'} ({router_detail})")
    if active_ws:
        emit(f"- active OpenClaw workspace: {active_ws}")
    elif active_ws_err:
        emit(f"- active OpenClaw workspace: unknown ({active_ws_err})")
    for note in plugin_notes:
        if note:
            emit(f"- plugin note: {note}")

    if args.json:
        print(json.dumps(summary, indent=2))

    emit("\nNext step:")
    emit(f"  {summary['next']}")
    return 0 if router_ok and doctor_ok else 1


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
        {"name": "oauth_native_plugin", "ok": (paths["oauth_plugin"] / "openclaw.plugin.json").exists(), "detail": shell_path(paths["oauth_plugin"])} ,
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


def add_channel_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--channel", choices=["telegram", "discord", "both", "none"], default=None, help="Operator surfaces to configure")
    parser.add_argument("--telegram-sender-id", action="append", dest="telegram_sender_ids", help="Allowed Telegram sender ID (repeatable)")
    parser.add_argument("--telegram-chat-id", action="append", dest="telegram_chat_ids", help="Allowed Telegram chat ID (repeatable)")
    parser.add_argument("--discord-channel-id", action="append", dest="discord_channel_ids", help="Allowed Discord channel ID (repeatable)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oauth-routing", description="Public wrapper for OpenClaw Codex OAuth routing")
    sub = parser.add_subparsers(dest="command")

    setup_parser = add_workspace_arg(sub.add_parser("setup", help="Guided setup flow for install/init/plugin/scheduler wiring"))
    setup_parser.add_argument("--managed-agent", action="append", dest="managed_agents", help="Managed agent id (repeatable; default: main)")
    add_channel_args(setup_parser)
    setup_parser.add_argument("--enable-plugin", dest="enable_plugin", action="store_true", default=None, help="Enable the native /oauth plugin during setup")
    setup_parser.add_argument("--disable-plugin", dest="enable_plugin", action="store_false", help="Do not enable the native /oauth plugin during setup")
    setup_parser.add_argument("--enable-scheduler", dest="enable_scheduler", action="store_true", default=None, help="Enable scheduler jobs during setup")
    setup_parser.add_argument("--disable-scheduler", dest="enable_scheduler", action="store_false", help="Skip scheduler enable during setup")
    setup_parser.add_argument("--openclaw-profile", default=None, help="Optional OpenClaw profile for plugin/config operations")
    setup_parser.add_argument("--force", action="store_true", help="Overwrite existing config during setup")
    setup_parser.add_argument("--yes", action="store_true", help="Accept defaults for interactive confirmations")
    setup_parser.add_argument("--json", action="store_true", help="Emit final setup summary JSON")

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
    if args.command == "setup":
        return setup_cmd(args)
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
