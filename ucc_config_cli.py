import argparse
import json
import os
import sys
from getpass import getpass
from typing import Any, Dict, List


def default_config_path() -> str:
    # Respect PANCORE_CONFIG if it points to a file path; else use ./config/panCoreConfig.json
    env_path = os.environ.get("PANCORE_CONFIG")
    if env_path:
        # If env is a directory, place file inside it
        if os.path.isdir(env_path):
            return os.path.join(env_path, "panCoreConfig.json")
        return env_path
    return os.path.join(os.path.dirname(__file__), "config", "panCoreConfig.json")


def load_config(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_config(path: str, data: Dict[str, Any]) -> None:
    folder = os.path.dirname(path)
    if folder and not os.path.isdir(folder):
        os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def validate_config(data: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(data, dict):
        return ["Config must be a JSON object"]
    api = data.get("api") or {}
    if not isinstance(api, dict):
        errors.append("'api' must be an object")
    else:
        if not api.get("username"):
            errors.append("api.username is required")
        if not api.get("password"):
            errors.append("api.password is required")
        port = api.get("port", 443)
        try:
            port = int(port)
            if port <= 0 or port > 65535:
                errors.append("api.port must be 1-65535")
        except Exception:
            errors.append("api.port must be an integer")
        verify = api.get("verify_ssl", False)
        if not isinstance(verify, (bool, int)):
            errors.append("api.verify_ssl must be boolean")
    devices = data.get("devices")
    if not isinstance(devices, list) or not devices:
        errors.append("devices must be a non-empty list")
    else:
        for i, dev in enumerate(devices):
            if not isinstance(dev, dict):
                errors.append(f"devices[{i}] must be an object")
                continue
            host = dev.get("host") or dev.get("hostname") or dev.get("ip")
            if not host:
                errors.append(f"devices[{i}].host is required")
            if "port" in dev:
                try:
                    p = int(dev["port"])  # noqa: F841
                except Exception:
                    errors.append(f"devices[{i}].port must be an integer if provided")
    return errors


essay = """
This utility manages the URL Category Checker configuration file (panCoreConfig.json).
It writes/validates the same JSON that the Flask app reads to build firewall connections.

Default path resolution:
- If PANCORE_CONFIG is set, it uses that path (or drops panCoreConfig.json inside if it's a directory).
- Otherwise: ./config/panCoreConfig.json relative to this repository.
""".strip()


def resolve_config_path(args: argparse.Namespace | None) -> str:
    # Prefer explicit CLI flag --conffile/-c, then legacy --path, else env/default
    if args is not None:
        path = getattr(args, "conffile", None) or getattr(args, "path", None)
        if path:
            return path
    return default_config_path()


def cmd_show(args: argparse.Namespace) -> int:
    path = resolve_config_path(args)
    data = load_config(path)
    if not data:
        print(f"No config found at {path}")
        return 1
    out = json.loads(json.dumps(data))  # deep-ish copy
    if not getattr(args, "show_secret", False):
        try:
            if "api" in out and "password" in out["api"]:
                out["api"]["password"] = "***"
        except Exception:
            pass
    print(json.dumps(out, indent=2))
    return 0


def parse_devices_list(dev_items: List[str]) -> List[Dict[str, Any]]:
    devices: List[Dict[str, Any]] = []
    for item in dev_items:
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            host, port_str = item.rsplit(":", 1)
            try:
                devices.append({"host": host.strip(), "port": int(port_str)})
            except Exception:
                devices.append({"host": host.strip()})
        else:
            devices.append({"host": item})
    return devices


def cmd_set(args: argparse.Namespace) -> int:
    path = resolve_config_path(args)
    cfg = load_config(path)
    if not isinstance(cfg.get("api"), dict):
        cfg["api"] = {}
    if args.username is not None:
        cfg["api"]["username"] = args.username
    if args.password is not None:
        cfg["api"]["password"] = args.password
    if args.port is not None:
        cfg["api"]["port"] = int(args.port)
    if args.verify_ssl is not None:
        cfg["api"]["verify_ssl"] = bool(args.verify_ssl)

    if args.device:
        new_devs = parse_devices_list(args.device)
        if args.overwrite:
            cfg["devices"] = new_devs
        else:
            cur = cfg.get("devices") or []
            if not isinstance(cur, list):
                cur = []
            cfg["devices"] = cur + new_devs

    save_config(path, cfg)
    errs = validate_config(cfg)
    if errs:
        print(f"Saved to {path}, but found validation issues:")
        for e in errs:
            print(f" - {e}")
        return 2
    print(f"Configuration saved to {path} and validated OK.")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    path = resolve_config_path(args)
    cfg = load_config(path)
    errs = validate_config(cfg)
    if errs:
        print(f"Invalid configuration at {path}:")
        for e in errs:
            print(f" - {e}")
        return 2
    print("Configuration is valid.")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    path = resolve_config_path(args)
    print(f"Initializing configuration at {path}...")
    username = input("API Username: ")
    password = getpass("API Password: ")
    port_in = input("API Port [443]: ").strip() or "443"
    try:
        port = int(port_in)
    except Exception:
        print("Port must be an integer; defaulting to 443")
        port = 443
    verify_in = input("Verify SSL (y/N): ").strip().lower()
    verify_ssl = verify_in in ("y", "yes", "true", "1")

    dev_str = input("Firewall hosts (comma-separated, host or host:port): ").strip()
    devices = parse_devices_list([s for s in dev_str.split(",") if s.strip()])

    cfg = {
        "api": {
            "username": username,
            "password": password,
            "port": port,
            "verify_ssl": verify_ssl,
        },
        "devices": devices or [],
    }

    save_config(path, cfg)
    errs = validate_config(cfg)
    if errs:
        print(f"Saved to {path}, but found validation issues:")
        for e in errs:
            print(f" - {e}")
        return 2
    print(f"Configuration initialized at {path}.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="URL Category Checker configuration utility", epilog=essay)
    # Keep --path for backward compatibility; prefer -c/--conffile like panInventory
    p.add_argument("-c", "--conffile", help="Path to panCoreConfig.json (overrides PANCORE_CONFIG/default)")
    p.add_argument("--path", help=argparse.SUPPRESS)

    sub = p.add_subparsers(dest="cmd", required=False)

    s_show = sub.add_parser("show", help="Display current configuration (password redacted by default)")
    s_show.add_argument("--show-secret", action="store_true", help="Show api.password in clear text")
    s_show.set_defaults(func=cmd_show)

    s_set = sub.add_parser("set", help="Set fields non-interactively and save")
    s_set.add_argument("--username")
    s_set.add_argument("--password")
    s_set.add_argument("--port", type=int)
    s_set.add_argument("--verify-ssl", action="store_true", dest="verify_ssl")
    s_set.add_argument("--no-verify-ssl", action="store_false", dest="verify_ssl")
    s_set.add_argument("--device", action="append", help="Add device host or host:port; repeatable")
    s_set.add_argument("--overwrite", action="store_true", help="Overwrite existing devices list instead of appending")
    s_set.set_defaults(func=cmd_set)

    s_val = sub.add_parser("validate", help="Validate configuration file")
    s_val.set_defaults(func=cmd_validate)

    s_init = sub.add_parser("init", help="Interactive wizard to create configuration")
    s_init.set_defaults(func=cmd_init)

    return p


def _prompt_bool(prompt: str, default: bool = False) -> bool:
    suf = "Y/n" if default else "y/N"
    ans = input(f"{prompt} [{suf}]: ").strip().lower()
    if not ans:
        return default
    return ans in ("y", "yes", "true", "1")


def interactive_menu() -> int:
    # Default path resolution mirrors panInventory style: assume panCoreConfig.json unless overridden.
    default_path = default_config_path()
    print("URL Category Checker — Config Utility")
    print("No arguments provided; entering interactive mode. Press Ctrl+C to exit at any time.\n")
    while True:
        print(f"Current config file: {default_path}")
        print("Select an action:")
        print("  1) Init configuration (interactive wizard)")
        print("  2) Validate configuration")
        print("  3) Show configuration")
        print("  4) Set fields (username/password/port/verify/devices)")
        print("  Q) Quit")
        choice = input("> ").strip().lower()
        if choice in ("q", "quit", "exit"):  # graceful exit with code 0
            print("Goodbye.")
            return 0
        try:
            if choice == "1":
                ns = argparse.Namespace(conffile=default_path, path=None)
                return cmd_init(ns)
            elif choice == "2":
                ns = argparse.Namespace(conffile=default_path, path=None)
                return cmd_validate(ns)
            elif choice == "3":
                ns = argparse.Namespace(conffile=default_path, path=None, show_secret=False)
                return cmd_show(ns)
            elif choice == "4":
                # Gather fields optionally
                print("Leave any field blank to keep existing value.")
                username = input("Username: ").strip() or None
                password = getpass("Password: ").strip() or None
                port_txt = input("Port [blank to keep]: ").strip()
                port = int(port_txt) if port_txt else None
                verify_ssl = None
                ans = input("Verify SSL? [y/N/blank keep]: ").strip().lower()
                if ans in ("y", "yes", "true", "1"):
                    verify_ssl = True
                elif ans in ("n", "no", "false", "0"):
                    verify_ssl = False
                dev_line = input("Devices (comma separated host or host:port) [blank to skip]: ").strip()
                devices = [s for s in dev_line.split(",") if s.strip()] if dev_line else []
                overwrite = False
                if devices:
                    overwrite = _prompt_bool("Overwrite existing devices list?", default=False)
                ns = argparse.Namespace(
                    conffile=default_path,
                    path=None,
                    username=username,
                    password=password,
                    port=port,
                    verify_ssl=verify_ssl,
                    device=devices if devices else None,
                    overwrite=overwrite,
                )
                return cmd_set(ns)
            else:
                print("Please select 1, 2, 3, 4 or Q.\n")
        except KeyboardInterrupt:
            print("\nAborted by user.")
            return 130
        except Exception as ex:
            print(f"Error: {ex}")
            return 1


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    # If no args, enter interactive menu rather than exiting with code 2
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return interactive_menu()
    args = parser.parse_args(argv)
    # Provide graceful help if no subcommand chosen (e.g., only -c provided)
    if not hasattr(args, "func"):
        print("No command provided; starting interactive mode. Use -h for help.")
        return interactive_menu()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
