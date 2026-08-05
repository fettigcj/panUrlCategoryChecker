#!/usr/bin/env python3
"""
panCheckURL - CLI utility to check URL categories across firewalls discovered from Panorama configs.

Design goals
- Mirror panInventory-style startup: argparse, pancore.configStart(), pancore.buildPano_obj()
- Take a single -c/--config path that points to a directory (recommended) containing JSON config files, or a single JSON file
- Distribute URL checks across available firewalls (round-robin)
- Honor an exclusion list of firewall serial numbers (one per line) at config/FirewallExclusionList.txt by default
- Output as table/csv/json; exit code 0 on success with at least one result, 1 on argument/usage error

Examples
  py panCheckURL.py -c config/panCoreConfig.json --urls-file urls.txt
  py panCheckURL.py -c config --urls "example.com,https://paloaltonetworks.com" --output json
  type urls.txt | py panCheckURL.py -c config/panCoreConfig.json --stdin
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse
import time
from collections import deque

# Optional pancore import from submodule/package
try:
    from pancore import panCore  # type: ignore
except Exception:
    panCore = None  # type: ignore

# pan-os-python
try:
    from panos.firewall import Firewall  # type: ignore
except Exception:
    Firewall = None  # type: ignore


# -------- Path helpers (robust when __file__ may be missing under some IDEs) --------
def _this_dir() -> str:
    try:
        d = os.path.dirname(__file__)  # type: ignore[name-defined]
        if d:
            return d
    except Exception:
        pass
    try:
        a0 = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
        if a0 and os.path.exists(a0):
            d2 = os.path.dirname(a0)
            if d2:
                return d2
    except Exception:
        pass
    return os.getcwd()


def _resolve_candidate(path_like: str, *alternates: str) -> str:
    """Return the first existing path among: given path_like (as-is), CWD\\path_like (if relative),
    script_dir\\path_like (if relative), and any explicit alternates provided. If none exist, return the
    presumed CWD candidate so callers can still present a sensible path or write there.
    """
    if not path_like:
        return path_like
    if os.path.isabs(path_like):
        return path_like
    cwd_candidate = os.path.join(os.getcwd(), path_like)
    if os.path.exists(cwd_candidate):
        return cwd_candidate
    sd_candidate = os.path.join(_this_dir(), path_like)
    if os.path.exists(sd_candidate):
        return sd_candidate
    for alt in alternates:
        if os.path.exists(alt):
            return alt
    return cwd_candidate


# ---------------- URL helpers ----------------


# ---------------- URL helpers ----------------
ALLOWED_SCHEMES = {"http", "https"}

def normalize_urls(text: str) -> List[str]:
    """Normalize a blob of text into URL-like strings WITHOUT forcing a protocol.
    - Accept bare domains like 'cnn.com' or 'www.cnn.com'.
    - If a protocol (http/https) is provided, strip it so we pass just the host/path to 'test url'.
    - Support comma-separated entries and '#' comments.
    - De-duplicate while preserving order (case-insensitive keys).
    """
    urls: List[str] = []
    seen_ci: set[str] = set()
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith('#'):
            continue
        parts = [p.strip() for p in s.split(',') if p.strip()]
        for p in parts:
            q = p
            # Strip protocol prefixes if present
            lp = q.lower()
            if lp.startswith('http://'):
                q = q[7:]
            elif lp.startswith('https://'):
                q = q[8:]
            elif q.startswith('//'):
                q = q[2:]
            q = q.strip()
            if not q:
                continue
            # Basic sanitation: drop surrounding brackets/angles/quotes often pasted
            q = q.strip(" <>\"'")
            key = q.lower()
            if key in seen_ci:
                continue
            seen_ci.add(key)
            urls.append(q)
    return urls


# ---------------- Config and firewall discovery ----------------

def default_exclude_path() -> str:
    # Prefer relative path so IDE runs from different CWDs still work
    return _resolve_candidate(os.path.join('config', 'FirewallExclusionList.txt'))


def load_exclusions(path: Optional[str]) -> set[str]:
    excludes: set[str] = set()
    if not path:
        path = default_exclude_path()
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                excludes.add(s)
    return excludes


def build_groups(config_files: List[str]) -> List[List[Any]]:
    """For each config file, call pancore to produce a list of Firewall objects.
    Returns a list of groups, each being a List[Firewall]. If pancore is unavailable or an error occurs,
    returns an empty list for that group.
    """
    groups: List[List[Any]] = []
    if panCore is None:
        return groups
    for cfg in config_files:
        try:
            panCore.configStart(headless=True, configStorage=cfg)
            pano_addr = getattr(panCore, 'panAddress', None)
            pan_user = getattr(panCore, 'panUser', 'optional')
            pan_pass = getattr(panCore, 'panPass', 'optional')
            pan_key = getattr(panCore, 'panKey', 'optional')
            tup = panCore.buildPano_obj(panAddress=pano_addr, panUser=pan_user, panPass=pan_pass, panKey=pan_key)
            if isinstance(tup, tuple) and len(tup) >= 3:
                _pano_obj, _dgs, firewalls, *_rest = tup
                if isinstance(firewalls, list):
                    groups.append(firewalls)
                else:
                    groups.append([])
            else:
                groups.append([])
        except SystemExit:
            # pancore may sys.exit() on certain errors; treat as empty group
            groups.append([])
        except Exception:
            groups.append([])
    return groups


def build_groups_from_local_schema(config_files: List[str]) -> List[List[Any]]:
    """Fallback: read simple JSON schema {api:{}, devices:[]} and construct Firewall objects.
    Returns empty groups if parsing fails or pan-os-python is unavailable.
    """
    groups: List[List[Any]] = []
    if Firewall is None:
        return [[] for _ in config_files]
    for cfg in config_files:
        lst: List[Any] = []
        try:
            with open(cfg, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            api = data.get('api', {})
            username = api.get('username')
            password = api.get('password')
            port = int(api.get('port', 443))
            devices = data.get('devices', [])
            for dev in devices:
                host = dev.get('host') or dev.get('hostname') or dev.get('ip')
                if not host:
                    continue
                dev_port = int(dev.get('port', port))
                try:
                    fw = Firewall(hostname=host, api_username=username, api_password=password, port=dev_port)
                    lst.append(fw)
                except Exception:
                    continue
        except Exception:
            lst = []
        groups.append(lst)
    return groups


def resolve_fw_identity(fw: Any) -> Tuple[str, str]:
    """Return (hostname_or_ip, serial). Attempts to avoid expensive calls when possible."""
    host = getattr(fw, 'hostname', None) or getattr(fw, 'host', None) or getattr(fw, 'ip', None) or ""
    serial = getattr(fw, 'serial', None) or getattr(fw, 'serialnumber', None) or ""
    if not serial:
        # Try to fetch from system info; guard with lock per object if many threads race
        try:
            # Some pan-os-python versions provide refresh_system_info(); fallback to show_system_info via xapi
            if hasattr(fw, 'refresh_system_info'):
                fw.refresh_system_info()
                serial = getattr(fw, 'serial', None) or getattr(fw, 'serialnumber', None) or ""
            elif hasattr(fw, 'xapi'):
                info = fw.op(cmd="show system info", xml=True)
                # info may be XML string or ET; try basic parsing through pan-os-python converter to dict if present
                # As a fallback, just keep empty serial
                if hasattr(fw, 'about') and isinstance(fw.about(), dict):
                    serial = fw.about().get('serial', serial)
        except Exception:
            pass
    return str(host or ""), str(serial or "")


def filter_exclusions(groups: List[List[Any]], exclude_serials: set[str]) -> List[List[Any]]:
    if not exclude_serials:
        return groups
    filtered: List[List[Any]] = []
    for g in groups:
        keep: List[Any] = []
        for fw in g:
            _host, serial = resolve_fw_identity(fw)
            if serial and serial in exclude_serials:
                continue
            keep.append(fw)
        filtered.append(keep)
    return filtered


# ---------------- URL category check engine ----------------

def check_url_on_firewall(fw: Any, url: str, timeout: int = 15) -> Tuple[str, Dict[str, Dict[str, str]], str, str, Optional[str]]:
    """Run 'test url <url>' on the given firewall.
    Returns tuple: (url, categories_by_db, fw_host, fw_serial, error)
    where categories_by_db = {
        'baseDB': {'category1': str, 'category2': str},
        'cloudDB': {'category1': str, 'category2': str},
    }
    Missing values are empty strings. """
    host, serial = resolve_fw_identity(fw)
    cats: Dict[str, Dict[str, str]] = {
        'baseDB': {'category1': '', 'category2': ''},
        'cloudDB': {'category1': '', 'category2': ''},
    }
    error: Optional[str] = None
    try:
        # Build XML command explicitly and request raw response (cmd_xml=False)
        cmd = f"<test><url>{url}</url></test>"
        resp_el = panCore.xmlToLXML(fw.op(cmd=cmd, cmd_xml=False))
        # The device returns the interesting info as plain text under //response/result
        # Example lines:
        #   www.cnn.com news low-risk (Base db) mlav_flag=0, mica_flags=0 expires in 0 seconds
        #   www.cnn.com news low-risk (Cloud db)
        try:
            # Prefer XPath string() to collapse child text, then split into lines
            text_blob = resp_el.xpath('string(//response/result)') if hasattr(resp_el, 'xpath') else str(resp_el)
        except Exception:
            text_blob = str(resp_el)
        lines = [ln.strip() for ln in str(text_blob).splitlines() if ln.strip()]
        # Parse each line; identify Base vs Cloud by the token '(Base' or '(Cloud'
        for ln in lines:
            parts = ln.split()
            if not parts:
                continue
            # Identify DB type
            db_key = None
            for i, tok in enumerate(parts):
                t = tok.lower()
                if t.startswith('(base'):
                    db_key = 'baseDB'
                    break
                if t.startswith('(cloud'):
                    db_key = 'cloudDB'
                    break
            # Extract categories: tokens immediately after the echoed URL until '(' starts
            cat1 = parts[1] if len(parts) > 1 and not parts[1].startswith('(') else ''
            cat2 = parts[2] if len(parts) > 2 and not parts[2].startswith('(') else ''
            # If URL echo isn't present for some reason, fallback to first two non-paren tokens
            if not cat1:
                non_paren = [p for p in parts if not p.startswith('(')]
                if non_paren:
                    # Assume first token is URL or host; next two are categories if present
                    if len(non_paren) >= 2:
                        cat1 = non_paren[1] if len(non_paren) > 1 else ''
                    if len(non_paren) >= 3:
                        cat2 = non_paren[2] if len(non_paren) > 2 else ''
            if db_key:
                cats[db_key]['category1'] = cat1 or cats[db_key]['category1']
                cats[db_key]['category2'] = cat2 or cats[db_key]['category2']
        # If nothing parsed at all, set an error
        if not any((cats['baseDB']['category1'], cats['cloudDB']['category1'])):
            error = "No categories parsed"
    except Exception as e:
        error = f"{type(e).__name__}: {e}"
    return url, cats, host, serial, error


def round_robin_assign(urls: List[str], targets: List[Any]) -> List[Tuple[str, Any]]:
    pairs: List[Tuple[str, Any]] = []
    if not targets:
        return pairs
    tcount = len(targets)
    for i, u in enumerate(urls):
        pairs.append((u, targets[i % tcount]))
    return pairs


# ---------------- CLI and main ----------------



def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Check URL categories across firewalls discovered from Panorama configs.", allow_abbrev=False)
    # Defaults for file-based inputs (robust if __file__ is unavailable under an IDE)
    urls_default = _resolve_candidate('exampleList.txt')
    ex_default = default_exclude_path()

    p.add_argument('-c', '--config', default=_resolve_candidate('config'), help='Path to a config directory (default: ./config) or a single JSON file')
    p.add_argument('--urls-file', default=urls_default, help=f'Path to a text file with one URL per line (default: {urls_default})')
    p.add_argument('--no-default-file', action='store_true', help='Do not read URLs from the default --urls-file unless an explicit file is provided')
    p.add_argument('--urls', help='Comma- or line-separated URLs provided directly as a string')
    p.add_argument('--stdin', action='store_true', help='Read URLs from STDIN')
    p.add_argument('--workers', type=int, default=int(os.environ.get('UCC_MAX_WORKERS', '16')), help='Max worker threads (default from UCC_MAX_WORKERS or 16)')
    p.add_argument('--timeout', type=int, default=int(os.environ.get('UCC_REQUEST_TIMEOUT', '15')), help='Per-request timeout seconds (default from UCC_REQUEST_TIMEOUT or 15)')
    p.add_argument('--exclude-file', default=ex_default, help=f'Path to FirewallExclusionList.txt (default: {ex_default})')
    p.add_argument('--per-group', action='store_true', help='Process each config group separately (do not flatten)')
    p.add_argument('--output', choices=['table', 'csv', 'json'], default='table', help='Output format (default: table)')
    p.add_argument('--interactive', dest='interactive', action='store_true', help='Force interactive prompts when inputs are missing')
    p.add_argument('--no-interactive', dest='interactive', action='store_false', help='Disable interactive prompts; exit with error if inputs are missing')
    p.set_defaults(interactive=None)
    p.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity (can repeat)')
    p.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (errors only)')
    p.add_argument('--dry-run', action='store_true', help='Show planned targets and exit without querying devices')
    # Throttling: per-panorama/group max ops within a sliding window
    p.add_argument('--pan-rate', type=int, default=int(os.environ.get('UCC_PAN_RATE', '5')), help='Max API ops per panorama per window (default from UCC_PAN_RATE or 5)')
    p.add_argument('--pan-window', type=int, default=int(os.environ.get('UCC_PAN_WINDOW', '1')), help='Window size in seconds for --pan-rate (default from UCC_PAN_WINDOW or 1)')
    # Filter specific config files by basename (when -c points to a directory)
    p.add_argument('--include-configs', action='append', help='Limit to these config JSON basenames (repeat or comma-separate). Applies when --config is a directory.')
    # Parse known args and ignore the rest (e.g., any IDE/debugger flags)
    args, unknown = p.parse_known_args(argv)
    # Normalize include-configs list
    inc_raw = getattr(args, 'include_configs', None)
    inc_set = set()
    if inc_raw:
        for item in inc_raw:
            for part in (item.split(',') if isinstance(item, str) else []):
                nm = part.strip()
                if nm:
                    inc_set.add(nm)
    setattr(args, '_include_configs_set', inc_set)
    # Mark whether --urls-file came from the default value
    try:
        setattr(args, '_urls_default_value', urls_default)
        setattr(args, '_urls_file_is_default', getattr(args, 'urls_file', None) == urls_default)
    except Exception:
        pass
    if unknown and getattr(args, 'verbose', 0):
        print(f"Warning: ignoring unknown args: {' '.join(unknown)}", file=sys.stderr)
    return args


def discover_configs(config_path: Optional[str]) -> List[str]:
    """Resolve a single --config argument into a list of JSON config file paths.
    - If config_path is a directory (recommended), return all .json files inside (sorted,
      preferring panCoreConfig.json first if present).
    - If config_path is a file, return [that file].
    - If None/empty, default to ./config directory next to this script and list .json files there.
    """
    path = _resolve_candidate(config_path) if config_path else _resolve_candidate('config')
    files: List[str] = []
    if os.path.isdir(path):
        try:
            for name in os.listdir(path):
                if name.lower().endswith('.json'):
                    files.append(os.path.join(path, name))
        except Exception:
            files = []
        # Prefer canonical name first
        files = sorted(files, key=lambda p: (0 if os.path.basename(p) == 'panCoreConfig.json' else 1, p.lower()))
        return files
    # Not a dir: treat as a single file
    return [path] if path else []


def read_urls_from_sources(args: argparse.Namespace) -> List[str]:
    blobs: List[str] = []
    # 1) Inline --urls always takes priority and can coexist with file/stdin
    if getattr(args, 'urls', None):
        blobs.append(args.urls)
    # 2) URLs file: default is exampleList.txt; include only if the file exists
    file_path = getattr(args, 'urls_file', None)
    if file_path:
        # Honor --no-default-file: skip reading the implicit default file unless a non-default was explicitly provided
        is_default = bool(getattr(args, '_urls_file_is_default', False))
        if getattr(args, 'no_default_file', False) and is_default:
            file_path = None
        if file_path:
            file_path = _resolve_candidate(file_path)
            if os.path.isfile(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as fh:
                        blobs.append(fh.read())
                except Exception:
                    pass
    # 3) Explicit --stdin flag
    if getattr(args, 'stdin', False) and not sys.stdin.closed:
        try:
            data = sys.stdin.read()
            if data:
                blobs.append(data)
        except Exception:
            pass
    # 4) If still nothing and input is piped, read from stdin implicitly
    if not blobs:
        try:
            if not sys.stdin.isatty():
                data = sys.stdin.read()
                if data:
                    blobs.append(data)
        except Exception:
            pass
    if not blobs:
        return []
    return normalize_urls("\n".join(blobs))


# ---------------- Interactive helpers ----------------

def is_interactive_session(args: argparse.Namespace) -> bool:
    if args.interactive is True:
        return True
    if args.interactive is False:
        return False
    # Auto: interactive when attached to a TTY (typical for PyCharm Run/Debug and terminals)
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def _config_dir() -> str:
    return os.path.join(_this_dir(), 'config')


def list_config_candidates(base_dir: Optional[str] = None) -> List[str]:
    """Find plausible pancore config JSON files under base_dir (defaults to ./config)."""
    base = _resolve_candidate(base_dir) if base_dir else _config_dir()
    cands: List[str] = []
    try:
        for name in os.listdir(base):
            if name.lower().endswith('.json'):
                cands.append(os.path.join(base, name))
    except Exception:
        pass
    # Prefer the canonical name first if present
    cands_sorted = sorted(cands, key=lambda p: (0 if os.path.basename(p) == 'panCoreConfig.json' else 1, p.lower()))
    return cands_sorted


def prompt_select_configs(cands: List[str]) -> List[str]:
    if not cands:
        print("No config files found in ./config.")
        if _yn("Would you like to create a new config now?"):
            cfg = prompt_create_pancore_config()
            return [cfg] if cfg else []
        return []
    print("Found the following config files:")
    for i, p in enumerate(cands, 1):
        print(f"  {i}) {p}")
    print("Options: [a]ll, comma-separated numbers (e.g., 1,3), [n]one, [c]reate new")
    while True:
        sel = input("> ").strip().lower()
        if sel in ('a', 'all', ''):
            return cands
        if sel in ('n', 'none'):
            return []
        if sel in ('c', 'create'):
            cfg = prompt_create_pancore_config()
            return [cfg] if cfg else []
        try:
            idxs = [int(x) for x in sel.split(',') if x.strip()]
            chosen: List[str] = []
            for idx in idxs:
                if 1 <= idx <= len(cands):
                    chosen.append(cands[idx - 1])
            if chosen:
                return chosen
        except Exception:
            pass
        print("Please enter 'a', 'n', 'c', or numbers like 1,2")


def _yn(message: str, default_yes: bool = True) -> bool:
    suf = 'Y/n' if default_yes else 'y/N'
    ans = input(f"{message} [{suf}]: ").strip().lower()
    if not ans:
        return default_yes
    return ans in ('y', 'yes', 'true', '1')


def prompt_create_pancore_config(path: Optional[str] = None) -> Optional[str]:
    """Create a basic pancore-compatible config JSON using 'localFile' method."""
    base = _config_dir()
    if not path:
        path = os.path.join(base, 'panCoreConfig.json')
    try:
        if not os.path.isdir(base):
            os.makedirs(base, exist_ok=True)
    except Exception:
        pass
    print("Creating a new pancore config file.")
    print("This stores Panorama access under 'localFile'. You can edit later if needed.")
    panAddress = input("Panorama address (hostname or IP): ").strip()
    panUser = input("Panorama username: ").strip()
    try:
        from getpass import getpass as _gp
        panPass = _gp("Panorama password: ")
    except Exception:
        panPass = input("Panorama password: ")
    template = {
        "method": "localFile",
        "scmConfURL": "https://api.sase.paloaltonetworks.com/sse/config/v1",
        "scmAuthURL": "https://auth.apps.paloaltonetworks.com/oauth2/access_token",
        "localFile": {
            "panAddress": panAddress or "null",
            "panUser": panUser or "null",
            "panPass": panPass or "null",
            "panKey": "null",
            "panAuthType": "password",
            "scmUser": "null",
            "scmPass": "null",
            "scmTSG": "null"
        },
        "panScan": {
            "MessageToUser": "set haMember to 'active' if scripts calling this config file will need to edit config elements.",
            "haMember": "passive",
            "dbHost": "null",
            "dbUser": "null",
            "dbPass": "null"},
        "environmentVariables": {
            "MessageToUser": "THESE ARE NOT TO STORE LOGON INFO. THESE ARE TO STORE WHERE TO GET THAT LOGON INFO",
            "panAddress": "panAddress",
            "panKey": "panKey",
            "panUser": "panUser",
            "panPass": "panPass",
            "panAuthType": "panAuthType",
            "scmUser": "scmUser",
            "scmPass": "scmPass",
            "scmTSG": "scmTSG"}
    }
    try:
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(template, fh, indent=2)
        print(f"Wrote config to {path}")
        return path
    except Exception as e:
        print(f"Error writing config: {e}", file=sys.stderr)
        return None


def prompt_urls_interactive() -> List[str]:
    print("Enter URLs to check. You can paste multiple lines or comma-separated. Finish with an empty line:")
    lines: List[str] = []
    while True:
        try:
            s = input()
        except EOFError:
            break
        if not s.strip():
            break
        lines.append(s)
    blob = "\n".join(lines).strip()
    if not blob:
        # Offer file path
        p = input("Or provide a path to a text file with one URL per line (Enter to skip): ").strip()
        if p and os.path.isfile(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    blob = fh.read()
            except Exception as e:
                print(f"Could not read file: {e}", file=sys.stderr)
                blob = ''
    return normalize_urls(blob)


# ---------------- Output helpers ----------------

def print_table(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print("No results")
        return
    cols = [
        "url",
        "category",
        "category1_base",
        "category2_base",
        "category1_cloud",
        "category2_cloud",
        "disagree",
        "fw_host",
        "fw_serial",
        "group",
        "status",
    ]
    # Render disagree as Y/N for table view
    display_rows = []
    for r in rows:
        r2 = dict(r)
        if isinstance(r2.get('disagree'), bool):
            r2['disagree'] = 'Y' if r2['disagree'] else 'N'
        display_rows.append(r2)
    widths = {c: max(len(c), max(len(str(r.get(c, ''))) for r in display_rows)) for c in cols}
    fmt = " ".join([f"{{:{widths[c]}}}" for c in cols])
    print(fmt.format(*cols))
    print(" ".join(["-" * widths[c] for c in cols]))
    for r in display_rows:
        print(fmt.format(
            r.get('url', ''),
            r.get('category', ''),
            r.get('category1_base', ''),
            r.get('category2_base', ''),
            r.get('category1_cloud', ''),
            r.get('category2_cloud', ''),
            r.get('disagree', ''),
            r.get('fw_host', ''),
            r.get('fw_serial', ''),
            r.get('group', ''),
            r.get('status', ''),
        ))


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    urls = read_urls_from_sources(args)

    # Interactive URL prompt if needed
    interactive = is_interactive_session(args)
    if not urls:
        if interactive:
            print("No URLs provided via --urls/--urls-file/--stdin; entering interactive URL prompt...")
            urls = prompt_urls_interactive()
        if not urls:
            # Provide a clear stdout message as some IDEs hide stderr
            print("No URLs provided. Use --urls/--urls-file/--stdin or run with --interactive to be prompted.")
            print("Tip: example -> py panCheckURL.py --urls 'example.com, paloaltonetworks.com'")
            return 1

    # Resolve configs: if none specified, discover and possibly prompt
    cfgs = discover_configs(args.config)
    # Optional filtering by --include-configs (only applies cleanly when --config is a directory)
    inc_set = getattr(args, '_include_configs_set', set())
    if inc_set:
        cfgs = [p for p in cfgs if os.path.basename(p) in inc_set]
    # If discover_configs returned only the default path but it doesn't exist, treat as empty in interactive mode
    if interactive and (not args.config):
        # Offer choices from ./config
        cands = list_config_candidates()
        if cands:
            print("No -c/--config provided. Discovered the following configs in ./config. Choose which to use:")
        cfgs = prompt_select_configs(cands)
    # If still empty and not interactive, keep cfgs as is (may be single default path)

    # Build groups via pancore first
    groups = build_groups(cfgs)

    # If pancore yielded no firewalls, try local schema fallback for each config
    if (not groups or all(len(g) == 0 for g in groups)) and cfgs:
        if interactive:
            print("No firewalls discovered via pancore; trying local JSON schema (api/devices) fallback...")
        groups = build_groups_from_local_schema(cfgs)

    if not groups or all(len(g) == 0 for g in groups):
        if interactive:
            print("No firewalls discovered from the selected configs.")
            # Offer to create a new config and retry once
            if _yn("Create a new pancore config now?"):
                new_cfg = prompt_create_pancore_config()
                if new_cfg:
                    retry_cfgs = [new_cfg]
                    groups = build_groups(retry_cfgs)
                    if not groups or all(len(g) == 0 for g in groups):
                        groups = build_groups_from_local_schema(retry_cfgs)
        if not groups or all(len(g) == 0 for g in groups):
            print("Error: no firewalls discovered from provided configs.")
            if cfgs:
                print("Configs tried:")
                for pth in cfgs:
                    print(f"  - {pth}")
            return 1

    excludes = load_exclusions(args.exclude_file)
    groups = filter_exclusions(groups, excludes)

    # Dry-run info
    if args.dry_run:
        print("Dry run: would query these firewalls (by group):")
        for i, g in enumerate(groups, 1):
            print(f" Group {i} ({len(g)} firewalls)")
            for fw in g:
                host, serial = resolve_fw_identity(fw)
                print(f"   - {host} [{serial or 'no-serial'}]")
        print(f"Total URLs: {len(urls)}")
        return 0

    results: List[Dict[str, Any]] = []

    class RateLimiter:
        def __init__(self, capacity: int, window_sec: int):
            self.capacity = max(1, int(capacity))
            self.window = max(1, int(window_sec))
            self._lock = threading.Lock()
            self._events: deque[float] = deque()
        def acquire(self):
            # Block until a token is available within the window
            while True:
                now = time.time()
                with self._lock:
                    # Drop expired
                    cutoff = now - self.window
                    while self._events and self._events[0] < cutoff:
                        self._events.popleft()
                    if len(self._events) < self.capacity:
                        self._events.append(now)
                        return
                    # Need to wait until earliest expires
                    wait_for = max(0.001, self._events[0] - cutoff)
                time.sleep(min(0.2, wait_for))

    def run_dynamic(batch_urls: List[str], group_list: List[List[Any]], label_for_group: Optional[List[int]] = None) -> None:
        # Prepare per-group rotating firewall deques and ratelimiters
        group_deques: List[deque] = [deque(g) for g in group_list]
        ratelimiters: List[RateLimiter] = [RateLimiter(args.pan_rate, args.pan_window) for _ in group_list]
        group_rr: deque[int] = deque(range(len(group_list)))

        def process_one(u: str) -> Dict[str, Any]:
            last_err: Optional[str] = None
            tried = 0
            total_fws = sum(len(dq) for dq in group_deques)
            if total_fws == 0:
                return {"url": u, "category": "", "category1_base": "", "category2_base": "", "category1_cloud": "", "category2_cloud": "", "disagree": False, "fw_host": "", "fw_serial": "", "group": "", "status": "No firewalls"}
            # Try up to total_fws attempts, rotating groups and FWs each time
            while tried < total_fws:
                gi = group_rr[0]
                group_rr.rotate(-1)
                dq = group_deques[gi]
                if not dq:
                    tried += 1
                    continue
                # throttle per panorama/group
                ratelimiters[gi].acquire()
                fw = dq[0]
                dq.rotate(-1)
                try:
                    u2, cats, host, serial, err = check_url_on_firewall(fw, u, args.timeout)
                except Exception as e:
                    host, serial = resolve_fw_identity(fw)
                    u2, cats, err = u, {"baseDB": {"category1": "", "category2": ""}, "cloudDB": {"category1": "", "category2": ""}}, f"{type(e).__name__}: {e}"
                if not err and cats:
                    b1 = cats.get('baseDB', {}).get('category1', '')
                    b2 = cats.get('baseDB', {}).get('category2', '')
                    c1 = cats.get('cloudDB', {}).get('category1', '')
                    c2 = cats.get('cloudDB', {}).get('category2', '')
                    # Back-compat summary category: prefer cloud primary, then base primary
                    summary = c1 or b1 or ''
                    disagree = (bool(b1 and c1 and b1 != c1) or bool(b2 and c2 and b2 != c2))
                    return {
                        "url": u2,
                        "category": summary,
                        "category1_base": b1,
                        "category2_base": b2,
                        "category1_cloud": c1,
                        "category2_cloud": c2,
                        "disagree": disagree,
                        "fw_host": host,
                        "fw_serial": serial,
                        "group": (label_for_group[gi] if label_for_group else 1),
                        "status": "OK",
                    }
                else:
                    last_err = err or "Unknown error"
                    tried += 1
                    continue
            return {"url": u, "category": "", "category1_base": "", "category2_base": "", "category1_cloud": "", "category2_cloud": "", "disagree": False, "fw_host": "", "fw_serial": "", "group": (label_for_group[gi] if label_for_group else 1), "status": last_err or "All firewalls failed"}

        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as exe:
            futs = [exe.submit(process_one, u) for u in batch_urls]
            for fut in as_completed(futs):
                try:
                    row = fut.result()
                except Exception as e:
                    row = {"url": "", "category": "", "fw_host": "", "fw_serial": "", "group": "", "status": f"{type(e).__name__}: {e}"}
                results.append(row)

    if args.per_group:
        for idx, g in enumerate(groups, 1):
            if not g:
                continue
            run_dynamic(urls, [g], [idx])
    else:
        # Use all groups together; still throttle per original group
        label_map = list(range(1, len(groups) + 1))
        run_dynamic(urls, groups, label_map)

    # Output
    if args.output == 'json':
        # Build mapping as requested: {"responses": {url: {cloudDB: {...}, baseDB: {...}, disagree: bool}}}
        resp_map: Dict[str, Dict[str, Any]] = {}
        for r in results:
            if r.get('status') != 'OK':
                continue
            u = r.get('url', '')
            if not u:
                continue
            resp_map[u] = {
                'cloudDB': {
                    'category1': r.get('category1_cloud', ''),
                    'category2': r.get('category2_cloud', ''),
                },
                'baseDB': {
                    'category1': r.get('category1_base', ''),
                    'category2': r.get('category2_base', ''),
                },
                'disagree': bool(r.get('disagree', False)),
            }
        # Compute per-group availability/health metadata so UIs can highlight issues (e.g., expired credentials)
        group_meta: List[Dict[str, Any]] = []
        # Initialize counters per group index present in label_map (1-based indices were used)
        group_indices = set()
        for r in results:
            g = r.get('group')
            if g:
                group_indices.add(int(g))
        for gi in sorted(group_indices):
            ok = sum(1 for r in results if r.get('group') == gi and r.get('status') == 'OK')
            errs = [r.get('status') for r in results if r.get('group') == gi and r.get('status') != 'OK']
            # Try to infer fw_count from the planning phase: we no longer have direct access to len(groups[gi-1]) here,
            # but we can approximate from unique fw_serials seen in either OK or error rows.
            fw_ids = set()
            for r in results:
                if r.get('group') == gi:
                    key = (r.get('fw_host',''), r.get('fw_serial',''))
                    fw_ids.add(key)
            group_meta.append({
                'index': gi,
                'fw_count_observed': len([k for k in fw_ids if any(k)]),
                'ok_count': ok,
                'error_count': len(errs),
                'available': ok > 0,
                'last_error': errs[-1] if errs else '',
            })
        # Also include detailed rows so UIs can attribute results to specific firewalls
        print(json.dumps({'responses': resp_map, 'groups': group_meta, 'rows': results}, indent=2))
    elif args.output == 'csv':
        fieldnames = [
            "url",
            "category",
            "category1_base",
            "category2_base",
            "category1_cloud",
            "category2_cloud",
            "disagree",
            "fw_host",
            "fw_serial",
            "group",
            "status",
        ]
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            row = dict(r)
            if isinstance(row.get('disagree'), bool):
                row['disagree'] = 'Y' if row['disagree'] else 'N'
            writer.writerow(row)
    else:
        print_table(results)
        ok = sum(1 for r in results if r.get('status') == 'OK')
        err = len(results) - ok
        print(f"\nSummary: {len(results)} checks, {ok} OK, {err} errors")

    return 0 if results else 1


if __name__ == '__main__':
    raise SystemExit(main())
