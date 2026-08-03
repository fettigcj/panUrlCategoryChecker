import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

from flask import Flask, render_template, request

# Make the pancore submodule importable if not installed as a package
SUBMODULE_PATH = os.path.join(os.path.dirname(__file__), 'pancore')
if os.path.isdir(SUBMODULE_PATH) and SUBMODULE_PATH not in sys.path:
    sys.path.insert(0, SUBMODULE_PATH)

try:
    import pancore  # noqa: F401  # reserved for future shared helpers
except Exception:
    pancore = None  # optional; app can still run without importing from pancore directly

# pan-os-python (Firewall objects)
try:
    from panos.firewall import Firewall
except Exception as e:  # pragma: no cover
    Firewall = None  # type: ignore


def create_app() -> Flask:
    app = Flask(__name__)
    app.config['MAX_WORKERS'] = int(os.environ.get('UCC_MAX_WORKERS', '16'))
    app.config['REQUEST_TIMEOUT'] = int(os.environ.get('UCC_REQUEST_TIMEOUT', '15'))

    # Load firewall objects once at startup
    firewalls = build_firewalls()

    @app.get('/')
    def index():
        return render_template('index.html', fw_count=len(firewalls))

    @app.post('/check')
    def check():
        raw = request.form.get('urls', '')
        urls = normalize_urls(raw)
        if not urls:
            return render_template('results.html', results=[], errors=['No valid URLs provided'], fw_count=len(firewalls))
        # Run parallel checks
        results, errors = check_urls_parallel(urls, firewalls, max_workers=app.config['MAX_WORKERS'], timeout=app.config['REQUEST_TIMEOUT'])
        return render_template('results.html', results=results, errors=errors, fw_count=len(firewalls))

    return app


# ========== Firewall utilities ==========

def load_config_path() -> str:
    # Prefer env var; else config/panCoreConfig.json in repo
    env_path = os.environ.get('PANCORE_CONFIG')
    if env_path and os.path.isfile(env_path):
        return env_path
    fallback = os.path.join(os.path.dirname(__file__), 'config', 'panCoreConfig.json')
    return fallback


def build_firewalls() -> List[Any]:
    """Build a list of pan-os-python Firewall objects from configuration.

    Expected JSON structure (config/panCoreConfig.json):
    {
      "api": {"username": "apiuser", "password": "apipass", "port": 443, "verify_ssl": false},
      "devices": [
        {"host": "fw1.example.com"},
        {"host": "fw2.example.com", "port": 443}
      ]
    }
    You can also point PANCORE_CONFIG to an alternate JSON path.
    """
    import json

    cfg_file = load_config_path()
    firewalls: List[Any] = []
    if not os.path.isfile(cfg_file):
        return firewalls
    with open(cfg_file, 'r', encoding='utf-8') as fh:
        cfg = json.load(fh)
    api = cfg.get('api', {})
    username = api.get('username')
    password = api.get('password')
    port = int(api.get('port', 443))
    verify_ssl = bool(api.get('verify_ssl', False))
    devices = cfg.get('devices', [])

    if Firewall is None:
        return firewalls

    for dev in devices:
        host = dev.get('host') or dev.get('hostname') or dev.get('ip')
        if not host:
            continue
        dev_port = int(dev.get('port', port))
        fw = Firewall(hostname=host, api_username=username, api_password=password, port=dev_port)
        # Optionally set verify SSL on the underlying HTTP client if available
        try:
            if hasattr(fw, 'xapi') and hasattr(fw.xapi, 'verify'):
                fw.xapi.verify = verify_ssl
        except Exception:
            pass
        firewalls.append(fw)
    return firewalls


# ========== URL processing and checks ==========

ALLOWED_SCHEMES = {"http", "https"}


def normalize_urls(text_block: str) -> List[str]:
    """Convert a pasted text block into a list of normalized URL strings."""
    urls: List[str] = []
    for raw in text_block.splitlines():
        s = raw.strip()
        if not s:
            continue
        # If missing scheme, default to http://
        if '://' not in s:
            s = 'http://' + s
        try:
            p = urlparse(s)
            if p.scheme.lower() not in ALLOWED_SCHEMES or not p.netloc:
                continue
            # drop fragments; keep path/query
            normalized = f"{p.scheme}://{p.netloc}{p.path or ''}"
            if p.query:
                normalized += f"?{p.query}"
            urls.append(normalized)
        except Exception:
            continue
    # de-duplicate preserving order
    seen = set()
    uniq: List[str] = []
    for u in urls:
        if u not in seen:
            uniq.append(u)
            seen.add(u)
    return uniq


def _parse_category_from_op(xml_elem: ET.Element) -> Tuple[str, str]:
    """Best-effort parse of category from test url op response.
    Returns (category, raw_text).
    """
    raw_text = ET.tostring(xml_elem, encoding='unicode') if xml_elem is not None else ''
    category = ''
    if xml_elem is None:
        return category, raw_text
    # Look for <category> nodes first
    cat_nodes = xml_elem.findall('.//category')
    if cat_nodes:
        text = (cat_nodes[0].text or '').strip()
        if text:
            return text, raw_text
    # Fallback: look for result text containing "category" token
    result_nodes = xml_elem.findall('.//result')
    for rn in result_nodes:
        t = (rn.text or '').strip()
        if 'category' in t.lower():
            # naive parse: take last token after 'category'
            parts = t.split()
            if 'category' in [x.lower() for x in parts]:
                try:
                    idx = [x.lower() for x in parts].index('category')
                    if idx + 1 < len(parts):
                        return parts[idx + 1].strip('[]()'), raw_text
                except Exception:
                    pass
    return category, raw_text


def check_urls_parallel(urls: List[str], firewalls: List[Any], max_workers: int = 16, timeout: int = 15) -> Tuple[List[Dict[str, Any]], List[str]]:
    if not firewalls:
        return [], ["No firewalls are configured. Add devices to config/panCoreConfig.json or set PANCORE_CONFIG."]

    jobs: List[Tuple[str, Any]] = []
    # Round-robin assign URLs to firewalls
    for i, u in enumerate(urls):
        fw = firewalls[i % len(firewalls)]
        jobs.append((u, fw))

    results: List[Dict[str, Any]] = []
    errors: List[str] = []

    def worker(u: str, fw: Any) -> Dict[str, Any]:
        try:
            # pan-os-python accepts XML command string. Use op with cmd xml element or string.
            # Command format: <test><url>example.com</url></test> OR CLI-style 'test url <url>'
            # We use CLI-style as requested.
            xml_elem = fw.op(f"test url {u}")  # type: ignore[attr-defined]
            category, raw = _parse_category_from_op(xml_elem)
            return {
                'url': u,
                'category': category or '(unknown)',
                'firewall': getattr(fw, 'hostname', getattr(fw, 'host', 'unknown')),
                'raw': raw,
                'ok': True,
            }
        except Exception as ex:
            return {
                'url': u,
                'category': '',
                'firewall': getattr(fw, 'hostname', getattr(fw, 'host', 'unknown')),
                'error': str(ex),
                'ok': False,
            }

    # Use a bounded pool
    pool_size = min(max_workers, max(1, len(jobs)))
    with ThreadPoolExecutor(max_workers=pool_size) as ex:
        future_map = {ex.submit(worker, u, fw): (u, fw) for (u, fw) in jobs}
        for fut in as_completed(future_map, timeout=None):
            try:
                item = fut.result(timeout=timeout)
                results.append(item)
            except Exception as e:
                u, fw = future_map[fut]
                results.append({'url': u, 'category': '', 'firewall': getattr(fw, 'hostname', 'unknown'), 'error': f'timeout/error: {e}', 'ok': False})

    # Preserve input order in output
    order = {u: i for i, u in enumerate(urls)}
    results.sort(key=lambda r: order.get(r.get('url', ''), 0))
    return results, errors


# Create app instance for WSGI/Flask CLI
app = create_app()

if __name__ == '__main__':  # pragma: no cover
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=True)
