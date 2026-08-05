import os
import sys
import io
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Ensure Flask is importable; if not, try to re-exec using the repo's local venv ---
try:
    from flask import Flask, render_template, request  # type: ignore
except ModuleNotFoundError:
    # If running outside the repo's venv, try to relaunch with it automatically
    repo_root = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(repo_root, 'Scripts', 'python.exe')
    if os.name == 'nt' and os.path.isfile(candidate):
        # Avoid infinite loop: detect if we're already using this interpreter
        try:
            current = os.path.abspath(sys.executable)
        except Exception:
            current = ''
        if os.path.normcase(current) != os.path.normcase(os.path.abspath(candidate)):
            # Re-exec with the repo venv Python
            os.execv(candidate, [candidate, __file__] + sys.argv[1:])
    # If that didn't work, re-raise so the error is visible
    raise

# We delegate URL checks to the CLI engine in panCheckURL.py
try:
    import panCheckURL as ucc
except Exception:
    ucc = None  # type: ignore


def create_app() -> Flask:
    app = Flask(__name__)

    # Jinja filter to get basename of a path
    @app.template_filter('basename')
    def _basename_filter(value: str) -> str:
        try:
            return os.path.basename(value)
        except Exception:
            return value or ''

    @app.get('/')
    def index():
        # Count configs and pass list to allow selection on the form
        cfgs = discover_configs_safe()
        return render_template('index.html', fw_count=len(cfgs), cfg_path='config', cfg_exists=bool(cfgs), configs=cfgs)

    @app.post('/check')
    def check():
        raw = request.form.get('urls', '')
        urls = normalize_urls_web(raw)
        # Selected configs by basename
        selected = request.form.getlist('configs') or []
        if not urls:
            return render_template('results.html', results=[], errors=['No valid URLs provided'], fw_count=0)
        # If configs exist but none selected, prompt user to pick at least one
        all_cfgs = discover_configs_safe()
        if all_cfgs and len(selected) == 0:
            return render_template('results.html', results=[], errors=['No configs selected. Please choose at least one configuration.'], fw_count=len(all_cfgs), groups=[])
        rows, errors, group_meta = run_pancheck(urls, include_configs=selected)
        return render_template('results.html', results=rows, errors=errors, fw_count=len(discover_configs_safe()), groups=group_meta)

    @app.get('/config')
    def show_config():
        cfgs = discover_configs_safe()
        return render_template('config.html', configs=cfgs)

    @app.get('/availability')
    def availability():
        # Run a light probe against a tiny URL set to determine group availability
        probe_urls = ['example.com']
        _rows, errors, group_meta = run_pancheck(probe_urls, per_group=True, max_workers=4, timeout=8)
        return render_template('availability.html', groups=group_meta, errors=errors)

    return app


# ========== Helpers to bridge to panCheckURL ==========

def normalize_urls_web(text_block: str) -> List[str]:
    s = (text_block or '').strip()
    if not s:
        return []
    try:
        # Reuse CLI normalizer if available for perfect parity
        if ucc and hasattr(ucc, 'normalize_urls'):
            return getattr(ucc, 'normalize_urls')(s)
    except Exception:
        pass
    # Fallback: simple split by lines/commas and strip protocol
    items: List[str] = []
    for raw in s.replace(',', '\n').splitlines():
        t = raw.strip().strip('"\'')
        if not t or t.startswith('#'):
            continue
        if t.startswith('http://'):
            t = t[7:]
        elif t.startswith('https://'):
            t = t[8:]
        if t.startswith('//'):
            t = t[2:]
        items.append(t)
    # de-dup preserve order
    seen = set()
    out: List[str] = []
    for u in items:
        k = u.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(u)
    return out


def discover_configs_safe() -> List[str]:
    try:
        if ucc and hasattr(ucc, 'discover_configs'):
            # Default to ./config directory
            return getattr(ucc, 'discover_configs')(getattr(ucc, '_resolve_candidate')('config'))
    except Exception:
        pass
    # Fallback: list JSON files under ./config
    base = os.path.join(os.path.dirname(__file__), 'config')
    files: List[str] = []
    try:
        for name in os.listdir(base):
            if name.lower().endswith('.json'):
                files.append(os.path.join(base, name))
    except Exception:
        return []
    return sorted(files)


def run_pancheck(urls: List[str], per_group: bool = False, max_workers: int = 16, timeout: int = 15, include_configs: List[str] | None = None) -> tuple[List[Dict[str, Any]], List[str], List[Dict[str, Any]]]: 
    """Invoke panCheckURL.main in-process and capture JSON output.
    Returns (rows_for_ui, errors, group_meta)
    """
    if not ucc:
        return [], ["panCheckURL module not available"], []
    # Build argv for the CLI
    argv = [
        '-c', 'config',
        '--urls', '\n'.join(urls),
        '--output', 'json',
        '--workers', str(max_workers),
        '--timeout', str(timeout),
        '--no-default-file',
    ]
    if include_configs:
        for nm in include_configs:
            argv.extend(['--include-configs', os.path.basename(nm)])
    if per_group:
        argv.append('--per-group')
    # Capture stdout
    buf = io.StringIO()
    old_stdout = sys.stdout
    try:
        sys.stdout = buf
        try:
            ucc.main(argv)
        except SystemExit as se:
            # Some entrypoints might raise SystemExit; ignore and use buffer
            pass
    finally:
        sys.stdout = old_stdout
    txt = buf.getvalue()
    try:
        data = json.loads(txt) if txt.strip().startswith('{') else {}
    except Exception:
        data = {}
    # Parse results
    rows_ui: List[Dict[str, Any]] = []
    errors: List[str] = []
    if isinstance(data, dict):
        # Prefer detailed rows when available
        rows_json = data.get('rows', [])
        if isinstance(rows_json, list) and rows_json:
            for r in rows_json:
                # Map to UI fields expected by results.html
                rows_ui.append({
                    'url': r.get('url',''),
                    'category': r.get('category',''),
                    'firewall': (r.get('fw_host','') + (f" [{r.get('fw_serial')}]" if r.get('fw_serial') else '')),
                    'ok': r.get('status') == 'OK',
                    'raw': '',
                    'error': '' if r.get('status') == 'OK' else (r.get('status') or ''),
                    'category1_base': r.get('category1_base',''),
                    'category2_base': r.get('category2_base',''),
                    'category1_cloud': r.get('category1_cloud',''),
                    'category2_cloud': r.get('category2_cloud',''),
                    'disagree': r.get('disagree', False),
                    'group': r.get('group',''),
                })
        else:
            # Fallback to older responses map
            responses = data.get('responses', {})
            for u, perdb in (responses.items() if isinstance(responses, dict) else []):
                cloud = perdb.get('cloudDB', {}) if isinstance(perdb, dict) else {}
                base = perdb.get('baseDB', {}) if isinstance(perdb, dict) else {}
                cat = cloud.get('category1') or base.get('category1') or ''
                rows_ui.append({
                    'url': u,
                    'category': cat,
                    'firewall': '',
                    'ok': True,
                    'raw': '',
                    'error': ''
                })
        groups = data.get('groups', [])
    else:
        groups = []
        # Try to detect error text in the buffer
        if txt and not txt.strip().startswith('{'):
            errors.append(txt.strip()[:1000])
    return rows_ui, errors, groups


# ========== URL processing and checks ==========

ALLOWED_SCHEMES = {"http", "https"}


def normalize_urls(text_block: str) -> List[str]:
    """Convert a pasted text block into a list of URL strings WITHOUT forcing a protocol.
    - Accept bare domains like 'cnn.com' or 'www.cnn.com'.
    - If http/https is provided, strip it so we pass just the host/path to 'test url'.
    - Preserve path and query when present.
    - De-duplicate while preserving order (case-insensitive comparison).
    """
    urls: List[str] = []
    seen_ci: set[str] = set()
    for raw in text_block.splitlines():
        s = (raw or '').strip()
        if not s:
            continue
        # Support comma-separated entries on the same line
        parts = [p.strip() for p in s.split(',') if p.strip()]
        for p in parts:
            q = p
            lp = q.lower()
            if lp.startswith('http://'):
                q = q[7:]
            elif lp.startswith('https://'):
                q = q[8:]
            elif q.startswith('//'):
                q = q[2:]
            q = q.strip(" <>\"'")
            if not q:
                continue
            key = q.lower()
            if key in seen_ci:
                continue
            seen_ci.add(key)
            urls.append(q)
    return urls


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
