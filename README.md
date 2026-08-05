URL Category Checker
====================

A minimal Flask app that accepts a list of URLs, distributes the checks across a pool of Palo Alto Networks firewalls, and retrieves URL category data using the operational command "test url <url>".

Highlights
- Reuses shared code via the pancore submodule (see ./pancore)
- Builds firewall objects via pancore.panCore when available (mirrors panInventory startup); falls back to JSON parsing
- Parallelizes URL checks with a thread pool and dynamic dispatch that retries on firewall failures
- Simple web UI and WSGI entrypoint for Apache mod_wsgi

Requirements
- Python 3.11+
- pan-os-python
- Flask 3+

Setup
1) Clone and init submodules
   git clone --recurse-submodules https://github.com/yourorg/urlCategoryChecker
   cd urlCategoryChecker
   # or, if you already cloned
   git submodule update --init --recursive

2) Create/activate a virtual environment and install deps
   py -3.11 -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt

3) Configure firewalls (CLI recommended)
   - Easiest: run with no arguments to enter interactive mode:
     python ucc_config_cli.py
   - Or run the explicit interactive wizard:
     python ucc_config_cli.py init
   - Or set fields non-interactively:
     python ucc_config_cli.py set --username APIUSER --password APIPASS --port 443 --no-verify-ssl \
       --device fw1.example.com --device fw2.example.com:443
   - Validate and view:
     python ucc_config_cli.py validate
     python ucc_config_cli.py show
   - Config path: by default we assume ./config/panCoreConfig.json unless overridden.
     Use -c/--conffile to specify a path, or set environment variable PANCORE_CONFIG.
   - Alternatively, you can still copy config/panCoreConfig.json.example to config/panCoreConfig.json and edit manually

   Example JSON:
   {
     "api": {"username": "apiuser", "password": "apipass", "port": 443, "verify_ssl": false},
     "devices": [
       {"host": "fw1.example.com"},
       {"host": "fw2.example.com", "port": 443}
     ]
   }

4) Run locally
   flask --app app run --debug
   # or
   python app.py
   # Tip: If you simply do `py app.py`, the script will auto-switch to the repo's local venv at `./Scripts/python.exe`
   # on Windows if Flask isn't importable in your current interpreter. Alternatively, activate the venv first:
   #   .\\Scripts\\activate
   #   pip install -r requirements.txt

5) Use
   - Open http://127.0.0.1:5000/
   - Paste one URL per line; protocol (http/https) is optional and not required. The tool will not prepend a scheme and will send the host/path as provided.
   - Links:
     - Show config: lists discovered config JSON files (read-only)
     - Test availability: runs a light probe and shows per-group availability/last error

Deployment (Apache mod_wsgi)
- Ensure Python venv is available on the server and dependencies installed
- IMPORTANT: Initialize/update the pancore submodule on the server after clone/pull:

    git submodule update --init --recursive

  If pancore was deinitialized earlier, you may need:

    git submodule deinit -f pancore
    git checkout -- pancore
    git submodule update --init --recursive

- Point WSGIScriptAlias to the wsgi.py file in this repo

  Example httpd.conf snippet:
  WSGIDaemonProcess urlcat python-home=C:/var/panApps/urlCategoryChecker/.venv threads=10
  WSGIScriptAlias /urlcat C:/var/panApps/urlCategoryChecker/wsgi.py
  <Directory C:/var/panApps/urlCategoryChecker>
      Require all granted
  </Directory>

Troubleshooting
- pancore folder is empty on the server: run the submodule init/update commands above. You must perform this on each server after cloning or when deploying updates that move the submodule pointer.
- The app attempts to parse categories from the op command response using a best-effort XML parser. Adjust parsing if your PAN-OS version returns a different structure.
- Set UCC_MAX_WORKERS and UCC_REQUEST_TIMEOUT env vars to tune concurrency and timeouts.
- If pancore is published to PyPI or a private index, you may uninstall the submodule and depend on the package instead.


Submodule notes
----------------
- This repo vendors pancore as a Git submodule at `./pancore` pointing to `https://github.com/fettigcj/pancore.git` (branch `main`).
- The upstream now contains only the minimal package files; no `panInventory` content is included here.

Common commands:
- Initializing after clone:
  git submodule update --init --recursive
- Updating to the latest upstream commit on `main`:
  git submodule update --remote --merge
  git add pancore
  git commit -m "Update pancore submodule to latest main"
  git push

If you need to refresh completely (rare):
  git submodule deinit -f pancore
  git rm -f pancore
  git submodule add -b main https://github.com/fettigcj/pancore.git pancore
  git commit -m "Re-add pancore submodule cleanly"


panCheckURL CLI
----------------
`panCheckURL.py` is a new CLI utility that mirrors panInventory's startup flow but focuses on checking URL categories across firewalls discovered from Panorama.

Key features:
- Uses `pancore.panCore.configStart()` and `pancore.panCore.buildPano_obj()` to discover firewalls
- Accepts a config path via `-c/--config` that points to a directory (recommended) containing one or more JSON configs, or to a single JSON file; all JSONs in the directory are used as groups
- Distributes URL checks dynamically with retry and per-Panorama throttling; optional `--per-group` to keep groups separate
- Honors an exclusion list of firewall serial numbers in `config/FirewallExclusionList.txt`
- Outputs results as a table (default), CSV, or JSON. Table/CSV include columns for base/cloud primary and secondary categories and a 'disagree' flag when Base and Cloud databases differ.
- Interactive mode when inputs are missing (great for PyCharm “Run File”): prompts to enter URLs, auto-discovers configs in `./config`, lets you select All/some, or create a new config on the spot.

Examples:
- Single config file, URLs from a text file:
  py panCheckURL.py -c config/panCoreConfig.json --urls-file urls.txt

- Config directory (contains one or more JSON files), inline URLs, JSON output:
  py panCheckURL.py -c config --urls "example.com,https://paloaltonetworks.com" --output json

- Read URLs from STDIN (PowerShell):
  Get-Content .\urls.txt | py panCheckURL.py -c config\panCoreConfig.json --stdin

- No arguments (interactive):
  py panCheckURL.py
  # You’ll be prompted for URLs and to pick config(s) from the ./config folder, or to create a new one.

Options:
- `-c/--config` Path to a config directory (default `./config`) or a single `panCore` JSON file. When a directory is given, all `.json` files inside are used as separate groups.
- `--urls-file <file>` Read line-separated URLs from a file (default: `exampleList.txt` in the repo root, if present).
- `--urls "..."` Provide URLs inline (comma or newline separated).
- `--stdin` Read URLs from STDIN.
- `--workers N` Max threads (default 16 or `UCC_MAX_WORKERS`).
- `--timeout SEC` Per-request timeout (default 15 or `UCC_REQUEST_TIMEOUT`).
- `--pan-rate N` Max API ops per Panorama/group per window (default 5 or `UCC_PAN_RATE`).
- `--pan-window SEC` Throttling window size in seconds (default 1 or `UCC_PAN_WINDOW`).
- `--exclude-file <path>` Path to exclusion list (default `config/FirewallExclusionList.txt`).
- `--per-group` Process each config's firewalls separately (no flattening).
- `--output {table,csv,json}` Select output format.
  - JSON outputs an object: {"responses": {"<url>": {"cloudDB": {"category1": "...", "category2": "..."}, "baseDB": {"category1": "...", "category2": "..."}, "disagree": true|false}}}
- `--interactive` Force prompts when inputs are missing (overrides auto-detection).
- `--no-interactive` Disable prompts; exit with errors if inputs are missing.
- `--dry-run` Print planned targets without querying.

Exclusion list format:
- File: `config/FirewallExclusionList.txt`
- One serial number per line; `#` comments and blank lines are ignored.

Troubleshooting notes:
- Use `--debug` (repeat up to 3 times) to see detailed discovery steps from pancore, including which config files were used, the Panorama address detected, whether `ping` to Panorama succeeded, and the result of `buildPano_obj` (firewall counts). Example:
  `py panCheckURL.py -c config --urls cnn.com --debug --debug`
- Add `--no-fallback` to disable the local JSON schema fallback so you can isolate pancore behavior.
- If you see "no firewalls discovered", the tool tries pancore first, then (unless `--no-fallback` is set) falls back to a simple `api/devices` schema inside your JSON. In interactive runs it will offer to create a new config and retry.
- If running in PyCharm and you previously saw argparse errors from debug flags, those are now ignored. If you run with no inputs, the tool prints a clear message and/or enters interactive prompts when possible.
