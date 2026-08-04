URL Category Checker
====================

A minimal Flask app that accepts a list of URLs, distributes the checks across a pool of Palo Alto Networks firewalls, and retrieves URL category data using the operational command "test url <url>".

Highlights
- Reuses shared code via the pancore submodule (see ./pancore)
- Builds a list of pan-os-python Firewall objects from a JSON config
- Parallelizes URL checks with a thread pool
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

5) Use
   - Open http://127.0.0.1:5000/
   - Paste one URL per line; scheme will default to http:// if omitted

Deployment (Apache mod_wsgi)
- Ensure Python venv is available on the server and dependencies installed
- Point WSGIScriptAlias to the wsgi.py file in this repo

  Example httpd.conf snippet:
  WSGIDaemonProcess urlcat python-home=C:/var/panApps/urlCategoryChecker/.venv threads=10
  WSGIScriptAlias /urlcat C:/var/panApps/urlCategoryChecker/wsgi.py
  <Directory C:/var/panApps/urlCategoryChecker>
      Require all granted
  </Directory>

Notes
- The app attempts to parse categories from the op command response using a best-effort XML parser. Adjust parsing if your PAN-OS version returns a different structure.
- Set UCC_MAX_WORKERS and UCC_REQUEST_TIMEOUT env vars to tune concurrency and timeouts.
- If pancore is published to PyPI or a private index, you may uninstall the submodule and depend on the package instead.
