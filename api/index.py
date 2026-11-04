import os
import sys

# Ensure root directory is on sys.path so app and its modules can be imported
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from werkzeug.middleware.proxy_fix import ProxyFix
from app import app

# Vercel operates behind an HTTPS reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
