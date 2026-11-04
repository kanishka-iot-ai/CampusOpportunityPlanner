import os
import sys

# Ensure root directory is on sys.path so app and its modules can be imported
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app

# Vercel looks for the WSGI/ASGI 'app' object in this module
