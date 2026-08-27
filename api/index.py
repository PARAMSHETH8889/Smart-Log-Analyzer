"""
Vercel Serverless WSGI Entry Point for Smart Log Analyzer & Anomaly Detector.
"""

import sys
import os
from pathlib import Path

# Add project root directory to sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

# Ensure VERCEL environment is recognized
os.environ["VERCEL"] = "1"

from app import create_app

# Create Flask WSGI app instance for Vercel
app = create_app("production")

# Ensure database tables exist in serverless environment
with app.app_context():
    from models import db
    db.create_all()
