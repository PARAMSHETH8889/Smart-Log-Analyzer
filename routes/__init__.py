"""Routes package initialization."""
from flask import Blueprint

dashboard_bp = Blueprint("dashboard", __name__)
logs_bp = Blueprint("logs", __name__)

# Import route modules to register views on blueprints
from routes import dashboard  # noqa: E402, F401
from routes import logs  # noqa: E402, F401
