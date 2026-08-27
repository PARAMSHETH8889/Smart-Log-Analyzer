"""
Shared pytest fixtures.
"""

import pytest
from app import create_app
from models import db


@pytest.fixture
def app():
    """Create testing application instance with in-memory database."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()
