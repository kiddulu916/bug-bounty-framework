"""Test configuration and fixtures for the bug bounty framework."""

import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from bbf.core.database.connection import db_manager
from bbf.core.database.models import Base

# Set test environment
os.environ["BBF_TESTING"] = "true"

@pytest.fixture(scope="session")
def test_db_engine():
    """Create a test database engine."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)

@pytest.fixture(scope="function")
def test_db_session(test_db_engine):
    """Create a test database session."""
    Session = sessionmaker(bind=test_db_engine)
    session = Session()
    try:
        yield session
    finally:
        session.rollback()
        session.close()

@pytest.fixture(scope="function", autouse=True)
def mock_db_manager(test_db_engine, test_db_session):
    """Mock the database manager to use the test database."""
    # Store original attributes
    original_engine = db_manager._engine
    original_session_factory = db_manager._session_factory
    original_is_initialized = db_manager._is_initialized
    
    # Set test attributes
    db_manager._engine = test_db_engine
    db_manager._session_factory = sessionmaker(bind=test_db_engine)
    db_manager._is_initialized = True
    
    yield
    
    # Restore original attributes
    db_manager._engine = original_engine
    db_manager._session_factory = original_session_factory
    db_manager._is_initialized = original_is_initialized

@pytest.fixture(scope="function", autouse=True)
def test_env():
    """Set up test environment variables."""
    # Store original environment
    original_env = dict(os.environ)
    
    # Set test environment variables
    os.environ.update({
        "BBF_TESTING": "true",
        "BBF_DB_URL": "sqlite:///:memory:",
        "BBF_DB_ECHO": "false"
    })
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env) 