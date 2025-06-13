"""Integration test fixtures and configuration."""

import asyncio
import os
import pytest
import pytest_asyncio
from typing import AsyncGenerator, Dict, Any
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from bbf.core.database.models import Base, Finding
from bbf.core.database.service import finding_service
from bbf.core.config import get_config
from bbf.core.session import Session
from bbf.plugins.recon.subdomain_enum import SubdomainEnumPlugin
from bbf.plugins.recon.port_scan import PortScannerPlugin
from bbf.plugins.recon.web_tech import WebTechPlugin
from bbf.plugins.recon.dir_brute import DirBrutePlugin
from bbf.plugins.vuln.scanner import VulnScannerPlugin

# Test database URL - using in-memory SQLite for tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest_asyncio.fixture(scope="session")
async def engine():
    """Create a test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        future=True,
        poolclass=NullPool
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    await engine.dispose()

@pytest_asyncio.fixture(scope="function")
async def db_session(engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()
        await session.close()

@pytest_asyncio.fixture(scope="function")
async def test_session(db_session) -> AsyncGenerator[Session, None]:
    """Create a test session with database access."""
    session = Session(
        id="test-session",
        target="example.com",
        config=get_config()
    )
    session.db = db_session
    yield session
    await session.cleanup()

@pytest_asyncio.fixture(scope="function")
async def mock_finding_service(db_session) -> AsyncGenerator[Any, None]:
    """Create a mock finding service for testing."""
    original_session = finding_service.session
    finding_service.session = db_session
    yield finding_service
    finding_service.session = original_session

@pytest.fixture
def test_targets() -> Dict[str, Any]:
    """Provide test targets for scanning."""
    return {
        "domains": ["example.com", "test.example.com"],
        "urls": [
            "http://example.com",
            "https://test.example.com",
            "http://api.example.com"
        ],
        "ips": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
    }

@pytest.fixture
def test_findings() -> Dict[str, Any]:
    """Provide test findings for database operations."""
    return {
        "subdomain": {
            "root_domain": "example.com",
            "subdomain": "test.example.com",
            "source": "subdomain_enum",
            "confidence": 0.9,
            "metadata": {
                "ip": "93.184.216.34",
                "nameservers": ["ns1.example.com"],
                "techniques": ["dns_enum"]
            }
        },
        "port": {
            "root_domain": "example.com",
            "subdomain": "test.example.com",
            "ports": [80, 443],
            "source": "port_scan",
            "confidence": 0.95,
            "metadata": {
                "protocols": ["tcp"],
                "services": {
                    "80": "http",
                    "443": "https"
                }
            }
        },
        "web_tech": {
            "root_domain": "example.com",
            "subdomain": "test.example.com",
            "web_tech": ["nginx", "php"],
            "source": "web_tech",
            "confidence": 0.8,
            "metadata": {
                "versions": {
                    "nginx": "1.18.0",
                    "php": "7.4.0"
                }
            }
        }
    }

@pytest.fixture
def plugins(test_session) -> Dict[str, Any]:
    """Provide initialized plugin instances for testing."""
    return {
        "subdomain": SubdomainEnumPlugin(test_session),
        "port_scan": PortScannerPlugin(test_session),
        "web_tech": WebTechPlugin(test_session),
        "dir_brute": DirBrutePlugin(test_session),
        "vuln_scanner": VulnScannerPlugin(test_session)
    }

@pytest.fixture
def mock_http_responses() -> Dict[str, Any]:
    """Provide mock HTTP responses for testing."""
    return {
        "success": {
            "status": 200,
            "headers": {
                "Server": "nginx/1.18.0",
                "X-Powered-By": "PHP/7.4.0"
            },
            "body": "<html><body>Test Page</body></html>"
        },
        "not_found": {
            "status": 404,
            "headers": {},
            "body": "Not Found"
        },
        "error": {
            "status": 500,
            "headers": {},
            "body": "Internal Server Error"
        }
    }

@pytest.fixture
def mock_dns_responses() -> Dict[str, Any]:
    """Provide mock DNS responses for testing."""
    return {
        "success": {
            "A": ["93.184.216.34"],
            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "MX": ["mail.example.com"]
        },
        "not_found": {
            "A": [],
            "AAAA": [],
            "NS": [],
            "MX": []
        }
    }

@pytest.fixture
def test_config() -> Dict[str, Any]:
    """Provide test configuration."""
    return {
        "timeout": 30,
        "max_redirects": 5,
        "user_agent": "BBF-Test/1.0",
        "max_concurrent_requests": 10,
        "verify_ssl": False,
        "wordlists": {
            "directory": "test_wordlist.txt",
            "subdomain": "test_subdomains.txt"
        },        
    } 