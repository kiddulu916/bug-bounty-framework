"""
Test suite for the plugin manager.

This module tests:
- Plugin registration and management
- Session creation and management
- Plugin execution and result storage
- Error handling and cleanup
"""

import asyncio
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any

from bbf.core.plugin_manager import PluginManager, PluginConfig
from bbf.core.database.models import ScanSession, PluginResult
from bbf.core.plugins.base import BasePlugin
from bbf.core.database.service import scan_service, finding_service

# Test data
TEST_TARGET = "example.com"
TEST_CONFIG = {
    "plugins": ["subdomain_enum", "port_scan"],
    "timeout": 30,
    "rate_limit": 10
}

class MockPlugin(BasePlugin):
    """Mock plugin for testing."""
    
    name = "mock_plugin"
    
    def __init__(self):
        """Initialize mock plugin."""
        super().__init__()
        self.executed = False
        
    async def execute(self, target: str) -> Dict[str, Any]:
        """Execute mock plugin.
        
        Args:
            target: The target to scan.
            
        Returns:
            Dict[str, Any]: Mock results.
        """
        self.executed = True
        return {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "success"
        }

@pytest.fixture
def plugin_manager():
    """Create plugin manager instance."""
    return PluginManager()

@pytest.fixture
def mock_plugin():
    """Create mock plugin instance."""
    return MockPlugin()

@pytest.fixture
def mock_session():
    """Create mock scan session."""
    return ScanSession(
        id=1,
        target=TEST_TARGET,
        start_time=datetime.utcnow(),
        end_time=None,
        status="running",
        configuration=TEST_CONFIG
    )

@pytest.mark.asyncio
async def test_plugin_registration(plugin_manager, mock_plugin):
    """Test plugin registration."""
    # Register plugin
    plugin_manager.register_plugin(MockPlugin)
    
    # Verify plugin is registered
    assert "mock_plugin" in plugin_manager.plugins
    assert plugin_manager.get_plugin("mock_plugin") is not None
    
    # Verify plugin instance is created
    plugin = plugin_manager.get_plugin("mock_plugin")
    assert isinstance(plugin, MockPlugin)
    assert not plugin.executed

@pytest.mark.asyncio
async def test_create_scan_session(plugin_manager):
    """Test scan session creation."""
    # Create session
    with patch.object(scan_service, 'create_scan_session') as mock_create:
        mock_create.return_value = ScanSession(
            id=1,
            target=TEST_TARGET,
            start_time=datetime.utcnow(),
            end_time=None,
            status="running",
            configuration=TEST_CONFIG
        )
        
        session = await plugin_manager.create_scan_session(TEST_TARGET, TEST_CONFIG)
        
        # Verify session creation
        assert session.id == 1
        assert session.target == TEST_TARGET
        assert session.status == "running"
        assert session in plugin_manager.active_sessions.values()
        
        # Verify service call
        mock_create.assert_called_once()

@pytest.mark.asyncio
async def test_execute_plugin(plugin_manager, mock_session):
    """Test plugin execution."""
    # Register plugin
    plugin_manager.register_plugin(MockPlugin)
    plugin_manager.active_sessions[mock_session.id] = mock_session
    
    # Mock database operations
    with patch.object(scan_service, 'add_plugin_result') as mock_add_result, \
         patch.object(scan_service, 'update_plugin_result') as mock_update_result, \
         patch.object(finding_service, 'add_subdomain_findings') as mock_add_findings:
        
        # Mock plugin result
        mock_result = PluginResult(
            id=1,
            session_id=mock_session.id,
            plugin_name="mock_plugin",
            start_time=datetime.utcnow(),
            end_time=None,
            status="running"
        )
        mock_add_result.return_value = mock_result
        
        # Execute plugin
        result = await plugin_manager.execute_plugin(
            mock_session.id,
            "mock_plugin"
        )
        
        # Verify plugin execution
        assert result.id == mock_result.id
        assert result.plugin_name == "mock_plugin"
        assert result.status == "completed"
        
        # Verify service calls
        mock_add_result.assert_called_once()
        mock_update_result.assert_called_once()
        mock_add_findings.assert_not_called()  # No findings for mock plugin

@pytest.mark.asyncio
async def test_execute_session(plugin_manager, mock_session):
    """Test session execution."""
    # Register plugins
    plugin_manager.register_plugin(MockPlugin)
    plugin_manager.active_sessions[mock_session.id] = mock_session
    
    # Mock database operations
    with patch.object(scan_service, 'add_plugin_result') as mock_add_result, \
         patch.object(scan_service, 'update_plugin_result') as mock_update_result, \
         patch.object(scan_service, 'update_session_status') as mock_update_session:
        
        # Mock plugin results
        mock_result = PluginResult(
            id=1,
            session_id=mock_session.id,
            plugin_name="mock_plugin",
            start_time=datetime.utcnow(),
            end_time=None,
            status="running"
        )
        mock_add_result.return_value = mock_result
        
        # Execute session
        await plugin_manager.execute_session(mock_session.id)
        
        # Verify session execution
        assert mock_session.id not in plugin_manager.active_sessions
        
        # Verify service calls
        mock_add_result.assert_called()
        mock_update_result.assert_called()
        mock_update_session.assert_called_once_with(
            mock.ANY,  # Database session
            mock_session.id,
            "completed"
        )

@pytest.mark.asyncio
async def test_plugin_execution_error(plugin_manager, mock_session):
    """Test plugin execution error handling."""
    # Create error-raising plugin
    class ErrorPlugin(BasePlugin):
        name = "error_plugin"
        
        async def execute(self, target: str) -> Dict[str, Any]:
            raise Exception("Test error")
    
    # Register plugin
    plugin_manager.register_plugin(ErrorPlugin)
    plugin_manager.active_sessions[mock_session.id] = mock_session
    
    # Mock database operations
    with patch.object(scan_service, 'add_plugin_result') as mock_add_result, \
         patch.object(scan_service, 'update_plugin_result') as mock_update_result:
        
        # Mock plugin result
        mock_result = PluginResult(
            id=1,
            session_id=mock_session.id,
            plugin_name="error_plugin",
            start_time=datetime.utcnow(),
            end_time=None,
            status="running"
        )
        mock_add_result.return_value = mock_result
        
        # Execute plugin and expect error
        with pytest.raises(Exception) as exc_info:
            await plugin_manager.execute_plugin(mock_session.id, "error_plugin")
        
        assert str(exc_info.value) == "Test error"
        
        # Verify error was recorded
        mock_update_result.assert_called_once_with(
            mock.ANY,  # Database session
            mock_result.id,
            end_time=mock.ANY,
            status="failed",
            error="Test error"
        )

@pytest.mark.asyncio
async def test_session_execution_error(plugin_manager, mock_session):
    """Test session execution error handling."""
    # Create error-raising plugin
    class ErrorPlugin(BasePlugin):
        name = "error_plugin"
        
        async def execute(self, target: str) -> Dict[str, Any]:
            raise Exception("Test error")
    
    # Register plugin
    plugin_manager.register_plugin(ErrorPlugin)
    plugin_manager.active_sessions[mock_session.id] = mock_session
    
    # Mock database operations
    with patch.object(scan_service, 'add_plugin_result') as mock_add_result, \
         patch.object(scan_service, 'update_plugin_result') as mock_update_result, \
         patch.object(scan_service, 'update_session_status') as mock_update_session:
        
        # Mock plugin result
        mock_result = PluginResult(
            id=1,
            session_id=mock_session.id,
            plugin_name="error_plugin",
            start_time=datetime.utcnow(),
            end_time=None,
            status="running"
        )
        mock_add_result.return_value = mock_result
        
        # Execute session and expect error
        with pytest.raises(Exception) as exc_info:
            await plugin_manager.execute_session(mock_session.id)
        
        assert str(exc_info.value) == "Test error"
        
        # Verify error was recorded
        mock_update_result.assert_called_once()
        mock_update_session.assert_called_once_with(
            mock.ANY,  # Database session
            mock_session.id,
            "failed"
        )
        assert mock_session.id not in plugin_manager.active_sessions

@pytest.mark.asyncio
async def test_get_session_summary(plugin_manager, mock_session):
    """Test getting session summary."""
    # Mock database operations
    with patch.object(scan_service, 'get_session_summary') as mock_get_summary:
        mock_get_summary.return_value = {
            "total_plugins": 2,
            "completed_plugins": 1,
            "failed_plugins": 1,
            "total_findings": 10
        }
        
        # Get summary
        summary = plugin_manager.get_session_summary(mock_session.id)
        
        # Verify summary
        assert summary["total_plugins"] == 2
        assert summary["completed_plugins"] == 1
        assert summary["failed_plugins"] == 1
        assert summary["total_findings"] == 10
        
        # Verify service call
        mock_get_summary.assert_called_once_with(mock_session.id)

@pytest.mark.asyncio
async def test_get_session_findings(plugin_manager, mock_session):
    """Test getting session findings."""
    # Mock database operations
    with patch.object(finding_service, 'get_session_findings') as mock_get_findings:
        mock_get_findings.return_value = {
            "subdomains": [
                {"name": "sub1.example.com", "ip": "1.1.1.1"},
                {"name": "sub2.example.com", "ip": "2.2.2.2"}
            ],
            "ports": [
                {"host": "example.com", "port": 80, "service": "http"},
                {"host": "example.com", "port": 443, "service": "https"}
            ]
        }
        
        # Get findings
        findings = plugin_manager.get_session_findings(mock_session.id)
        
        # Verify findings
        assert len(findings["subdomains"]) == 2
        assert len(findings["ports"]) == 2
        assert findings["subdomains"][0]["name"] == "sub1.example.com"
        assert findings["ports"][0]["port"] == 80
        
        # Verify service call
        mock_get_findings.assert_called_once_with(mock_session.id)

@pytest.mark.asyncio
async def test_get_active_sessions(plugin_manager, mock_session):
    """Test getting active sessions."""
    # Add session to active sessions
    plugin_manager.active_sessions[mock_session.id] = mock_session
    
    # Get active sessions
    active_sessions = plugin_manager.get_active_sessions()
    
    # Verify sessions
    assert len(active_sessions) == 1
    assert active_sessions[0].id == mock_session.id
    assert active_sessions[0].target == TEST_TARGET

@pytest.mark.asyncio
async def test_get_available_plugins(plugin_manager):
    """Test getting available plugins."""
    # Register plugins
    plugin_manager.register_plugin(MockPlugin)
    
    # Get available plugins
    plugins = plugin_manager.get_available_plugins()
    
    # Verify plugins
    assert len(plugins) == 1
    assert "mock_plugin" in plugins 