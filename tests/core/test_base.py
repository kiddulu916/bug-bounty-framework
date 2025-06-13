"""
Tests for the base module.

This module contains test cases for the core base functionality,
including base classes and fundamental framework components.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import asyncio
from datetime import datetime
import json

from bbf.core.base import BasePlugin, BaseStage, BaseService
from bbf.core.exceptions import PluginError, StageError, ServiceError
from bbf.core.database.models import Finding, Stage, Plugin

# Test data
TEST_CONFIG = {
    'name': 'test_plugin',
    'version': '1.0.0',
    'description': 'Test plugin for unit testing',
    'author': 'Test Author',
    'tags': ['test', 'unit'],
    'settings': {
        'timeout': 30,
        'max_retries': 3,
        'concurrent_tasks': 5
    }
}

TEST_METADATA = {
    'start_time': datetime.now().isoformat(),
    'end_time': None,
    'status': 'initialized',
    'progress': 0.0,
    'findings': [],
    'errors': []
}

class TestPlugin(BasePlugin):
    """Test plugin implementation."""
    
    async def initialize(self):
        """Initialize the test plugin."""
        await super().initialize()
        self._initialized = True
    
    async def execute(self, target):
        """Execute the test plugin."""
        if not self._initialized:
            raise PluginError("Plugin not initialized")
        return [{'type': 'test', 'severity': 'low', 'confidence': 0.8}]
    
    async def cleanup(self):
        """Cleanup the test plugin."""
        await super().cleanup()
        self._initialized = False

class TestStage(BaseStage):
    """Test stage implementation."""
    
    async def initialize(self):
        """Initialize the test stage."""
        await super().initialize()
        self._initialized = True
    
    async def execute(self, target):
        """Execute the test stage."""
        if not self._initialized:
            raise StageError("Stage not initialized")
        return [{'type': 'test', 'severity': 'low', 'confidence': 0.8}]
    
    async def cleanup(self):
        """Cleanup the test stage."""
        await super().cleanup()
        self._initialized = False

class TestService(BaseService):
    """Test service implementation."""
    
    async def initialize(self):
        """Initialize the test service."""
        await super().initialize()
        self._initialized = True
    
    async def execute(self, data):
        """Execute the test service."""
        if not self._initialized:
            raise ServiceError("Service not initialized")
        return {'status': 'success', 'data': data}
    
    async def cleanup(self):
        """Cleanup the test service."""
        await super().cleanup()
        self._initialized = False

@pytest.fixture
def base_plugin():
    """Create a base plugin instance for testing."""
    return TestPlugin()

@pytest.fixture
def base_stage():
    """Create a base stage instance for testing."""
    return TestStage()

@pytest.fixture
def base_service():
    """Create a base service instance for testing."""
    return TestService()

@pytest.mark.asyncio
async def test_base_plugin_initialization(base_plugin):
    """Test base plugin initialization."""
    # Test initialization
    await base_plugin.initialize()
    assert base_plugin._initialized
    assert base_plugin._metadata == {}
    assert base_plugin._findings == []
    assert base_plugin._errors == []
    
    # Test execution
    results = await base_plugin.execute("test_target")
    assert isinstance(results, list)
    assert len(results) > 0
    assert all(isinstance(f, dict) for f in results)
    
    # Test cleanup
    await base_plugin.cleanup()
    assert not base_plugin._initialized

@pytest.mark.asyncio
async def test_base_plugin_error_handling(base_plugin):
    """Test base plugin error handling."""
    # Test execution without initialization
    with pytest.raises(PluginError):
        await base_plugin.execute("test_target")
    
    # Test double initialization
    await base_plugin.initialize()
    with pytest.raises(PluginError):
        await base_plugin.initialize()
    
    # Test double cleanup
    await base_plugin.cleanup()
    await base_plugin.cleanup()  # Should not raise

@pytest.mark.asyncio
async def test_base_stage_initialization(base_stage):
    """Test base stage initialization."""
    # Test initialization
    await base_stage.initialize()
    assert base_stage._initialized
    assert base_stage._metadata == {}
    assert base_stage._findings == []
    assert base_stage._errors == []
    
    # Test execution
    results = await base_stage.execute("test_target")
    assert isinstance(results, list)
    assert len(results) > 0
    assert all(isinstance(f, dict) for f in results)
    
    # Test cleanup
    await base_stage.cleanup()
    assert not base_stage._initialized

@pytest.mark.asyncio
async def test_base_stage_error_handling(base_stage):
    """Test base stage error handling."""
    # Test execution without initialization
    with pytest.raises(StageError):
        await base_stage.execute("test_target")
    
    # Test double initialization
    await base_stage.initialize()
    with pytest.raises(StageError):
        await base_stage.initialize()
    
    # Test double cleanup
    await base_stage.cleanup()
    await base_stage.cleanup()  # Should not raise

@pytest.mark.asyncio
async def test_base_service_initialization(base_service):
    """Test base service initialization."""
    # Test initialization
    await base_service.initialize()
    assert base_service._initialized
    assert base_service._metadata == {}
    
    # Test execution
    result = await base_service.execute({"test": "data"})
    assert isinstance(result, dict)
    assert result['status'] == 'success'
    assert result['data'] == {"test": "data"}
    
    # Test cleanup
    await base_service.cleanup()
    assert not base_service._initialized

@pytest.mark.asyncio
async def test_base_service_error_handling(base_service):
    """Test base service error handling."""
    # Test execution without initialization
    with pytest.raises(ServiceError):
        await base_service.execute({"test": "data"})
    
    # Test double initialization
    await base_service.initialize()
    with pytest.raises(ServiceError):
        await base_service.initialize()
    
    # Test double cleanup
    await base_service.cleanup()
    await base_service.cleanup()  # Should not raise

@pytest.mark.asyncio
async def test_base_metadata_handling(base_plugin):
    """Test metadata handling in base classes."""
    await base_plugin.initialize()
    
    # Test metadata updates
    base_plugin.update_metadata({'status': 'running'})
    assert base_plugin._metadata['status'] == 'running'
    
    base_plugin.update_metadata({'progress': 0.5})
    assert base_plugin._metadata['progress'] == 0.5
    
    # Test metadata validation
    with pytest.raises(ValueError):
        base_plugin.update_metadata({'progress': 1.5})  # Invalid progress
    
    with pytest.raises(ValueError):
        base_plugin.update_metadata({'status': 'invalid'})  # Invalid status

@pytest.mark.asyncio
async def test_base_finding_handling(base_plugin):
    """Test finding handling in base classes."""
    await base_plugin.initialize()
    
    # Test adding findings
    finding = {
        'type': 'test',
        'severity': 'low',
        'confidence': 0.8,
        'description': 'Test finding'
    }
    base_plugin.add_finding(finding)
    assert len(base_plugin._findings) == 1
    assert base_plugin._findings[0] == finding
    
    # Test finding validation
    with pytest.raises(ValueError):
        base_plugin.add_finding({'type': 'test'})  # Missing required fields
    
    with pytest.raises(ValueError):
        base_plugin.add_finding({
            'type': 'test',
            'severity': 'invalid',
            'confidence': 0.8
        })  # Invalid severity

@pytest.mark.asyncio
async def test_base_error_handling(base_plugin):
    """Test error handling in base classes."""
    await base_plugin.initialize()
    
    # Test adding errors
    error = PluginError("Test error")
    base_plugin.add_error(error)
    assert len(base_plugin._errors) == 1
    assert str(base_plugin._errors[0]) == str(error)
    
    # Test error logging
    with patch('logging.error') as mock_log:
        base_plugin.log_error(error)
        mock_log.assert_called_once()
    
    # Test error aggregation
    base_plugin.add_error(PluginError("Another error"))
    assert len(base_plugin._errors) == 2
    assert all(isinstance(e, PluginError) for e in base_plugin._errors) 