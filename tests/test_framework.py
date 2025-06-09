"""
Unit tests for the Bug Bounty Framework core functionality.
"""

import asyncio
import json
import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

from bbf import BFFramework, load_config
from bbf.core.plugin import BasePlugin, plugin
from bbf.core.state import StateManager
from bbf.core.exceptions import PluginExecutionError, StageExecutionError

# Test plugins
@plugin
class TestPluginSuccess(BasePlugin):
    """Test plugin that always succeeds."""
    name = "test_plugin_success"
    
    async def execute(self, target, **kwargs):
        return {"status": "success", "target": target}

@plugin
class TestPluginError(BasePlugin):
    """Test plugin that always raises an error."""
    name = "test_plugin_error"
    
    async def execute(self, target, **kwargs):
        raise ValueError("Test error")

@plugin
class TestPluginSlow(BasePlugin):
    """Test plugin that takes time to execute."""
    name = "test_plugin_slow"
    
    async def execute(self, target, **kwargs):
        await asyncio.sleep(0.1)
        return {"status": "slow_success", "target": target}

class TestBFFramework:
    """Test cases for the BFFramework class."""
    
    @pytest.fixture
    def sample_config(self, tmp_path):
        """Create a sample configuration for testing."""
        config = {
            "target": "example.com",
            "output_dir": str(tmp_path / "output"),
            "log_level": "INFO",
            "stages": {
                "recon": {
                    "enabled": True,
                    "plugins": ["test_plugin_success", "test_plugin_slow"]
                },
                "scan": {
                    "enabled": True,
                    "plugins": ["test_plugin_success"]
                },
                "test": {
                    "enabled": False,
                    "plugins": []
                },
                "report": {
                    "enabled": True,
                    "plugins": []
                }
            },
            "plugins": {
                "test_plugin_success": {},
                "test_plugin_slow": {}
            }
        }
        return config
    
    @pytest.fixture
    def error_config(self, tmp_path):
        """Create a configuration with an erroring plugin."""
        config = {
            "target": "example.com",
            "output_dir": str(tmp_path / "output"),
            "log_level": "INFO",
            "stages": {
                "recon": {
                    "enabled": True,
                    "plugins": ["test_plugin_error"],
                    "continue_on_error": False
                },
                "scan": {
                    "enabled": True,
                    "plugins": ["test_plugin_success"]
                }
            },
            "plugins": {
                "test_plugin_error": {},
                "test_plugin_success": {}
            }
        }
        return config
    
    @pytest.mark.asyncio
    async def test_framework_initialization(self, sample_config):
        """Test framework initialization with a sample config."""
        framework = BFFramework(sample_config)
        await framework.initialize()
        
        assert framework.target == "example.com"
        assert isinstance(framework.state_manager, StateManager)
        assert len(framework.stages) == 4  # recon, scan, test, report
        assert framework.stages["recon"].enabled
        assert not framework.stages["test"].enabled
        
        await framework.close()
    
    @pytest.mark.asyncio
    async def test_run_stage_success(self, sample_config):
        """Test running a stage successfully."""
        framework = BFFramework(sample_config)
        await framework.initialize()
        
        # Run recon stage
        results = await framework.run_stage("recon")
        
        assert isinstance(results, dict)
        assert "test_plugin_success" in results
        assert "test_plugin_slow" in results
        assert results["test_plugin_success"]["status"] == "success"
        assert results["test_plugin_slow"]["status"] == "slow_success"
        
        await framework.close()
    
    @pytest.mark.asyncio
    async def test_run_stage_error(self, error_config):
        """Test error handling when a plugin fails."""
        framework = BFFramework(error_config)
        await framework.initialize()
        
        # Run recon stage which has an erroring plugin
        with pytest.raises(StageExecutionError) as exc_info:
            await framework.run_stage("recon")
        
        assert "Error in stage 'recon'" in str(exc_info.value)
        assert isinstance(exc_info.value.__cause__, PluginExecutionError)
        assert "Test error" in str(exc_info.value.__cause__)
        
        # The scan stage should not have run due to the error
        assert "scan" not in framework.state_manager.state.get("completed_stages", [])
        
        await framework.close()
    
    @pytest.mark.asyncio
    async def test_run_all_stages(self, sample_config):
        """Test running all stages in sequence."""
        framework = BFFramework(sample_config)
        await framework.initialize()
        
        # Run all stages
        results = await framework.run()
        
        # Check that expected stages were run
        assert "recon" in results
        assert "scan" in results
        assert "test" not in results  # Disabled in config
        assert "report" in results
        
        # Check that plugins were executed
        assert "test_plugin_success" in results["recon"]
        assert "test_plugin_slow" in results["recon"]
        assert "test_plugin_success" in results["scan"]
        
        # Check that state was saved
        assert os.path.exists(sample_config["output_dir"])
        
        await framework.close()
    
    @pytest.mark.asyncio
    async def test_state_persistence(self, sample_config, tmp_path):
        """Test that framework state is persisted between runs."""
        # Run first pass
        framework1 = BFFramework(sample_config)
        await framework1.initialize()
        await framework1.run_stage("recon")
        await framework1.close()
        
        # Create new framework instance with same config
        framework2 = BFFramework(sample_config)
        await framework2.initialize()
        
        # Check that state was loaded
        assert "recon" in framework2.state_manager.state.get("completed_stages", [])
        
        # Run scan stage
        await framework2.run_stage("scan")
        await framework2.close()
        
        # Verify both stages are in the state
        framework3 = BFFramework(sample_config)
        await framework3.initialize()
        completed_stages = framework3.state_manager.state.get("completed_stages", [])
        assert "recon" in completed_stages
        assert "scan" in completed_stages
        
        await framework3.close()
    
    @pytest.mark.asyncio
    async def test_plugin_config_loading(self):
        """Test that plugin configuration is loaded correctly."""
        config = {
            "target": "example.com",
            "output_dir": "./reports",
            "stages": {
                "recon": {
                    "enabled": True,
                    "plugins": ["test_plugin_success"]
                }
            },
            "plugins": {
                "test_plugin_success": {
                    "test_option": "test_value"
                }
            }
        }
        
        framework = BFFramework(config)
        await framework.initialize()
        
        # Get the plugin instance
        plugin = framework.stages["recon"].plugins[0]
        assert plugin.config.get("test_option") == "test_value"
        
        await framework.close()

class TestStateManager:
    """Test cases for the StateManager class."""
    
    @pytest.fixture
    def state_file(self, tmp_path):
        """Create a temporary state file for testing."""
        return tmp_path / "state.json"
    
    def test_state_initialization(self, state_file):
        """Test state manager initialization."""
        state_manager = StateManager(state_file)
        assert state_manager.state == {}
    
    def test_state_loading(self, state_file):
        """Test loading state from a file."""
        # Create a state file
        state_data = {"test_key": "test_value", "completed_stages": ["recon"]}
        with open(state_file, 'w') as f:
            json.dump(state_data, f)
        
        # Load the state
        state_manager = StateManager(state_file)
        assert state_manager.state == state_data
    
    def test_state_saving(self, state_file):
        """Test saving state to a file."""
        state_manager = StateManager(state_file)
        state_manager.state["test_key"] = "test_value"
        state_manager.state["completed_stages"] = ["recon"]
        
        # Save the state
        state_manager.save_state()
        
        # Verify the file was created and contains the correct data
        assert state_file.exists()
        with open(state_file, 'r') as f:
            saved_state = json.load(f)
        
        assert saved_state == state_manager.state
    
    def test_state_updates(self, state_file):
        """Test updating state values."""
        state_manager = StateManager(state_file)
        
        # Update state
        state_manager.update_state({"test_key": "value1"})
        assert state_manager.state["test_key"] == "value1"
        
        # Nested update
        state_manager.update_state({"nested": {"key": "value"}})
        assert state_manager.state["nested"]["key"] == "value"
        
        # Merge with existing nested
        state_manager.update_state({"nested": {"key2": "value2"}})
        assert state_manager.state["nested"]["key"] == "value"
        assert state_manager.state["nested"]["key2"] == "value2"
    
    def test_state_context_manager(self, state_file):
        """Test using StateManager as a context manager."""
        with StateManager(state_file) as state_manager:
            state_manager.state["test_key"] = "test_value"
            # State should be saved when exiting the context
        
        # Verify the state was saved
        assert state_file.exists()
        with open(state_file, 'r') as f:
            saved_state = json.load(f)
        
        assert saved_state["test_key"] == "test_value"
