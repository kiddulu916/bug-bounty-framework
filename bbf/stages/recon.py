"""
Reconnaissance stage implementation for the Bug Bounty Framework.

This module provides the ReconStage class that implements the reconnaissance
phase of security testing. It includes subdomain enumeration, port scanning,
and other information gathering techniques.
"""

from typing import Any, Dict, List, Optional
import logging
from datetime import datetime

from bbf.core.stage import Stage
from bbf.core.exceptions import StageError

logger = logging.getLogger(__name__)

class ReconStage(Stage):
    """Reconnaissance stage for gathering information about the target.
    
    This stage implements various reconnaissance techniques including:
    - Subdomain enumeration
    - Port scanning
    - Web discovery
    - Technology detection
    
    Attributes:
        name (str): The name of the stage.
        description (str): A description of what the stage does.
        enabled (bool): Whether the stage is enabled.
        required_previous_stages (List[str]): List of stages that must be completed before this stage.
        required_plugins (List[str]): List of plugins that must be available for this stage.
        timeout (int): Maximum time in seconds for the stage to complete.
    """
    
    name = "recon"
    description = "Gathers information about the target using various reconnaissance techniques"
    required_plugins = ["subdomain_enum"]  # We'll add more plugins as we implement them
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the reconnaissance stage.
        
        Args:
            config: Optional configuration dictionary for the stage.
        """
        super().__init__(config)
        self._plugins = self.required_plugins  # For now, we only have subdomain enumeration
        
    async def _initialize(self) -> None:
        """Initialize the reconnaissance stage.
        
        This method:
        1. Validates that all required plugins are available
        2. Initializes any resources needed by the stage
        3. Sets up the stage state
        
        Raises:
            StageError: If initialization fails.
        """
        try:
            # Initialize stage state
            self._state.update({
                'target': None,
                'subdomains': [],
                'ports': [],
                'web_services': [],
                'technologies': []
            })
            
            # Initialize plugins
            for plugin_name in self._plugins:
                plugin = self._plugin_registry.get_plugin(plugin_name)
                if plugin:
                    try:
                        await plugin.initialize()
                    except Exception as e:
                        logger.error(f"Plugin {plugin_name} initialization failed: {str(e)}")
                        raise StageError(f"Plugin initialization failed: {str(e)}")
                        
        except Exception as e:
            logger.error(f"Reconnaissance stage initialization failed: {str(e)}")
            raise StageError(f"Stage initialization failed: {str(e)}")
            
    async def _execute(self, target: str, **kwargs) -> None:
        """Execute the reconnaissance stage.
        
        This method:
        1. Executes all enabled plugins in parallel
        2. Aggregates the results
        3. Updates the stage state
        
        Args:
            target: The target to test (e.g., domain name, IP address).
            **kwargs: Additional arguments for the stage.
            
        Raises:
            StageError: If execution fails.
        """
        try:
            # Update stage state
            self._state['target'] = target
            self._state['status'] = 'running'
            
            # Execute plugins and process results
            for plugin_name, result in self._results.items():
                if plugin_name == 'subdomain_enum':
                    # Process subdomain enumeration results
                    if isinstance(result, dict) and 'subdomains' in result:
                        self._state['subdomains'].extend(result['subdomains'])
                        
            # Deduplicate results
            self._state['subdomains'] = list(set(self._state['subdomains']))
            
            # Log results
            logger.info(f"Found {len(self._state['subdomains'])} subdomains")
            
        except Exception as e:
            logger.error(f"Reconnaissance stage execution failed: {str(e)}")
            raise StageError(f"Stage execution failed: {str(e)}")
            
    async def _cleanup(self) -> None:
        """Clean up reconnaissance stage resources.
        
        This method:
        1. Cleans up any resources used by the stage
        2. Cleans up plugin resources
        
        Raises:
            StageError: If cleanup fails.
        """
        try:
            # Clean up plugins
            for plugin_name in self._plugins:
                plugin = self._plugin_registry.get_plugin(plugin_name)
                if plugin:
                    try:
                        await plugin.cleanup()
                    except Exception as e:
                        logger.error(f"Plugin {plugin_name} cleanup failed: {str(e)}")
                        
        except Exception as e:
            logger.error(f"Reconnaissance stage cleanup failed: {str(e)}")
            raise StageError(f"Stage cleanup failed: {str(e)}")
            
    def get_subdomains(self) -> List[str]:
        """Get the list of discovered subdomains.
        
        Returns:
            List of discovered subdomains.
        """
        return self._state['subdomains'].copy()
        
    def get_ports(self) -> List[int]:
        """Get the list of discovered ports.
        
        Returns:
            List of discovered ports.
        """
        return self._state['ports'].copy()
        
    def get_web_services(self) -> List[Dict[str, Any]]:
        """Get the list of discovered web services.
        
        Returns:
            List of discovered web services.
        """
        return self._state['web_services'].copy()
        
    def get_technologies(self) -> List[Dict[str, Any]]:
        """Get the list of discovered technologies.
        
        Returns:
            List of discovered technologies.
        """
        return self._state['technologies'].copy()
