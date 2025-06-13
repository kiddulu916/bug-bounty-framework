"""
Plugin manager module.

This module handles:
- Plugin loading and registration
- Plugin execution and coordination
- Session management
- Result storage
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Type
from dataclasses import dataclass

from bbf.core.database.service import scan_service, finding_service
from bbf.core.database.models import ScanSession, PluginResult
from bbf.plugins.base import BasePlugin

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class PluginConfig:
    """Plugin configuration."""
    name: str
    enabled: bool = True
    config: Dict[str, Any] = None

class PluginManager:
    """Manages plugin execution and database integration."""
    
    def __init__(self):
        """Initialize the plugin manager."""
        self.plugins: Dict[str, Type[BasePlugin]] = {}
        self.active_sessions: Dict[int, ScanSession] = {}
        
    def register_plugin(self, plugin_class: Type[BasePlugin]) -> None:
        """Register a plugin class.
        
        Args:
            plugin_class: The plugin class to register.
        """
        plugin = plugin_class()
        self.plugins[plugin.name] = plugin_class
        logger.info(f"Registered plugin: {plugin.name}")
        
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a plugin instance by name.
        
        Args:
            name: The name of the plugin.
            
        Returns:
            Optional[BasePlugin]: The plugin instance if found, None otherwise.
        """
        plugin_class = self.plugins.get(name)
        if plugin_class:
            return plugin_class()
        return None
        
    async def create_scan_session(self, target: str, config: Dict[str, Any]) -> ScanSession:
        """Create a new scan session.
        
        Args:
            target: The target to scan.
            config: Session configuration.
            
        Returns:
            ScanSession: The created scan session.
        """
        with scan_service.session_repo.get_session() as session:
            scan_session = scan_service.create_scan_session(
                session,
                target=target,
                config=config
            )
            self.active_sessions[scan_session.id] = scan_session
            return scan_session
            
    async def execute_plugin(self, session_id: int, plugin_name: str,
                           plugin_config: Optional[Dict[str, Any]] = None) -> PluginResult:
        """Execute a plugin and store its results.
        
        Args:
            session_id: The scan session ID.
            plugin_name: The name of the plugin to execute.
            plugin_config: Optional plugin configuration.
            
        Returns:
            PluginResult: The plugin execution result.
            
        Raises:
            ValueError: If the plugin is not found or the session is invalid.
        """
        # Get session
        session = self.active_sessions.get(session_id)
        if not session:
            raise ValueError(f"Invalid session ID: {session_id}")
            
        # Get plugin
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            raise ValueError(f"Plugin not found: {plugin_name}")
            
        # Update plugin configuration
        if plugin_config:
            for key, value in plugin_config.items():
                setattr(plugin, key, value)
                
        # Execute plugin
        start_time = datetime.utcnow()
        try:
            # Get database session
            with scan_service.session_repo.get_session() as db_session:
                # Create plugin result record
                plugin_result = scan_service.add_plugin_result(
                    db_session,
                    session_id=session_id,
                    plugin_name=plugin_name,
                    start_time=start_time,
                    end_time=None,
                    status='running'
                )
                
                # Execute plugin
                results = await plugin.execute(session.target)
                
                # Store findings based on plugin type
                if plugin_name == 'subdomain_enum':
                    findings = finding_service.add_subdomain_findings(
                        db_session,
                        plugin_result.id,
                        results
                    )
                elif plugin_name == 'port_scan':
                    findings = finding_service.add_port_scan_results(
                        db_session,
                        plugin_result.id,
                        results
                    )
                elif plugin_name == 'web_tech':
                    findings = finding_service.add_web_technology_findings(
                        db_session,
                        plugin_result.id,
                        results
                    )
                elif plugin_name == 'dir_brute':
                    findings = finding_service.add_directory_findings(
                        db_session,
                        plugin_result.id,
                        results
                    )
                elif plugin_name == 'vuln_scan':
                    findings = finding_service.add_vulnerability_findings(
                        db_session,
                        plugin_result.id,
                        results
                    )
                else:
                    findings = []
                    
                # Update plugin result
                end_time = datetime.utcnow()
                scan_service.update_plugin_result(
                    db_session,
                    plugin_result.id,
                    end_time=end_time,
                    status='completed',
                    output=results
                )
                
                return plugin_result
                
        except Exception as e:
            logger.error(f"Plugin execution failed: {e}")
            # Update plugin result with error
            with scan_service.session_repo.get_session() as db_session:
                end_time = datetime.utcnow()
                scan_service.update_plugin_result(
                    db_session,
                    plugin_result.id,
                    end_time=end_time,
                    status='failed',
                    error=str(e)
                )
            raise
            
    async def execute_session(self, session_id: int,
                            plugin_configs: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        """Execute all enabled plugins for a session.
        
        Args:
            session_id: The scan session ID.
            plugin_configs: Optional plugin-specific configurations.
            
        Raises:
            ValueError: If the session is invalid.
        """
        session = self.active_sessions.get(session_id)
        if not session:
            raise ValueError(f"Invalid session ID: {session_id}")
            
        # Get enabled plugins from session config
        enabled_plugins = session.configuration.get('plugins', [])
        if not enabled_plugins:
            enabled_plugins = list(self.plugins.keys())
            
        # Execute plugins concurrently
        tasks = []
        for plugin_name in enabled_plugins:
            if plugin_name in self.plugins:
                config = plugin_configs.get(plugin_name) if plugin_configs else None
                task = asyncio.create_task(
                    self.execute_plugin(session_id, plugin_name, config)
                )
                tasks.append(task)
                
        # Wait for all plugins to complete
        try:
            await asyncio.gather(*tasks)
            # Update session status
            with scan_service.session_repo.get_session() as db_session:
                scan_service.update_session_status(db_session, session_id, 'completed')
        except Exception as e:
            logger.error(f"Session execution failed: {e}")
            # Update session status
            with scan_service.session_repo.get_session() as db_session:
                scan_service.update_session_status(db_session, session_id, 'failed')
            raise
        finally:
            # Remove session from active sessions
            self.active_sessions.pop(session_id, None)
            
    def get_session_summary(self, session_id: int) -> Dict[str, Any]:
        """Get summary statistics for a session.
        
        Args:
            session_id: The scan session ID.
            
        Returns:
            Dict[str, Any]: Session summary statistics.
        """
        return scan_service.get_session_summary(session_id)
        
    def get_session_findings(self, session_id: int) -> Dict[str, List[Any]]:
        """Get all findings for a session.
        
        Args:
            session_id: The scan session ID.
            
        Returns:
            Dict[str, List[Any]]: Session findings by type.
        """
        return finding_service.get_session_findings(session_id)
        
    def get_active_sessions(self) -> List[ScanSession]:
        """Get all active scan sessions.
        
        Returns:
            List[ScanSession]: List of active sessions.
        """
        return list(self.active_sessions.values())
        
    def get_available_plugins(self) -> List[str]:
        """Get list of available plugins.
        
        Returns:
            List[str]: List of plugin names.
        """
        return list(self.plugins.keys())

# Create plugin manager instance
plugin_manager = PluginManager()
