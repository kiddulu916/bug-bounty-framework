"""
Scan stage for the Bug Bounty Framework.

This module implements the ScanStage class which is responsible for
performing vulnerability scanning on the target based on the information
gathered during the reconnaissance phase.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Set

from .base_stage import Stage
from ..core.exceptions import StageError

logger = logging.getLogger(__name__)

class ScanStage(Stage):
    """
    Scan stage for the Bug Bounty Framework.
    
    This stage is responsible for performing vulnerability scanning on the target
    based on the information gathered during the reconnaissance phase.
    """
    
    name = "scan"
    description = "Perform vulnerability scanning on the target."
    
    # Default plugins for the scan stage
    DEFAULT_PLUGINS = [
        # Web application scanning
        "web_vulnerability_scanner",
        "api_scanning",
        "cors_misconfiguration",
        "csrf_scanning",
        "ssrf_scanning",
        "xxe_scanning",
        "insecure_direct_object_reference",
        "security_headers_analysis",
        "ssl_tls_scanning",
        "content_security_policy_analysis",
        
        # Infrastructure scanning
        "nmap_vuln_scan",
        "heartbleed_scan",
        "shellshock_scan",
        "poodle_scan",
        "drown_scan",
        "sweet32_scan",
        "log4j_scan",
        "spring4shell_scan",
        "zero_logon_scan",
        "eternal_blue_scan",
    ]
    
    def __init__(self, framework):
        """
        Initialize the ScanStage.
        
        Args:
            framework: Reference to the parent framework instance
        """
        super().__init__(framework)
        self.target = None
        self.scope = None
        self.recon_data = {}
    
    async def initialize(self) -> None:
        """
        Initialize the scan stage.
        
        This method loads the configuration and sets up the target and scope.
        """
        await super().initialize()
        
        # Load configuration
        self.target = self.framework.config.get('target')
        if not self.target:
            raise StageError("No target specified in configuration")
        
        self.scope = self.framework.config.get('scope', {})
        
        # Get recon data from previous stage
        self.recon_data = self.framework.state.get_global('recon_results', {})
        if not self.recon_data:
            logger.warning("No reconnaissance data found. Some scans may be limited.")
        
        # Initialize results structure
        self._results = {
            'target': self.target,
            'scope': self.scope,
            'vulnerabilities': [],
            'findings': [],
            'scans': {},
        }
        
        logger.info(f"Initialized scan stage for target: {self.target}")
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the scan stage.
        
        This method runs all configured scan plugins and aggregates their results.
        
        Args:
            **kwargs: Additional arguments
            
        Returns:
            Dictionary containing the results of the scan stage
        """
        logger.info(f"Starting vulnerability scanning on target: {self.target}")
        
        # Run all configured plugins
        plugin_results = await self.run_plugins(
            target=self.target,
            scope=self.scope,
            recon_data=self.recon_data
        )
        
        # Process plugin results
        for plugin_name, result in plugin_results.items():
            if not result.get('success', False):
                self.logger.warning(f"Plugin {plugin_name} failed: {result.get('error')}")
                continue
                
            # Process the plugin's results
            await self._process_plugin_results(plugin_name, result.get('results', {}))
        
        # Perform additional analysis on the collected data
        await self._analyze_results()
        
        logger.info(f"Completed vulnerability scanning on target: {self.target}")
        logger.info(f"Found {len(self._results['vulnerabilities'])} potential vulnerabilities")
        
        return self._results
    
    async def get_plugins(self) -> List[str]:
        """
        Get the list of plugins to run in this stage.
        
        Returns:
            List of plugin names to run
        """
        # Get plugins from config or use defaults
        plugins = self.framework.config.get('stages', {}).get('scan', {}).get('plugins', self.DEFAULT_PLUGINS)
        return [p for p in plugins if p in self.DEFAULT_PLUGINS]  # Filter to only allow known plugins
    
    async def _process_plugin_results(self, plugin_name: str, results: Dict[str, Any]) -> None:
        """
        Process the results from a plugin.
        
        Args:
            plugin_name: Name of the plugin that produced the results
            results: The results from the plugin
        """
        if not results:
            return
            
        # Store the raw results
        self._results['scans'][plugin_name] = results
        
        # Extract vulnerabilities if any
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            self._results['vulnerabilities'].extend(vulnerabilities)
            logger.info(f"Plugin {plugin_name} found {len(vulnerabilities)} potential vulnerabilities")
    
    async def _analyze_results(self) -> None:
        """
        Perform additional analysis on the collected data.
        """
        # Categorize vulnerabilities by severity
        severity_counts = {}
        for vuln in self._results['vulnerabilities']:
            severity = vuln.get('severity', 'info').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Add summary to results
        self._results['summary'] = {
            'total_vulnerabilities': len(self._results['vulnerabilities']),
            'severity_counts': severity_counts,
        }
        
        # Log summary
        logger.info(f"Scan completed. Found {len(self._results['vulnerabilities'])} potential vulnerabilities:")
        for severity, count in severity_counts.items():
            logger.info(f"  - {severity.upper()}: {count}")
    
    async def cleanup(self) -> None:
        """
        Clean up resources used by the scan stage.
        """
        await super().cleanup()
        
        # Save results to the framework state
        self.framework.state.set_global('scan_results', self._results)
