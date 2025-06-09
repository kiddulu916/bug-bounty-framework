"""
Reconnaissance stage for the Bug Bounty Framework.

This module implements the ReconStage class which is responsible for
performing reconnaissance on the target to gather information.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Set

from .base_stage import Stage
from ..core.exceptions import StageError

logger = logging.getLogger(__name__)

class ReconStage(Stage):
    """
    Reconnaissance stage for the Bug Bounty Framework.
    
    This stage is responsible for gathering information about the target,
    including subdomains, IP addresses, open ports, and other relevant data.
    """
    
    name = "recon"
    description = "Gather information about the target through passive and active reconnaissance."
    
    # Default plugins for the recon stage
    DEFAULT_PLUGINS = [
        # Passive reconnaissance plugins
        "subdomain_enumeration",
        "dns_enumeration",
        "whois_lookup",
        "certificate_analysis",
        "search_engine_dorking",
        
        # Active reconnaissance plugins
        "port_scanning",
        "service_detection",
        "web_technology_detection",
    ]
    
    def __init__(self, framework):
        """
        Initialize the ReconStage.
        
        Args:
            framework: Reference to the parent framework instance
        """
        super().__init__(framework)
        self.target = None
        self.scope = None
        self.plugins = []
    
    async def initialize(self) -> None:
        """
        Initialize the recon stage.
        
        This method loads the configuration and sets up the target and scope.
        """
        await super().initialize()
        
        # Load configuration
        self.target = self.framework.config.get('target')
        if not self.target:
            raise StageError("No target specified in configuration")
        
        self.scope = self.framework.config.get('scope', {})
        
        # Initialize results structure
        self._results = {
            'target': self.target,
            'scope': self.scope,
            'subdomains': [],
            'ip_addresses': [],
            'ports': [],
            'services': {},
            'technologies': [],
            'vulnerabilities': [],
            'findings': [],
        }
        
        logger.info(f"Initialized recon stage for target: {self.target}")
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the reconnaissance stage.
        
        This method runs all configured recon plugins and aggregates their results.
        
        Args:
            **kwargs: Additional arguments
            
        Returns:
            Dictionary containing the results of the recon stage
        """
        logger.info(f"Starting reconnaissance on target: {self.target}")
        
        # Run all configured plugins
        plugin_results = await self.run_plugins(target=self.target, scope=self.scope)
        
        # Process plugin results
        for plugin_name, result in plugin_results.items():
            if not result.get('success', False):
                self.logger.warning(f"Plugin {plugin_name} failed: {result.get('error')}")
                continue
                
            # Process the plugin's results
            await self._process_plugin_results(plugin_name, result.get('results', {}))
        
        # Perform additional analysis on the collected data
        await self._analyze_results()
        
        logger.info(f"Completed reconnaissance on target: {self.target}")
        logger.info(f"Found {len(self._results['subdomains'])} subdomains")
        logger.info(f"Found {len(self._results['ip_addresses'])} unique IP addresses")
        logger.info(f"Found {len(self._results['ports'])} open ports")
        
        return self._results
    
    async def get_plugins(self) -> List[str]:
        """
        Get the list of plugins to run in this stage.
        
        Returns:
            List of plugin names to run
        """
        # Get plugins from config or use defaults
        plugins = self.framework.config.get('stages', {}).get('recon', {}).get('plugins', self.DEFAULT_PLUGINS)
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
        self._results.setdefault('plugin_results', {})[plugin_name] = results
        
        # Process results based on plugin type
        if plugin_name == 'subdomain_enumeration':
            self._process_subdomains(results.get('subdomains', []))
        elif plugin_name == 'dns_enumeration':
            self._process_dns_records(results.get('records', []))
        elif plugin_name == 'port_scanning':
            self._process_port_scan(results.get('ports', []))
        elif plugin_name == 'service_detection':
            self._process_services(results.get('services', []))
        elif plugin_name == 'web_technology_detection':
            self._process_technologies(results.get('technologies', []))
    
    def _process_subdomains(self, subdomains: List[str]) -> None:
        """
        Process discovered subdomains.
        
        Args:
            subdomains: List of discovered subdomains
        """
        if not subdomains:
            return
            
        # Add new subdomains to the results
        existing = set(self._results['subdomains'])
        new_subdomains = [s for s in subdomains if s not in existing]
        
        if new_subdomains:
            self._results['subdomains'].extend(new_subdomains)
            self.logger.info(f"Discovered {len(new_subdomains)} new subdomains")
    
    def _process_dns_records(self, records: List[Dict[str, Any]]) -> None:
        """
        Process DNS records.
        
        Args:
            records: List of DNS records
        """
        if not records:
            return
            
        # Store DNS records
        self._results.setdefault('dns_records', []).extend(records)
        
        # Extract IP addresses
        ip_addresses = set()
        for record in records:
            if record.get('type') in ('A', 'AAAA') and record.get('data'):
                ip_addresses.add(record['data'])
        
        # Add new IP addresses to the results
        existing_ips = set(self._results['ip_addresses'])
        new_ips = [ip for ip in ip_addresses if ip not in existing_ips]
        
        if new_ips:
            self._results['ip_addresses'].extend(new_ips)
            self.logger.info(f"Discovered {len(new_ips)} new IP addresses")
    
    def _process_port_scan(self, ports: List[Dict[str, Any]]) -> None:
        """
        Process port scan results.
        
        Args:
            ports: List of open ports
        """
        if not ports:
            return
            
        # Store port information
        existing_ports = {(p.get('port'), p.get('protocol')) for p in self._results['ports']}
        
        for port in ports:
            port_key = (port.get('port'), port.get('protocol'))
            if port_key not in existing_ports:
                self._results['ports'].append(port)
    
    def _process_services(self, services: List[Dict[str, Any]]) -> None:
        """
        Process service detection results.
        
        Args:
            services: List of detected services
        """
        if not services:
            return
            
        # Store service information
        for service in services:
            port_key = f"{service.get('port')}/{service.get('protocol', 'tcp')}"
            self._results['services'][port_key] = service
    
    def _process_technologies(self, technologies: List[Dict[str, Any]]) -> None:
        """
        Process technology detection results.
        
        Args:
            technologies: List of detected technologies
        """
        if not technologies:
            return
            
        # Store technology information
        existing_tech = {(t.get('name'), t.get('version')) for t in self._results['technologies']}
        
        for tech in technologies:
            tech_key = (tech.get('name'), tech.get('version'))
            if tech_key not in existing_tech:
                self._results['technologies'].append(tech)
    
    async def _analyze_results(self) -> None:
        """
        Perform additional analysis on the collected data.
        """
        # Look for potential issues based on the collected data
        findings = []
        
        # Check for common misconfigurations
        if '80/tcp' in self._results['services'] and '443/tcp' not in self._results['services']:
            findings.append({
                'type': 'misconfiguration',
                'severity': 'medium',
                'title': 'HTTP without HTTPS',
                'description': 'The server is only accessible via HTTP, not HTTPS',
                'remediation': 'Configure HTTPS with a valid certificate',
            })
        
        # Check for outdated technologies
        for tech in self._results['technologies']:
            if tech.get('outdated', False):
                findings.append({
                    'type': 'outdated_software',
                    'severity': 'high',
                    'title': f"Outdated {tech.get('name')} version",
                    'description': f"{tech.get('name')} version {tech.get('version')} is outdated",
                    'remediation': f'Upgrade {tech.get("name")} to the latest version',
                })
        
        # Add findings to results
        if findings:
            self._results['findings'].extend(findings)
            self.logger.warning(f"Found {len(findings)} potential issues")
    
    async def cleanup(self) -> None:
        """
        Clean up resources used by the recon stage.
        """
        await super().cleanup()
        
        # Save results to the framework state
        self.framework.state.set_global('recon_results', self._results)
