"""
Test stage for the Bug Bounty Framework.

This module implements the TestStage class which is responsible for
validating potential vulnerabilities found during the scanning phase.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Set

from .base_stage import Stage
from ..core.exceptions import StageError

logger = logging.getLogger(__name__)

class TestStage(Stage):
    """
    Test stage for the Bug Bounty Framework.
    
    This stage is responsible for validating potential vulnerabilities
    found during the scanning phase through controlled exploitation
    and proof-of-concept testing.
    """
    
    name = "test"
    description = "Validate potential vulnerabilities through controlled testing."
    
    # Default plugins for the test stage
    DEFAULT_PLUGINS = [
        # Web application testing
        "sql_injection_tester",
        "xss_tester",
        "command_injection_tester",
        "lfi_tester",
        "rce_tester",
        "ssrf_tester",
        "xxe_tester",
        "deserialization_tester",
        "jwt_vulnerability_tester",
        "graphql_injection_tester",
        
        # Authentication testing
        "auth_bypass_tester",
        "bruteforce_tester",
        "session_management_tester",
        "otp_bypass_tester",
        "oauth_vulnerability_tester",
        
        # Business logic testing
        "business_logic_tester",
        "privilege_escalation_tester",
        "access_control_tester",
    ]
    
    def __init__(self, framework):
        """
        Initialize the TestStage.
        
        Args:
            framework: Reference to the parent framework instance
        """
        super().__init__(framework)
        self.target = None
        self.scope = None
        self.scan_data = {}
        self.recon_data = {}
    
    async def initialize(self) -> None:
        """
        Initialize the test stage.
        
        This method loads the configuration and sets up the target and scope.
        """
        await super().initialize()
        
        # Load configuration
        self.target = self.framework.config.get('target')
        if not self.target:
            raise StageError("No target specified in configuration")
        
        self.scope = self.framework.config.get('scope', {})
        
        # Get data from previous stages
        self.recon_data = self.framework.state.get_global('recon_results', {})
        self.scan_data = self.framework.state.get_global('scan_results', {})
        
        if not self.scan_data:
            logger.warning("No scan data found. Testing will be limited.")
        
        # Initialize results structure
        self._results = {
            'target': self.target,
            'scope': self.scope,
            'confirmed_vulnerabilities': [],
            'false_positives': [],
            'inconclusive': [],
            'findings': [],
            'tests': {},
        }
        
        logger.info(f"Initialized test stage for target: {self.target}")
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the test stage.
        
        This method runs all configured test plugins to validate potential
        vulnerabilities found during the scanning phase.
        
        Args:
            **kwargs: Additional arguments
            
        Returns:
            Dictionary containing the results of the test stage
        """
        logger.info(f"Starting vulnerability testing on target: {self.target}")
        
        # Get potential vulnerabilities from scan results
        potential_vulns = self.scan_data.get('vulnerabilities', [])
        
        if not potential_vulns:
            logger.warning("No potential vulnerabilities found to test")
            return self._results
        
        # Group vulnerabilities by type for more efficient testing
        vulns_by_type = self._group_vulnerabilities_by_type(potential_vulns)
        
        # Run appropriate testers for each vulnerability type
        for vuln_type, vulns in vulns_by_type.items():
            tester_name = f"{vuln_type}_tester"
            
            # Skip if we don't have a tester for this vulnerability type
            if tester_name not in self.DEFAULT_PLUGINS:
                logger.warning(f"No tester available for vulnerability type: {vuln_type}")
                self._results['inconclusive'].extend(vulns)
                continue
            
            # Run the tester plugin
            try:
                result = await self._run_tester(tester_name, vulns)
                self._results['tests'][tester_name] = result
                
                # Process the results
                await self._process_tester_results(tester_name, result, vulns)
                
            except Exception as e:
                logger.error(f"Tester {tester_name} failed: {e}", exc_info=True)
                self._results['inconclusive'].extend(vulns)
        
        # Generate summary
        await self._generate_summary()
        
        logger.info(f"Completed vulnerability testing on target: {self.target}")
        logger.info(f"Confirmed {len(self._results['confirmed_vulnerabilities'])} vulnerabilities")
        logger.info(f"Marked {len(self._results['false_positives'])} as false positives")
        logger.info(f"{len(self._results['inconclusive'])} tests were inconclusive")
        
        return self._results
    
    def _group_vulnerabilities_by_type(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group vulnerabilities by their type.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Dictionary mapping vulnerability types to lists of vulnerabilities
        """
        vulns_by_type = {}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown').lower()
            if vuln_type not in vulns_by_type:
                vulns_by_type[vuln_type] = []
            vulns_by_type[vuln_type].append(vuln)
        
        return vulns_by_type
    
    async def _run_tester(self, tester_name: str, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Run a specific tester plugin.
        
        Args:
            tester_name: Name of the tester plugin to run
            vulnerabilities: List of vulnerabilities to test
            
        Returns:
            Dictionary containing the test results
        """
        logger.info(f"Running {tester_name} on {len(vulnerabilities)} potential vulnerabilities")
        
        # Create test context
        context = {
            'target': self.target,
            'vulnerabilities': vulnerabilities,
            'recon_data': self.recon_data,
            'scan_data': self.scan_data,
        }
        
        # Run the tester plugin
        plugin_results = await self.run_plugins(
            plugins=[tester_name],
            context=context
        )
        
        return plugin_results.get(tester_name, {})
    
    async def _process_tester_results(
        self,
        tester_name: str,
        result: Dict[str, Any],
        original_vulns: List[Dict[str, Any]]
    ) -> None:
        """
        Process the results from a tester plugin.
        
        Args:
            tester_name: Name of the tester plugin
            result: Results from the tester plugin
            original_vulns: Original vulnerabilities that were tested
        """
        if not result.get('success', False):
            logger.error(f"Tester {tester_name} failed: {result.get('error')}")
            self._results['inconclusive'].extend(original_vulns)
            return
        
        # Extract test results
        test_results = result.get('results', {})
        confirmed = test_results.get('confirmed', [])
        false_positives = test_results.get('false_positives', [])
        inconclusive = test_results.get('inconclusive', [])
        
        # Update results
        self._results['confirmed_vulnerabilities'].extend(confirmed)
        self._results['false_positives'].extend(false_positives)
        self._results['inconclusive'].extend(inconclusive)
        
        # Log summary
        logger.info(
            f"{tester_name} results: {len(confirmed)} confirmed, "
            f"{len(false_positives)} false positives, "
            f"{len(inconclusive)} inconclusive"
        )
    
    async def _generate_summary(self) -> None:
        """Generate a summary of the test results."""
        # Categorize confirmed vulnerabilities by severity
        severity_counts = {}
        for vuln in self._results['confirmed_vulnerabilities']:
            severity = vuln.get('severity', 'info').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Add summary to results
        self._results['summary'] = {
            'total_confirmed': len(self._results['confirmed_vulnerabilities']),
            'total_false_positives': len(self._results['false_positives']),
            'total_inconclusive': len(self._results['inconclusive']),
            'severity_counts': severity_counts,
        }
    
    async def cleanup(self) -> None:
        """
        Clean up resources used by the test stage.
        """
        await super().cleanup()
        
        # Save results to the framework state
        self.framework.state.set_global('test_results', self._results)
