"""
Report stage for the Bug Bounty Framework.

This module implements the ReportStage class which is responsible for
generating comprehensive reports from the findings of previous stages.
"""

import asyncio
import logging
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

from .base_stage import Stage
from ..core.exceptions import StageError

logger = logging.getLogger(__name__)

class ReportStage(Stage):
    """
    Report stage for the Bug Bounty Framework.
    
    This stage is responsible for generating comprehensive reports
    from the findings of the previous stages (Recon, Scan, Test).
    """
    
    name = "report"
    description = "Generate comprehensive reports from the findings."
    
    # Default plugins for the report stage
    DEFAULT_PLUGINS = [
        "html_report_generator",
        "markdown_report_generator",
        "json_report_generator",
        "pdf_report_generator",
        "jira_integration",
        "defect_dojo_integration",
    ]
    
    def __init__(self, framework):
        """
        Initialize the ReportStage.
        
        Args:
            framework: Reference to the parent framework instance
        """
        super().__init__(framework)
        self.target = None
        self.scope = {}
        self.recon_data = {}
        self.scan_data = {}
        self.test_data = {}
        self.output_dir = None
    
    async def initialize(self) -> None:
        """
        Initialize the report stage.
        
        This method loads the configuration and sets up the output directory.
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
        self.test_data = self.framework.state.get_global('test_results', {})
        
        # Set up output directory
        self.output_dir = Path(self.framework.config.get('output_dir', 'reports'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize results structure
        self._results = {
            'target': self.target,
            'scope': self.scope,
            'report_files': [],
            'generated_at': datetime.utcnow().isoformat(),
        }
        
        logger.info(f"Initialized report stage for target: {self.target}")
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the report stage.
        
        This method runs all configured report generators and integrations.
        
        Args:
            **kwargs: Additional arguments
            
        Returns:
            Dictionary containing the results of the report stage
        """
        logger.info(f"Generating reports for target: {self.target}")
        
        # Prepare report data
        report_data = self._prepare_report_data()
        
        # Run all configured report generators
        plugin_results = await self.run_plugins(
            report_data=report_data,
            output_dir=str(self.output_dir.absolute()),
            target=self.target
        )
        
        # Process plugin results
        for plugin_name, result in plugin_results.items():
            if not result.get('success', False):
                logger.warning(f"Report plugin {plugin_name} failed: {result.get('error')}")
                continue
                
            # Process the plugin's results
            self._process_plugin_results(plugin_name, result.get('results', {}))
        
        # Generate a summary
        await self._generate_summary()
        
        logger.info(f"Report generation complete. Reports saved to: {self.output_dir}")
        
        return self._results
    
    def _prepare_report_data(self) -> Dict[str, Any]:
        """
        Prepare the data to be included in the reports.
        
        Returns:
            Dictionary containing all the data to be included in the reports
        """
        return {
            'metadata': {
                'target': self.target,
                'scope': self.scope,
                'generated_at': self._results['generated_at'],
                'framework_version': self.framework.config.get('version', '1.0.0'),
            },
            'execution': {
                'start_time': self.framework.state.get_global('start_time'),
                'end_time': datetime.utcnow().isoformat(),
                'stages_completed': self.framework.state.get_global('completed_stages', []),
            },
            'recon': self.recon_data,
            'scan': self.scan_data,
            'test': self.test_data,
        }
    
    def _process_plugin_results(self, plugin_name: str, results: Dict[str, Any]) -> None:
        """
        Process the results from a report plugin.
        
        Args:
            plugin_name: Name of the plugin that produced the results
            results: The results from the plugin
        """
        if not results:
            return
        
        # Store the raw results
        self._results.setdefault('plugin_results', {})[plugin_name] = results
        
        # Extract generated report files
        report_files = results.get('report_files', [])
        if report_files:
            self._results['report_files'].extend(report_files)
            
            # Log the generated files
            for file_path in report_files:
                file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                logger.info(f"Generated report: {file_path} ({self._format_file_size(file_size)})")
    
    async def _generate_summary(self) -> None:
        """Generate a summary of the report generation."""
        # Count vulnerabilities by severity
        vuln_summary = {}
        if 'test' in self.test_data and 'confirmed_vulnerabilities' in self.test_data['test']:
            for vuln in self.test_data['test']['confirmed_vulnerabilities']:
                severity = vuln.get('severity', 'info').lower()
                vuln_summary[severity] = vuln_summary.get(severity, 0) + 1
        
        # Add summary to results
        self._results['summary'] = {
            'total_reports': len(self._results.get('report_files', [])),
            'vulnerabilities': vuln_summary,
            'report_files': [str(f) for f in self._results.get('report_files', [])],
        }
        
        # Log summary
        logger.info("\n" + "=" * 80)
        logger.info("REPORT SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Target: {self.target}")
        logger.info(f"Reports generated: {len(self._results.get('report_files', []))}")
        
        if vuln_summary:
            logger.info("\nVulnerabilities found:")
            for severity, count in sorted(vuln_summary.items(), key=lambda x: x[0], reverse=True):
                logger.info(f"  - {severity.upper()}: {count}")
        
        logger.info("\nGenerated report files:")
        for file_path in self._results.get('report_files', []):
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            logger.info(f"  - {file_path} ({self._format_file_size(file_size)})")
        
        logger.info("=" * 80 + "\n")
    
    @staticmethod
    def _format_file_size(size_bytes: int) -> str:
        """
        Format a file size in a human-readable format.
        
        Args:
            size_bytes: File size in bytes
            
        Returns:
            Formatted file size string (e.g., "1.5 MB")
        """
        if size_bytes < 1024:
            return f"{size_bytes} B"
        
        for unit in ['KB', 'MB', 'GB', 'TB']:
            size_bytes /= 1024
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
        
        return f"{size_bytes:.1f} PB"
    
    async def cleanup(self) -> None:
        """
        Clean up resources used by the report stage.
        """
        await super().cleanup()
        
        # Save results to the framework state
        self.framework.state.set_global('report_results', self._results)
        
        # Save a JSON version of the full report
        report_file = self.output_dir / f"full_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(self._results, f, indent=2)
        
        logger.info(f"Full report saved to: {report_file}")
