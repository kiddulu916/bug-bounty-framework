"""
Command-line interface for the Bug Bounty Framework.

This module provides a command-line interface for running the framework.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any

from bbf.core.framework import BFFramework
from bbf.core.config import load_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
    ]
)

logger = logging.getLogger("bbf.cli")

class CLI:
    """Command-line interface for the Bug Bounty Framework."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """
        Create the argument parser.
        
        Returns:
            Configured argument parser
        """
        parser = argparse.ArgumentParser(
            description='Bug Bounty Framework - A modular framework for bug bounty and security testing',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        # Global options
        parser.add_argument(
            '-c', '--config',
            type=str,
            help='Path to configuration file (YAML)'
        )
        
        parser.add_argument(
            '-t', '--target',
            type=str,
            help='Target to scan (overrides config file)'
        )
        
        parser.add_argument(
            '-o', '--output-dir',
            type=str,
            help='Output directory for reports (overrides config file)'
        )
        
        parser.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
        
        parser.add_argument(
            '--log-file',
            type=str,
            help='Log file path (overrides config file)'
        )
        
        # Stage selection
        stage_group = parser.add_argument_group('Stage Selection')
        stage_group.add_argument(
            '--recon',
            action='store_true',
            help='Run only the reconnaissance stage'
        )
        
        stage_group.add_argument(
            '--scan',
            action='store_true',
            help='Run only the scanning stage'
        )
        
        stage_group.add_argument(
            '--test',
            action='store_true',
            help='Run only the testing stage'
        )
        
        stage_group.add_argument(
            '--report',
            action='store_true',
            help='Run only the reporting stage'
        )
        
        # Plugin options
        plugin_group = parser.add_argument_group('Plugin Options')
        plugin_group.add_argument(
            '--list-plugins',
            action='store_true',
            help='List all available plugins and exit'
        )
        
        # Output options
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument(
            '--json',
            action='store_true',
            help='Output results in JSON format'
        )
        
        output_group.add_argument(
            '--no-save',
            action='store_true',
            help='Do not save results to disk'
        )
        
        # Advanced options
        advanced_group = parser.add_argument_group('Advanced Options')
        advanced_group.add_argument(
            '--max-workers',
            type=int,
            help='Maximum number of worker threads'
        )
        
        advanced_group.add_argument(
            '--state-file',
            type=str,
            help='Path to state file'
        )
        
        return parser
    
    def parse_args(self, args=None):
        """
        Parse command-line arguments.
        
        Args:
            args: Arguments to parse (default: sys.argv[1:])
            
        Returns:
            Parsed arguments
        """
        return self.parser.parse_args(args)
    
    def _setup_logging(self, args, config: Dict[str, Any]) -> None:
        """
        Set up logging based on command-line arguments and configuration.
        
        Args:
            args: Parsed command-line arguments
            config: Configuration dictionary
        """
        # Set log level
        log_level = logging.INFO
        if args.verbose:
            log_level = logging.DEBUG
        elif 'log_level' in config:
            log_level = getattr(logging, config['log_level'].upper(), logging.INFO)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        
        # Add file handler if specified
        log_file = args.log_file or config.get('log_file')
        if log_file and not args.no_save:
            os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
    
    def _get_enabled_stages(self, args) -> Dict[str, bool]:
        """
        Determine which stages to enable based on command-line arguments.
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Dictionary mapping stage names to enabled/disabled status
        """
        # If no stage flags are set, enable all stages
        if not any([args.recon, args.scan, args.test, args.report]):
            return {
                'recon': True,
                'scan': True,
                'test': True,
                'report': True
            }
        
        # Otherwise, only enable the specified stages
        return {
            'recon': args.recon,
            'scan': args.scan,
            'test': args.test,
            'report': args.report or args.recon or args.scan or args.test
        }
    
    async def run(self, args=None) -> int:
        """
        Run the CLI.
        
        Args:
            args: Command-line arguments (default: sys.argv[1:])
            
        Returns:
            Exit code
        """
        # Parse command-line arguments
        args = self.parse_args(args)
        
        # Load configuration
        try:
            config = self._load_config(args)
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return 1
        
        # Set up logging
        self._setup_logging(args, config)
        
        # List plugins and exit if requested
        if args.list_plugins:
            await self._list_plugins()
            return 0
        
        # Create output directory
        output_dir = args.output_dir or config.get('output_dir', 'reports')
        if not args.no_save:
            os.makedirs(output_dir, exist_ok=True)
        
        # Determine which stages to run
        enabled_stages = self._get_enabled_stages(args)
        
        # Initialize the framework
        try:
            framework = BFFramework(config)
            await framework.initialize()
            
            logger.info("Starting Bug Bounty Framework")
            logger.info(f"Target: {config.get('target')}")
            
            # Run the enabled stages
            results = {}
            
            if enabled_stages['recon']:
                logger.info("\n=== Starting Reconnaissance Stage ===")
                results['recon'] = await framework.run_stage('recon')
            
            if enabled_stages['scan']:
                logger.info("\n=== Starting Scanning Stage ===")
                results['scan'] = await framework.run_stage('scan')
            
            if enabled_stages['test']:
                logger.info("\n=== Starting Testing Stage ===")
                results['test'] = await framework.run_stage('test')
            
            if enabled_stages['report']:
                logger.info("\n=== Generating Report ===")
                report_results = await framework.run_stage('report')
                if report_results:
                    results['report'] = report_results
            
            # Output results
            if args.json:
                print(json.dumps(results, indent=2, default=str))
            
            logger.info("\nScan completed successfully!")
            return 0
            
        except KeyboardInterrupt:
            logger.warning("\nScan interrupted by user")
            return 130  # SIGINT
        except Exception as e:
            logger.error(f"An error occurred: {e}", exc_info=args.verbose)
            return 1
        finally:
            if 'framework' in locals():
                await framework.close()
    
    def _load_config(self, args) -> Dict[str, Any]:
        """
        Load configuration from file and command-line arguments.
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Merged configuration dictionary
        """
        # Start with default configuration
        config = {}
        
        # Load from config file if specified
        if args.config:
            try:
                config_manager = load_config(args.config)
                config = config_manager.to_dict()
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")
        
        # Override with command-line arguments
        if args.target:
            config['target'] = args.target
        
        if args.output_dir:
            config['output_dir'] = args.output_dir
        
        if args.max_workers is not None:
            config['max_workers'] = args.max_workers
        
        if args.state_file:
            config['state_file'] = args.state_file
        
        # Ensure required configuration is present
        if 'target' not in config or not config['target']:
            raise ValueError("No target specified. Use --target or specify in config file.")
        
        return config
    
    async def _list_plugins(self) -> None:
        """List all available plugins."""
        from bbf.core.plugin import get_plugins
        
        plugins = get_plugins()
        
        if not plugins:
            print("No plugins found.")
            return
        
        print("\nAvailable Plugins:")
        print("==================")
        
        for name, plugin_class in sorted(plugins.items()):
            print(f"\n{name}:")
            print(f"  Description: {getattr(plugin_class, 'description', 'No description')}")
            print(f"  Version: {getattr(plugin_class, 'version', 'Unknown')}")
            
            # Print default config if available
            default_config = getattr(plugin_class, 'DEFAULT_CONFIG', None)
            if default_config:
                print("  Default Configuration:")
                for key, value in default_config.items():
                    print(f"    {key}: {value}")

def main():
    """Entry point for the CLI."""
    cli = CLI()
    sys.exit(asyncio.run(cli.run()))

if __name__ == "__main__":
    main()
