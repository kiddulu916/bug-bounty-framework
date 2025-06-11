"""
Bug Bounty Framework (BBF)

A modular, extensible framework for automating bug bounty and security testing workflows.

BBF is designed to help security researchers and bug bounty hunters automate the process
of discovering and validating security vulnerabilities in web applications and networks.

Key Features:
- Modular plugin architecture
- Asynchronous execution
- Stage-based workflow (Recon, Scan, Test, Report)
- Extensible design for custom plugins
- Comprehensive error handling and logging
- State management for long-running scans
- Parallel execution of plugins
- Configuration management
- Report generation

Example Usage:
    ```python
    from bbf import BFFramework, load_config
    
    # Load configuration from file
    config = load_config("config.yaml")
    
    # Initialize the framework
    framework = BFFramework(config)
    
    # Run the framework
    import asyncio
    asyncio.run(framework.run())
    ```
"""

__version__ = "0.1.0"
__author__ = "Corey Hilsenbeck <cor.hils@gmail.com>"
__license__ = "MIT"
__url__ = "https://github.com/kiddulu/bug-bounty-framework"
__description__ = "A modular, extensible framework for bug bounty and security testing"

# Import core components for easier access
from bbf.core.framework import BFFramework
from bbf.core.config import load_config
from bbf.core.base import BasePlugin
from bbf.core.state import StateManager

# Import stages
from bbf.stages import (
    Stage,  # BaseStage is an alias for Stage
    ReconStage,
    ScanStage,
    TestStage,
    ReportStage
)

# Make commonly used classes available at package level
__all__ = [
    'BFFramework',
    'load_config',
    'BasePlugin',
    'StateManager',
    'Stage',  # Exported as Stage, not BaseStage
    'ReconStage',
    'ScanStage',
    'TestStage',
    'ReportStage',
]
