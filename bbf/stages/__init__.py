"""
Stage implementations for the Bug Bounty Framework.

This package contains the default stage implementations that form the
core execution flow of the framework.
"""

from .base_stage import Stage
from .recon import ReconStage
from .scan import ScanStage
from .test import TestStage
from .report import ReportStage

# For backward compatibility, export Stage as BaseStage
BaseStage = Stage

__all__ = [
    'Stage',
    'BaseStage',  # For backward compatibility
    'ReconStage',
    'ScanStage',
    'TestStage',
    'ReportStage',
]
