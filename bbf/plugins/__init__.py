"""
Plugins package for the Bug Bounty Framework.

This package contains all the plugins that can be used by the framework.
Plugins are organized by the stage they belong to.

Example plugins are provided in the example_plugins module for testing and
reference purposes. These can be used as templates for creating custom plugins.
"""

from .base_plugin import BasePlugin
from .example_plugins import (
    SubdomainEnumerationPlugin,
    PortScanPlugin,
)

# Export base plugin and example plugins
__all__ = [
    'BasePlugin',
    'SubdomainEnumerationPlugin',
    'PortScanPlugin',
]
