"""
Example plugins for testing the Bug Bounty Framework.

This module contains example plugins that can be used for testing purposes.
"""

from bbf.core.plugin import BasePlugin, plugin

@plugin
class SubdomainEnumerationPlugin(BasePlugin):
    """Example plugin for subdomain enumeration."""
    
    name = "subdomain_enumeration"
    description = "Example plugin for enumerating subdomains"
    version = "1.0.0"
    
    def __init__(self, config=None):
        super().__init__(config)
        self.verbose = config.get('verbose', False) if config else False
    
    async def run(self, *args, **kwargs) -> dict:
        """
        Run the subdomain enumeration plugin.
        
        Args:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
            
        Returns:
            Dictionary containing the results of the enumeration
        """
        # Extract target from args or kwargs
        target = args[0] if args else kwargs.get('target', '')
        if not target:
            raise ValueError("Target is required for subdomain enumeration")
            
        return await self.execute(target, **kwargs)
        
    async def execute(self, target: str, **kwargs) -> dict:
        """
        Execute the subdomain enumeration.
        
        Args:
            target: The target domain to enumerate subdomains for
            **kwargs: Additional arguments
            
        Returns:
            Dictionary containing the results of the enumeration
        """
        self.log.info(f"Enumerating subdomains for {target}")
        
        # This is just an example - in a real plugin, this would perform actual enumeration
        example_subdomains = [
            f"www.{target}",
            f"mail.{target}",
            f"api.{target}",
            f"dev.{target}",
        ]
        
        return {
            "status": "completed",
            "target": target,
            "subdomains_found": example_subdomains,
            "count": len(example_subdomains)
        }

@plugin
class PortScanPlugin(BasePlugin):
    """Example plugin for port scanning."""
    
    name = "port_scan"
    description = "Example plugin for port scanning"
    version = "1.0.0"
    depends_on = ["subdomain_enumeration"]
    
    def __init__(self, config=None):
        super().__init__(config)
        self.timeout = config.get('timeout', 5) if config else 5
    
    async def run(self, *args, **kwargs) -> dict:
        """
        Run the port scan plugin.
        
        Args:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
            
        Returns:
            Dictionary containing the results of the port scan
        """
        # Extract target from args or kwargs
        target = args[0] if args else kwargs.get('target', '')
        if not target:
            raise ValueError("Target is required for port scanning")
            
        return await self.execute(target, **kwargs)
        
    async def execute(self, target: str, **kwargs) -> dict:
        """
        Execute a port scan on the target.
        
        Args:
            target: The target host to scan
            **kwargs: Additional arguments
            
        Returns:
            Dictionary containing the results of the port scan
        """
        self.log.info(f"Scanning ports for {target}")
        
        # This is just an example - in a real plugin, this would perform an actual port scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080]
        
        # Simulate finding some open ports
        import random
        open_ports = [port for port in common_ports if random.random() > 0.7]
        
        return {
            "status": "completed",
            "target": target,
            "open_ports": open_ports,
            "port_count": len(open_ports)
        }

# This list makes it easy to import all example plugins
__all__ = ["SubdomainEnumerationPlugin", "PortScanPlugin"]
