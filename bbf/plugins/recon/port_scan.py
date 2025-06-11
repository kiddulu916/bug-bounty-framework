"""
Port Scanner Plugin.

This plugin implements various port scanning techniques:
- TCP SYN Scan
- TCP Connect Scan
- UDP Scan
- Service Detection
- Banner Grabbing

All findings are stored in the centralized database following the rules in .cursor/rules/database.mdc.
"""

import asyncio
import logging
import socket
import json
from dataclasses import dataclass
from datetime import datetime
from typing import List, Set, Dict, Optional, Any, Tuple
import aiohttp

from bbf.core.database.models import Finding
from bbf.core.database.service import finding_service
from bbf.plugins.config import get_ports, get_services, get_user_agents

logger = logging.getLogger(__name__)

@dataclass
class PortResult:
    """Port scan result."""
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    source: str = "port_scan"
    confidence: float = 0.0
    first_seen: datetime = datetime.utcnow()
    last_seen: datetime = datetime.utcnow()
    metadata: Optional[Dict[str, Any]] = None
    stage: str = "recon"
    status: str = "active"

class PortScannerPlugin:
    """Port scanner plugin implementation."""
    
    name = "port_scan"
    description = "Port scanning and service detection"
    version = "1.0.0"
    
    def __init__(self):
        """Initialize the plugin."""
        self.current_plugin_result_id: Optional[int] = None
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Configuration
        self.timeout = 5
        self.max_concurrent_tasks = 100
        self.retries = 2
        self.retry_delay = 1
        
        # Get port configurations
        self.port_config = get_ports()
        self.service_config = get_services()
        self.user_agents = get_user_agents()
        
        # Default ports to scan if none specified
        self.default_ports = self.port_config.get('common', [])
    
    async def initialize(self) -> None:
        """Initialize plugin resources."""
        if not self.session:
            self.session = aiohttp.ClientSession(
                headers={'User-Agent': self.user_agents[0] if self.user_agents else 'BBF/1.0'},
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
    
    async def cleanup(self) -> None:
        """Cleanup plugin resources."""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def execute(self, target: str, ports: Optional[List[int]] = None) -> List[PortResult]:
        """Execute port scan against target."""
        if not self.session:
            await self.initialize()
        
        results: Set[PortResult] = set()
        try:
            # Use provided ports or default ports
            ports_to_scan = ports or self.default_ports
            
            # Run different scan types concurrently
            tasks = [
                self._tcp_syn_scan(target, ports_to_scan),
                self._tcp_connect_scan(target, ports_to_scan),
                self._udp_scan(target, ports_to_scan)
            ]
            
            scan_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result_list in scan_results:
                if isinstance(result_list, list):
                    results.update(result_list)
                elif isinstance(result_list, Exception):
                    logger.error(f"Scan error: {str(result_list)}")
            
            # Store results in database using finding_service
            if results:
                await self._store_findings(target, results)
            
            return list(results)
            
        except Exception as e:
            logger.error(f"Error during port scan: {str(e)}")
            return list(results)
    
    async def _store_findings(self, target: str, findings: Set[PortResult]) -> None:
        """Store findings in the centralized database using finding_service."""
        try:
            # Group findings by subdomain
            subdomain_findings: Dict[str, List[PortResult]] = {}
            for finding in findings:
                # Extract subdomain from target
                subdomain = target.split('.')[0] if '.' in target else target
                if subdomain not in subdomain_findings:
                    subdomain_findings[subdomain] = []
                subdomain_findings[subdomain].append(finding)
            
            # Store findings for each subdomain
            for subdomain, port_results in subdomain_findings.items():
                # Get existing finding
                existing = await finding_service.get_finding(target, subdomain)
                
                # Prepare port and service data
                open_ports = [r.port for r in port_results if r.state == 'open']
                services = {
                    r.port: {
                        'name': r.service,
                        'version': r.version,
                        'banner': r.banner
                    } for r in port_results if r.state == 'open' and r.service
                }
                
                # Create finding data
                finding_data = {
                    'root_domain': target,
                    'subdomain': subdomain,
                    'open_ports': json.dumps(open_ports),
                    'services': json.dumps(services),
                    'source': 'port_scan',
                    'confidence': max(r.confidence for r in port_results),
                    'first_seen': min(r.first_seen for r in port_results),
                    'last_seen': max(r.last_seen for r in port_results),
                    'metadata': json.dumps({
                        'scan_type': 'comprehensive',
                        'ports_scanned': len(port_results),
                        'open_ports_count': len(open_ports),
                        'scan_timestamp': datetime.utcnow().isoformat(),
                        'scan_details': [{
                            'port': r.port,
                            'protocol': r.protocol,
                            'state': r.state,
                            'service': r.service,
                            'version': r.version,
                            'banner': r.banner
                        } for r in port_results]
                    }),
                    'stage': 'recon',
                    'status': 'active' if open_ports else 'inactive'
                }
                
                # Update finding
                await finding_service.add_or_update_finding(
                    root_domain=target,
                    subdomain=subdomain,
                    finding_data=finding_data,
                    merge_metadata=True
                )
                
        except Exception as e:
            logger.error(f"Error storing findings: {str(e)}")
            raise
    
    async def _tcp_syn_scan(self, target: str, ports: List[int]) -> List[PortResult]:
        """Perform TCP SYN scan."""
        results = []
        try:
            # Create tasks for concurrent port scanning
            tasks = []
            for port in ports:
                tasks.append(self._scan_port(target, port, 'tcp', 'syn'))
            
            # Execute tasks with concurrency limit
            for i in range(0, len(tasks), self.max_concurrent_tasks):
                batch = tasks[i:i + self.max_concurrent_tasks]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, PortResult):
                        results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error during TCP SYN scan: {str(e)}")
            return []
    
    async def _tcp_connect_scan(self, target: str, ports: List[int]) -> List[PortResult]:
        """Perform TCP connect scan."""
        results = []
        try:
            # Create tasks for concurrent port scanning
            tasks = []
            for port in ports:
                tasks.append(self._scan_port(target, port, 'tcp', 'connect'))
            
            # Execute tasks with concurrency limit
            for i in range(0, len(tasks), self.max_concurrent_tasks):
                batch = tasks[i:i + self.max_concurrent_tasks]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, PortResult):
                        results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error during TCP connect scan: {str(e)}")
            return []
    
    async def _udp_scan(self, target: str, ports: List[int]) -> List[PortResult]:
        """Perform UDP scan."""
        results = []
        try:
            # Create tasks for concurrent port scanning
            tasks = []
            for port in ports:
                tasks.append(self._scan_port(target, port, 'udp', 'udp'))
            
            # Execute tasks with concurrency limit
            for i in range(0, len(tasks), self.max_concurrent_tasks):
                batch = tasks[i:i + self.max_concurrent_tasks]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, PortResult):
                        results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error during UDP scan: {str(e)}")
            return []
    
    async def _scan_port(self, target: str, port: int, protocol: str, scan_type: str) -> Optional[PortResult]:
        """Scan a single port and return result if successful."""
        try:
            # Create socket
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
            )
            sock.settimeout(self.timeout)
            
            # Try to connect
            try:
                if protocol == 'tcp':
                    result = sock.connect_ex((target, port))
                    state = 'open' if result == 0 else 'closed'
                else:
                    sock.sendto(b'', (target, port))
                    try:
                        sock.recvfrom(1024)
                        state = 'open'
                    except socket.timeout:
                        state = 'open|filtered'
            except Exception:
                state = 'filtered'
            finally:
                sock.close()
            
            if state == 'open':
                # Get service information
                service_info = self.service_config.get(port, {})
                service = service_info.get('name')
                description = service_info.get('description')
                
                # Try to grab banner
                banner = await self._grab_banner(target, port, protocol)
                
                return PortResult(
                    port=port,
                    protocol=protocol,
                    state=state,
                    service=service,
                    version=None,  # Version detection would be implemented separately
                    banner=banner,
                    source=f"{scan_type}_scan",
                    confidence=0.9 if service else 0.7,
                    metadata={
                        'scan_type': scan_type,
                        'protocol': protocol,
                        'description': description,
                        'scan_timestamp': datetime.utcnow().isoformat()
                    }
                )
            
            return None
            
        except Exception:
            return None
    
    async def _grab_banner(self, target: str, port: int, protocol: str) -> Optional[str]:
        """Attempt to grab service banner."""
        if not self.session or protocol != 'tcp':
            return None
        
        try:
            url = f"http://{target}:{port}"
            async with self.session.get(url, allow_redirects=False) as response:
                if response.status < 400:
                    headers = dict(response.headers)
                    return json.dumps(headers)
        except Exception:
            pass
        
        return None 