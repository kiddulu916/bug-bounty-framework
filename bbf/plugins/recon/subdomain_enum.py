"""
Subdomain Enumeration Plugin.

This plugin implements various subdomain discovery techniques:
- Certificate Transparency Logs
- Internet Archive (Wayback Machine)
- DNS Zone Transfers
- DNS Brute Force (using SecLists wordlist)
- Reverse DNS Lookups

All findings are stored in the centralized database following the rules in .cursor/rules/database.mdc.
"""

import asyncio
import logging
import aiodns
import socket
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Set, Dict, Optional, Any
from pathlib import Path

from bbf.core.database.models import Finding
from bbf.core.database.service import finding_service
from bbf.plugins.config import get_wordlist, get_services

logger = logging.getLogger(__name__)

@dataclass
class SubdomainResult:
    """Subdomain enumeration result."""
    subdomain: str
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    open_ports: Optional[List[int]] = None
    services: Optional[Dict[int, str]] = None
    tls_status: Optional[Dict[str, Any]] = None
    source: str = "unknown"
    confidence: float = 0.0
    first_seen: datetime = datetime.utcnow()
    last_seen: datetime = datetime.utcnow()
    metadata: Optional[Dict[str, Any]] = None
    stage: str = "recon"
    status: str = "active"

class SubdomainEnumPlugin:
    """Subdomain enumeration plugin implementation."""
    
    name = "subdomain_enum"
    description = "Subdomain discovery and enumeration"
    version = "1.0.0"
    
    def __init__(self):
        """Initialize the plugin."""
        self.resolver: Optional[aiodns.DNSResolver] = None
        self.current_plugin_result_id: Optional[int] = None
        
        # Configuration
        self.timeout = 30
        self.max_concurrent_tasks = 50
        
        # DNS settings
        self.nameservers = [
            "8.8.8.8",  # Google DNS
            "1.1.1.1",  # Cloudflare DNS
            "9.9.9.9"   # Quad9 DNS
        ]
    
    async def initialize(self) -> None:
        """Initialize plugin resources."""
        if not self.resolver:
            self.resolver = aiodns.DNSResolver()
            self.resolver.nameservers = self.nameservers
    
    async def cleanup(self) -> None:
        """Cleanup plugin resources."""
        self.resolver = None
    
    async def execute(self, target_domain: str) -> List[SubdomainResult]:
        """Execute subdomain enumeration against target domain."""
        if not self.resolver:
            await self.initialize()
        
        results: Set[SubdomainResult] = set()
        try:
            # Run all enumeration techniques concurrently
            tasks = [
                self._enumerate_from_ct_logs(target_domain),
                self._enumerate_from_wayback(target_domain),
                self._enumerate_from_dns_zone_transfer(target_domain),
                self._enumerate_from_dns_bruteforce(target_domain),
                self._enumerate_from_reverse_dns(target_domain)
            ]
            
            enum_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result_list in enum_results:
                if isinstance(result_list, list):
                    results.update(result_list)
                elif isinstance(result_list, Exception):
                    logger.error(f"Enumeration error: {str(result_list)}")
            
            # Store results in database using finding_service
            if results:
                await self._store_findings(target_domain, results)
            
            return list(results)
            
        except Exception as e:
            logger.error(f"Error during subdomain enumeration: {str(e)}")
            return list(results)
    
    async def _store_findings(self, root_domain: str, findings: Set[SubdomainResult]) -> None:
        """Store findings in the centralized database using finding_service."""
        try:
            for finding in findings:
                # Create finding data
                finding_data = {
                    'root_domain': root_domain,
                    'subdomain': finding.subdomain,
                    'ipv4': finding.ipv4,
                    'ipv6': finding.ipv6,
                    'open_ports': json.dumps(finding.open_ports) if finding.open_ports else None,
                    'services': json.dumps(finding.services) if finding.services else None,
                    'tls_status': json.dumps(finding.tls_status) if finding.tls_status else None,
                    'source': finding.source,
                    'confidence': finding.confidence,
                    'first_seen': finding.first_seen,
                    'last_seen': finding.last_seen,
                    'metadata': json.dumps(finding.metadata) if finding.metadata else None,
                    'stage': finding.stage,
                    'status': finding.status
                }
                
                # Use finding_service to store/update finding
                await finding_service.add_or_update_finding(
                    root_domain=root_domain,
                    subdomain=finding.subdomain,
                    finding_data=finding_data,
                    merge_metadata=True  # Preserve existing metadata
                )
                
        except Exception as e:
            logger.error(f"Error storing findings: {str(e)}")
            raise
    
    async def _enumerate_from_ct_logs(self, domain: str) -> List[SubdomainResult]:
        """Enumerate subdomains from local Certificate Transparency logs database."""
        results = []
        try:
            with sqlite3.connect(self.ct_log_db_path) as conn:
                # Query recent certificates (last 30 days)
                cutoff_date = datetime.utcnow() - timedelta(days=30)
                cursor = conn.execute("""
                    SELECT DISTINCT subdomain, not_before, not_after, issuer
                    FROM ct_logs
                    WHERE domain = ? AND not_after > ?
                    ORDER BY not_before DESC
                """, (domain, cutoff_date))
                
                for row in cursor:
                    subdomain, not_before, not_after, issuer = row
                    # Resolve IP address
                    ipv4, ipv6 = await self._resolve_ip(f"{subdomain}.{domain}")
                    
                    results.append(SubdomainResult(
                        subdomain=subdomain,
                        ipv4=ipv4,
                        ipv6=ipv6,
                        source="ct_logs",
                        confidence=0.9,
                        metadata={
                            'not_before': not_before,
                            'not_after': not_after,
                            'issuer': issuer
                        }
                    ))
            
            return results
            
        except Exception as e:
            logger.error(f"Error during CT logs enumeration: {str(e)}")
            return []
    
    async def _enumerate_from_wayback(self, domain: str) -> List[SubdomainResult]:
        """Enumerate subdomains from local Wayback Machine database."""
        results = []
        try:
            with sqlite3.connect(self.wayback_db_path) as conn:
                # Query recent snapshots (last 90 days)
                cutoff_date = datetime.utcnow() - timedelta(days=90)
                cursor = conn.execute("""
                    SELECT DISTINCT subdomain, url, timestamp, status_code
                    FROM wayback_snapshots
                    WHERE domain = ? AND timestamp > ?
                    ORDER BY timestamp DESC
                """, (domain, cutoff_date))
                
                for row in cursor:
                    subdomain, url, timestamp, status_code = row
                    # Resolve IP address
                    ipv4, ipv6 = await self._resolve_ip(f"{subdomain}.{domain}")
                    
                    results.append(SubdomainResult(
                        subdomain=subdomain,
                        ipv4=ipv4,
                        ipv6=ipv6,
                        source="wayback",
                        confidence=0.8,
                        metadata={
                            'url': url,
                            'timestamp': timestamp,
                            'status_code': status_code
                        }
                    ))
            
            return results
            
        except Exception as e:
            logger.error(f"Error during Wayback enumeration: {str(e)}")
            return []
    
    async def _enumerate_from_dns_zone_transfer(self, domain: str) -> List[SubdomainResult]:
        """Attempt DNS zone transfer for subdomain enumeration."""
        results = []
        try:
            # Get nameservers for the domain
            ns_records = await self.resolver.query(domain, 'NS')
            
            for ns in ns_records:
                try:
                    # Create a new resolver for the nameserver
                    ns_resolver = aiodns.DNSResolver()
                    ns_resolver.nameservers = [ns.host]
                    
                    # Attempt zone transfer
                    try:
                        axfr_records = await ns_resolver.query(domain, 'AXFR')
                        for record in axfr_records:
                            if record.hostname.endswith(f".{domain}"):
                                subdomain = record.hostname[:-len(domain)-1]
                                ipv4, ipv6 = await self._resolve_ip(f"{subdomain}.{domain}")
                                
                                results.append(SubdomainResult(
                                    subdomain=subdomain,
                                    ipv4=ipv4,
                                    ipv6=ipv6,
                                    source="zone_transfer",
                                    confidence=0.95,
                                    metadata={'nameserver': ns.host}
                                ))
                    except Exception:
                        # Zone transfer failed, try to enumerate common records
                        for record_type in ['A', 'AAAA', 'CNAME']:
                            try:
                                records = await ns_resolver.query(domain, record_type)
                                for record in records:
                                    if hasattr(record, 'hostname') and record.hostname.endswith(f".{domain}"):
                                        subdomain = record.hostname[:-len(domain)-1]
                                        ipv4, ipv6 = await self._resolve_ip(f"{subdomain}.{domain}")
                                        
                                        results.append(SubdomainResult(
                                            subdomain=subdomain,
                                            ipv4=ipv4,
                                            ipv6=ipv6,
                                            source="dns_records",
                                            confidence=0.9,
                                            metadata={
                                                'record_type': record_type,
                                                'nameserver': ns.host
                                            }
                                        ))
                            except Exception:
                                continue
                except Exception:
                    continue
            
            return results
            
        except Exception as e:
            logger.error(f"Error during DNS zone transfer: {str(e)}")
            return []
    
    async def _enumerate_from_dns_bruteforce(self, domain: str) -> List[SubdomainResult]:
        """Perform DNS bruteforce using centralized wordlist."""
        results = []
        try:
            # Get wordlist from centralized config
            wordlist = get_wordlist('subdomain')
            if not wordlist:
                logger.error("Failed to load subdomain wordlist")
                return []
            
            logger.info(f"Loaded {len(wordlist)} subdomains from wordlist")
            
            # Create tasks for concurrent DNS lookups
            tasks = []
            for word in wordlist:
                subdomain = f"{word}.{domain}"
                tasks.append(self._resolve_subdomain(subdomain))
            
            # Execute tasks with concurrency limit
            for i in range(0, len(tasks), self.max_concurrent_tasks):
                batch = tasks[i:i + self.max_concurrent_tasks]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, SubdomainResult):
                        results.append(result)
                        logger.debug(f"Found subdomain: {result.subdomain} ({result.ipv4}, {result.ipv6})")
            
            logger.info(f"DNS bruteforce found {len(results)} subdomains")
            return results
            
        except Exception as e:
            logger.error(f"Error during DNS bruteforce: {str(e)}")
            return []
    
    async def _enumerate_from_reverse_dns(self, domain: str) -> List[SubdomainResult]:
        """Enumerate subdomains through reverse DNS lookups."""
        results = []
        try:
            # Get IP range for the domain
            ipv4, ipv6 = await self._resolve_ip(domain)
            if not ipv4 and not ipv6:
                return []
            
            # Get network range
            if ipv4:
                ip_parts = ipv4.split('.')
                network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
            else:
                ip_parts = ipv6.split(':')
                network = f"{ip_parts[0]}:{ip_parts[1]}:{ip_parts[2]}:{ip_parts[3]}:{ip_parts[4]}:{ip_parts[5]}:{ip_parts[6]}:{ip_parts[7]}"
            
            # Create tasks for reverse DNS lookups
            tasks = []
            for i in range(1, 255):
                if ipv4:
                    ip = f"{network}.{i}"
                else:
                    ip = f"{network}:{i}"
                tasks.append(self._reverse_lookup(ip, domain))
            
            # Execute tasks with concurrency limit
            for i in range(0, len(tasks), self.max_concurrent_tasks):
                batch = tasks[i:i + self.max_concurrent_tasks]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, SubdomainResult):
                        results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error during reverse DNS enumeration: {str(e)}")
            return []
    
    async def _resolve_ip(self, hostname: str) -> tuple[Optional[str], Optional[str]]:
        """Resolve hostname to IPv4 and IPv6 addresses."""
        try:
            ipv4 = None
            ipv6 = None
            
            # Resolve IPv4
            try:
                answers = await self.resolver.query(hostname, 'A')
                if answers:
                    ipv4 = answers[0].host
            except Exception:
                pass
            
            # Resolve IPv6
            try:
                answers = await self.resolver.query(hostname, 'AAAA')
                if answers:
                    ipv6 = answers[0].host
            except Exception:
                pass
            
            return ipv4, ipv6
            
        except Exception:
            return None, None
    
    async def _resolve_subdomain(self, subdomain: str) -> Optional[SubdomainResult]:
        """Resolve subdomain and return result if successful."""
        try:
            ipv4, ipv6 = await self._resolve_ip(subdomain)
            if ipv4 or ipv6:
                # Get service information from centralized config
                services = get_services()
                service_info = {}
                
                # Check common ports for services
                for port in [80, 443, 22, 21, 25, 53]:
                    if port in services:
                        service_info[port] = services[port]['name']
                
                return SubdomainResult(
                    subdomain=subdomain.split('.')[0],
                    ipv4=ipv4,
                    ipv6=ipv6,
                    services=service_info,
                    source="dns_bruteforce",
                    confidence=0.7,
                    stage="recon",
                    status="active",
                    metadata={
                        'resolved_at': datetime.utcnow().isoformat(),
                        'nameservers': self.nameservers
                    }
                )
            return None
        except Exception:
            return None
    
    async def _reverse_lookup(self, ip: str, domain: str) -> Optional[SubdomainResult]:
        """Perform reverse DNS lookup and return result if it matches domain."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname.endswith(f".{domain}"):
                subdomain = hostname[:-len(domain)-1]
                ipv4, ipv6 = await self._resolve_ip(f"{subdomain}.{domain}")
                return SubdomainResult(
                    subdomain=subdomain,
                    ipv4=ipv4,
                    ipv6=ipv6,
                    source="reverse_dns",
                    confidence=0.8
                )
            return None
        except Exception:
            return None 