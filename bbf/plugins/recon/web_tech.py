"""
Web Technology Detection Plugin for Bug Bounty Framework.

This plugin implements various techniques for detecting web technologies:
- HTTP header analysis
- HTML content analysis
- JavaScript file analysis
- Meta tag analysis
- Cookie analysis
- CSS/JS framework detection
- CMS detection
- Web server fingerprinting

All findings are stored in the centralized database following the rules in .cursor/rules/database.mdc.
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
import aiohttp.client_exceptions
from bs4 import BeautifulSoup
import json
import yarl

from bbf.core.database.models import Finding
from bbf.core.database.service import finding_service
from bbf.plugins.config import get_technologies, get_headers

logger = logging.getLogger(__name__)

@dataclass
class TechResult:
    """Web technology detection result data structure."""
    url: str
    name: str
    category: str
    version: Optional[str] = None
    confidence: float = 1.0
    evidence: Optional[str] = None
    timestamp: datetime = None
    metadata: Optional[Dict[str, Any]] = None
    stage: str = "recon"
    status: str = "active"

class WebTechPlugin:
    """Web technology detection plugin implementation."""
    
    def __init__(self):
        """Initialize the web technology detection plugin."""
        self.name = "web_tech"
        self.description = "Web technology and framework detection"
        self.version = "1.0.0"
        self.session = None
        self.current_plugin_result_id = None
        
        # Default configuration
        self.timeout = 10.0
        self.max_redirects = 5
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        
        # Get technology signatures from centralized config
        self.tech_signatures = get_technologies()
        
    async def initialize(self):
        """Initialize plugin resources."""
        self.session = aiohttp.ClientSession(
            headers={'User-Agent': self.user_agent},
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )
        
    async def cleanup(self):
        """Clean up plugin resources."""
        if self.session:
            await self.session.close()
            self.session = None
            
    async def execute(self, target: str, config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Execute web technology detection against the target.
        
        Args:
            target: Target URL
            config: Optional configuration dictionary
                - timeout: Request timeout in seconds
                - max_redirects: Maximum number of redirects to follow
                - user_agent: Custom user agent string
                
        Returns:
            List of detected technologies
        """
        if not config:
            config = {}
            
        # Get configuration
        timeout = config.get('timeout', self.timeout)
        max_redirects = config.get('max_redirects', self.max_redirects)
        user_agent = config.get('user_agent', self.user_agent)
        
        # Initialize results
        results: Set[TechResult] = set()
        
        try:
            # Normalize target URL
            if not target.startswith(('http://', 'https://')):
                target = f'https://{target}'
                
            # Extract domain and subdomain
            parsed_url = urlparse(target)
            domain = parsed_url.netloc
            subdomain = domain.split('.')[0] if '.' in domain else domain
                
            # Fetch main page
            async with self.session.get(
                target,
                allow_redirects=True,
                max_redirects=max_redirects,
                timeout=timeout
            ) as response:
                # Get response data
                html = await response.text()
                headers = dict(response.headers)
                cookies = dict(response.cookies)
                final_url = str(response.url)
                
                # Parse HTML
                soup = BeautifulSoup(html, 'html.parser')
                
                # Detect technologies
                tech_tasks = [
                    self._detect_from_headers(headers, final_url),
                    self._detect_from_html(soup, final_url),
                    self._detect_from_meta(soup, final_url),
                    self._detect_from_cookies(cookies, final_url),
                    self._detect_from_scripts(soup, final_url)
                ]
                
                # Run detection tasks concurrently
                tech_results = await asyncio.gather(*tech_tasks, return_exceptions=True)
                
                # Process results
                for tech_result in tech_results:
                    if isinstance(tech_result, Exception):
                        logger.error(f"Technology detection failed: {tech_result}")
                        continue
                        
                    for tech in tech_result:
                        # Skip duplicates
                        if any(r.name == tech.name and r.category == tech.category 
                              for r in results):
                            continue
                            
                        # Add to results
                        results.add(tech)
                
                # Store results in database using finding_service
                if results:
                    await self._store_findings(domain, subdomain, results)
                    
        except Exception as e:
            logger.error(f"Web technology detection failed: {e}")
            
        return [self._result_to_dict(r) for r in results]
    
    async def _store_findings(self, domain: str, subdomain: str, findings: Set[TechResult]) -> None:
        """Store findings in the centralized database using finding_service."""
        try:
            # Get existing finding
            existing = await finding_service.get_finding(domain, subdomain)
            
            # Prepare technology data
            tech_data = {
                tech.name: {
                    'category': tech.category,
                    'version': tech.version,
                    'confidence': tech.confidence,
                    'evidence': tech.evidence,
                    'detected_at': tech.timestamp.isoformat()
                } for tech in findings
            }
            
            # Create finding data
            finding_data = {
                'root_domain': domain,
                'subdomain': subdomain,
                'web_tech': json.dumps(tech_data),
                'source': 'web_tech_detection',
                'confidence': max(tech.confidence for tech in findings),
                'first_seen': min(tech.timestamp for tech in findings),
                'last_seen': max(tech.timestamp for tech in findings),
                'metadata': json.dumps({
                    'scan_type': 'comprehensive',
                    'technologies_detected': len(findings),
                    'scan_timestamp': datetime.utcnow().isoformat(),
                    'scan_details': [self._result_to_dict(tech) for tech in findings]
                }),
                'stage': 'recon',
                'status': 'active'
            }
            
            # Update finding
            await finding_service.add_or_update_finding(
                root_domain=domain,
                subdomain=subdomain,
                finding_data=finding_data,
                merge_metadata=True
            )
            
        except Exception as e:
            logger.error(f"Error storing findings: {str(e)}")
            raise
    
    def _result_to_dict(self, result: TechResult) -> Dict[str, Any]:
        """Convert TechResult to dictionary."""
        return {
            'url': result.url,
            'name': result.name,
            'category': result.category,
            'version': result.version,
            'confidence': result.confidence,
            'evidence': result.evidence,
            'timestamp': result.timestamp.isoformat() if result.timestamp else None,
            'metadata': result.metadata,
            'stage': result.stage,
            'status': result.status
        }
        
    async def _detect_from_headers(self, headers: Dict[str, str], url: str) -> List[TechResult]:
        """Detect technologies from HTTP headers."""
        results = []
        
        # Server detection
        server = headers.get('server', '').lower()
        if server:
            for tech, signatures in self.tech_signatures['servers'].items():
                for pattern, _ in signatures:
                    if re.search(pattern, server, re.I):
                        results.append(TechResult(
                            url=url,
                            name=tech,
                            category='server',
                            version=None,  # TODO: Extract version from server string
                            confidence=0.9,
                            evidence=f"Server header: {server}",
                            timestamp=datetime.utcnow()
                        ))
                        
        # X-Powered-By detection
        powered_by = headers.get('x-powered-by', '').lower()
        if powered_by:
            for tech, signatures in self.tech_signatures['servers'].items():
                for pattern, _ in signatures:
                    if re.search(pattern, powered_by, re.I):
                        results.append(TechResult(
                            url=url,
                            name=tech,
                            category='server',
                            version=None,
                            confidence=0.8,
                            evidence=f"X-Powered-By header: {powered_by}",
                            timestamp=datetime.utcnow()
                        ))
                        
        return results
        
    async def _detect_from_html(self, soup: BeautifulSoup, url: str) -> List[TechResult]:
        """Detect technologies from HTML content."""
        results = []
        
        # Framework detection
        for tech, signatures in self.tech_signatures['frameworks'].items():
            for pattern, _ in signatures:
                if soup.find(string=re.compile(pattern, re.I)):
                    results.append(TechResult(
                        url=url,
                        name=tech,
                        category='framework',
                        version=None,
                        confidence=0.9,
                        evidence=f"HTML content match: {pattern}",
                        timestamp=datetime.utcnow()
                    ))
                    
        # CMS detection
        for tech, signatures in self.tech_signatures['cms'].items():
            for pattern, _ in signatures:
                if soup.find(string=re.compile(pattern, re.I)):
                    results.append(TechResult(
                        url=url,
                        name=tech,
                        category='cms',
                        version=None,
                        confidence=0.9,
                        evidence=f"HTML content match: {pattern}",
                        timestamp=datetime.utcnow()
                    ))
                    
        return results
        
    async def _detect_from_meta(self, soup: BeautifulSoup, url: str) -> List[TechResult]:
        """Detect technologies from meta tags."""
        results = []
        
        # Check meta tags
        for meta in soup.find_all('meta'):
            # Generator
            if meta.get('name') == 'generator':
                content = meta.get('content', '').lower()
                for tech, signatures in self.tech_signatures['cms'].items():
                    if tech in content:
                        version = None
                        if ' ' in content:
                            version = content.split(' ')[-1]
                        results.append(TechResult(
                            url=url,
                            name=tech,
                            category='cms',
                            version=version,
                            confidence=1.0,
                            evidence=f"Meta generator: {content}",
                            timestamp=datetime.utcnow()
                        ))
                        
            # Framework detection
            if meta.get('name') in ['framework', 'framework-version']:
                content = meta.get('content', '').lower()
                for tech, signatures in self.tech_signatures['frameworks'].items():
                    if tech in content:
                        version = None
                        if ' ' in content:
                            version = content.split(' ')[-1]
                        results.append(TechResult(
                            url=url,
                            name=tech,
                            category='framework',
                            version=version,
                            confidence=0.9,
                            evidence=f"Meta {meta['name']}: {content}",
                            timestamp=datetime.utcnow()
                        ))
                        
        return results
        
    async def _detect_from_cookies(self, cookies: Dict[str, str], url: str) -> List[TechResult]:
        """Detect technologies from cookies."""
        results = []
        
        # CMS detection from cookies
        for cookie_name in cookies:
            cookie_name_lower = cookie_name.lower()
            for tech, signatures in self.tech_signatures['cms'].items():
                if tech in cookie_name_lower:
                    results.append(TechResult(
                        url=url,
                        name=tech,
                        category='cms',
                        version=None,
                        confidence=0.8,
                        evidence=f"Cookie name: {cookie_name}",
                        timestamp=datetime.utcnow()
                    ))
                    
        return results
        
    async def _detect_from_scripts(self, soup: BeautifulSoup, url: str) -> List[TechResult]:
        """Detect technologies from script tags and content."""
        results = []
        
        # Check script sources
        for script in soup.find_all('script', src=True):
            src = script['src'].lower()
            
            # Framework detection
            for tech, signatures in self.tech_signatures['frameworks'].items():
                for pattern, _ in signatures:
                    if re.search(pattern, src, re.I):
                        version = None
                        # Try to extract version from URL
                        version_match = re.search(r'[v-](\d+\.\d+\.\d+)', src)
                        if version_match:
                            version = version_match.group(1)
                        results.append(TechResult(
                            url=url,
                            name=tech,
                            category='framework',
                            version=version,
                            confidence=0.9,
                            evidence=f"Script source: {src}",
                            timestamp=datetime.utcnow()
                        ))
                        
        # Check inline scripts
        for script in soup.find_all('script'):
            if not script.get('src'):
                content = script.string
                if content:
                    # Framework detection
                    for tech, signatures in self.tech_signatures['frameworks'].items():
                        for pattern, _ in signatures:
                            if re.search(pattern, content, re.I):
                                results.append(TechResult(
                                    url=url,
                                    name=tech,
                                    category='framework',
                                    version=None,
                                    confidence=0.9,
                                    evidence=f"Script content match: {pattern}",
                                    timestamp=datetime.utcnow()
                                ))
                                
        return results 