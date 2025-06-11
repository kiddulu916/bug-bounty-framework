"""
Vulnerability Scanner Plugin for Bug Bounty Framework.

This plugin implements various vulnerability scanning techniques:
- SQL Injection detection
- XSS (Cross-Site Scripting) detection
- CSRF (Cross-Site Request Forgery) detection
- Open Redirect detection
- File Inclusion detection
- Command Injection detection
- SSRF (Server-Side Request Forgery) detection
- XXE (XML External Entity) detection
"""

import asyncio
import logging
import re
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Tuple, Union
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import aiohttp
import aiohttp.client_exceptions
from bs4 import BeautifulSoup
import yarl

from bbf.core.database.models import Finding
from bbf.core.database.service import finding_service
from bbf.plugins.base import BasePlugin
from bbf.plugins.config import get_payloads, get_error_patterns

logger = logging.getLogger(__name__)

@dataclass
class VulnResult:
    """Vulnerability detection result data structure."""
    url: str
    type: str
    severity: str
    description: str
    evidence: str
    payload: Optional[str] = None
    parameter: Optional[str] = None
    confidence: float = 1.0
    timestamp: datetime = None
    stage: str = 'vuln'
    status: str = 'active'

class VulnScannerPlugin(BasePlugin):
    """Vulnerability scanner plugin implementation."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the vulnerability scanner plugin."""
        super().__init__(config)
        self.name = "vuln_scanner"
        self.description = "Vulnerability detection and analysis"
        self.version = "1.0.0"
        self.author = "BBF Team"
        self.session = None
        
        # Default configuration
        self.timeout = config.get('timeout', 10.0)
        self.max_redirects = config.get('max_redirects', 5)
        self.user_agent = config.get('user_agent', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        self.max_concurrent_requests = config.get('max_concurrent_requests', 10)
        self.verify_ssl = config.get('verify_ssl', True)
        
        # Get payloads and error patterns from centralized config
        self.payloads = get_payloads()
        self.error_patterns = get_error_patterns()
        
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
        Execute vulnerability scanning against the target.
        
        Args:
            target: Target URL
            config: Optional configuration dictionary
                - timeout: Request timeout in seconds
                - max_redirects: Maximum number of redirects to follow
                - user_agent: Custom user agent string
                - max_concurrent_requests: Maximum number of concurrent requests
                - verify_ssl: Whether to verify SSL certificates
                
        Returns:
            List of detected vulnerabilities
        """
        if not config:
            config = {}
            
        # Get configuration
        timeout = config.get('timeout', self.timeout)
        max_redirects = config.get('max_redirects', self.max_redirects)
        user_agent = config.get('user_agent', self.user_agent)
        max_concurrent = config.get('max_concurrent_requests', self.max_concurrent_requests)
        verify_ssl = config.get('verify_ssl', self.verify_ssl)
        
        # Initialize results
        results = []
        
        try:
            # Normalize target URL
            if not target.startswith(('http://', 'https://')):
                target = f'https://{target}'
                
            # Get target information
            async with self.session.get(
                target,
                allow_redirects=True,
                max_redirects=max_redirects,
                timeout=timeout,
                ssl=verify_ssl
            ) as response:
                # Get response data
                html = await response.text()
                final_url = str(response.url)
                
                # Parse HTML
                soup = BeautifulSoup(html, 'html.parser')
                
                # Find all forms and links
                forms = soup.find_all('form')
                links = soup.find_all('a', href=True)
                
                # Prepare scan tasks
                scan_tasks = []
                
                # Form scanning tasks
                for form in forms:
                    form_tasks = [
                        self._scan_form_sql_injection(form, final_url),
                        self._scan_form_xss(form, final_url),
                        self._scan_form_csrf(form, final_url),
                        self._scan_form_open_redirect(form, final_url),
                        self._scan_form_file_inclusion(form, final_url),
                        self._scan_form_command_injection(form, final_url)
                    ]
                    scan_tasks.extend(form_tasks)
                    
                # Link scanning tasks
                for link in links:
                    link_tasks = [
                        self._scan_link_open_redirect(link, final_url),
                        self._scan_link_file_inclusion(link, final_url),
                        self._scan_link_ssrf(link, final_url)
                    ]
                    scan_tasks.extend(link_tasks)
                    
                # Run scan tasks with concurrency limit
                semaphore = asyncio.Semaphore(max_concurrent)
                async def bounded_scan(task):
                    async with semaphore:
                        return await task
                        
                scan_results = await asyncio.gather(
                    *[bounded_scan(task) for task in scan_tasks],
                    return_exceptions=True
                )
                
                # Process results
                for scan_result in scan_results:
                    if isinstance(scan_result, Exception):
                        logger.error(f"Scan task failed: {scan_result}")
                        continue
                        
                    if scan_result:
                        # Skip duplicates
                        if any(r['url'] == scan_result.url and 
                              r['type'] == scan_result.type and
                              r['parameter'] == scan_result.parameter
                              for r in results):
                            continue
                            
                        # Convert to dict and add to results
                        results.append({
                            'url': scan_result.url,
                            'type': scan_result.type,
                            'severity': scan_result.severity,
                            'description': scan_result.description,
                            'evidence': scan_result.evidence,
                            'payload': scan_result.payload,
                            'parameter': scan_result.parameter,
                            'confidence': scan_result.confidence,
                            'timestamp': datetime.utcnow(),
                            'stage': scan_result.stage,
                            'status': scan_result.status
                        })
                        
                # Store results in database
                if results:
                    await self._store_findings(target, results)
                    
        except Exception as e:
            logger.error(f"Vulnerability scanning failed: {e}")
            
        return results
        
    async def _store_findings(self, target: str, results: List[Dict[str, Any]]) -> None:
        """Store findings in the centralized database.
        
        Args:
            target: The target URL.
            results: List of vulnerability findings.
        """
        try:
            # Parse target URL
            parsed_url = urlparse(target)
            root_domain = parsed_url.netloc
            subdomain = root_domain.split('.')[0]
            
            # Group vulnerabilities by type
            vulns_by_type = {}
            for result in results:
                if result['type'] not in vulns_by_type:
                    vulns_by_type[result['type']] = []
                vulns_by_type[result['type']].append({
                    'url': result['url'],
                    'severity': result['severity'],
                    'description': result['description'],
                    'evidence': result['evidence'],
                    'payload': result['payload'],
                    'parameter': result['parameter'],
                    'confidence': result['confidence']
                })
            
            # Prepare finding data
            finding_data = {
                'root_domain': root_domain,
                'subdomain': subdomain,
                'source': 'vulnerability_scan',
                'stage': 'vuln',
                'status': 'active',
                'metadata': json.dumps({
                    'scan_type': 'comprehensive',
                    'vulnerabilities_found': len(results),
                    'vulnerabilities_by_type': vulns_by_type,
                    'scan_timestamp': datetime.now().isoformat(),
                    'scan_details': {
                        'vulnerability_types_checked': list(self.payloads.keys()),
                        'scan_configuration': {
                            'timeout': self.timeout,
                            'max_redirects': self.max_redirects,
                            'max_concurrent_requests': self.max_concurrent_requests,
                            'verify_ssl': self.verify_ssl
                        }
                    }
                })
            }
            
            # Store finding
            await finding_service.add_or_update_finding(
                finding_data=finding_data,
                merge_metadata=True
            )
            
            logger.info(f"Stored {len(results)} vulnerabilities in database")
            
        except Exception as e:
            logger.error(f"Failed to store findings in database: {str(e)}")
            raise PluginError(f"Failed to store findings in database: {str(e)}")
            
    async def _scan_form_sql_injection(self, form: BeautifulSoup, base_url: str) -> Optional[VulnResult]:
        """Scan form for SQL injection vulnerabilities."""
        try:
            # Get form details
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea'])
            
            # Skip if no inputs
            if not inputs:
                return None
                
            # Prepare form data
            form_data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    form_data[name] = self.payloads['sql_injection'][0]
                    
            # Skip if no form data
            if not form_data:
                return None
                
            # Construct URL
            url = urljoin(base_url, action)
            
            # Send request
            if method == 'post':
                async with self.session.post(url, data=form_data) as response:
                    content = await response.text()
                    
                    # Check for SQL errors
                    for pattern in self.error_patterns['sql_injection']:
                        if re.search(pattern, content, re.I):
                            return VulnResult(
                                url=url,
                                type='sql_injection',
                                severity='high',
                                description='SQL Injection vulnerability detected',
                                evidence=f"SQL error pattern matched: {pattern}",
                                payload=form_data[list(form_data.keys())[0]],
                                parameter=list(form_data.keys())[0],
                                confidence=0.9,
                                timestamp=datetime.utcnow()
                            )
            else:
                # GET request
                params = urlencode(form_data)
                test_url = f"{url}?{params}"
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    
                    # Check for SQL errors
                    for pattern in self.error_patterns['sql_injection']:
                        if re.search(pattern, content, re.I):
                            return VulnResult(
                                url=test_url,
                                type='sql_injection',
                                severity='high',
                                description='SQL Injection vulnerability detected',
                                evidence=f"SQL error pattern matched: {pattern}",
                                payload=form_data[list(form_data.keys())[0]],
                                parameter=list(form_data.keys())[0],
                                confidence=0.9,
                                timestamp=datetime.utcnow()
                            )
                            
        except Exception as e:
            logger.error(f"SQL injection scan failed: {e}")
            
        return None
        
    async def _scan_form_xss(self, form: BeautifulSoup, base_url: str) -> Optional[VulnResult]:
        """Scan form for XSS vulnerabilities."""
        try:
            # Get form details
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea'])
            
            # Skip if no inputs
            if not inputs:
                return None
                
            # Prepare form data
            form_data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    form_data[name] = self.payloads['xss'][0]
                    
            # Skip if no form data
            if not form_data:
                return None
                
            # Construct URL
            url = urljoin(base_url, action)
            
            # Send request
            if method == 'post':
                async with self.session.post(url, data=form_data) as response:
                    content = await response.text()
                    
                    # Check for XSS payload
                    for pattern in self.error_patterns['xss']:
                        if re.search(pattern, content, re.I):
                            return VulnResult(
                                url=url,
                                type='xss',
                                severity='high',
                                description='Cross-Site Scripting (XSS) vulnerability detected',
                                evidence=f"XSS payload reflected: {pattern}",
                                payload=form_data[list(form_data.keys())[0]],
                                parameter=list(form_data.keys())[0],
                                confidence=0.9,
                                timestamp=datetime.utcnow()
                            )
            else:
                # GET request
                params = urlencode(form_data)
                test_url = f"{url}?{params}"
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    
                    # Check for XSS payload
                    for pattern in self.error_patterns['xss']:
                        if re.search(pattern, content, re.I):
                            return VulnResult(
                                url=test_url,
                                type='xss',
                                severity='high',
                                description='Cross-Site Scripting (XSS) vulnerability detected',
                                evidence=f"XSS payload reflected: {pattern}",
                                payload=form_data[list(form_data.keys())[0]],
                                parameter=list(form_data.keys())[0],
                                confidence=0.9,
                                timestamp=datetime.utcnow()
                            )
                            
        except Exception as e:
            logger.error(f"XSS scan failed: {e}")
            
        return None
        
    async def _scan_form_csrf(self, form: BeautifulSoup, base_url: str) -> Optional[VulnResult]:
        """Scan form for CSRF vulnerabilities."""
        try:
            # Check for CSRF token
            csrf_token = form.find('input', attrs={'name': re.compile(r'csrf|token', re.I)})
            if not csrf_token:
                # No CSRF token found
                action = form.get('action', '')
                method = form.get('method', 'post').lower()
                
                if method == 'post':
                    return VulnResult(
                        url=urljoin(base_url, action),
                        type='csrf',
                        severity='medium',
                        description='Potential CSRF vulnerability - no CSRF token found',
                        evidence="Form submission without CSRF protection",
                        confidence=0.7,
                        timestamp=datetime.utcnow()
                    )
                    
        except Exception as e:
            logger.error(f"CSRF scan failed: {e}")
            
        return None
        
    async def _scan_form_open_redirect(self, form: BeautifulSoup, base_url: str) -> Optional[VulnResult]:
        """Scan form for open redirect vulnerabilities."""
        try:
            # Get form details
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea'])
            
            # Look for redirect parameters
            redirect_params = ['redirect', 'return', 'url', 'next', 'target', 'destination']
            
            for input_tag in inputs:
                name = input_tag.get('name', '').lower()
                if any(param in name for param in redirect_params):
                    # Found potential redirect parameter
                    form_data = {name: self.payloads['open_redirect'][0]}
                    
                    # Construct URL
                    url = urljoin(base_url, action)
                    
                    # Send request
                    if method == 'post':
                        async with self.session.post(url, data=form_data, allow_redirects=False) as response:
                            if response.status in (301, 302, 303, 307, 308):
                                location = response.headers.get('location', '')
                                if any(payload in location for payload in self.payloads['open_redirect']):
                                    return VulnResult(
                                        url=url,
                                        type='open_redirect',
                                        severity='medium',
                                        description='Open Redirect vulnerability detected',
                                        evidence=f"Redirect to external domain: {location}",
                                        payload=form_data[name],
                                        parameter=name,
                                        confidence=0.9,
                                        timestamp=datetime.utcnow()
                                    )
                    else:
                        # GET request
                        params = urlencode(form_data)
                        test_url = f"{url}?{params}"
                        async with self.session.get(test_url, allow_redirects=False) as response:
                            if response.status in (301, 302, 303, 307, 308):
                                location = response.headers.get('location', '')
                                if any(payload in location for payload in self.payloads['open_redirect']):
                                    return VulnResult(
                                        url=test_url,
                                        type='open_redirect',
                                        severity='medium',
                                        description='Open Redirect vulnerability detected',
                                        evidence=f"Redirect to external domain: {location}",
                                        payload=form_data[name],
                                        parameter=name,
                                        confidence=0.9,
                                        timestamp=datetime.utcnow()
                                    )
                                    
        except Exception as e:
            logger.error(f"Open redirect scan failed: {e}")
            
        return None
        
    async def _scan_form_file_inclusion(self, form: BeautifulSoup, base_url: str) -> Optional[VulnResult]:
        """Scan form for file inclusion vulnerabilities."""
        try:
            # Get form details
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea'])
            
            # Look for file parameters
            file_params = ['file', 'page', 'include', 'path', 'doc', 'document']
            
            for input_tag in inputs:
                name = input_tag.get('name', '').lower()
                if any(param in name for param in file_params):
                    # Found potential file parameter
                    form_data = {name: self.payloads['file_inclusion'][0]}
                    
                    # Construct URL
                    url = urljoin(base_url, action)
                    
                    # Send request
                    if method == 'post':
                        async with self.session.post(url, data=form_data) as response:
                            content = await response.text()
                            
                            # Check for file inclusion errors
                            for pattern in self.error_patterns['file_inclusion']:
                                if re.search(pattern, content, re.I):
                                    return VulnResult(
                                        url=url,
                                        type='file_inclusion',
                                        severity='high',
                                        description='File Inclusion vulnerability detected',
                                        evidence=f"File inclusion error pattern matched: {pattern}",
                                        payload=form_data[name],
                                        parameter=name,
                                        confidence=0.9,
                                        timestamp=datetime.utcnow()
                                    )
                    else:
                        # GET request
                        params = urlencode(form_data)
                        test_url = f"{url}?{params}"
                        async with self.session.get(test_url) as response:
                            content = await response.text()
                            
                            # Check for file inclusion errors
                            for pattern in self.error_patterns['file_inclusion']:
                                if re.search(pattern, content, re.I):
                                    return VulnResult(
                                        url=test_url,
                                        type='file_inclusion',
                                        severity='high',
                                        description='File Inclusion vulnerability detected',
                                        evidence=f"File inclusion error pattern matched: {pattern}",
                                        payload=form_data[name],
                                        parameter=name,
                                        confidence=0.9,
                                        timestamp=datetime.utcnow()
                                    )
                                    
        except Exception as e:
            logger.error(f"File inclusion scan failed: {e}")
            
        return None
        
    async def _scan_form_command_injection(self, form: BeautifulSoup, base_url: str) -> Optional[VulnResult]:
        """Scan form for command injection vulnerabilities."""
        try:
            # Get form details
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea'])
            
            # Look for command parameters
            cmd_params = ['cmd', 'command', 'exec', 'execute', 'system', 'shell']
            
            for input_tag in inputs:
                name = input_tag.get('name', '').lower()
                if any(param in name for param in cmd_params):
                    # Found potential command parameter
                    form_data = {name: self.payloads['command_injection'][0]}
                    
                    # Construct URL
                    url = urljoin(base_url, action)
                    
                    # Send request
                    if method == 'post':
                        async with self.session.post(url, data=form_data) as response:
                            content = await response.text()
                            
                            # Check for command injection errors
                            for pattern in self.error_patterns['command_injection']:
                                if re.search(pattern, content, re.I):
                                    return VulnResult(
                                        url=url,
                                        type='command_injection',
                                        severity='critical',
                                        description='Command Injection vulnerability detected',
                                        evidence=f"Command injection error pattern matched: {pattern}",
                                        payload=form_data[name],
                                        parameter=name,
                                        confidence=0.9,
                                        timestamp=datetime.utcnow()
                                    )
                    else:
                        # GET request
                        params = urlencode(form_data)
                        test_url = f"{url}?{params}"
                        async with self.session.get(test_url) as response:
                            content = await response.text()
                            
                            # Check for command injection errors
                            for pattern in self.error_patterns['command_injection']:
                                if re.search(pattern, content, re.I):
                                    return VulnResult(
                                        url=test_url,
                                        type='command_injection',
                                        severity='critical',
                                        description='Command Injection vulnerability detected',
                                        evidence=f"Command injection error pattern matched: {pattern}",
                                        payload=form_data[name],
                                        parameter=name,
                                        confidence=0.9,
                                        timestamp=datetime.utcnow()
                                    )
                                    
        except Exception as e:
            logger.error(f"Command injection scan failed: {e}")
            
        return None
        
    async def _scan_link_open_redirect(self, link: BeautifulSoup, base_url: str) -> Optional[VulnResult]:
        """Scan link for open redirect vulnerabilities."""
        try:
            href = link.get('href', '')
            if not href:
                return None
                
            # Parse URL
            url = urljoin(base_url, href)
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Look for redirect parameters
            redirect_params = ['redirect', 'return', 'url', 'next', 'target', 'destination']
            
            for param in redirect_params:
                if param in params:
                    # Found potential redirect parameter
                    test_params = params.copy()
                    test_params[param] = [self.payloads['open_redirect'][0]]
                    
                    # Construct test URL
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    # Send request
                    async with self.session.get(test_url, allow_redirects=False) as response:
                        if response.status in (301, 302, 303, 307, 308):
                            location = response.headers.get('location', '')
                            if any(payload in location for payload in self.payloads['open_redirect']):
                                return VulnResult(
                                    url=test_url,
                                    type='open_redirect',
                                    severity='medium',
                                    description='Open Redirect vulnerability detected',
                                    evidence=f"Redirect to external domain: {location}",
                                    payload=self.payloads['open_redirect'][0],
                                    parameter=param,
                                    confidence=0.9,
                                    timestamp=datetime.utcnow()
                                )
                                
        except Exception as e:
            logger.error(f"Link open redirect scan failed: {e}")
            
        return None
        
    async def _scan_link_file_inclusion(self, link: BeautifulSoup, base_url: str) -> Optional[VulnResult]:
        """Scan link for file inclusion vulnerabilities."""
        try:
            href = link.get('href', '')
            if not href:
                return None
                
            # Parse URL
            url = urljoin(base_url, href)
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Look for file parameters
            file_params = ['file', 'page', 'include', 'path', 'doc', 'document']
            
            for param in file_params:
                if param in params:
                    # Found potential file parameter
                    test_params = params.copy()
                    test_params[param] = [self.payloads['file_inclusion'][0]]
                    
                    # Construct test URL
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    # Send request
                    async with self.session.get(test_url) as response:
                        content = await response.text()
                        
                        # Check for file inclusion errors
                        for pattern in self.error_patterns['file_inclusion']:
                            if re.search(pattern, content, re.I):
                                return VulnResult(
                                    url=test_url,
                                    type='file_inclusion',
                                    severity='high',
                                    description='File Inclusion vulnerability detected',
                                    evidence=f"File inclusion error pattern matched: {pattern}",
                                    payload=self.payloads['file_inclusion'][0],
                                    parameter=param,
                                    confidence=0.9,
                                    timestamp=datetime.utcnow()
                                )
                                
        except Exception as e:
            logger.error(f"Link file inclusion scan failed: {e}")
            
        return None
        
    async def _scan_link_ssrf(self, link: BeautifulSoup, base_url: str) -> Optional[VulnResult]:
        """Scan link for SSRF vulnerabilities."""
        try:
            href = link.get('href', '')
            if not href:
                return None
                
            # Parse URL
            url = urljoin(base_url, href)
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Look for URL parameters
            url_params = ['url', 'uri', 'path', 'src', 'dest', 'redirect', 'proxy']
            
            for param in url_params:
                if param in params:
                    # Found potential URL parameter
                    for payload in self.payloads['ssrf']:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        
                        # Construct test URL
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                        
                        # Send request
                        async with self.session.get(test_url) as response:
                            content = await response.text()
                            
                            # Check for SSRF indicators
                            if any(indicator in content.lower() for indicator in ['localhost', '127.0.0.1', '[::1]']):
                                return VulnResult(
                                    url=test_url,
                                    type='ssrf',
                                    severity='high',
                                    description='Server-Side Request Forgery (SSRF) vulnerability detected',
                                    evidence=f"SSRF payload successful: {payload}",
                                    payload=payload,
                                    parameter=param,
                                    confidence=0.8,
                                    timestamp=datetime.utcnow()
                                )
                                
        except Exception as e:
            logger.error(f"Link SSRF scan failed: {e}")
            
        return None 