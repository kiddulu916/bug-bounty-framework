"""
Vulnerability Scanner Plugin for Bug Bounty Framework.

This plugin implements various vulnerability scanning techniques to identify
security issues in web applications, including:
- Common vulnerability checks (XSS, SQLi, etc.)
- Misconfiguration detection
- Security header analysis
- SSL/TLS analysis
"""

import asyncio
import ssl
import re
import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse
import aiohttp
import OpenSSL
from datetime import datetime

from bbf.core.plugin import BasePlugin, PluginError
from bbf.core.types import ScanResult, ScanStatus

logger = logging.getLogger(__name__)

class VulnCategory(Enum):
    """Categories of vulnerabilities that can be detected."""
    INJECTION = "injection"  # SQL, NoSQL, Command, etc.
    XSS = "xss"  # Cross-site scripting
    CSRF = "csrf"  # Cross-site request forgery
    AUTH = "auth"  # Authentication/Authorization
    CONFIG = "config"  # Misconfiguration
    CRYPTO = "crypto"  # Cryptographic issues
    HEADER = "header"  # Security header issues
    SSL = "ssl"  # SSL/TLS issues
    OTHER = "other"  # Other vulnerabilities

@dataclass
class Vulnerability:
    """Information about a detected vulnerability."""
    name: str
    category: VulnCategory
    severity: str  # critical, high, medium, low, info
    description: str
    location: str  # URL or endpoint where found
    evidence: str  # Proof of vulnerability
    cwe: Optional[str] = None  # Common Weakness Enumeration ID
    cve: Optional[str] = None  # Common Vulnerabilities and Exposures ID
    remediation: Optional[str] = None  # How to fix
    timestamp: datetime = datetime.now()

class VulnerabilityScannerPlugin(BasePlugin):
    """Plugin for scanning web applications for vulnerabilities."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the vulnerability scanner plugin.
        
        Args:
            config: Optional configuration dictionary with the following keys:
                - timeout: Request timeout in seconds (default: 30)
                - max_redirects: Maximum number of redirects to follow (default: 5)
                - user_agent: User agent string (default: "BBF/1.0")
                - verify_ssl: Whether to verify SSL certificates (default: True)
                - enabled_checks: List of vulnerability checks to enable
                - rate_limit: Maximum requests per second (default: 10)
                - headers_to_check: List of security headers to check
                - ssl_versions: List of SSL/TLS versions to check
                - injection_points: List of parameters to test for injection
        """
        super().__init__(config)
        
        # Plugin metadata
        self.name = "vulnerability_scanner"
        self.description = "Scans web applications for common vulnerabilities"
        self.version = "1.0.0"
        self.enabled = True
        
        # Configuration with defaults
        self.timeout = config.get("timeout", 30)
        self.max_redirects = config.get("max_redirects", 5)
        self.user_agent = config.get("user_agent", "BBF/1.0")
        self.verify_ssl = config.get("verify_ssl", True)
        self.enabled_checks = config.get("enabled_checks", [
            "xss", "sqli", "csrf", "headers", "ssl", "config"
        ])
        self.rate_limit = config.get("rate_limit", 10)
        self.headers_to_check = config.get("headers_to_check", [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "Referrer-Policy"
        ])
        self.ssl_versions = config.get("ssl_versions", [
            "TLSv1.2",
            "TLSv1.3"
        ])
        self.injection_points = config.get("injection_points", [
            "id", "page", "file", "path", "query", "search",
            "input", "data", "user", "username", "password"
        ])
        
        # Test payloads for various vulnerabilities
        self.test_payloads = {
            "xss": [
                "<script>alert(1)</script>",
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
                "\"><script>alert(1)</script>"
            ],
            "sqli": [
                "' OR '1'='1",
                "1' OR '1'='1",
                "1; DROP TABLE users",
                "1' UNION SELECT null--"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ]
        }
        
        # Session for making requests
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        
    async def execute(self, target: str) -> ScanResult:
        """Execute the vulnerability scan against the target.
        
        Args:
            target: The target URL to scan
            
        Returns:
            ScanResult containing discovered vulnerabilities
            
        Raises:
            PluginError: If the scan fails
        """
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={"User-Agent": self.user_agent}
            )
            self.semaphore = asyncio.Semaphore(self.rate_limit)
            
        try:
            # Validate target URL
            if not target.startswith(("http://", "https://")):
                target = f"http://{target}"
                
            # Run all enabled checks in parallel
            tasks = []
            if "headers" in self.enabled_checks:
                tasks.append(self._check_security_headers(target))
            if "ssl" in self.enabled_checks:
                tasks.append(self._check_ssl_tls(target))
            if "xss" in self.enabled_checks:
                tasks.append(self._check_xss(target))
            if "sqli" in self.enabled_checks:
                tasks.append(self._check_sqli(target))
            if "csrf" in self.enabled_checks:
                tasks.append(self._check_csrf(target))
            if "config" in self.enabled_checks:
                tasks.append(self._check_misconfigurations(target))
                
            # Wait for all checks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            vulnerabilities = []
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Check failed: {str(result)}")
                    continue
                if isinstance(result, list):
                    vulnerabilities.extend(result)
                    
            return ScanResult(
                plugin_name=self.name,
                status=ScanStatus.COMPLETED,
                data={
                    "vulnerabilities": [
                        {
                            "name": v.name,
                            "category": v.category.value,
                            "severity": v.severity,
                            "description": v.description,
                            "location": v.location,
                            "evidence": v.evidence,
                            "cwe": v.cwe,
                            "cve": v.cve,
                            "remediation": v.remediation,
                            "timestamp": v.timestamp.isoformat()
                        }
                        for v in vulnerabilities
                    ]
                }
            )
            
        except Exception as e:
            raise PluginError(f"Vulnerability scan failed: {str(e)}")
            
    async def _check_security_headers(self, target: str) -> List[Vulnerability]:
        """Check for missing or misconfigured security headers."""
        vulnerabilities = []
        
        async with self.semaphore:
            try:
                async with self.session.get(target) as response:
                    headers = response.headers
                    
                    # Check each security header
                    for header in self.headers_to_check:
                        if header not in headers:
                            vulnerabilities.append(Vulnerability(
                                name=f"Missing {header}",
                                category=VulnCategory.HEADER,
                                severity="medium",
                                description=f"The {header} security header is not set",
                                location=target,
                                evidence=f"Header {header} not found in response",
                                cwe="CWE-1021",
                                remediation=f"Add the {header} header to your server configuration"
                            ))
                        elif header == "Strict-Transport-Security":
                            # Check HSTS configuration
                            hsts = headers[header]
                            if "max-age=0" in hsts:
                                vulnerabilities.append(Vulnerability(
                                    name="HSTS Disabled",
                                    category=VulnCategory.HEADER,
                                    severity="high",
                                    description="HSTS is disabled (max-age=0)",
                                    location=target,
                                    evidence=f"HSTS header: {hsts}",
                                    cwe="CWE-523",
                                    remediation="Enable HSTS with a reasonable max-age value"
                                ))
                                
            except Exception as e:
                logger.error(f"Header check failed: {str(e)}")
                
        return vulnerabilities
        
    async def _check_ssl_tls(self, target: str) -> List[Vulnerability]:
        """Check SSL/TLS configuration."""
        vulnerabilities = []
        
        if not target.startswith("https://"):
            vulnerabilities.append(Vulnerability(
                name="No HTTPS",
                category=VulnCategory.SSL,
                severity="high",
                description="The site does not use HTTPS",
                location=target,
                evidence="Site uses HTTP instead of HTTPS",
                cwe="CWE-319",
                remediation="Enable HTTPS and redirect HTTP to HTTPS"
            ))
            return vulnerabilities
            
        try:
            # Parse the hostname
            hostname = urlparse(target).netloc
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Connect and get certificate
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    if not_after < datetime.now():
                        vulnerabilities.append(Vulnerability(
                            name="Expired SSL Certificate",
                            category=VulnCategory.SSL,
                            severity="high",
                            description="The SSL certificate has expired",
                            location=target,
                            evidence=f"Certificate expired on {not_after}",
                            cwe="CWE-298",
                            remediation="Renew the SSL certificate"
                        ))
                        
                    # Check certificate chain
                    if not cert.get("issuer"):
                        vulnerabilities.append(Vulnerability(
                            name="Invalid Certificate Chain",
                            category=VulnCategory.SSL,
                            severity="high",
                            description="The SSL certificate chain is invalid",
                            location=target,
                            evidence="Missing certificate issuer information",
                            cwe="CWE-295",
                            remediation="Ensure proper certificate chain is configured"
                        ))
                        
        except ssl.SSLError as e:
            vulnerabilities.append(Vulnerability(
                name="SSL/TLS Error",
                category=VulnCategory.SSL,
                severity="high",
                description=f"SSL/TLS configuration error: {str(e)}",
                location=target,
                evidence=str(e),
                cwe="CWE-326",
                remediation="Fix SSL/TLS configuration issues"
            ))
        except Exception as e:
            logger.error(f"SSL check failed: {str(e)}")
            
        return vulnerabilities
        
    async def _check_xss(self, target: str) -> List[Vulnerability]:
        """Check for Cross-Site Scripting vulnerabilities."""
        vulnerabilities = []
        
        # Get all forms and input parameters
        async with self.semaphore:
            try:
                async with self.session.get(target) as response:
                    html = await response.text()
                    
                    # Find all forms
                    forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL)
                    for form in forms:
                        # Find all input fields
                        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', form)
                        for input_name in inputs:
                            # Test each payload
                            for payload in self.test_payloads["xss"]:
                                # Submit form with payload
                                data = {input_name: payload}
                                async with self.session.post(target, data=data) as resp:
                                    content = await resp.text()
                                    if payload in content:
                                        vulnerabilities.append(Vulnerability(
                                            name="Cross-Site Scripting (XSS)",
                                            category=VulnCategory.XSS,
                                            severity="high",
                                            description="Reflected XSS vulnerability found",
                                            location=f"{target} (parameter: {input_name})",
                                            evidence=f"Payload reflected: {payload}",
                                            cwe="CWE-79",
                                            remediation="Implement proper input validation and output encoding"
                                        ))
                                        break
                                        
            except Exception as e:
                logger.error(f"XSS check failed: {str(e)}")
                
        return vulnerabilities
        
    async def _check_sqli(self, target: str) -> List[Vulnerability]:
        """Check for SQL Injection vulnerabilities."""
        vulnerabilities = []
        
        # Test each injection point
        for param in self.injection_points:
            for payload in self.test_payloads["sqli"]:
                async with self.semaphore:
                    try:
                        # Test GET parameter
                        url = f"{target}?{param}={payload}"
                        async with self.session.get(url) as response:
                            content = await response.text()
                            
                            # Check for SQL error messages
                            sql_errors = [
                                "SQL syntax",
                                "mysql_fetch_array",
                                "ORA-",
                                "PostgreSQL",
                                "SQLite3::",
                                "Warning: mysql_",
                                "Microsoft SQL Server",
                                "ODBC Driver"
                            ]
                            
                            for error in sql_errors:
                                if error.lower() in content.lower():
                                    vulnerabilities.append(Vulnerability(
                                        name="SQL Injection",
                                        category=VulnCategory.INJECTION,
                                        severity="critical",
                                        description="SQL injection vulnerability found",
                                        location=f"{target} (parameter: {param})",
                                        evidence=f"SQL error detected: {error}",
                                        cwe="CWE-89",
                                        remediation="Use parameterized queries and input validation"
                                    ))
                                    break
                                    
                    except Exception as e:
                        logger.error(f"SQLi check failed: {str(e)}")
                        
        return vulnerabilities
        
    async def _check_csrf(self, target: str) -> List[Vulnerability]:
        """Check for Cross-Site Request Forgery vulnerabilities."""
        vulnerabilities = []
        
        async with self.semaphore:
            try:
                async with self.session.get(target) as response:
                    html = await response.text()
                    
                    # Find all forms
                    forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL)
                    for form in forms:
                        # Check for CSRF token
                        if not re.search(r'<input[^>]*name=["\']csrf[^"\']*["\'][^>]*>', form, re.I):
                            vulnerabilities.append(Vulnerability(
                                name="Missing CSRF Protection",
                                category=VulnCategory.CSRF,
                                severity="high",
                                description="Form lacks CSRF protection",
                                location=target,
                                evidence="No CSRF token found in form",
                                cwe="CWE-352",
                                remediation="Implement CSRF tokens for all state-changing operations"
                            ))
                            
            except Exception as e:
                logger.error(f"CSRF check failed: {str(e)}")
                
        return vulnerabilities
        
    async def _check_misconfigurations(self, target: str) -> List[Vulnerability]:
        """Check for common misconfigurations."""
        vulnerabilities = []
        
        async with self.semaphore:
            try:
                # Check for directory listing
                test_paths = ["/images/", "/img/", "/files/", "/uploads/", "/backup/"]
                for path in test_paths:
                    url = urljoin(target, path)
                    async with self.session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            if "<title>Index of" in content or "<h1>Index of" in content:
                                vulnerabilities.append(Vulnerability(
                                    name="Directory Listing Enabled",
                                    category=VulnCategory.CONFIG,
                                    severity="medium",
                                    description="Directory listing is enabled",
                                    location=url,
                                    evidence="Directory listing page found",
                                    cwe="CWE-548",
                                    remediation="Disable directory listing in web server configuration"
                                ))
                                
                # Check for common sensitive files
                sensitive_files = [
                    "/.git/config",
                    "/.env",
                    "/wp-config.php",
                    "/config.php",
                    "/backup.sql",
                    "/phpinfo.php"
                ]
                for file in sensitive_files:
                    url = urljoin(target, file)
                    async with self.session.get(url) as response:
                        if response.status == 200:
                            vulnerabilities.append(Vulnerability(
                                name="Sensitive File Exposure",
                                category=VulnCategory.CONFIG,
                                severity="high",
                                description="Sensitive file is publicly accessible",
                                location=url,
                                evidence=f"File accessible: {file}",
                                cwe="CWE-538",
                                remediation="Remove or restrict access to sensitive files"
                            ))
                            
            except Exception as e:
                logger.error(f"Misconfiguration check failed: {str(e)}")
                
        return vulnerabilities
        
    async def cleanup(self):
        """Clean up resources used by the plugin."""
        if self.session:
            await self.session.close()
            self.session = None
        self.semaphore = None 