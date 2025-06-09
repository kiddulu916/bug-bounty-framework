"""
Subdomain Enumeration Plugin for the Bug Bounty Framework.

This plugin performs subdomain enumeration using various techniques
including DNS brute-forcing, search engines, and certificate transparency logs.
"""

import asyncio
import logging
import random
import socket
import time
from typing import Dict, List, Any, Optional, Set, Tuple

from bbf.plugins import BasePlugin
from bbf.core.exceptions import PluginExecutionError

# Try to import optional dependencies
try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger("bbf.plugins.subdomain_enumeration")

class SubdomainEnumerationPlugin(BasePlugin):
    """
    Subdomain Enumeration Plugin for the Bug Bounty Framework.
    
    This plugin discovers subdomains of a target domain using various techniques:
    - DNS brute-forcing
    - Search engine scraping (Google, Bing, etc.)
    - Certificate Transparency logs
    - Common subdomain wordlists
    """
    
    name = "subdomain_enumeration"
    description = "Discover subdomains of a target domain using various techniques"
    version = "1.0.0"
    
    # Default configuration
    DEFAULT_CONFIG = {
        'wordlist': '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-50000.txt',  # Path to custom wordlist file
        'max_workers': 50,  # Maximum number of concurrent DNS lookups
        'timeout': 5,  # DNS lookup timeout in seconds
        'rate_limit': 0.1,  # Delay between requests in seconds
        'use_search_engines': True,  # Whether to use search engines
        'use_cert_transparency': True,  # Whether to check certificate transparency logs
        'recursive': True,  # Whether to recursively enumerate subdomains
        'max_recursion': 9,  # Maximum recursion depth
        'user_agents': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        ],
        'search_engines': [
            'https://www.google.com/search?q=site:*.{}'
        ],
        'ct_logs': [
            'https://crt.sh/?q=%.{}&output=json',
            'https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names',
        ],
    }
    
    # Common subdomain wordlist (first 100 entries as an example)
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'webmail', 'smtp', 'pop', 'pop3', 'imap', 'ftp', 'ssh', 'vpn',
        'api', 'dev', 'staging', 'test', 'prod', 'production', 'app', 'apps', 'admin',
        'adminpanel', 'administrator', 'login', 'signin', 'signup', 'register', 'auth',
        'secure', 'ssl', 'cloud', 'cdn', 'static', 'assets', 'media', 'files', 'img',
        'images', 'js', 'css', 'blog', 'forums', 'forum', 'community', 'support', 'help',
        'kb', 'wiki', 'docs', 'documentation', 'download', 'downloads', 'upload', 'uploads',
        'cpanel', 'whm', 'webdisk', 'webmail', 'autodiscover', 'owa', 'exchange', 'lync',
        'lyncdiscover', 'sip', 'meet', 'teams', 'sharepoint', 'portal', 'intranet',
        'extranet', 'remote', 'vpn', 'vps', 'ns1', 'ns2', 'ns3', 'ns4', 'dns1', 'dns2',
        'mx', 'mx1', 'mx2', 'mx3', 'mx4', 'mail1', 'mail2', 'mail3', 'mail4', 'smtp1',
        'smtp2', 'pop3', 'pop3s', 'imap', 'imaps', 'relay', 'relays', 'proxy', 'proxies',
        'cache', 'caches', 'balancer', 'loadbalancer', 'lb', 'gateway', 'gw', 'router',
        'firewall', 'fw', 'ids', 'ips', 'waf', 'vulnerability', 'scanner', 'monitor'
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the SubdomainEnumerationPlugin.
        
        Args:
            config: Plugin configuration dictionary
        """
        super().__init__(config or {})
        
        # Merge default config with user config
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        
        # Initialize DNS resolver
        self.resolver = None
        if dns:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = self.config['timeout']
            self.resolver.lifetime = self.config['timeout']
        
        # Initialize session for HTTP requests
        self.session = None
        if requests:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': random.choice(self.config['user_agents']),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'DNT': '1',
            })
        
        # Results storage
        self.subdomains = set()
        self.checked = set()
        self.failed = set()
    
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Execute the subdomain enumeration.
        
        Args:
            target: The target domain to enumerate subdomains for
            **kwargs: Additional arguments
            
        Returns:
            Dictionary containing the results of the subdomain enumeration
            
        Raises:
            PluginExecutionError: If the plugin fails to execute
        """
        try:
            logger.info(f"Starting subdomain enumeration for: {target}")
            
            # Normalize the target domain
            target = self._normalize_domain(target)
            
            # Load wordlist
            wordlist = await self._load_wordlist()
            
            # Enumerate subdomains using different techniques
            tasks = []
            
            # 1. Check common subdomains
            tasks.append(self._check_common_subdomains(target, wordlist))
            
            # 2. Search engine scraping (if enabled)
            if self.config['use_search_engines'] and self.session:
                tasks.append(self._search_engines(target))
            
            # 3. Certificate Transparency logs (if enabled)
            if self.config['use_cert_transparency'] and self.session:
                tasks.append(self._check_cert_transparency(target))
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            subdomains = set()
            for result in results:
                if isinstance(result, set):
                    subdomains.update(result)
            
            # Convert to list and sort
            subdomains = sorted(subdomains)
            
            logger.info(f"Found {len(subdomains)} unique subdomains for {target}")
            
            # Save results
            self.add_result('subdomains', subdomains)
            self.add_result('target', target)
            self.add_result('timestamp', time.time())
            
            return self.results
            
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {e}", exc_info=True)
            raise PluginExecutionError(f"Subdomain enumeration failed: {e}") from e
    
    async def _load_wordlist(self) -> List[str]:
        """
        Load the wordlist for subdomain brute-forcing.
        
        Returns:
            List of subdomain candidates
        """
        wordlist = set(self.COMMON_SUBDOMAINS)
        
        # Load custom wordlist if specified
        if self.config['wordlist']:
            try:
                with open(self.config['wordlist'], 'r') as f:
                    wordlist.update(line.strip() for line in f if line.strip())
            except Exception as e:
                logger.warning(f"Failed to load custom wordlist: {e}")
        
        return list(wordlist)
    
    async def _check_common_subdomains(self, domain: str, wordlist: List[str]) -> Set[str]:
        """
        Check for common subdomains using DNS resolution.
        
        Args:
            domain: The target domain
            wordlist: List of subdomain candidates
            
        Returns:
            Set of found subdomains
        """
        if not self.resolver:
            logger.warning("DNS resolver not available. Skipping DNS brute-forcing.")
            return set()
        
        logger.info(f"Checking {len(wordlist)} common subdomains for {domain}")
        
        semaphore = asyncio.Semaphore(self.config['max_workers'])
        tasks = []
        
        for sub in wordlist:
            subdomain = f"{sub}.{domain}"
            if subdomain not in self.checked:
                self.checked.add(subdomain)
                tasks.append(self._check_subdomain(subdomain, semaphore))
        
        # Run tasks in batches to avoid overwhelming the system
        batch_size = self.config['max_workers'] * 2
        results = []
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            results.extend(r for r in batch_results if isinstance(r, str))
            
            # Rate limiting
            if i + batch_size < len(tasks):
                await asyncio.sleep(self.config['rate_limit'])
        
        return set(results)
    
    async def _check_subdomain(self, subdomain: str, semaphore: asyncio.Semaphore) -> Optional[str]:
        """
        Check if a subdomain resolves to an IP address.
        
        Args:
            subdomain: The subdomain to check
            semaphore: Semaphore for limiting concurrency
            
        Returns:
            The subdomain if it resolves, None otherwise
        """
        async with semaphore:
            try:
                # Try A record first
                answers = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.resolver.resolve(subdomain, 'A')
                )
                if answers:
                    logger.debug(f"Found subdomain: {subdomain}")
                    return subdomain
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
                pass
            except Exception as e:
                logger.debug(f"Error checking {subdomain}: {e}")
                self.failed.add(subdomain)
            
            return None
    
    async def _search_engines(self, domain: str) -> Set[str]:
        """
        Search for subdomains using search engines.
        
        Args:
            domain: The target domain
            
        Returns:
            Set of found subdomains
        """
        if not self.session:
            return set()
        
        logger.info(f"Searching for subdomains of {domain} using search engines")
        
        subdomains = set()
        
        for search_url in self.config['search_engines']:
            try:
                url = search_url.format(domain)
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.session.get(url, timeout=10)
                )
                
                if response.status_code == 200:
                    # Extract subdomains from the response
                    found = self._extract_subdomains(response.text, domain)
                    subdomains.update(found)
                    
                    logger.debug(f"Found {len(found)} subdomains from {url}")
                
                # Be nice to search engines
                await asyncio.sleep(random.uniform(1, 3))
                
            except Exception as e:
                logger.debug(f"Error searching {search_url}: {e}")
        
        return subdomains
    
    async def _check_cert_transparency(self, domain: str) -> Set[str]:
        """
        Check Certificate Transparency logs for subdomains.
        
        Args:
            domain: The target domain
            
        Returns:
            Set of found subdomains
        """
        if not self.session:
            return set()
        
        logger.info(f"Checking Certificate Transparency logs for {domain}")
        
        subdomains = set()
        
        for ct_url in self.config['ct_logs']:
            try:
                url = ct_url.format(domain)
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.session.get(url, timeout=10)
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Different CT logs have different response formats
                        if 'crt.sh' in url:
                            # crt.sh format
                            for entry in data:
                                name_value = entry.get('name_value', '')
                                for name in name_value.split('\n'):
                                    name = name.strip()
                                    if name and (name.endswith(domain) or f'.{domain}' in name):
                                        subdomains.add(name.lower())
                        elif 'certspotter' in url:
                            # certspotter format
                            for cert in data:
                                for name in cert.get('dns_names', []):
                                    if name.endswith(domain):
                                        subdomains.add(name.lower())
                    except (ValueError, KeyError) as e:
                        logger.debug(f"Error parsing CT log response: {e}")
                
                # Be nice to CT log services
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.debug(f"Error checking CT log {ct_url}: {e}")
        
        return subdomains
    
    def _extract_subdomains(self, text: str, domain: str) -> Set[str]:
        """
        Extract subdomains from text using regex.
        
        Args:
            text: The text to search in
            domain: The target domain
            
        Returns:
            Set of found subdomains
        """
        import re
        
        # Simple regex to find subdomains
        pattern = r'([a-zA-Z0-9][a-zA-Z0-9-]*\.)*' + re.escape(domain)
        matches = re.findall(pattern, text, re.IGNORECASE)
        
        # Filter and normalize results
        subdomains = set()
        for match in matches:
            if match and match.endswith(domain) and len(match) > len(domain):
                subdomain = match.lower().rstrip('.')
                if subdomain not in self.checked:
                    self.checked.add(subdomain)
                    subdomains.add(subdomain)
        
        return subdomains
    
    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """
        Normalize a domain name.
        
        Args:
            domain: The domain to normalize
            
        Returns:
            Normalized domain
        """
        domain = domain.lower().strip()
        if domain.startswith('http://'):
            domain = domain[7:]
        elif domain.startswith('https://'):
            domain = domain[8:]
        if domain.startswith('www.'):
            domain = domain[4:]
        if domain.endswith('/'):
            domain = domain[:-1]
        return domain
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        await super().cleanup()
        
        # Close session if it exists
        if hasattr(self, 'session') and self.session:
            await asyncio.get_event_loop().run_in_executor(
                None,
                self.session.close
            )

# Register the plugin
from bbf.core.plugin import plugin

@plugin
class SubdomainEnumeration(SubdomainEnumerationPlugin):
    """Subdomain Enumeration Plugin"""
    pass
