"""
Directory Bruteforce Plugin for the Bug Bounty Framework.

This plugin performs directory and file bruteforcing against web servers,
testing for common paths and sensitive files.
"""

import asyncio
import logging
import re
import json
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime
import aiohttp
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urljoin, urlparse
import aiofiles
import os
from bs4 import BeautifulSoup

from bbf.core.base import BasePlugin
from bbf.core.exceptions import PluginError
from bbf.core.database.models import Finding
from bbf.core.database.service import finding_service
from bbf.plugins.config import get_wordlist
from bbf.core.validation import validate_plugin

logger = logging.getLogger(__name__)

class ResourceType(Enum):
    """Enumeration of resource types."""
    DIRECTORY = "directory"
    FILE = "file"
    BACKUP = "backup"
    SENSITIVE = "sensitive"
    OTHER = "other"

@dataclass
class Resource:
    """Information about a discovered resource."""
    path: str
    type: ResourceType
    status_code: int
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    is_accessible: bool = True
    is_interesting: bool = False
    timestamp: datetime = datetime.now()
    stage: str = 'recon'
    status: str = 'active'

class DirBrutePlugin(BasePlugin):
    """Plugin for discovering directories and files on web servers.
    
    This plugin implements various techniques for resource discovery:
    - Directory bruteforcing
    - File extension scanning
    - Backup file detection
    - Sensitive file detection
    - Common path scanning
    
    Attributes:
        name (str): The name of the plugin.
        description (str): A description of what the plugin does.
        version (str): The version of the plugin.
        enabled (bool): Whether the plugin is enabled.
        timeout (int): Maximum time in seconds for the plugin to complete.
        max_redirects (int): Maximum number of redirects to follow.
        user_agent (str): User agent string for requests.
        verify_ssl (bool): Whether to verify SSL certificates.
        wordlist_path (str): Path to the wordlist file.
        extensions (List[str]): List of file extensions to scan.
        backup_extensions (List[str]): List of backup file extensions.
        sensitive_patterns (List[str]): List of patterns for sensitive files.
        rate_limit (int): Maximum number of concurrent requests.
    """
    
    name = "dir_brute"
    description = "Discovers directories and files on web servers"
    version = "1.0.0"
    
    # Configuration
    enabled = True
    timeout = 30  # 30 seconds default timeout
    max_redirects = 5
    user_agent = "Mozilla/5.0 (compatible; BBF/1.0; +https://github.com/bbf)"
    verify_ssl = True
    rate_limit = 10  # Maximum concurrent requests
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the directory bruteforce plugin.
        
        Args:
            config: Optional configuration dictionary for the plugin.
        """
        super().__init__(config)
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._wordlist: List[str] = []
        self._results: Dict[str, List[Resource]] = {}
        
        # Get configurations from centralized config
        self.extensions = config.get('extensions', ['.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.js', '.css', '.txt', '.xml', '.json', '.vbs', '.ps1', '.pl', '.pm', '.cgi', '.lib', '.htaccess', '.htpasswd', '.pem', '.crt', '.key', '.der', '.yml', '.yaml', '.env', '.svg', '.csv', '.pdf', '.docm', '.docx', '.xlsm', '.xml', '.xls', '.exe', '.pif', '.msi', '.hta', '.zip', '.rar', '.tar', '.jar', '.war', '.cpio', '.apk', '.7z', '.git'])
        self.backup_extensions = config.get('backup_extensions', ['.bak', '.backup', '.old', '.tmp', '.temp', '.swp', '.swo', '.~', '.orig'])
        self.sensitive_patterns = config.get('sensitive_patterns', [
            r'\.git/',
            r'\.svn/',
            r'\.env',
            r'wp-config\.php',
            r'config\.php',
            r'database\.php',
            r'\.htaccess',
            r'\.htpasswd',
            r'\.DS_Store',
            r'\.idea/',
            r'\.vscode/',
            r'\.well-known/',
            r'robots\.txt',
            r'sitemap\.xml',
            r'crossdomain\.xml',
            r'phpinfo\.php',
            r'info\.php',
            r'test\.php',
            r'admin/',
            r'login/',
            r'backup/',
            r'backups/',
            r'config/',
            r'conf/',
            r'debug/',
            r'dev/',
            r'development/',
            r'logs/',
            r'log/',
            r'private/',
            r'secret/',
            r'secrets/',
            r'secure/',
            r'security/',
            r'test/',
            r'testing/',
            r'upload/',
            r'uploads/'
        ])
        
    async def initialize(self) -> None:
        """Initialize the plugin.
        
        This method:
        1. Validates the configuration
        2. Sets up the HTTP session
        3. Loads the wordlist from centralized config
        4. Creates a semaphore for rate limiting
        
        Raises:
            PluginError: If initialization fails.
        """
        try:
            # Set up HTTP session
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': self.user_agent}
            )
            
            # Create semaphore for rate limiting
            self._semaphore = asyncio.Semaphore(self.rate_limit)
            
            # Load wordlist from centralized config
            self._wordlist = get_wordlist('directory')
            if not self._wordlist:
                raise PluginError("Failed to load directory wordlist from centralized config")
                
            logger.info(f"Initialized directory bruteforce plugin with {len(self._wordlist)} entries")
            
        except Exception as e:
            logger.error(f"Plugin initialization failed: {str(e)}")
            raise PluginError(f"Plugin initialization failed: {str(e)}")
            
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the directory bruteforce scan.
        
        This method:
        1. Normalizes the target URL
        2. Scans for directories
        3. Scans for files with extensions
        4. Scans for backup files
        5. Scans for sensitive files
        6. Aggregates and processes results
        7. Stores findings in centralized database
        
        Args:
            target: The target URL to scan.
            **kwargs: Additional arguments for the plugin.
            
        Returns:
            Dict containing the scan results.
            
        Raises:
            PluginError: If execution fails.
        """
        if not self._session or not self._semaphore:
            raise PluginError("Plugin not initialized")
            
        try:
            # Initialize results
            self._results[target] = []
            start_time = datetime.now()
            
            # Normalize target URL
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"
                
            # Run scan techniques in parallel
            tasks = [
                self._scan_directories(target),
                self._scan_files(target),
                self._scan_backups(target),
                self._scan_sensitive(target)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Scan technique failed: {str(result)}")
                elif isinstance(result, list):
                    self._results[target].extend(result)
                    
            # Process and categorize results
            self._process_results(target)
            
            # Store findings in database
            await self._store_findings(target)
            
            # Calculate execution time
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            
            return {
                'target': target,
                'resources': [
                    {
                        'path': res.path,
                        'type': res.type.value,
                        'status_code': res.status_code,
                        'content_length': res.content_length,
                        'content_type': res.content_type,
                        'is_accessible': res.is_accessible,
                        'is_interesting': res.is_interesting,
                        'stage': res.stage,
                        'status': res.status
                    }
                    for res in self._results[target]
                ],
                'count': len(self._results[target]),
                'execution_time': execution_time
            }
            
        except Exception as e:
            logger.error(f"Plugin execution failed: {str(e)}")
            raise PluginError(f"Plugin execution failed: {str(e)}")
            
    async def _store_findings(self, target: str) -> None:
        """Store findings in the centralized database.
        
        Args:
            target: The target URL.
        """
        try:
            # Parse target URL
            parsed_url = urlparse(target)
            root_domain = parsed_url.netloc
            subdomain = root_domain.split('.')[0]
            
            # Group resources by type
            resources_by_type = {}
            for resource in self._results[target]:
                if resource.type.value not in resources_by_type:
                    resources_by_type[resource.type.value] = []
                resources_by_type[resource.type.value].append({
                    'path': resource.path,
                    'status_code': resource.status_code,
                    'content_length': resource.content_length,
                    'content_type': resource.content_type,
                    'is_accessible': resource.is_accessible,
                    'is_interesting': resource.is_interesting
                })
            
            # Prepare finding data
            finding_data = {
                'root_domain': root_domain,
                'subdomain': subdomain,
                'source': 'directory_bruteforce',
                'stage': 'recon',
                'status': 'active',
                'metadata': json.dumps({
                    'scan_type': 'comprehensive',
                    'resources_found': len(self._results[target]),
                    'resources_by_type': resources_by_type,
                    'scan_timestamp': datetime.now().isoformat(),
                    'scan_details': {
                        'extensions_checked': self.extensions,
                        'backup_extensions_checked': self.backup_extensions,
                        'sensitive_patterns_checked': self.sensitive_patterns
                    }
                })
            }
            
            # Store finding
            await finding_service.add_or_update_finding(
                finding_data=finding_data,
                merge_metadata=True
            )
            
            logger.info(f"Stored {len(self._results[target])} resources in database")
            
        except Exception as e:
            logger.error(f"Failed to store findings in database: {str(e)}")
            raise PluginError(f"Failed to store findings in database: {str(e)}")
            
    async def _scan_directories(self, target: str) -> List[Resource]:
        """Scan for directories using the wordlist.
        
        Args:
            target: The target URL.
            
        Returns:
            List of discovered resources.
        """
        resources: List[Resource] = []
        tasks = []
        
        for path in self._wordlist:
            url = urljoin(target, path)
            tasks.append(self._check_resource(url, ResourceType.DIRECTORY))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Resource):
                resources.append(result)
                
        return resources
        
    async def _scan_files(self, target: str) -> List[Resource]:
        """Scan for files with common extensions.
        
        Args:
            target: The target URL.
            
        Returns:
            List of discovered resources.
        """
        resources: List[Resource] = []
        tasks = []
        
        for path in self._wordlist:
            for ext in self.extensions:
                url = urljoin(target, f"{path}{ext}")
                tasks.append(self._check_resource(url, ResourceType.FILE))
                
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Resource):
                resources.append(result)
                
        return resources
        
    async def _scan_backups(self, target: str) -> List[Resource]:
        """Scan for backup files.
        
        Args:
            target: The target URL.
            
        Returns:
            List of discovered resources.
        """
        resources: List[Resource] = []
        tasks = []
        
        for path in self._wordlist:
            for ext in self.backup_extensions:
                url = urljoin(target, f"{path}{ext}")
                tasks.append(self._check_resource(url, ResourceType.BACKUP))
                
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Resource):
                resources.append(result)
                
        return resources
        
    async def _scan_sensitive(self, target: str) -> List[Resource]:
        """Scan for sensitive files and directories.
        
        Args:
            target: The target URL.
            
        Returns:
            List of discovered resources.
        """
        resources: List[Resource] = []
        tasks = []
        
        for pattern in self.sensitive_patterns:
            url = urljoin(target, pattern.rstrip('/'))
            tasks.append(self._check_resource(url, ResourceType.SENSITIVE))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Resource):
                resources.append(result)
                
        return resources
        
    async def _check_resource(self, url: str, resource_type: ResourceType) -> Optional[Resource]:
        """Check if a resource exists and is accessible.
        
        Args:
            url: The URL to check.
            resource_type: The type of resource.
            
        Returns:
            Resource object if the resource exists and is accessible, None otherwise.
        """
        async with self._semaphore:  # Rate limiting
            try:
                async with self._session.head(
                    url,
                    allow_redirects=True,
                    max_redirects=self.max_redirects,
                    ssl=self.verify_ssl
                ) as response:
                    if response.status < 400:  # Resource exists and is accessible
                        return Resource(
                            path=urlparse(url).path,
                            type=resource_type,
                            status_code=response.status,
                            content_length=int(response.headers.get('Content-Length', 0)),
                            content_type=response.headers.get('Content-Type'),
                            is_accessible=True,
                            is_interesting=self._is_interesting_resource(url, response)
                        )
                    elif response.status == 401 or response.status == 403:
                        # Resource exists but requires authentication
                        return Resource(
                            path=urlparse(url).path,
                            type=resource_type,
                            status_code=response.status,
                            is_accessible=False,
                            is_interesting=True  # Authentication required is interesting
                        )
                        
            except aiohttp.ClientError as e:
                logger.debug(f"Failed to check resource {url}: {str(e)}")
                
        return None
        
    def _is_interesting_resource(self, url: str, response: aiohttp.ClientResponse) -> bool:
        """Determine if a resource is interesting based on various factors.
        
        Args:
            url: The resource URL.
            response: The HTTP response.
            
        Returns:
            True if the resource is interesting, False otherwise.
        """
        # Check status code
        if response.status in (200, 201, 202, 203, 204):
            # Check content length
            content_length = int(response.headers.get('Content-Length', 0))
            if content_length > 0 and content_length < 1000000:  # Not too large
                # Check content type
                content_type = response.headers.get('Content-Type', '').lower()
                if any(t in content_type for t in ['text', 'json', 'xml', 'html']):
                    # Check URL patterns
                    path = urlparse(url).path.lower()
                    return any(
                        pattern.lower() in path
                        for pattern in self.sensitive_patterns
                    )
                    
        return False
        
    def _process_results(self, target: str) -> None:
        """Process and categorize scan results.
        
        This method:
        1. Removes duplicate entries
        2. Sorts results by type and path
        3. Updates the results dictionary
        
        Args:
            target: The target URL.
        """
        # Remove duplicates based on path
        unique_results = {
            res.path: res
            for res in self._results[target]
        }
        
        # Sort results
        self._results[target] = sorted(
            unique_results.values(),
            key=lambda x: (x.type.value, x.path)
        ) 