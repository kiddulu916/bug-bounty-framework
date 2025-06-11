"""
Plugin Marketplace System

This module provides functionality for discovering, installing, and managing plugins
from a central marketplace. It includes features for:
- Plugin discovery and search
- Plugin installation and updates
- Plugin ratings and reviews
- Plugin analytics and usage statistics
- Plugin dependency resolution
- Plugin security verification
"""

import asyncio
import json
import logging
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin

import aiohttp
import semver
from packaging import version

from bbf.core.exceptions import (
    MarketplaceError,
    PluginInstallationError,
    PluginVerificationError,
    PluginUpdateError,
)
from bbf.core.plugin import PluginRegistry
from bbf.core.validation import validate_plugin

logger = logging.getLogger(__name__)

class PluginPackage:
    """Represents a plugin package in the marketplace."""
    
    def __init__(
        self,
        name: str,
        version: str,
        description: str,
        author: str,
        repository: str,
        dependencies: Dict[str, str],
        tags: List[str],
        rating: float = 0.0,
        downloads: int = 0,
        verified: bool = False,
        metadata: Optional[Dict] = None
    ):
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.repository = repository
        self.dependencies = dependencies
        self.tags = tags
        self.rating = rating
        self.downloads = downloads
        self.verified = verified
        self.metadata = metadata or {}
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    @classmethod
    def from_dict(cls, data: Dict) -> 'PluginPackage':
        """Create a PluginPackage from a dictionary."""
        return cls(
            name=data['name'],
            version=data['version'],
            description=data['description'],
            author=data['author'],
            repository=data['repository'],
            dependencies=data.get('dependencies', {}),
            tags=data.get('tags', []),
            rating=data.get('rating', 0.0),
            downloads=data.get('downloads', 0),
            verified=data.get('verified', False),
            metadata=data.get('metadata', {})
        )

    def to_dict(self) -> Dict:
        """Convert the plugin package to a dictionary."""
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': self.author,
            'repository': self.repository,
            'dependencies': self.dependencies,
            'tags': self.tags,
            'rating': self.rating,
            'downloads': self.downloads,
            'verified': self.verified,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class PluginReview:
    """Represents a review for a plugin."""
    
    def __init__(
        self,
        plugin_name: str,
        author: str,
        rating: float,
        comment: str,
        version: str,
        created_at: Optional[datetime] = None
    ):
        self.plugin_name = plugin_name
        self.author = author
        self.rating = max(0.0, min(5.0, rating))
        self.comment = comment
        self.version = version
        self.created_at = created_at or datetime.utcnow()

    @classmethod
    def from_dict(cls, data: Dict) -> 'PluginReview':
        """Create a PluginReview from a dictionary."""
        return cls(
            plugin_name=data['plugin_name'],
            author=data['author'],
            rating=data['rating'],
            comment=data['comment'],
            version=data['version'],
            created_at=datetime.fromisoformat(data['created_at'])
        )

    def to_dict(self) -> Dict:
        """Convert the review to a dictionary."""
        return {
            'plugin_name': self.plugin_name,
            'author': self.author,
            'rating': self.rating,
            'comment': self.comment,
            'version': self.version,
            'created_at': self.created_at.isoformat()
        }

class Marketplace:
    """Manages the plugin marketplace functionality."""
    
    def __init__(
        self,
        registry: PluginRegistry,
        marketplace_url: str,
        cache_dir: Optional[str] = None,
        verify_ssl: bool = True
    ):
        self.registry = registry
        self.marketplace_url = marketplace_url.rstrip('/')
        self.cache_dir = cache_dir or os.path.join(tempfile.gettempdir(), 'bbf_marketplace')
        self.verify_ssl = verify_ssl
        self._session: Optional[aiohttp.ClientSession] = None
        self._packages: Dict[str, PluginPackage] = {}
        self._reviews: Dict[str, List[PluginReview]] = {}
        
        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)

    async def __aenter__(self) -> 'Marketplace':
        """Set up the marketplace session."""
        self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up the marketplace session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def search(
        self,
        query: str,
        tags: Optional[List[str]] = None,
        min_rating: float = 0.0,
        verified_only: bool = False
    ) -> List[PluginPackage]:
        """Search for plugins in the marketplace."""
        if not self._session:
            raise MarketplaceError("Marketplace session not initialized")

        params = {
            'q': query,
            'min_rating': min_rating,
            'verified': verified_only
        }
        if tags:
            params['tags'] = ','.join(tags)

        async with self._session.get(
            f"{self.marketplace_url}/search",
            params=params,
            ssl=self.verify_ssl
        ) as response:
            if response.status != 200:
                raise MarketplaceError(f"Search failed: {response.status}")
            
            data = await response.json()
            return [PluginPackage.from_dict(pkg) for pkg in data['packages']]

    async def get_package(self, name: str) -> Optional[PluginPackage]:
        """Get a specific plugin package."""
        if not self._session:
            raise MarketplaceError("Marketplace session not initialized")

        async with self._session.get(
            f"{self.marketplace_url}/package/{name}",
            ssl=self.verify_ssl
        ) as response:
            if response.status == 404:
                return None
            if response.status != 200:
                raise MarketplaceError(f"Failed to get package: {response.status}")
            
            data = await response.json()
            return PluginPackage.from_dict(data)

    async def get_reviews(
        self,
        plugin_name: str,
        min_rating: float = 0.0,
        limit: int = 10
    ) -> List[PluginReview]:
        """Get reviews for a plugin."""
        if not self._session:
            raise MarketplaceError("Marketplace session not initialized")

        params = {
            'min_rating': min_rating,
            'limit': limit
        }

        async with self._session.get(
            f"{self.marketplace_url}/package/{plugin_name}/reviews",
            params=params,
            ssl=self.verify_ssl
        ) as response:
            if response.status != 200:
                raise MarketplaceError(f"Failed to get reviews: {response.status}")
            
            data = await response.json()
            return [PluginReview.from_dict(review) for review in data['reviews']]

    async def install(
        self,
        name: str,
        version: Optional[str] = None,
        force: bool = False
    ) -> None:
        """Install a plugin from the marketplace."""
        if not self._session:
            raise MarketplaceError("Marketplace session not initialized")

        # Get package information
        package = await self.get_package(name)
        if not package:
            raise PluginInstallationError(f"Plugin {name} not found")

        if version and version != package.version:
            raise PluginInstallationError(
                f"Version {version} not found for plugin {name}"
            )

        # Check if plugin is already installed
        if name in self.registry.plugins and not force:
            raise PluginInstallationError(
                f"Plugin {name} is already installed. Use force=True to reinstall"
            )

        # Download plugin
        async with self._session.get(
            f"{self.marketplace_url}/package/{name}/download",
            params={'version': version} if version else None,
            ssl=self.verify_ssl
        ) as response:
            if response.status != 200:
                raise PluginInstallationError(
                    f"Failed to download plugin: {response.status}"
                )

            # Create temporary directory for plugin
            with tempfile.TemporaryDirectory() as temp_dir:
                plugin_path = os.path.join(temp_dir, f"{name}.zip")
                
                # Save plugin to temporary file
                with open(plugin_path, 'wb') as f:
                    f.write(await response.read())

                # Extract and validate plugin
                try:
                    # Extract plugin
                    shutil.unpack_archive(plugin_path, temp_dir)
                    
                    # Find plugin module
                    plugin_dir = os.path.join(temp_dir, name)
                    if not os.path.exists(plugin_dir):
                        raise PluginInstallationError(
                            f"Invalid plugin package structure for {name}"
                        )

                    # Validate plugin
                    plugin_module = self._load_plugin_module(plugin_dir)
                    validate_plugin(plugin_module)

                    # Install plugin
                    plugin_path = os.path.join(
                        self.registry.plugin_dir,
                        name
                    )
                    if os.path.exists(plugin_path):
                        shutil.rmtree(plugin_path)
                    shutil.copytree(plugin_dir, plugin_path)

                    # Register plugin
                    self.registry.register(plugin_module)

                except Exception as e:
                    raise PluginInstallationError(
                        f"Failed to install plugin {name}: {str(e)}"
                    )

    async def update(self, name: str, force: bool = False) -> None:
        """Update an installed plugin to the latest version."""
        if not self._session:
            raise MarketplaceError("Marketplace session not initialized")

        # Get current version
        if name not in self.registry.plugins:
            raise PluginUpdateError(f"Plugin {name} is not installed")

        current_version = self.registry.plugins[name].version

        # Get latest version
        package = await self.get_package(name)
        if not package:
            raise PluginUpdateError(f"Plugin {name} not found in marketplace")

        if version.parse(package.version) <= version.parse(current_version):
            if not force:
                raise PluginUpdateError(
                    f"Plugin {name} is already at the latest version"
                )

        # Install latest version
        await self.install(name, package.version, force=True)

    async def uninstall(self, name: str) -> None:
        """Uninstall a plugin."""
        if name not in self.registry.plugins:
            raise PluginInstallationError(f"Plugin {name} is not installed")

        try:
            # Unregister plugin
            self.registry.unregister(name)

            # Remove plugin files
            plugin_path = os.path.join(self.registry.plugin_dir, name)
            if os.path.exists(plugin_path):
                shutil.rmtree(plugin_path)

        except Exception as e:
            raise PluginInstallationError(
                f"Failed to uninstall plugin {name}: {str(e)}"
            )

    async def submit_review(
        self,
        plugin_name: str,
        author: str,
        rating: float,
        comment: str
    ) -> None:
        """Submit a review for a plugin."""
        if not self._session:
            raise MarketplaceError("Marketplace session not initialized")

        # Verify plugin exists
        if plugin_name not in self.registry.plugins:
            raise MarketplaceError(f"Plugin {plugin_name} is not installed")

        review = PluginReview(
            plugin_name=plugin_name,
            author=author,
            rating=rating,
            comment=comment,
            version=self.registry.plugins[plugin_name].version
        )

        async with self._session.post(
            f"{self.marketplace_url}/package/{plugin_name}/review",
            json=review.to_dict(),
            ssl=self.verify_ssl
        ) as response:
            if response.status != 200:
                raise MarketplaceError(f"Failed to submit review: {response.status}")

    def _load_plugin_module(self, plugin_dir: str) -> type:
        """Load a plugin module from a directory."""
        # Add plugin directory to Python path
        sys.path.insert(0, os.path.dirname(plugin_dir))
        try:
            # Import plugin module
            module_name = os.path.basename(plugin_dir)
            module = __import__(module_name)
            
            # Find plugin class
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type) and
                    issubclass(attr, self.registry.base_plugin) and
                    attr != self.registry.base_plugin
                ):
                    return attr
            
            raise PluginInstallationError(
                f"No plugin class found in {module_name}"
            )
        finally:
            # Remove plugin directory from Python path
            sys.path.pop(0) 