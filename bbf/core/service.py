"""
Core service management system for the Bug Bounty Framework.

This module provides functionality for managing core services, including:
- Service discovery and registration
- Health checks and monitoring
- Metrics collection and reporting
- Logging and tracing
- Service configuration
"""

import asyncio
import json
import logging
import os
import signal
import time
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type, TypeVar, Union

import aiohttp
import prometheus_client
from aiohttp import web
from .exceptions import (
    ServiceError,
    ServiceRegistrationError,
    ServiceDiscoveryError,
    ServiceHealthError,
    ServiceConfigError
)

logger = logging.getLogger(__name__)

# Type variables for generic functions
T = TypeVar('T')

class ServiceStatus(Enum):
    """Service status enumeration."""
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"

class ServiceHealth:
    """
    Service health information.
    
    This class tracks the health status of a service, including:
    - Current status
    - Health checks
    - Metrics
    - Last update time
    """
    
    def __init__(self, service_name: str):
        """
        Initialize service health.
        
        Args:
            service_name: Name of the service
        """
        self.service_name = service_name
        self.status = ServiceStatus.STARTING
        self.health_checks: Dict[str, bool] = {}
        self.metrics: Dict[str, float] = {}
        self.last_update = datetime.utcnow()
        self.error_count = 0
        self.warning_count = 0
    
    def update_status(self, status: ServiceStatus) -> None:
        """
        Update service status.
        
        Args:
            status: New service status
        """
        self.status = status
        self.last_update = datetime.utcnow()
    
    def update_health_check(self, check_name: str, is_healthy: bool) -> None:
        """
        Update health check status.
        
        Args:
            check_name: Name of the health check
            is_healthy: Whether the check passed
        """
        self.health_checks[check_name] = is_healthy
        self.last_update = datetime.utcnow()
        
        if not is_healthy:
            self.error_count += 1
            self.status = ServiceStatus.DEGRADED
    
    def update_metric(self, metric_name: str, value: float) -> None:
        """
        Update service metric.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
        """
        self.metrics[metric_name] = value
        self.last_update = datetime.utcnow()
    
    def is_healthy(self) -> bool:
        """
        Check if service is healthy.
        
        Returns:
            bool: True if service is healthy, False otherwise
        """
        return (
            self.status == ServiceStatus.RUNNING and
            all(self.health_checks.values()) and
            self.error_count == 0
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert health information to dictionary.
        
        Returns:
            Dictionary containing health information
        """
        return {
            'service_name': self.service_name,
            'status': self.status.value,
            'health_checks': self.health_checks,
            'metrics': self.metrics,
            'last_update': self.last_update.isoformat(),
            'error_count': self.error_count,
            'warning_count': self.warning_count,
            'is_healthy': self.is_healthy()
        }

class ServiceConfig:
    """
    Service configuration.
    
    This class manages service configuration, including:
    - Configuration loading and validation
    - Configuration persistence
    - Configuration updates
    """
    
    def __init__(self, service_name: str, config_path: Optional[Path] = None):
        """
        Initialize service configuration.
        
        Args:
            service_name: Name of the service
            config_path: Path to configuration file
        """
        self.service_name = service_name
        self.config_path = config_path or Path(f'data/services/{service_name}/config.json')
        self.config: Dict[str, Any] = {}
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
            else:
                # Create default configuration
                self.config = self._create_default_config()
                self._save_config()
        except Exception as e:
            logger.error(f"Failed to load config for {self.service_name}: {e}")
            self.config = self._create_default_config()
    
    def _create_default_config(self) -> Dict[str, Any]:
        """
        Create default configuration.
        
        Returns:
            Dictionary containing default configuration
        """
        return {
            'service_name': self.service_name,
            'enabled': True,
            'host': 'localhost',
            'port': 8080,
            'timeout': 30,
            'max_connections': 100,
            'log_level': 'INFO',
            'metrics_enabled': True,
            'health_check_interval': 30,
            'retry_count': 3,
            'retry_delay': 1,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }
    
    def _save_config(self) -> None:
        """Save configuration to file."""
        try:
            # Create directory if it doesn't exist
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save configuration
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save config for {self.service_name}: {e}")
            raise ServiceConfigError(f"Failed to save config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value.
        
        Args:
            key: Configuration key
            value: Configuration value
        """
        self.config[key] = value
        self.config['updated_at'] = datetime.utcnow().isoformat()
        self._save_config()
    
    def update(self, **kwargs) -> None:
        """
        Update multiple configuration values.
        
        Args:
            **kwargs: Configuration key-value pairs
        """
        self.config.update(kwargs)
        self.config['updated_at'] = datetime.utcnow().isoformat()
        self._save_config()
    
    def validate(self) -> bool:
        """
        Validate configuration.
        
        Returns:
            bool: True if configuration is valid, False otherwise
            
        Raises:
            ServiceConfigError: If validation fails
        """
        try:
            # Required fields
            required_fields = {'service_name', 'enabled', 'host', 'port'}
            missing_fields = required_fields - set(self.config.keys())
            if missing_fields:
                raise ServiceConfigError(
                    f"Missing required fields: {', '.join(missing_fields)}"
                )
            
            # Field types
            if not isinstance(self.config['service_name'], str):
                raise ServiceConfigError("service_name must be a string")
            if not isinstance(self.config['enabled'], bool):
                raise ServiceConfigError("enabled must be a boolean")
            if not isinstance(self.config['host'], str):
                raise ServiceConfigError("host must be a string")
            if not isinstance(self.config['port'], int):
                raise ServiceConfigError("port must be an integer")
            
            # Field ranges
            if not 0 <= self.config['port'] <= 65535:
                raise ServiceConfigError("port must be between 0 and 65535")
            if self.config['timeout'] < 0:
                raise ServiceConfigError("timeout must be non-negative")
            if self.config['max_connections'] < 1:
                raise ServiceConfigError("max_connections must be positive")
            
            return True
            
        except Exception as e:
            if isinstance(e, ServiceConfigError):
                raise
            raise ServiceConfigError(f"Configuration validation failed: {str(e)}")

class Service:
    """
    Base class for all services.
    
    This class provides common functionality for:
    - Service lifecycle management
    - Health checks
    - Metrics collection
    - Logging
    - Configuration
    """
    
    def __init__(self, name: str, config_path: Optional[Path] = None):
        """
        Initialize service.
        
        Args:
            name: Service name
            config_path: Path to configuration file
        """
        self.name = name
        self.config = ServiceConfig(name, config_path)
        self.health = ServiceHealth(name)
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        
        # Set up logging
        self.logger = logging.getLogger(f"bbf.services.{name}")
        self.logger.setLevel(self.config.get('log_level', 'INFO'))
        
        # Set up metrics
        if self.config.get('metrics_enabled', True):
            self._setup_metrics()
    
    def _setup_metrics(self) -> None:
        """Set up service metrics."""
        # Create metrics
        self.metrics = {
            'request_count': prometheus_client.Counter(
                f'{self.name}_requests_total',
                'Total number of requests',
                ['method', 'endpoint', 'status']
            ),
            'request_latency': prometheus_client.Histogram(
                f'{self.name}_request_duration_seconds',
                'Request latency in seconds',
                ['method', 'endpoint']
            ),
            'error_count': prometheus_client.Counter(
                f'{self.name}_errors_total',
                'Total number of errors',
                ['type']
            ),
            'active_connections': prometheus_client.Gauge(
                f'{self.name}_active_connections',
                'Number of active connections'
            )
        }
    
    async def start(self) -> None:
        """
        Start the service.
        
        This method:
        1. Validates configuration
        2. Sets up routes
        3. Starts the web server
        4. Initializes health checks
        5. Starts metrics collection
        
        Raises:
            ServiceError: If service fails to start
        """
        try:
            # Validate configuration
            self.config.validate()
            
            # Set up routes
            self._setup_routes()
            
            # Create runner
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            
            # Start server
            self.site = web.TCPSite(
                self.runner,
                self.config.get('host', 'localhost'),
                self.config.get('port', 8080)
            )
            await self.site.start()
            
            # Update health
            self.health.update_status(ServiceStatus.RUNNING)
            
            # Start health checks
            asyncio.create_task(self._run_health_checks())
            
            # Start metrics collection
            if self.config.get('metrics_enabled', True):
                asyncio.create_task(self._collect_metrics())
            
            self.logger.info(
                f"Service {self.name} started on "
                f"{self.config.get('host')}:{self.config.get('port')}"
            )
            
        except Exception as e:
            self.health.update_status(ServiceStatus.ERROR)
            self.logger.error(f"Failed to start service {self.name}: {e}")
            raise ServiceError(f"Service failed to start: {str(e)}") from e
    
    async def stop(self) -> None:
        """
        Stop the service.
        
        This method:
        1. Updates service status
        2. Stops the web server
        3. Cleans up resources
        
        Raises:
            ServiceError: If service fails to stop
        """
        try:
            # Update health
            self.health.update_status(ServiceStatus.STOPPING)
            
            # Stop server
            if self.site:
                await self.site.stop()
            if self.runner:
                await self.runner.cleanup()
            
            # Update health
            self.health.update_status(ServiceStatus.STOPPED)
            
            self.logger.info(f"Service {self.name} stopped")
            
        except Exception as e:
            self.health.update_status(ServiceStatus.ERROR)
            self.logger.error(f"Failed to stop service {self.name}: {e}")
            raise ServiceError(f"Service failed to stop: {str(e)}") from e
    
    def _setup_routes(self) -> None:
        """Set up service routes."""
        # Health check endpoint
        self.app.router.add_get('/health', self._handle_health)
        
        # Metrics endpoint
        if self.config.get('metrics_enabled', True):
            self.app.router.add_get('/metrics', self._handle_metrics)
        
        # Configuration endpoint
        self.app.router.add_get('/config', self._handle_get_config)
        self.app.router.add_put('/config', self._handle_update_config)
    
    async def _handle_health(self, request: web.Request) -> web.Response:
        """
        Handle health check request.
        
        Args:
            request: HTTP request
            
        Returns:
            HTTP response
        """
        return web.json_response(self.health.to_dict())
    
    async def _handle_metrics(self, request: web.Request) -> web.Response:
        """
        Handle metrics request.
        
        Args:
            request: HTTP request
            
        Returns:
            HTTP response
        """
        if not self.config.get('metrics_enabled', True):
            raise web.HTTPForbidden(reason="Metrics are disabled")
        
        return web.Response(
            body=prometheus_client.generate_latest(),
            content_type=prometheus_client.CONTENT_TYPE_LATEST
        )
    
    async def _handle_get_config(self, request: web.Request) -> web.Response:
        """
        Handle get configuration request.
        
        Args:
            request: HTTP request
            
        Returns:
            HTTP response
        """
        return web.json_response(self.config.config)
    
    async def _handle_update_config(self, request: web.Request) -> web.Response:
        """
        Handle update configuration request.
        
        Args:
            request: HTTP request
            
        Returns:
            HTTP response
        """
        try:
            # Get new configuration
            new_config = await request.json()
            
            # Update configuration
            self.config.update(**new_config)
            
            # Validate configuration
            self.config.validate()
            
            return web.json_response(self.config.config)
            
        except Exception as e:
            raise web.HTTPBadRequest(reason=str(e))
    
    async def _run_health_checks(self) -> None:
        """Run periodic health checks."""
        while True:
            try:
                # Run health checks
                await self._check_health()
                
                # Wait for next check
                await asyncio.sleep(
                    self.config.get('health_check_interval', 30)
                )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health check failed: {e}")
                self.health.update_status(ServiceStatus.DEGRADED)
    
    async def _check_health(self) -> None:
        """
        Run health checks.
        
        This method should be implemented by subclasses to perform
        service-specific health checks.
        """
        # Default health check: check if server is running
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://{self.config.get('host')}:{self.config.get('port')}/health"
                ) as response:
                    if response.status == 200:
                        self.health.update_health_check('server', True)
                    else:
                        self.health.update_health_check('server', False)
        except Exception as e:
            self.logger.error(f"Server health check failed: {e}")
            self.health.update_health_check('server', False)
    
    async def _collect_metrics(self) -> None:
        """Collect service metrics."""
        while True:
            try:
                # Update metrics
                self.metrics['active_connections'].set(
                    len(self.app['websockets']) if 'websockets' in self.app else 0
                )
                
                # Wait for next collection
                await asyncio.sleep(1)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Metrics collection failed: {e}")

class ServiceRegistry:
    """
    Registry for managing services.
    
    This class provides a central interface for:
    - Service registration and discovery
    - Health monitoring
    - Metrics aggregation
    - Configuration management
    """
    
    _instance = None
    _services: Dict[str, Service] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def register(cls, service: Service) -> None:
        """
        Register a service.
        
        Args:
            service: Service to register
            
        Raises:
            ServiceRegistrationError: If registration fails
        """
        try:
            if service.name in cls._services:
                raise ServiceRegistrationError(
                    f"Service '{service.name}' is already registered"
                )
            
            cls._services[service.name] = service
            logger.info(f"Registered service: {service.name}")
            
        except Exception as e:
            if isinstance(e, ServiceRegistrationError):
                raise
            raise ServiceRegistrationError(f"Failed to register service: {str(e)}")
    
    @classmethod
    def unregister(cls, service_name: str) -> None:
        """
        Unregister a service.
        
        Args:
            service_name: Name of the service to unregister
            
        Raises:
            ServiceRegistrationError: If unregistration fails
        """
        try:
            if service_name not in cls._services:
                raise ServiceRegistrationError(
                    f"Service '{service_name}' is not registered"
                )
            
            del cls._services[service_name]
            logger.info(f"Unregistered service: {service_name}")
            
        except Exception as e:
            if isinstance(e, ServiceRegistrationError):
                raise
            raise ServiceRegistrationError(f"Failed to unregister service: {str(e)}")
    
    @classmethod
    def get_service(cls, service_name: str) -> Optional[Service]:
        """
        Get a registered service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Service if found, None otherwise
        """
        return cls._services.get(service_name)
    
    @classmethod
    def get_services(cls) -> Dict[str, Service]:
        """
        Get all registered services.
        
        Returns:
            Dictionary mapping service names to services
        """
        return cls._services.copy()
    
    @classmethod
    def get_healthy_services(cls) -> Dict[str, Service]:
        """
        Get all healthy services.
        
        Returns:
            Dictionary mapping service names to healthy services
        """
        return {
            name: service
            for name, service in cls._services.items()
            if service.health.is_healthy()
        }
    
    @classmethod
    async def start_all(cls) -> None:
        """
        Start all registered services.
        
        Raises:
            ServiceError: If any service fails to start
        """
        for service in cls._services.values():
            await service.start()
    
    @classmethod
    async def stop_all(cls) -> None:
        """
        Stop all registered services.
        
        Raises:
            ServiceError: If any service fails to stop
        """
        for service in cls._services.values():
            await service.stop()
    
    @classmethod
    def get_metrics(cls) -> Dict[str, Dict[str, float]]:
        """
        Get metrics for all services.
        
        Returns:
            Dictionary mapping service names to metrics
        """
        return {
            name: service.health.metrics
            for name, service in cls._services.items()
            if service.config.get('metrics_enabled', True)
        }
    
    @classmethod
    def get_health(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get health status for all services.
        
        Returns:
            Dictionary mapping service names to health status
        """
        return {
            name: service.health.to_dict()
            for name, service in cls._services.items()
        } 