"""
Core integration management system for the Bug Bounty Framework.

This module provides functionality for managing integrations, including:
- External service integration
- API gateway
- Service mesh
- Event bus
- Message queue
- Cache system
- Database integration
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, UTC
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Type, TypeVar, Union

import aiohttp
import aioredis
import asyncpg
import backoff
from aiohttp import web
from aiohttp.web import Request, Response
from aiohttp.web_middlewares import middleware
from aiohttp.web_request import Request
from aiohttp.web_response import Response
from aiohttp.web_exceptions import HTTPBadGateway, HTTPGatewayTimeout

from .exceptions import (
    IntegrationError,
    ServiceConnectionError,
    ServiceTimeoutError,
    ServiceResponseError,
    CacheError,
    DatabaseError,
    MessageQueueError,
    EventBusError
)

logger = logging.getLogger(__name__)

# Type variables for generic functions
T = TypeVar('T')

class IntegrationType(Enum):
    """Integration type enumeration."""
    HTTP = "http"
    WEBSOCKET = "websocket"
    DATABASE = "database"
    CACHE = "cache"
    MESSAGE_QUEUE = "message_queue"
    EVENT_BUS = "event_bus"

class IntegrationStatus(Enum):
    """Integration status enumeration."""
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"
    ERROR = "error"

class IntegrationConfig:
    """
    Integration configuration.
    
    This class manages integration configuration, including:
    - Connection settings
    - Retry policies
    - Timeout settings
    - Authentication
    - Monitoring
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize integration configuration.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path or Path('data/integration/config.json')
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
            logger.error(f"Failed to load integration config: {e}")
            self.config = self._create_default_config()
    
    def _create_default_config(self) -> Dict[str, Any]:
        """
        Create default configuration.
        
        Returns:
            Dictionary containing default configuration
        """
        return {
            'connections': {
                'default_timeout': 30,
                'max_retries': 3,
                'retry_delay': 1,
                'keep_alive': True,
                'keep_alive_timeout': 60,
                'max_connections': 100
            },
            'services': {
                'api_gateway': {
                    'enabled': True,
                    'type': 'http',
                    'url': 'http://localhost:8080',
                    'timeout': 30,
                    'retry_count': 3,
                    'retry_delay': 1
                },
                'cache': {
                    'enabled': True,
                    'type': 'redis',
                    'url': 'redis://localhost:6379',
                    'timeout': 5,
                    'retry_count': 3,
                    'retry_delay': 1
                },
                'database': {
                    'enabled': True,
                    'type': 'postgresql',
                    'url': 'postgresql://localhost:5432/bbf',
                    'timeout': 30,
                    'retry_count': 3,
                    'retry_delay': 1
                },
                'message_queue': {
                    'enabled': True,
                    'type': 'redis',
                    'url': 'redis://localhost:6379',
                    'timeout': 5,
                    'retry_count': 3,
                    'retry_delay': 1
                },
                'event_bus': {
                    'enabled': True,
                    'type': 'redis',
                    'url': 'redis://localhost:6379',
                    'timeout': 5,
                    'retry_count': 3,
                    'retry_delay': 1
                }
            },
            'monitoring': {
                'enabled': True,
                'metrics_enabled': True,
                'health_check_interval': 30,
                'log_level': 'INFO'
            },
            'created_at': datetime.now(UTC).isoformat(),
            'updated_at': datetime.now(UTC).isoformat()
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
            logger.error(f"Failed to save integration config: {e}")
            raise IntegrationError(f"Failed to save config: {e}")
    
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
        self.config['updated_at'] = datetime.now(UTC).isoformat()
        self._save_config()
    
    def update(self, **kwargs) -> None:
        """
        Update multiple configuration values.
        
        Args:
            **kwargs: Configuration key-value pairs
        """
        self.config.update(kwargs)
        self.config['updated_at'] = datetime.now(UTC).isoformat()
        self._save_config()

class IntegrationManager:
    """
    Integration manager for the framework.
    
    This class provides a central interface for:
    - Service connections
    - API gateway
    - Cache system
    - Database connections
    - Message queue
    - Event bus
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize integration manager.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = IntegrationConfig(config_path)
        self.connections: Dict[str, Any] = {}
        self.status: Dict[str, IntegrationStatus] = {}
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Set up integration logging."""
        log_level = self.config.get('monitoring', {}).get('log_level', 'INFO')
        self.logger = logging.getLogger('bbf.integration')
        self.logger.setLevel(log_level)
    
    async def connect(self, service_name: str) -> None:
        """
        Connect to a service.
        
        Args:
            service_name: Name of the service
            
        Raises:
            ServiceConnectionError: If connection fails
        """
        try:
            service_config = self.config.get('services', {}).get(service_name)
            if not service_config:
                raise ServiceConnectionError(f"Service {service_name} not configured")
            
            if not service_config.get('enabled', True):
                raise ServiceConnectionError(f"Service {service_name} is disabled")
            
            # Update status
            self.status[service_name] = IntegrationStatus.CONNECTING
            
            # Connect based on service type
            service_type = service_config.get('type')
            if service_type == 'http':
                await self._connect_http(service_name, service_config)
            elif service_type == 'redis':
                await self._connect_redis(service_name, service_config)
            elif service_type == 'postgresql':
                await self._connect_postgresql(service_name, service_config)
            else:
                raise ServiceConnectionError(f"Unsupported service type: {service_type}")
            
            # Update status
            self.status[service_name] = IntegrationStatus.CONNECTED
            self.logger.info(f"Connected to service: {service_name}")
            
        except Exception as e:
            self.status[service_name] = IntegrationStatus.ERROR
            self.logger.error(f"Failed to connect to service {service_name}: {e}")
            raise ServiceConnectionError(f"Connection failed: {str(e)}")
    
    async def disconnect(self, service_name: str) -> None:
        """
        Disconnect from a service.
        
        Args:
            service_name: Name of the service
            
        Raises:
            ServiceConnectionError: If disconnection fails
        """
        try:
            if service_name not in self.connections:
                return
            
            # Update status
            self.status[service_name] = IntegrationStatus.DISCONNECTING
            
            # Disconnect based on service type
            service_config = self.config.get('services', {}).get(service_name)
            service_type = service_config.get('type')
            
            if service_type == 'http':
                await self._disconnect_http(service_name)
            elif service_type == 'redis':
                await self._disconnect_redis(service_name)
            elif service_type == 'postgresql':
                await self._disconnect_postgresql(service_name)
            
            # Update status
            self.status[service_name] = IntegrationStatus.DISCONNECTED
            self.logger.info(f"Disconnected from service: {service_name}")
            
        except Exception as e:
            self.status[service_name] = IntegrationStatus.ERROR
            self.logger.error(f"Failed to disconnect from service {service_name}: {e}")
            raise ServiceConnectionError(f"Disconnection failed: {str(e)}")
    
    async def _connect_http(self, service_name: str, config: Dict[str, Any]) -> None:
        """
        Connect to HTTP service.
        
        Args:
            service_name: Name of the service
            config: Service configuration
            
        Raises:
            ServiceConnectionError: If connection fails
        """
        try:
            # Create session
            timeout = aiohttp.ClientTimeout(
                total=config.get('timeout', 30),
                connect=config.get('connect_timeout', 10),
                sock_read=config.get('read_timeout', 30)
            )
            
            session = aiohttp.ClientSession(
                timeout=timeout,
                headers=config.get('headers', {}),
                trust_env=config.get('trust_env', True)
            )
            
            # Test connection
            async with session.get(config['url']) as response:
                if response.status >= 400:
                    raise ServiceConnectionError(
                        f"Service returned status {response.status}"
                    )
            
            # Store connection
            self.connections[service_name] = session
            
        except Exception as e:
            raise ServiceConnectionError(f"HTTP connection failed: {str(e)}")
    
    async def _connect_redis(self, service_name: str, config: Dict[str, Any]) -> None:
        """
        Connect to Redis service.
        
        Args:
            service_name: Name of the service
            config: Service configuration
            
        Raises:
            ServiceConnectionError: If connection fails
        """
        try:
            # Create connection
            redis = await aioredis.create_redis_pool(
                config['url'],
                encoding='utf-8',
                timeout=config.get('timeout', 5),
                maxsize=config.get('max_connections', 10)
            )
            
            # Test connection
            await redis.ping()
            
            # Store connection
            self.connections[service_name] = redis
            
        except Exception as e:
            raise ServiceConnectionError(f"Redis connection failed: {str(e)}")
    
    async def _connect_postgresql(self, service_name: str, config: Dict[str, Any]) -> None:
        """
        Connect to PostgreSQL service.
        
        Args:
            service_name: Name of the service
            config: Service configuration
            
        Raises:
            ServiceConnectionError: If connection fails
        """
        try:
            # Create connection pool
            pool = await asyncpg.create_pool(
                config['url'],
                min_size=config.get('min_connections', 1),
                max_size=config.get('max_connections', 10),
                command_timeout=config.get('timeout', 30)
            )
            
            # Test connection
            async with pool.acquire() as conn:
                await conn.execute('SELECT 1')
            
            # Store connection
            self.connections[service_name] = pool
            
        except Exception as e:
            raise ServiceConnectionError(f"PostgreSQL connection failed: {str(e)}")
    
    async def _disconnect_http(self, service_name: str) -> None:
        """
        Disconnect from HTTP service.
        
        Args:
            service_name: Name of the service
            
        Raises:
            ServiceConnectionError: If disconnection fails
        """
        try:
            session = self.connections[service_name]
            await session.close()
            del self.connections[service_name]
        except Exception as e:
            raise ServiceConnectionError(f"HTTP disconnection failed: {str(e)}")
    
    async def _disconnect_redis(self, service_name: str) -> None:
        """
        Disconnect from Redis service.
        
        Args:
            service_name: Name of the service
            
        Raises:
            ServiceConnectionError: If disconnection fails
        """
        try:
            redis = self.connections[service_name]
            redis.close()
            await redis.wait_closed()
            del self.connections[service_name]
        except Exception as e:
            raise ServiceConnectionError(f"Redis disconnection failed: {str(e)}")
    
    async def _disconnect_postgresql(self, service_name: str) -> None:
        """
        Disconnect from PostgreSQL service.
        
        Args:
            service_name: Name of the service
            
        Raises:
            ServiceConnectionError: If disconnection fails
        """
        try:
            pool = self.connections[service_name]
            await pool.close()
            del self.connections[service_name]
        except Exception as e:
            raise ServiceConnectionError(f"PostgreSQL disconnection failed: {str(e)}")
    
    @backoff.on_exception(
        backoff.expo,
        (ServiceConnectionError, ServiceTimeoutError),
        max_tries=3
    )
    async def request(
        self,
        service_name: str,
        method: str,
        path: str,
        **kwargs
    ) -> Any:
        """
        Make a request to a service.
        
        Args:
            service_name: Name of the service
            method: HTTP method
            path: Request path
            **kwargs: Request arguments
            
        Returns:
            Service response
            
        Raises:
            ServiceConnectionError: If connection fails
            ServiceTimeoutError: If request times out
            ServiceResponseError: If service returns error
        """
        try:
            service_config = self.config.get('services', {}).get(service_name)
            if not service_config:
                raise ServiceConnectionError(f"Service {service_name} not configured")
            
            if service_name not in self.connections:
                await self.connect(service_name)
            
            # Get connection
            if service_config['type'] == 'http':
                session = self.connections[service_name]
                url = f"{service_config['url'].rstrip('/')}/{path.lstrip('/')}"
                
                async with session.request(method, url, **kwargs) as response:
                    if response.status >= 400:
                        raise ServiceResponseError(
                            f"Service returned status {response.status}"
                        )
                    return await response.json()
            
            raise ServiceConnectionError(f"Unsupported service type: {service_config['type']}")
            
        except aiohttp.ClientError as e:
            raise ServiceConnectionError(f"Request failed: {str(e)}")
        except asyncio.TimeoutError as e:
            raise ServiceTimeoutError(f"Request timed out: {str(e)}")
        except Exception as e:
            raise ServiceResponseError(f"Request failed: {str(e)}")
    
    async def get_cache(self, service_name: str, key: str) -> Optional[str]:
        """
        Get value from cache.
        
        Args:
            service_name: Name of the cache service
            key: Cache key
            
        Returns:
            Cached value if found, None otherwise
            
        Raises:
            CacheError: If cache operation fails
        """
        try:
            if service_name not in self.connections:
                await self.connect(service_name)
            
            redis = self.connections[service_name]
            return await redis.get(key)
            
        except Exception as e:
            raise CacheError(f"Cache get failed: {str(e)}")
    
    async def set_cache(
        self,
        service_name: str,
        key: str,
        value: str,
        expire: Optional[int] = None
    ) -> None:
        """
        Set value in cache.
        
        Args:
            service_name: Name of the cache service
            key: Cache key
            value: Cache value
            expire: Expiration time in seconds
            
        Raises:
            CacheError: If cache operation fails
        """
        try:
            if service_name not in self.connections:
                await self.connect(service_name)
            
            redis = self.connections[service_name]
            if expire:
                await redis.set(key, value, expire=expire)
            else:
                await redis.set(key, value)
            
        except Exception as e:
            raise CacheError(f"Cache set failed: {str(e)}")
    
    async def execute_query(
        self,
        service_name: str,
        query: str,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute database query.
        
        Args:
            service_name: Name of the database service
            query: SQL query
            *args: Query arguments
            **kwargs: Query options
            
        Returns:
            Query result
            
        Raises:
            DatabaseError: If query fails
        """
        try:
            if service_name not in self.connections:
                await self.connect(service_name)
            
            pool = self.connections[service_name]
            async with pool.acquire() as conn:
                return await conn.fetch(query, *args, **kwargs)
            
        except Exception as e:
            raise DatabaseError(f"Query failed: {str(e)}")
    
    async def publish_message(
        self,
        service_name: str,
        channel: str,
        message: str
    ) -> None:
        """
        Publish message to queue.
        
        Args:
            service_name: Name of the message queue service
            channel: Channel name
            message: Message to publish
            
        Raises:
            MessageQueueError: If publish fails
        """
        try:
            if service_name not in self.connections:
                await self.connect(service_name)
            
            redis = self.connections[service_name]
            await redis.publish(channel, message)
            
        except Exception as e:
            raise MessageQueueError(f"Message publish failed: {str(e)}")
    
    async def subscribe_message(
        self,
        service_name: str,
        channel: str
    ) -> AsyncIterator[str]:
        """
        Subscribe to message queue.
        
        Args:
            service_name: Name of the message queue service
            channel: Channel name
            
        Returns:
            Async iterator of messages
            
        Raises:
            MessageQueueError: If subscribe fails
        """
        try:
            if service_name not in self.connections:
                await self.connect(service_name)
            
            redis = self.connections[service_name]
            channel = redis.pubsub_channels[channel]
            
            while True:
                message = await channel.get()
                if message:
                    yield message.decode()
                
        except Exception as e:
            raise MessageQueueError(f"Message subscribe failed: {str(e)}")
    
    async def publish_event(
        self,
        service_name: str,
        event_type: str,
        event_data: Dict[str, Any]
    ) -> None:
        """
        Publish event to event bus.
        
        Args:
            service_name: Name of the event bus service
            event_type: Event type
            event_data: Event data
            
        Raises:
            EventBusError: If publish fails
        """
        try:
            if service_name not in self.connections:
                await self.connect(service_name)
            
            redis = self.connections[service_name]
            message = json.dumps({
                'type': event_type,
                'data': event_data,
                'timestamp': datetime.now(UTC).isoformat()
            })
            await redis.publish(f"events:{event_type}", message)
            
        except Exception as e:
            raise EventBusError(f"Event publish failed: {str(e)}")
    
    async def subscribe_event(
        self,
        service_name: str,
        event_type: str
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Subscribe to event bus.
        
        Args:
            service_name: Name of the event bus service
            event_type: Event type
            
        Returns:
            Async iterator of events
            
        Raises:
            EventBusError: If subscribe fails
        """
        try:
            if service_name not in self.connections:
                await self.connect(service_name)
            
            redis = self.connections[service_name]
            channel = redis.pubsub_channels[f"events:{event_type}"]
            
            while True:
                message = await channel.get()
                if message:
                    yield json.loads(message.decode())
                
        except Exception as e:
            raise EventBusError(f"Event subscribe failed: {str(e)}")
    
    @middleware
    async def integration_middleware(self, request: Request, handler: Any) -> Response:
        """
        Integration middleware for HTTP requests.
        
        This middleware:
        1. Handles service connections
        2. Manages request timeouts
        3. Implements retry logic
        4. Handles service errors
        
        Args:
            request: HTTP request
            handler: Request handler
            
        Returns:
            HTTP response
            
        Raises:
            IntegrationError: If middleware fails
        """
        try:
            # Add integration manager to request
            request['integration'] = self
            
            # Process request
            response = await handler(request)
            
            return response
            
        except ServiceConnectionError as e:
            raise HTTPBadGateway(reason=str(e))
        except ServiceTimeoutError as e:
            raise HTTPGatewayTimeout(reason=str(e))
        except Exception as e:
            logger.error(f"Integration middleware error: {e}")
            raise IntegrationError(f"Middleware failed: {str(e)}") 