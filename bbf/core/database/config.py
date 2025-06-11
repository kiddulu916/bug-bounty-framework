"""
Database configuration module.

This module handles:
- Database connection settings
- Environment variable loading
- Configuration validation
"""

import os
from typing import Dict, Any, Optional
from dataclasses import dataclass
from urllib.parse import quote_plus

@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    
    # Database connection settings
    host: str = os.getenv('DB_HOST', 'localhost')
    port: int = int(os.getenv('DB_PORT', '5432'))
    database: str = os.getenv('DB_NAME', 'bug_bounty_framework')
    user: str = os.getenv('DB_USER', 'postgres')
    password: str = os.getenv('DB_PASSWORD', 'postgres')
    
    # Connection pool settings
    pool_size: int = int(os.getenv('DB_POOL_SIZE', '5'))
    max_overflow: int = int(os.getenv('DB_MAX_OVERFLOW', '10'))
    pool_timeout: int = int(os.getenv('DB_POOL_TIMEOUT', '30'))
    pool_recycle: int = int(os.getenv('DB_POOL_RECYCLE', '3600'))
    
    # SSL settings
    ssl_mode: str = os.getenv('DB_SSL_MODE', 'prefer')
    ssl_cert: Optional[str] = os.getenv('DB_SSL_CERT')
    ssl_key: Optional[str] = os.getenv('DB_SSL_KEY')
    ssl_ca: Optional[str] = os.getenv('DB_SSL_CA')
    
    @property
    def connection_url(self) -> str:
        """Get the SQLAlchemy connection URL."""
        # URL encode the password to handle special characters
        password = quote_plus(self.password)
        
        # Build the base URL
        url = f"postgresql://{self.user}:{password}@{self.host}:{self.port}/{self.database}"
        
        # Add SSL parameters if enabled
        if self.ssl_mode != 'disable':
            ssl_params = []
            if self.ssl_mode:
                ssl_params.append(f"sslmode={self.ssl_mode}")
            if self.ssl_cert:
                ssl_params.append(f"sslcert={self.ssl_cert}")
            if self.ssl_key:
                ssl_params.append(f"sslkey={self.ssl_key}")
            if self.ssl_ca:
                ssl_params.append(f"sslrootcert={self.ssl_ca}")
            
            if ssl_params:
                url += "?" + "&".join(ssl_params)
        
        return url
    
    @property
    def engine_options(self) -> Dict[str, Any]:
        """Get SQLAlchemy engine options."""
        return {
            'pool_size': self.pool_size,
            'max_overflow': self.max_overflow,
            'pool_timeout': self.pool_timeout,
            'pool_recycle': self.pool_recycle,
            'echo': os.getenv('DB_ECHO', 'false').lower() == 'true'
        }
    
    def validate(self) -> None:
        """Validate the configuration settings."""
        # Validate required settings
        if not self.database:
            raise ValueError("Database name is required")
        if not self.user:
            raise ValueError("Database user is required")
        
        # Validate port number
        if not 1 <= self.port <= 65535:
            raise ValueError("Invalid port number")
        
        # Validate pool settings
        if self.pool_size < 1:
            raise ValueError("Pool size must be at least 1")
        if self.max_overflow < 0:
            raise ValueError("Max overflow cannot be negative")
        if self.pool_timeout < 1:
            raise ValueError("Pool timeout must be at least 1 second")
        if self.pool_recycle < 1:
            raise ValueError("Pool recycle must be at least 1 second")
        
        # Validate SSL settings
        valid_ssl_modes = ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full']
        if self.ssl_mode not in valid_ssl_modes:
            raise ValueError(f"Invalid SSL mode. Must be one of: {', '.join(valid_ssl_modes)}")
        
        # Validate SSL certificate settings
        if self.ssl_mode in ['verify-ca', 'verify-full']:
            if not self.ssl_ca:
                raise ValueError("SSL CA certificate is required for verify-ca and verify-full modes")
        
        if self.ssl_cert and not self.ssl_key:
            raise ValueError("SSL key is required when SSL certificate is provided")
        if self.ssl_key and not self.ssl_cert:
            raise ValueError("SSL certificate is required when SSL key is provided")

# Create configuration instance
db_config = DatabaseConfig()

# Validate configuration on import
db_config.validate() 