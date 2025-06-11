"""
AI Service Configuration

This module handles configuration management for AI services,
including validation, defaults, and environment variable support.
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..exceptions import FrameworkError
from .service import AIServiceConfigError


@dataclass
class AIServiceConfig:
    """Configuration for AI services."""
    
    # Service identification
    service_name: str
    service_version: str
    
    # API configuration
    api_key: str
    api_base: str
    api_version: str
    
    # Model configuration
    model_name: str
    model_version: str
    max_tokens: int
    temperature: float
    
    # Rate limiting
    requests_per_minute: int
    tokens_per_minute: int
    
    # Retry configuration
    max_retries: int
    retry_delay: float
    
    # Timeout configuration
    request_timeout: float
    connection_timeout: float
    
    # Cost tracking
    cost_per_token: float
    cost_per_request: float
    
    # Monitoring
    enable_metrics: bool
    enable_logging: bool
    log_level: str
    
    @classmethod
    def from_dict(cls, config: Dict[str, Any]) -> "AIServiceConfig":
        """Create configuration from dictionary.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            AIServiceConfig instance
            
        Raises:
            AIServiceConfigError: If configuration is invalid
        """
        try:
            return cls(**config)
        except TypeError as e:
            raise AIServiceConfigError(f"Invalid configuration: {str(e)}")
    
    @classmethod
    def from_env(cls, prefix: str = "AI_SERVICE_") -> "AIServiceConfig":
        """Create configuration from environment variables.
        
        Args:
            prefix: Environment variable prefix
            
        Returns:
            AIServiceConfig instance
            
        Raises:
            AIServiceConfigError: If required environment variables are missing
        """
        config = {}
        
        # Required environment variables
        required_vars = [
            "SERVICE_NAME",
            "API_KEY",
            "API_BASE",
            "MODEL_NAME",
        ]
        
        for var in required_vars:
            env_var = f"{prefix}{var}"
            value = os.getenv(env_var)
            if not value:
                raise AIServiceConfigError(f"Missing required environment variable: {env_var}")
            config[var.lower()] = value
        
        # Optional environment variables with defaults
        optional_vars = {
            "SERVICE_VERSION": "0.1.0",
            "API_VERSION": "v1",
            "MODEL_VERSION": "latest",
            "MAX_TOKENS": "2048",
            "TEMPERATURE": "0.7",
            "REQUESTS_PER_MINUTE": "60",
            "TOKENS_PER_MINUTE": "90000",
            "MAX_RETRIES": "3",
            "RETRY_DELAY": "1.0",
            "REQUEST_TIMEOUT": "30.0",
            "CONNECTION_TIMEOUT": "10.0",
            "COST_PER_TOKEN": "0.00002",
            "COST_PER_REQUEST": "0.0001",
            "ENABLE_METRICS": "true",
            "ENABLE_LOGGING": "true",
            "LOG_LEVEL": "INFO",
        }
        
        for var, default in optional_vars.items():
            env_var = f"{prefix}{var}"
            value = os.getenv(env_var, default)
            
            # Convert string values to appropriate types
            if var in ["MAX_TOKENS", "MAX_RETRIES"]:
                value = int(value)
            elif var in ["TEMPERATURE", "RETRY_DELAY", "REQUEST_TIMEOUT", 
                        "CONNECTION_TIMEOUT", "COST_PER_TOKEN", "COST_PER_REQUEST"]:
                value = float(value)
            elif var in ["ENABLE_METRICS", "ENABLE_LOGGING"]:
                value = value.lower() == "true"
            
            config[var.lower()] = value
        
        return cls.from_dict(config)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary.
        
        Returns:
            Configuration dictionary
        """
        return {
            "service_name": self.service_name,
            "service_version": self.service_version,
            "api_key": self.api_key,
            "api_base": self.api_base,
            "api_version": self.api_version,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "requests_per_minute": self.requests_per_minute,
            "tokens_per_minute": self.tokens_per_minute,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "request_timeout": self.request_timeout,
            "connection_timeout": self.connection_timeout,
            "cost_per_token": self.cost_per_token,
            "cost_per_request": self.cost_per_request,
            "enable_metrics": self.enable_metrics,
            "enable_logging": self.enable_logging,
            "log_level": self.log_level,
        }
    
    def validate(self) -> None:
        """Validate configuration values.
        
        Raises:
            AIServiceConfigError: If configuration is invalid
        """
        if not self.service_name:
            raise AIServiceConfigError("Service name is required")
        
        if not self.api_key:
            raise AIServiceConfigError("API key is required")
        
        if not self.api_base:
            raise AIServiceConfigError("API base URL is required")
        
        if not self.model_name:
            raise AIServiceConfigError("Model name is required")
        
        if self.max_tokens < 1:
            raise AIServiceConfigError("Max tokens must be positive")
        
        if not 0 <= self.temperature <= 1:
            raise AIServiceConfigError("Temperature must be between 0 and 1")
        
        if self.requests_per_minute < 1:
            raise AIServiceConfigError("Requests per minute must be positive")
        
        if self.tokens_per_minute < 1:
            raise AIServiceConfigError("Tokens per minute must be positive")
        
        if self.max_retries < 0:
            raise AIServiceConfigError("Max retries must be non-negative")
        
        if self.retry_delay < 0:
            raise AIServiceConfigError("Retry delay must be non-negative")
        
        if self.request_timeout < 0:
            raise AIServiceConfigError("Request timeout must be non-negative")
        
        if self.connection_timeout < 0:
            raise AIServiceConfigError("Connection timeout must be non-negative")
        
        if self.cost_per_token < 0:
            raise AIServiceConfigError("Cost per token must be non-negative")
        
        if self.cost_per_request < 0:
            raise AIServiceConfigError("Cost per request must be non-negative")
        
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_log_levels:
            raise AIServiceConfigError(f"Log level must be one of: {', '.join(valid_log_levels)}") 