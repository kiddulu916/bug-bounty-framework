"""
Unit tests for AI service configuration module.
"""

import os
import pytest
from datetime import datetime
from unittest.mock import patch

from bbf.core.ai.config import AIServiceConfig, AIServiceConfigError


@pytest.fixture
def valid_config_dict():
    """Provide a valid configuration dictionary for testing."""
    return {
        "service_name": "test-service",
        "service_version": "1.0.0",
        "api_key": "test-api-key",
        "api_base": "https://api.test.com",
        "api_version": "v1",
        "model_name": "test-model",
        "model_version": "1.0",
        "max_tokens": 1000,
        "temperature": 0.7,
        "requests_per_minute": 60,
        "tokens_per_minute": 1000,
        "max_retries": 3,
        "retry_delay": 1.0,
        "request_timeout": 30.0,
        "connection_timeout": 10.0,
        "cost_per_token": 0.00002,
        "cost_per_request": 0.0001,
        "enable_metrics": True,
        "enable_logging": True,
        "log_level": "INFO"
    }


@pytest.fixture
def test_env_vars():
    """Set up test environment variables."""
    env_vars = {
        "BBF_AI_SERVICE_NAME": "test-service",
        "BBF_AI_SERVICE_VERSION": "1.0.0",
        "BBF_AI_API_KEY": "test-api-key",
        "BBF_AI_API_BASE": "https://api.test.com",
        "BBF_AI_API_VERSION": "v1",
        "BBF_AI_MODEL_NAME": "test-model",
        "BBF_AI_MODEL_VERSION": "1.0",
        "BBF_AI_MAX_TOKENS": "1000",
        "BBF_AI_TEMPERATURE": "0.7",
        "BBF_AI_REQUESTS_PER_MINUTE": "60",
        "BBF_AI_TOKENS_PER_MINUTE": "1000",
        "BBF_AI_MAX_RETRIES": "3",
        "BBF_AI_RETRY_DELAY": "1.0",
        "BBF_AI_REQUEST_TIMEOUT": "30.0",
        "BBF_AI_CONNECTION_TIMEOUT": "10.0",
        "BBF_AI_COST_PER_TOKEN": "0.00002",
        "BBF_AI_COST_PER_REQUEST": "0.0001",
        "BBF_AI_ENABLE_METRICS": "true",
        "BBF_AI_ENABLE_LOGGING": "true",
        "BBF_AI_LOG_LEVEL": "INFO"
    }
    for key, value in env_vars.items():
        os.environ[key] = value
    yield env_vars
    for key in env_vars:
        os.environ.pop(key, None)


def test_config_initialization(valid_config_dict):
    """Test configuration initialization with valid parameters."""
    config = AIServiceConfig(**valid_config_dict)
    
    assert config.service_name == "test-service"
    assert config.service_version == "1.0.0"
    assert config.api_key == "test-api-key"
    assert config.api_base == "https://api.test.com"
    assert config.api_version == "v1"
    assert config.model_name == "test-model"
    assert config.model_version == "1.0"
    assert config.max_tokens == 1000
    assert config.temperature == 0.7
    assert config.requests_per_minute == 60
    assert config.tokens_per_minute == 1000
    assert config.max_retries == 3
    assert config.retry_delay == 1.0
    assert config.request_timeout == 30.0
    assert config.connection_timeout == 10.0
    assert config.cost_per_token == 0.00002
    assert config.cost_per_request == 0.0001
    assert config.enable_metrics is True
    assert config.enable_logging is True
    assert config.log_level == "INFO"


def test_config_validation():
    """Test configuration validation logic."""
    # Test missing required fields
    with pytest.raises(AIServiceConfigError) as exc_info:
        AIServiceConfig(service_name="test")
    assert "Missing required field" in str(exc_info.value)
    
    # Test invalid max_tokens
    with pytest.raises(AIServiceConfigError) as exc_info:
        AIServiceConfig(
            service_name="test",
            service_version="1.0.0",
            api_key="test-key",
            max_tokens=-1
        )
    assert "max_tokens must be positive" in str(exc_info.value)
    
    # Test invalid temperature
    with pytest.raises(AIServiceConfigError) as exc_info:
        AIServiceConfig(
            service_name="test",
            service_version="1.0.0",
            api_key="test-key",
            temperature=2.0
        )
    assert "temperature must be between 0 and 1" in str(exc_info.value)
    
    # Test invalid requests_per_minute
    with pytest.raises(AIServiceConfigError) as exc_info:
        AIServiceConfig(
            service_name="test",
            service_version="1.0.0",
            api_key="test-key",
            requests_per_minute=0
        )
    assert "requests_per_minute must be positive" in str(exc_info.value)


def test_config_from_dict(valid_config_dict):
    """Test creating configuration from dictionary."""
    config = AIServiceConfig.from_dict(valid_config_dict)
    assert isinstance(config, AIServiceConfig)
    assert config.service_name == valid_config_dict["service_name"]
    assert config.api_key == valid_config_dict["api_key"]
    
    # Test with invalid dictionary
    with pytest.raises(AIServiceConfigError):
        AIServiceConfig.from_dict({"invalid": "config"})


def test_config_from_env(test_env_vars):
    """Test creating configuration from environment variables."""
    config = AIServiceConfig.from_env()
    assert isinstance(config, AIServiceConfig)
    assert config.service_name == "test-service"
    assert config.api_key == "test-api-key"
    
    # Test with missing environment variables
    os.environ.pop("BBF_AI_API_KEY")
    with pytest.raises(AIServiceConfigError):
        AIServiceConfig.from_env()


def test_config_to_dict(valid_config_dict):
    """Test converting configuration to dictionary."""
    config = AIServiceConfig(**valid_config_dict)
    config_dict = config.to_dict()
    
    assert isinstance(config_dict, dict)
    assert config_dict["service_name"] == valid_config_dict["service_name"]
    assert config_dict["api_key"] == valid_config_dict["api_key"]
    assert config_dict["max_tokens"] == valid_config_dict["max_tokens"]


def test_config_defaults():
    """Test default values for optional configuration parameters."""
    config = AIServiceConfig(
        service_name="test",
        service_version="1.0.0",
        api_key="test-key"
    )
    
    assert config.api_base == "https://api.openai.com"
    assert config.api_version == "v1"
    assert config.model_name == "gpt-4"
    assert config.max_tokens == 2000
    assert config.temperature == 0.7
    assert config.requests_per_minute == 60
    assert config.tokens_per_minute == 90000
    assert config.max_retries == 3
    assert config.retry_delay == 1.0
    assert config.request_timeout == 30.0
    assert config.connection_timeout == 10.0
    assert config.cost_per_token == 0.00002
    assert config.cost_per_request == 0.0001
    assert config.enable_metrics is True
    assert config.enable_logging is True
    assert config.log_level == "INFO"


def test_config_immutability(valid_config_dict):
    """Test that configuration attributes cannot be modified after initialization."""
    config = AIServiceConfig(**valid_config_dict)
    
    with pytest.raises(AttributeError):
        config.service_name = "new-name"
    
    with pytest.raises(AttributeError):
        config.api_key = "new-key"


def test_config_equality(valid_config_dict):
    """Test configuration equality comparison."""
    config1 = AIServiceConfig(**valid_config_dict)
    config2 = AIServiceConfig(**valid_config_dict)
    config3 = AIServiceConfig(
        service_name="different",
        service_version="1.0.0",
        api_key="test-key"
    )
    
    assert config1 == config2
    assert config1 != config3
    assert hash(config1) == hash(config2)
    assert hash(config1) != hash(config3)


def test_config_string_representation(valid_config_dict):
    """Test string representation of configuration."""
    config = AIServiceConfig(**valid_config_dict)
    config_str = str(config)
    
    assert "test-service" in config_str
    assert "1.0.0" in config_str
    assert "test-api-key" not in config_str  # API key should be masked 