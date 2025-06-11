"""
Unit tests for AI service monitoring module.
"""

import asyncio
import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from bbf.core.ai.monitoring import AIServiceMonitor, ServiceMetrics


@pytest.fixture
def valid_config():
    """Provide a valid configuration for testing."""
    return {
        "service_name": "test-service",
        "service_version": "1.0.0",
        "api_key": "test-api-key",
        "model_name": "test-model",
        "max_tokens": 1000,
        "temperature": 0.7,
        "requests_per_minute": 60,
        "tokens_per_minute": 1000,
        "enable_metrics": True,
        "enable_logging": True,
        "log_level": "INFO"
    }


@pytest.fixture
async def monitor(valid_config):
    """Create a monitor instance for testing."""
    monitor = AIServiceMonitor(valid_config)
    await monitor.start()
    yield monitor
    await monitor.stop()


@pytest.mark.asyncio
async def test_monitor_initialization(valid_config):
    """Test monitor initialization with valid configuration."""
    monitor = AIServiceMonitor(valid_config)
    assert monitor.config == valid_config
    assert monitor.metrics.total_requests == 0
    assert monitor.metrics.successful_requests == 0
    assert monitor.metrics.failed_requests == 0
    assert monitor.metrics.total_tokens == 0
    assert monitor.metrics.total_cost == 0.0
    assert monitor.metrics.total_latency == 0.0
    assert monitor.metrics.min_latency == float("inf")
    assert monitor.metrics.max_latency == 0.0
    assert monitor.metrics.window_start is not None
    assert monitor.metrics.window_end is not None
    assert len(monitor.metrics.request_timestamps) == 0
    assert len(monitor.metrics.token_timestamps) == 0


@pytest.mark.asyncio
async def test_metrics_recording(monitor):
    """Test recording of service metrics."""
    # Record successful request
    await monitor.record_request(
        success=True,
        rate_limited=False,
        tokens_used=100,
        latency=0.5
    )
    
    assert monitor.metrics.total_requests == 1
    assert monitor.metrics.successful_requests == 1
    assert monitor.metrics.failed_requests == 0
    assert monitor.metrics.total_tokens == 100
    assert monitor.metrics.total_latency == 0.5
    assert monitor.metrics.min_latency == 0.5
    assert monitor.metrics.max_latency == 0.5
    assert len(monitor.metrics.request_timestamps) == 1
    assert len(monitor.metrics.token_timestamps) == 1
    
    # Record failed request
    await monitor.record_request(
        success=False,
        rate_limited=False,
        tokens_used=0,
        latency=0.3
    )
    
    assert monitor.metrics.total_requests == 2
    assert monitor.metrics.successful_requests == 1
    assert monitor.metrics.failed_requests == 1
    assert monitor.metrics.total_tokens == 100
    assert monitor.metrics.total_latency == 0.8
    assert monitor.metrics.min_latency == 0.3
    assert monitor.metrics.max_latency == 0.5
    assert len(monitor.metrics.request_timestamps) == 2
    assert len(monitor.metrics.token_timestamps) == 1


@pytest.mark.asyncio
async def test_health_check(monitor):
    """Test service health check functionality."""
    # Test healthy state
    health = await monitor.check_health()
    assert health["status"] == "healthy"
    assert "metrics" in health
    assert "rate_limits" in health
    
    # Test rate-limited state
    for _ in range(70):  # Exceed requests_per_minute
        await monitor.record_request(
            success=True,
            rate_limited=False,
            tokens_used=10,
            latency=0.1
        )
    
    health = await monitor.check_health()
    assert health["status"] == "rate_limited"
    assert health["rate_limits"]["requests_per_minute"]["exceeded"]
    
    # Test unhealthy state
    monitor.metrics.failed_requests = 10
    health = await monitor.check_health()
    assert health["status"] == "unhealthy"
    assert health["metrics"]["error_rate"] > 0.1


@pytest.mark.asyncio
async def test_metrics_window(monitor):
    """Test metrics window functionality."""
    # Record requests within window
    now = datetime.now()
    monitor.metrics.window_start = now - timedelta(minutes=1)
    monitor.metrics.window_end = now
    
    await monitor.record_request(
        success=True,
        rate_limited=False,
        tokens_used=100,
        latency=0.5
    )
    
    # Record requests outside window
    monitor.metrics.window_start = now - timedelta(minutes=2)
    monitor.metrics.window_end = now - timedelta(minutes=1)
    
    await monitor.record_request(
        success=True,
        rate_limited=False,
        tokens_used=200,
        latency=0.6
    )
    
    # Check that only requests within window are counted
    metrics = await monitor.get_metrics()
    assert metrics["total_requests"] == 1
    assert metrics["total_tokens"] == 100
    assert metrics["total_latency"] == 0.5


@pytest.mark.asyncio
async def test_metrics_reset(monitor):
    """Test metrics reset functionality."""
    # Record some metrics
    await monitor.record_request(
        success=True,
        rate_limited=False,
        tokens_used=100,
        latency=0.5
    )
    
    # Reset metrics
    await monitor.reset_metrics()
    
    assert monitor.metrics.total_requests == 0
    assert monitor.metrics.successful_requests == 0
    assert monitor.metrics.failed_requests == 0
    assert monitor.metrics.total_tokens == 0
    assert monitor.metrics.total_cost == 0.0
    assert monitor.metrics.total_latency == 0.0
    assert monitor.metrics.min_latency == float("inf")
    assert monitor.metrics.max_latency == 0.0
    assert len(monitor.metrics.request_timestamps) == 0
    assert len(monitor.metrics.token_timestamps) == 0


@pytest.mark.asyncio
async def test_cost_tracking(monitor):
    """Test cost tracking functionality."""
    monitor.config["cost_per_token"] = 0.00002
    monitor.config["cost_per_request"] = 0.0001
    
    await monitor.record_request(
        success=True,
        rate_limited=False,
        tokens_used=100,
        latency=0.5
    )
    
    metrics = await monitor.get_metrics()
    expected_token_cost = 100 * 0.00002
    expected_request_cost = 0.0001
    expected_total_cost = expected_token_cost + expected_request_cost
    
    assert metrics["token_cost"] == expected_token_cost
    assert metrics["request_cost"] == expected_request_cost
    assert metrics["total_cost"] == expected_total_cost


@pytest.mark.asyncio
async def test_latency_tracking(monitor):
    """Test latency tracking functionality."""
    latencies = [0.1, 0.5, 0.3, 0.8, 0.2]
    
    for latency in latencies:
        await monitor.record_request(
            success=True,
            rate_limited=False,
            tokens_used=10,
            latency=latency
        )
    
    metrics = await monitor.get_metrics()
    assert metrics["total_latency"] == sum(latencies)
    assert metrics["min_latency"] == min(latencies)
    assert metrics["max_latency"] == max(latencies)
    assert metrics["avg_latency"] == sum(latencies) / len(latencies)


@pytest.mark.asyncio
async def test_rate_limit_tracking(monitor):
    """Test rate limit tracking functionality."""
    # Record rate-limited requests
    for _ in range(3):
        await monitor.record_request(
            success=False,
            rate_limited=True,
            tokens_used=0,
            latency=0.1
        )
    
    metrics = await monitor.get_metrics()
    assert metrics["rate_limited_requests"] == 3
    assert metrics["failed_requests"] == 3
    
    # Check health status
    health = await monitor.check_health()
    assert health["rate_limits"]["requests_per_minute"]["exceeded"]


@pytest.mark.asyncio
async def test_monitor_cleanup(monitor):
    """Test monitor cleanup on stop."""
    assert monitor._monitor_task is not None
    await monitor.stop()
    assert monitor._monitor_task is None
    assert monitor._monitor_task.cancelled()


@pytest.mark.asyncio
async def test_health_check_periodic(monitor):
    """Test periodic health check functionality."""
    health_statuses = []
    
    async def health_callback(status):
        health_statuses.append(status)
    
    monitor.set_health_callback(health_callback)
    
    # Wait for a few health checks
    await asyncio.sleep(2)
    
    assert len(health_statuses) > 0
    for status in health_statuses:
        assert isinstance(status, dict)
        assert "status" in status
        assert "metrics" in status
        assert "rate_limits" in status 