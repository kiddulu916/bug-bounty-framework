"""
AI Service Monitoring

This module provides monitoring capabilities for AI services,
including health checks, metrics collection, and logging.
"""

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List, Optional

from .service import AIServiceError


@dataclass
class ServiceMetrics:
    """Metrics for AI service usage."""
    
    # Request metrics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rate_limited_requests: int = 0
    
    # Token metrics
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    
    # Cost metrics
    total_cost: float = 0.0
    token_cost: float = 0.0
    request_cost: float = 0.0
    
    # Latency metrics
    total_latency: float = 0.0
    min_latency: float = float('inf')
    max_latency: float = 0.0
    
    # Time window metrics
    window_start: datetime = field(default_factory=datetime.now)
    window_end: datetime = field(default_factory=datetime.now)
    
    # Request history for rate limiting
    request_timestamps: Deque[datetime] = field(default_factory=lambda: deque(maxlen=1000))
    token_timestamps: Deque[tuple[datetime, int]] = field(default_factory=lambda: deque(maxlen=1000))


class AIServiceMonitor:
    """Monitor for AI service health and metrics."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the service monitor.
        
        Args:
            config: Monitor configuration dictionary
        """
        self.config = config
        self.metrics = ServiceMetrics()
        self._setup_logging()
        self._setup_health_check()
    
    def _setup_logging(self) -> None:
        """Set up logging for the monitor."""
        if not self.config.get("enable_logging", True):
            return
        
        log_level = getattr(logging, self.config.get("log_level", "INFO").upper())
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler("ai_service.log")
            ]
        )
        
        self.logger = logging.getLogger("ai_service_monitor")
    
    def _setup_health_check(self) -> None:
        """Set up periodic health check."""
        self.health_check_interval = self.config.get("health_check_interval", 60)
        self.health_check_task = None
    
    async def start(self) -> None:
        """Start the service monitor."""
        if self.health_check_task is None:
            self.health_check_task = asyncio.create_task(self._health_check_loop())
            if self.config.get("enable_logging", True):
                self.logger.info("Service monitor started")
    
    async def stop(self) -> None:
        """Stop the service monitor."""
        if self.health_check_task is not None:
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass
            self.health_check_task = None
            if self.config.get("enable_logging", True):
                self.logger.info("Service monitor stopped")
    
    async def _health_check_loop(self) -> None:
        """Periodic health check loop."""
        while True:
            try:
                health = await self.check_health()
                if not health["is_healthy"]:
                    if self.config.get("enable_logging", True):
                        self.logger.warning(f"Service health check failed: {health['reason']}")
                await asyncio.sleep(self.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.config.get("enable_logging", True):
                    self.logger.error(f"Health check error: {str(e)}")
                await asyncio.sleep(self.health_check_interval)
    
    async def check_health(self) -> Dict[str, Any]:
        """Check the health of the AI service.
        
        Returns:
            Dictionary containing health status and metrics
        """
        now = datetime.now()
        
        # Check rate limits
        requests_in_window = sum(1 for ts in self.metrics.request_timestamps 
                               if now - ts < timedelta(minutes=1))
        tokens_in_window = sum(tokens for ts, tokens in self.metrics.token_timestamps 
                             if now - ts < timedelta(minutes=1))
        
        is_healthy = True
        reason = "Service is healthy"
        
        if requests_in_window >= self.config.get("requests_per_minute", 60):
            is_healthy = False
            reason = "Request rate limit exceeded"
        elif tokens_in_window >= self.config.get("tokens_per_minute", 90000):
            is_healthy = False
            reason = "Token rate limit exceeded"
        
        # Calculate window metrics
        window_duration = (now - self.metrics.window_start).total_seconds()
        if window_duration > 0:
            requests_per_second = self.metrics.total_requests / window_duration
            tokens_per_second = self.metrics.total_tokens / window_duration
            avg_latency = self.metrics.total_latency / self.metrics.total_requests if self.metrics.total_requests > 0 else 0
        else:
            requests_per_second = 0
            tokens_per_second = 0
            avg_latency = 0
        
        return {
            "is_healthy": is_healthy,
            "reason": reason,
            "timestamp": now.isoformat(),
            "metrics": {
                "requests": {
                    "total": self.metrics.total_requests,
                    "successful": self.metrics.successful_requests,
                    "failed": self.metrics.failed_requests,
                    "rate_limited": self.metrics.rate_limited_requests,
                    "per_second": requests_per_second,
                    "in_window": requests_in_window,
                },
                "tokens": {
                    "total": self.metrics.total_tokens,
                    "prompt": self.metrics.prompt_tokens,
                    "completion": self.metrics.completion_tokens,
                    "per_second": tokens_per_second,
                    "in_window": tokens_in_window,
                },
                "cost": {
                    "total": self.metrics.total_cost,
                    "token": self.metrics.token_cost,
                    "request": self.metrics.request_cost,
                },
                "latency": {
                    "average": avg_latency,
                    "minimum": self.metrics.min_latency if self.metrics.min_latency != float('inf') else 0,
                    "maximum": self.metrics.max_latency,
                },
            },
        }
    
    def record_request(self, 
                      success: bool, 
                      rate_limited: bool = False,
                      tokens: Optional[int] = None,
                      prompt_tokens: Optional[int] = None,
                      completion_tokens: Optional[int] = None,
                      latency: Optional[float] = None) -> None:
        """Record a service request.
        
        Args:
            success: Whether the request was successful
            rate_limited: Whether the request was rate limited
            tokens: Total tokens used
            prompt_tokens: Tokens used in prompt
            completion_tokens: Tokens used in completion
            latency: Request latency in seconds
        """
        now = datetime.now()
        
        # Update request metrics
        self.metrics.total_requests += 1
        if success:
            self.metrics.successful_requests += 1
        else:
            self.metrics.failed_requests += 1
        if rate_limited:
            self.metrics.rate_limited_requests += 1
        
        # Update token metrics
        if tokens is not None:
            self.metrics.total_tokens += tokens
            self.metrics.token_cost += tokens * self.config.get("cost_per_token", 0.00002)
            self.metrics.token_timestamps.append((now, tokens))
        if prompt_tokens is not None:
            self.metrics.prompt_tokens += prompt_tokens
        if completion_tokens is not None:
            self.metrics.completion_tokens += completion_tokens
        
        # Update cost metrics
        self.metrics.request_cost += self.config.get("cost_per_request", 0.0001)
        self.metrics.total_cost = self.metrics.token_cost + self.metrics.request_cost
        
        # Update latency metrics
        if latency is not None:
            self.metrics.total_latency += latency
            self.metrics.min_latency = min(self.metrics.min_latency, latency)
            self.metrics.max_latency = max(self.metrics.max_latency, latency)
        
        # Update request history
        self.metrics.request_timestamps.append(now)
        
        # Update time window
        self.metrics.window_end = now
        
        # Log metrics if enabled
        if self.config.get("enable_logging", True):
            self.logger.debug(
                f"Request recorded: success={success}, rate_limited={rate_limited}, "
                f"tokens={tokens}, latency={latency:.3f}s"
            )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current service metrics.
        
        Returns:
            Dictionary containing current metrics
        """
        return {
            "requests": {
                "total": self.metrics.total_requests,
                "successful": self.metrics.successful_requests,
                "failed": self.metrics.failed_requests,
                "rate_limited": self.metrics.rate_limited_requests,
            },
            "tokens": {
                "total": self.metrics.total_tokens,
                "prompt": self.metrics.prompt_tokens,
                "completion": self.metrics.completion_tokens,
            },
            "cost": {
                "total": self.metrics.total_cost,
                "token": self.metrics.token_cost,
                "request": self.metrics.request_cost,
            },
            "latency": {
                "average": self.metrics.total_latency / self.metrics.total_requests if self.metrics.total_requests > 0 else 0,
                "minimum": self.metrics.min_latency if self.metrics.min_latency != float('inf') else 0,
                "maximum": self.metrics.max_latency,
            },
            "window": {
                "start": self.metrics.window_start.isoformat(),
                "end": self.metrics.window_end.isoformat(),
                "duration": (self.metrics.window_end - self.metrics.window_start).total_seconds(),
            },
        }
    
    def reset_metrics(self) -> None:
        """Reset all metrics to initial values."""
        self.metrics = ServiceMetrics()
        if self.config.get("enable_logging", True):
            self.logger.info("Metrics reset") 