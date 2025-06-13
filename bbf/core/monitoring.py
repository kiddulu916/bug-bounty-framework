"""
Monitoring service for the bug bounty framework.

This module provides the AI monitoring service that handles monitoring,
analytics, and reporting of framework operations.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Union
from collections import defaultdict

from bbf.core.base import BaseService
from bbf.core.exceptions import MonitoringError

logger = logging.getLogger(__name__)

class AIMonitoringService(BaseService):
    """Service for monitoring and analytics using AI capabilities."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Monitoring state
        self._metrics: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._alerts: List[Dict[str, Any]] = []
        self._reports: List[Dict[str, Any]] = []
        
        # Monitoring settings
        self.metrics_retention_days = self.config.get('metrics_retention_days', 30)
        self.alert_thresholds = self.config.get('alert_thresholds', {
            'error_rate': 0.1,  # 10% error rate
            'execution_time': 3600,  # 1 hour
            'resource_usage': 0.8,  # 80% resource usage
            'finding_severity': 'high'  # High severity findings
        })
        self.report_interval = self.config.get('report_interval', 86400)  # 24 hours
    
    async def initialize(self) -> None:
        """Initialize the monitoring service."""
        if self._initialized:
            return
        
        logger.info("Initializing AI monitoring service")
        
        try:
            # Set up metrics collection
            self._setup_metrics_collection()
            
            # Set up alert monitoring
            self._setup_alert_monitoring()
            
            # Set up report generation
            self._setup_report_generation()
            
            self._initialized = True
            logger.info("Monitoring service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize monitoring service: {str(e)}")
            await self.cleanup()
            raise MonitoringError(f"Initialization failed: {str(e)}")
    
    async def cleanup(self) -> None:
        """Clean up monitoring resources."""
        if not self._initialized:
            return
        
        logger.info("Cleaning up monitoring service")
        
        try:
            # Stop metrics collection
            self._stop_metrics_collection()
            
            # Stop alert monitoring
            self._stop_alert_monitoring()
            
            # Stop report generation
            self._stop_report_generation()
            
            # Clear state
            self._metrics.clear()
            self._alerts.clear()
            self._reports.clear()
            
            self._initialized = False
            logger.info("Monitoring service cleaned up successfully")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
            raise MonitoringError(f"Cleanup failed: {str(e)}")
    
    async def record_metric(
        self,
        metric_name: str,
        value: Any,
        tags: Optional[Dict[str, str]] = None
    ) -> None:
        """Record a metric value."""
        if not self._initialized:
            raise MonitoringError("Monitoring service not initialized")
        
        try:
            metric = {
                'name': metric_name,
                'value': value,
                'tags': tags or {},
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self._metrics[metric_name].append(metric)
            logger.debug(f"Recorded metric: {metric_name}={value}")
            
            # Check for alerts
            await self._check_metric_alerts(metric)
            
        except Exception as e:
            logger.error(f"Failed to record metric: {str(e)}")
            raise MonitoringError(f"Failed to record metric: {str(e)}")
    
    async def get_metrics(
        self,
        metric_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        tags: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """Get metrics with optional filtering."""
        if not self._initialized:
            raise MonitoringError("Monitoring service not initialized")
        
        try:
            # Get metrics to query
            metrics_to_query = [metric_name] if metric_name else self._metrics.keys()
            
            # Collect matching metrics
            matching_metrics = []
            for name in metrics_to_query:
                if name not in self._metrics:
                    continue
                
                for metric in self._metrics[name]:
                    # Apply time filter
                    metric_time = datetime.fromisoformat(metric['timestamp'])
                    if start_time and metric_time < start_time:
                        continue
                    if end_time and metric_time > end_time:
                        continue
                    
                    # Apply tag filter
                    if tags:
                        if not all(
                            metric['tags'].get(k) == v
                            for k, v in tags.items()
                        ):
                            continue
                    
                    matching_metrics.append(metric)
            
            return matching_metrics
            
        except Exception as e:
            logger.error(f"Failed to get metrics: {str(e)}")
            raise MonitoringError(f"Failed to get metrics: {str(e)}")
    
    async def create_alert(
        self,
        alert_type: str,
        message: str,
        severity: str = 'warning',
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create a new alert."""
        if not self._initialized:
            raise MonitoringError("Monitoring service not initialized")
        
        try:
            alert = {
                'id': f"alert_{len(self._alerts) + 1}",
                'type': alert_type,
                'message': message,
                'severity': severity,
                'details': details or {},
                'created_at': datetime.utcnow().isoformat(),
                'status': 'active'
            }
            
            self._alerts.append(alert)
            logger.warning(f"Created alert: {alert['id']} - {message}")
            
            return alert['id']
            
        except Exception as e:
            logger.error(f"Failed to create alert: {str(e)}")
            raise MonitoringError(f"Failed to create alert: {str(e)}")
    
    async def get_alerts(
        self,
        alert_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get alerts with optional filtering."""
        if not self._initialized:
            raise MonitoringError("Monitoring service not initialized")
        
        try:
            matching_alerts = []
            
            for alert in self._alerts:
                # Apply type filter
                if alert_type and alert['type'] != alert_type:
                    continue
                
                # Apply severity filter
                if severity and alert['severity'] != severity:
                    continue
                
                # Apply status filter
                if status and alert['status'] != status:
                    continue
                
                # Apply time filter
                alert_time = datetime.fromisoformat(alert['created_at'])
                if start_time and alert_time < start_time:
                    continue
                if end_time and alert_time > end_time:
                    continue
                
                matching_alerts.append(alert)
            
            return matching_alerts
            
        except Exception as e:
            logger.error(f"Failed to get alerts: {str(e)}")
            raise MonitoringError(f"Failed to get alerts: {str(e)}")
    
    async def update_alert_status(
        self,
        alert_id: str,
        status: str,
        resolution: Optional[str] = None
    ) -> None:
        """Update the status of an alert."""
        if not self._initialized:
            raise MonitoringError("Monitoring service not initialized")
        
        try:
            # Find alert
            alert = next(
                (a for a in self._alerts if a['id'] == alert_id),
                None
            )
            if not alert:
                raise MonitoringError(f"Alert not found: {alert_id}")
            
            # Update status
            alert['status'] = status
            alert['updated_at'] = datetime.utcnow().isoformat()
            
            if resolution:
                alert['resolution'] = resolution
            
            logger.info(f"Updated alert {alert_id} status to {status}")
            
        except Exception as e:
            logger.error(f"Failed to update alert status: {str(e)}")
            raise MonitoringError(f"Failed to update alert status: {str(e)}")
    
    async def generate_report(
        self,
        report_type: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        include_metrics: bool = True,
        include_alerts: bool = True
    ) -> Dict[str, Any]:
        """Generate a monitoring report."""
        if not self._initialized:
            raise MonitoringError("Monitoring service not initialized")
        
        try:
            # Set time range
            if not end_time:
                end_time = datetime.utcnow()
            if not start_time:
                start_time = end_time - timedelta(days=1)
            
            # Collect report data
            report_data = {
                'type': report_type,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'generated_at': datetime.utcnow().isoformat()
            }
            
            # Include metrics
            if include_metrics:
                report_data['metrics'] = await self._aggregate_metrics(
                    start_time,
                    end_time
                )
            
            # Include alerts
            if include_alerts:
                report_data['alerts'] = await self.get_alerts(
                    start_time=start_time,
                    end_time=end_time
                )
            
            # Store report
            report = {
                'id': f"report_{len(self._reports) + 1}",
                **report_data
            }
            self._reports.append(report)
            
            logger.info(f"Generated report: {report['id']}")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate report: {str(e)}")
            raise MonitoringError(f"Failed to generate report: {str(e)}")
    
    async def get_reports(
        self,
        report_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get reports with optional filtering."""
        if not self._initialized:
            raise MonitoringError("Monitoring service not initialized")
        
        try:
            matching_reports = []
            
            for report in self._reports:
                # Apply type filter
                if report_type and report['type'] != report_type:
                    continue
                
                # Apply time filter
                report_time = datetime.fromisoformat(report['generated_at'])
                if start_time and report_time < start_time:
                    continue
                if end_time and report_time > end_time:
                    continue
                
                matching_reports.append(report)
            
            return matching_reports
            
        except Exception as e:
            logger.error(f"Failed to get reports: {str(e)}")
            raise MonitoringError(f"Failed to get reports: {str(e)}")
    
    def _setup_metrics_collection(self) -> None:
        """Set up periodic metrics collection."""
        # Start background task for metrics collection
        self._metrics_task = asyncio.create_task(self._collect_metrics())
    
    def _stop_metrics_collection(self) -> None:
        """Stop metrics collection."""
        if hasattr(self, '_metrics_task'):
            self._metrics_task.cancel()
    
    def _setup_alert_monitoring(self) -> None:
        """Set up alert monitoring."""
        # Start background task for alert monitoring
        self._alert_task = asyncio.create_task(self._monitor_alerts())
    
    def _stop_alert_monitoring(self) -> None:
        """Stop alert monitoring."""
        if hasattr(self, '_alert_task'):
            self._alert_task.cancel()
    
    def _setup_report_generation(self) -> None:
        """Set up periodic report generation."""
        # Start background task for report generation
        self._report_task = asyncio.create_task(self._generate_reports())
    
    def _stop_report_generation(self) -> None:
        """Stop report generation."""
        if hasattr(self, '_report_task'):
            self._report_task.cancel()
    
    async def _collect_metrics(self) -> None:
        """Background task for collecting metrics."""
        while True:
            try:
                # Collect system metrics
                await self.record_metric(
                    'system.cpu_usage',
                    self._get_cpu_usage(),
                    {'type': 'system'}
                )
                await self.record_metric(
                    'system.memory_usage',
                    self._get_memory_usage(),
                    {'type': 'system'}
                )
                
                # Collect framework metrics
                await self.record_metric(
                    'framework.active_targets',
                    len(self._get_active_targets()),
                    {'type': 'framework'}
                )
                await self.record_metric(
                    'framework.active_stages',
                    len(self._get_active_stages()),
                    {'type': 'framework'}
                )
                
                # Wait for next collection
                await asyncio.sleep(60)  # Collect every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error collecting metrics: {str(e)}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _monitor_alerts(self) -> None:
        """Background task for monitoring alerts."""
        while True:
            try:
                # Check for new alerts
                await self._check_system_alerts()
                await self._check_framework_alerts()
                
                # Clean up old alerts
                await self._cleanup_old_alerts()
                
                # Wait for next check
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error monitoring alerts: {str(e)}")
                await asyncio.sleep(300)  # Wait before retrying
    
    async def _generate_reports(self) -> None:
        """Background task for generating reports."""
        while True:
            try:
                # Generate daily report
                await self.generate_report(
                    'daily',
                    start_time=datetime.utcnow() - timedelta(days=1),
                    end_time=datetime.utcnow()
                )
                
                # Wait for next report
                await asyncio.sleep(self.report_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error generating report: {str(e)}")
                await asyncio.sleep(3600)  # Wait an hour before retrying
    
    async def _check_metric_alerts(self, metric: Dict[str, Any]) -> None:
        """Check if a metric value triggers an alert."""
        try:
            # Get threshold for metric
            threshold = self.alert_thresholds.get(metric['name'])
            if not threshold:
                return
            
            # Check threshold
            if metric['value'] > threshold:
                await self.create_alert(
                    'metric_threshold',
                    f"Metric {metric['name']} exceeded threshold",
                    'warning',
                    {
                        'metric': metric['name'],
                        'value': metric['value'],
                        'threshold': threshold
                    }
                )
                
        except Exception as e:
            logger.error(f"Error checking metric alerts: {str(e)}")
    
    async def _check_system_alerts(self) -> None:
        """Check for system-related alerts."""
        try:
            # Get recent system metrics
            cpu_metrics = await self.get_metrics(
                'system.cpu_usage',
                start_time=datetime.utcnow() - timedelta(minutes=5)
            )
            memory_metrics = await self.get_metrics(
                'system.memory_usage',
                start_time=datetime.utcnow() - timedelta(minutes=5)
            )
            
            # Check CPU usage
            if cpu_metrics:
                avg_cpu = sum(m['value'] for m in cpu_metrics) / len(cpu_metrics)
                if avg_cpu > self.alert_thresholds['resource_usage']:
                    await self.create_alert(
                        'high_cpu_usage',
                        f"High CPU usage detected: {avg_cpu:.1%}",
                        'warning',
                        {'metric': 'cpu_usage', 'value': avg_cpu}
                    )
            
            # Check memory usage
            if memory_metrics:
                avg_memory = sum(m['value'] for m in memory_metrics) / len(memory_metrics)
                if avg_memory > self.alert_thresholds['resource_usage']:
                    await self.create_alert(
                        'high_memory_usage',
                        f"High memory usage detected: {avg_memory:.1%}",
                        'warning',
                        {'metric': 'memory_usage', 'value': avg_memory}
                    )
                
        except Exception as e:
            logger.error(f"Error checking system alerts: {str(e)}")
    
    async def _check_framework_alerts(self) -> None:
        """Check for framework-related alerts."""
        try:
            # Get recent framework metrics
            target_metrics = await self.get_metrics(
                'framework.active_targets',
                start_time=datetime.utcnow() - timedelta(minutes=5)
            )
            stage_metrics = await self.get_metrics(
                'framework.active_stages',
                start_time=datetime.utcnow() - timedelta(minutes=5)
            )
            
            # Check for high target count
            if target_metrics:
                max_targets = max(m['value'] for m in target_metrics)
                if max_targets > self.max_concurrent_targets:
                    await self.create_alert(
                        'high_target_count',
                        f"High number of active targets: {max_targets}",
                        'warning',
                        {'metric': 'active_targets', 'value': max_targets}
                    )
            
            # Check for high stage count
            if stage_metrics:
                max_stages = max(m['value'] for m in stage_metrics)
                if max_stages > len(self._get_registered_stages()):
                    await self.create_alert(
                        'high_stage_count',
                        f"High number of active stages: {max_stages}",
                        'warning',
                        {'metric': 'active_stages', 'value': max_stages}
                    )
                
        except Exception as e:
            logger.error(f"Error checking framework alerts: {str(e)}")
    
    async def _cleanup_old_alerts(self) -> None:
        """Clean up old alerts."""
        try:
            cutoff_time = datetime.utcnow() - timedelta(days=self.metrics_retention_days)
            
            # Update status of old alerts
            for alert in self._alerts:
                if alert['status'] == 'active':
                    alert_time = datetime.fromisoformat(alert['created_at'])
                    if alert_time < cutoff_time:
                        await self.update_alert_status(
                            alert['id'],
                            'archived',
                            'Alert archived due to age'
                        )
                
        except Exception as e:
            logger.error(f"Error cleaning up old alerts: {str(e)}")
    
    async def _aggregate_metrics(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """Aggregate metrics for reporting."""
        try:
            # Get all metrics in time range
            metrics = await self.get_metrics(
                start_time=start_time,
                end_time=end_time
            )
            
            # Group by metric name
            grouped_metrics = defaultdict(list)
            for metric in metrics:
                grouped_metrics[metric['name']].append(metric['value'])
            
            # Calculate aggregates
            aggregates = {}
            for name, values in grouped_metrics.items():
                aggregates[name] = {
                    'count': len(values),
                    'min': min(values),
                    'max': max(values),
                    'avg': sum(values) / len(values)
                }
            
            return aggregates
            
        except Exception as e:
            logger.error(f"Error aggregating metrics: {str(e)}")
            return {}
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage."""
        # TODO: Implement actual CPU usage monitoring
        return 0.0
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage."""
        # TODO: Implement actual memory usage monitoring
        return 0.0
    
    def _get_active_targets(self) -> Set[str]:
        """Get set of active target IDs."""
        # TODO: Implement actual target tracking
        return set()
    
    def _get_active_stages(self) -> Set[str]:
        """Get set of active stage names."""
        # TODO: Implement actual stage tracking
        return set()
    
    def _get_registered_stages(self) -> Set[str]:
        """Get set of registered stage names."""
        # TODO: Implement actual stage registration tracking
        return set()
    
    @property
    def active_alerts(self) -> List[Dict[str, Any]]:
        """Get list of active alerts."""
        return [
            alert for alert in self._alerts
            if alert['status'] == 'active'
        ]
    
    @property
    def metrics_count(self) -> int:
        """Get total number of recorded metrics."""
        return sum(len(metrics) for metrics in self._metrics.values())
    
    @property
    def reports_count(self) -> int:
        """Get total number of generated reports."""
        return len(self._reports) 