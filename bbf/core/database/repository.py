"""
Repository module for database operations.

This module provides repository classes for each model, handling:
- CRUD operations
- Query building
- Data filtering
- Result aggregation
"""

from datetime import datetime, UTC
from typing import List, Optional, Dict, Any, Union
from sqlalchemy import and_, or_, desc, func, update
from sqlalchemy.orm import Session

from bbf.core.database.models import (
    ScanSession, PluginResult, Finding
)
from bbf.core.database.connection import db_manager

class BaseRepository:
    """Base repository class with common operations."""
    
    def __init__(self, model_class):
        self.model_class = model_class
        
    @db_manager.execute_in_transaction
    def create(self, session: Session, **kwargs) -> Any:
        """Create a new record."""
        instance = self.model_class(**kwargs)
        session.add(instance)
        return instance
        
    @db_manager.execute_in_transaction
    def get_by_id(self, session: Session, id: int) -> Optional[Any]:
        """Get a record by ID."""
        return session.query(self.model_class).get(id)
        
    @db_manager.execute_in_transaction
    def update(self, session: Session, id: int, **kwargs) -> Optional[Any]:
        """Update a record."""
        instance = session.query(self.model_class).get(id)
        if instance:
            for key, value in kwargs.items():
                setattr(instance, key, value)
        return instance
        
    @db_manager.execute_in_transaction
    def delete(self, session: Session, id: int) -> bool:
        """Delete a record."""
        instance = session.query(self.model_class).get(id)
        if instance:
            session.delete(instance)
            return True
        return False

class ScanSessionRepository(BaseRepository):
    """Repository for scan sessions."""
    
    def __init__(self):
        super().__init__(ScanSession)
        
    @db_manager.execute_in_transaction
    def get_active_sessions(self, session: Session) -> List[ScanSession]:
        """Get all active scan sessions."""
        return session.query(ScanSession).filter(
            ScanSession.status == 'running'
        ).order_by(ScanSession.start_time.desc()).all()
        
    @db_manager.execute_in_transaction
    def get_sessions_by_target(self, session: Session, target: str) -> List[ScanSession]:
        """Get all sessions for a target."""
        return session.query(ScanSession).filter(
            ScanSession.target == target
        ).order_by(desc(ScanSession.start_time)).all()
        
    @db_manager.execute_in_transaction
    def get_session_summary(self, session: Session, session_id: int) -> Dict[str, Any]:
        """Get summary statistics for a scan session."""
        scan = session.query(ScanSession).get(session_id)
        if not scan:
            return {}
            
        # Get findings summary
        findings = session.query(Finding).join(
            PluginResult
        ).filter(
            PluginResult.session_id == session_id
        ).all()
        
        # Calculate statistics
        total_findings = len(findings)
        active_findings = len([f for f in findings if f.status == 'active'])
        unique_subdomains = len(set(f.subdomain for f in findings))
        unique_ips = len(set(f.ipv4 for f in findings if f.ipv4)) + len(set(f.ipv6 for f in findings if f.ipv6))
        
        # Group by stage
        stage_stats = {}
        for finding in findings:
            stage = finding.stage
            if stage not in stage_stats:
                stage_stats[stage] = {
                    'total': 0,
                    'active': 0,
                    'sources': set()
                }
            stage_stats[stage]['total'] += 1
            if finding.status == 'active':
                stage_stats[stage]['active'] += 1
            stage_stats[stage]['sources'].add(finding.source)
            
        # Convert sets to lists for JSON serialization
        for stats in stage_stats.values():
            stats['sources'] = list(stats['sources'])
            
        return {
            'target': scan.target,
            'start_time': scan.start_time,
            'end_time': scan.end_time,
            'status': scan.status,
            'total_findings': total_findings,
            'active_findings': active_findings,
            'unique_subdomains': unique_subdomains,
            'unique_ips': unique_ips,
            'stage_stats': stage_stats
        }

    @db_manager.execute_in_transaction
    def update_session_status(self, session: Session, session_id: int, status: str) -> Optional[ScanSession]:
        """Update a session's status."""
        updates = {'status': status}
        if status in ['completed', 'failed']:
            updates['end_time'] = datetime.now(UTC)
        return self.update(session, session_id, **updates)

class PluginResultRepository(BaseRepository):
    """Repository for plugin results."""
    
    def __init__(self):
        super().__init__(PluginResult)
        
    @db_manager.execute_in_transaction
    def get_session_results(self, session: Session, session_id: int) -> List[PluginResult]:
        """Get all plugin results for a session."""
        return session.query(PluginResult).filter(
            PluginResult.session_id == session_id
        ).order_by(PluginResult.start_time).all()
        
    @db_manager.execute_in_transaction
    def get_plugin_results(self, session: Session, plugin_name: str) -> List[PluginResult]:
        """Get all results for a specific plugin."""
        return session.query(PluginResult).filter(
            PluginResult.plugin_name == plugin_name
        ).order_by(desc(PluginResult.start_time)).all()
        
    @db_manager.execute_in_transaction
    def update_result_status(self, session: Session, result_id: int, status: str) -> Optional[PluginResult]:
        """Update a result's status."""
        updates = {'status': status}
        if status in ['completed', 'failed']:
            updates['end_time'] = datetime.now(UTC)
        return self.update(session, result_id, **updates)

class FindingRepository(BaseRepository):
    """Repository for findings."""
    
    def __init__(self):
        super().__init__(Finding)
        
    @db_manager.execute_in_transaction
    def get_finding(self, session: Session, root_domain: str, subdomain: str) -> Optional[Finding]:
        """Get a finding by domain and subdomain."""
        return session.query(Finding).filter(
            and_(
                Finding.root_domain == root_domain,
                Finding.subdomain == subdomain
            )
        ).first()
        
    @db_manager.execute_in_transaction
    def get_domain_findings(self, session: Session, root_domain: str) -> List[Finding]:
        """Get all findings for a domain."""
        return session.query(Finding).filter(
            Finding.root_domain == root_domain
        ).order_by(Finding.last_seen.desc()).all()
        
    @db_manager.execute_in_transaction
    def get_findings_by_stage(self, session: Session, stage: str) -> List[Finding]:
        """Get all findings for a specific stage."""
        return session.query(Finding).filter(
            Finding.stage == stage
        ).order_by(Finding.last_seen.desc()).all()
        
    @db_manager.execute_in_transaction
    def get_findings_by_status(self, session: Session, status: str) -> List[Finding]:
        """Get all findings with a specific status."""
        return session.query(Finding).filter(
            Finding.status == status
        ).order_by(Finding.last_seen.desc()).all()
        
    @db_manager.execute_in_transaction
    def get_findings_by_source(self, session: Session, source: str) -> List[Finding]:
        """Get all findings from a specific source."""
        return session.query(Finding).filter(
            Finding.source == source
        ).order_by(Finding.last_seen.desc()).all()
        
    @db_manager.execute_in_transaction
    def get_active_findings(self, session: Session) -> List[Finding]:
        """Get all active findings."""
        return session.query(Finding).filter(
            Finding.status == 'active'
        ).order_by(Finding.last_seen.desc()).all()
        
    @db_manager.execute_in_transaction
    def update_finding_status(self, session: Session, finding_id: int, status: str) -> Optional[Finding]:
        """Update a finding's status."""
        finding = session.query(Finding).get(finding_id)
        if finding:
            finding.status = status
            finding.last_seen = datetime.now(UTC)
        return finding
        
    @db_manager.execute_in_transaction
    def merge_findings(self, session: Session, root_domain: str, subdomain: str, 
                      finding_data: Dict[str, Any], merge_metadata: bool = True) -> Finding:
        """Merge new finding data with existing finding."""
        finding = self.get_finding(session, root_domain, subdomain)
        
        if finding:
            # Update existing finding
            for key, value in finding_data.items():
                if key == 'metadata' and merge_metadata and finding.metadata:
                    # Merge metadata
                    existing_metadata = finding.metadata or {}
                    new_metadata = value or {}
                    finding.metadata = {**existing_metadata, **new_metadata}
                elif key == 'last_seen':
                    # Always update last_seen
                    finding.last_seen = datetime.now(UTC)
                elif key != 'id' and key != 'first_seen':
                    # Update other fields
                    setattr(finding, key, value)
        else:
            # Create new finding
            finding = self.create(session, **finding_data)
            
        return finding
        
    @db_manager.execute_in_transaction
    def get_findings_summary(self, session: Session, root_domain: str) -> Dict[str, Any]:
        """Get summary statistics for findings of a root domain."""
        findings = self.get_domain_findings(session, root_domain)
        
        # Calculate statistics
        total_findings = len(findings)
        active_findings = len([f for f in findings if f.status == 'active'])
        unique_subdomains = len(set(f.subdomain for f in findings))
        unique_ips = len(set(f.ipv4 for f in findings if f.ipv4)) + len(set(f.ipv6 for f in findings if f.ipv6))
        
        # Group by stage and source
        stage_stats = {}
        source_stats = {}
        
        for finding in findings:
            # Stage statistics
            stage = finding.stage
            if stage not in stage_stats:
                stage_stats[stage] = {
                    'total': 0,
                    'active': 0,
                    'sources': set()
                }
            stage_stats[stage]['total'] += 1
            if finding.status == 'active':
                stage_stats[stage]['active'] += 1
            stage_stats[stage]['sources'].add(finding.source)
            
            # Source statistics
            source = finding.source
            if source not in source_stats:
                source_stats[source] = {
                    'total': 0,
                    'active': 0,
                    'stages': set()
                }
            source_stats[source]['total'] += 1
            if finding.status == 'active':
                source_stats[source]['active'] += 1
            source_stats[source]['stages'].add(finding.stage)
            
        # Convert sets to lists for JSON serialization
        for stats in stage_stats.values():
            stats['sources'] = list(stats['sources'])
        for stats in source_stats.values():
            stats['stages'] = list(stats['stages'])
            
        return {
            'root_domain': root_domain,
            'total_findings': total_findings,
            'active_findings': active_findings,
            'unique_subdomains': unique_subdomains,
            'unique_ips': unique_ips,
            'stage_stats': stage_stats,
            'source_stats': source_stats
        }

# Create repository instances
scan_session_repo = ScanSessionRepository()
plugin_result_repo = PluginResultRepository()
finding_repo = FindingRepository() 