"""
Service layer for database operations.

This module provides service classes that handle:
- Business logic
- Plugin coordination
- Result processing
- Session management
"""

from datetime import datetime, UTC
from typing import List, Dict, Any, Optional, Union
from sqlalchemy.orm import Session

from bbf.core.database.models import (
    ScanSession, PluginResult, Finding
)
from bbf.core.database.repository import (
    scan_session_repo, plugin_result_repo,
    finding_repo
)
from bbf.core.database.connection import db_manager

class ScanService:
    """Service for managing scan sessions and results."""
    
    def __init__(self):
        self.session_repo = scan_session_repo
        self.plugin_repo = plugin_result_repo
        
    @db_manager.execute_in_transaction
    def create_scan_session(self, session: Session, target: str, config: Dict[str, Any]) -> ScanSession:
        """Create a new scan session."""
        return self.session_repo.create(
            session,
            target=target,
            start_time=datetime.now(UTC),
            status='running',
            configuration=config
        )
        
    @db_manager.execute_in_transaction
    def update_session_status(self, session: Session, session_id: int, status: str) -> Optional[ScanSession]:
        """Update scan session status."""
        updates = {'status': status}
        if status in ['completed', 'failed']:
            updates['end_time'] = datetime.now(UTC)
        return self.session_repo.update(session, session_id, **updates)
        
    @db_manager.execute_in_transaction
    def add_plugin_result(self, session: Session, session_id: int, plugin_name: str,
                         start_time: datetime, end_time: datetime, status: str,
                         error: Optional[str] = None, output: Optional[Dict[str, Any]] = None) -> PluginResult:
        """Add a plugin execution result."""
        return self.plugin_repo.create(
            session,
            session_id=session_id,
            plugin_name=plugin_name,
            start_time=start_time,
            end_time=end_time,
            status=status,
            error=error,
            output=output
        )
        
    def get_session_summary(self, session_id: int) -> Dict[str, Any]:
        """Get summary statistics for a scan session."""
        with db_manager.get_session() as session:
            return self.session_repo.get_session_summary(session, session_id)
            
    def get_active_sessions(self) -> List[ScanSession]:
        """Get all active scan sessions."""
        with db_manager.get_session() as session:
            return self.session_repo.get_active_sessions(session)
            
    def get_sessions_by_target(self, target: str) -> List[ScanSession]:
        """Get all sessions for a target."""
        with db_manager.get_session() as session:
            return self.session_repo.get_sessions_by_target(session, target)

class FindingService:
    """Service for managing scan findings."""
    
    def __init__(self):
        self.finding_repo = finding_repo
        
    @db_manager.execute_in_transaction
    def add_or_update_finding(self, session: Session, root_domain: str, subdomain: str,
                             finding_data: Dict[str, Any], merge_metadata: bool = True) -> Finding:
        """Add or update a finding."""
        return self.finding_repo.merge_findings(
            session,
            root_domain=root_domain,
            subdomain=subdomain,
            finding_data=finding_data,
            merge_metadata=merge_metadata
        )
        
    @db_manager.execute_in_transaction
    def update_finding_status(self, session: Session, finding_id: int, status: str) -> Optional[Finding]:
        """Update a finding's status."""
        return self.finding_repo.update_finding_status(session, finding_id, status)
        
    def get_finding(self, root_domain: str, subdomain: str) -> Optional[Finding]:
        """Get a specific finding."""
        with db_manager.get_session() as session:
            return self.finding_repo.get_finding(session, root_domain, subdomain)
            
    def get_findings_by_domain(self, root_domain: str) -> List[Finding]:
        """Get all findings for a root domain."""
        with db_manager.get_session() as session:
            return self.finding_repo.get_findings_by_domain(session, root_domain)
            
    def get_findings_by_stage(self, stage: str) -> List[Finding]:
        """Get all findings for a specific stage."""
        with db_manager.get_session() as session:
            return self.finding_repo.get_findings_by_stage(session, stage)
            
    def get_findings_by_status(self, status: str) -> List[Finding]:
        """Get all findings with a specific status."""
        with db_manager.get_session() as session:
            return self.finding_repo.get_findings_by_status(session, status)
            
    def get_findings_by_source(self, source: str) -> List[Finding]:
        """Get all findings from a specific source."""
        with db_manager.get_session() as session:
            return self.finding_repo.get_findings_by_source(session, source)
            
    def get_active_findings(self) -> List[Finding]:
        """Get all active findings."""
        with db_manager.get_session() as session:
            return self.finding_repo.get_active_findings(session)
            
    def get_findings_summary(self, root_domain: str) -> Dict[str, Any]:
        """Get summary statistics for findings of a root domain."""
        with db_manager.get_session() as session:
            return self.finding_repo.get_findings_summary(session, root_domain)
            
    def get_session_findings(self, session_id: int) -> Dict[str, List[Finding]]:
        """Get all findings for a session."""
        with db_manager.get_session() as session:
            # Get plugin results for the session
            plugin_results = plugin_result_repo.get_session_results(session, session_id)
            
            # Get findings for each plugin result
            findings = []
            for plugin_result in plugin_results:
                findings.extend(plugin_result.findings)
            
            # Group findings by stage
            stage_findings = {}
            for finding in findings:
                stage = finding.stage
                if stage not in stage_findings:
                    stage_findings[stage] = []
                stage_findings[stage].append(finding)
            
            return stage_findings

# Create service instances
scan_service = ScanService()
finding_service = FindingService() 