"""
Database models for storing plugin results and findings.

This module defines SQLAlchemy models for storing:
- Scan sessions
- Plugin results
- Findings (centralized table for all findings)
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, 
    JSON, Boolean, Enum, Text, Float, Table, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class ScanSession(Base):
    """Represents a complete scan session."""
    __tablename__ = 'scan_sessions'
    
    id = Column(Integer, primary_key=True)
    target = Column(String(255), nullable=False)
    start_time = Column(DateTime, default=datetime.utcnow, nullable=False)
    end_time = Column(DateTime, nullable=True)
    status = Column(String(50), nullable=False)  # running, completed, failed
    config = Column(JSON, nullable=True)  # Scan configuration
    summary = Column(JSON, nullable=True)  # Scan summary statistics
    
    # Relationships
    plugin_results = relationship("PluginResult", back_populates="session", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<ScanSession(target='{self.target}', status='{self.status}')>"

class PluginResult(Base):
    """Represents results from a single plugin execution."""
    __tablename__ = 'plugin_results'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('scan_sessions.id'), nullable=False)
    plugin_name = Column(String(100), nullable=False)
    start_time = Column(DateTime, default=datetime.utcnow, nullable=False)
    end_time = Column(DateTime, nullable=True)
    status = Column(String(50), nullable=False)  # running, completed, failed
    error = Column(Text, nullable=True)  # Error message if failed
    data = Column(JSON, nullable=True)  # Raw plugin output
    
    # Relationships
    session = relationship("ScanSession", back_populates="plugin_results")
    findings = relationship("Finding", back_populates="plugin_result", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<PluginResult(plugin='{self.plugin_name}', status='{self.status}')>"

class Finding(Base):
    """Centralized table for all findings."""
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True)
    plugin_result_id = Column(Integer, ForeignKey('plugin_results.id'), nullable=False)
    root_domain = Column(String(255), nullable=False)
    subdomain = Column(String(255), nullable=False)
    ipv4 = Column(String(45), nullable=True)  # IPv4 address
    ipv6 = Column(String(45), nullable=True)  # IPv6 address
    open_ports = Column(JSON, nullable=True)  # List of open ports
    services = Column(JSON, nullable=True)  # Map of port to service info
    tls_status = Column(String(50), nullable=True)  # TLS/SSL status
    vuln_status = Column(String(50), nullable=True)  # Vulnerability status
    web_tech = Column(JSON, nullable=True)  # Web technologies
    headers = Column(JSON, nullable=True)  # HTTP headers
    cookies = Column(JSON, nullable=True)  # Cookies
    source = Column(String(100), nullable=False)  # Source of the finding
    confidence = Column(Float, nullable=False, default=0.0)  # Confidence score
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    extra_metadata = Column(JSON, nullable=True, default=dict, comment="Additional extra metadata (e.g. extra details, extra info)")
    stage = Column(String(50), nullable=False)  # recon, vuln, etc.
    status = Column(String(50), nullable=False, default='active')  # active, inactive, fixed, etc.
    
    # Relationships
    plugin_result = relationship("PluginResult", back_populates="findings")
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_findings_root_domain', 'root_domain'),
        Index('idx_findings_subdomain', 'subdomain'),
        Index('idx_findings_source', 'source'),
        Index('idx_findings_stage', 'stage'),
        Index('idx_findings_status', 'status'),
        Index('idx_findings_first_seen', 'first_seen'),
        Index('idx_findings_last_seen', 'last_seen'),
        Index('idx_findings_confidence', 'confidence'),
        # Composite indexes for common query patterns
        Index('idx_findings_root_subdomain', 'root_domain', 'subdomain'),
        Index('idx_findings_stage_status', 'stage', 'status'),
        Index('idx_findings_source_stage', 'source', 'stage')
    )
    
    def __repr__(self):
        return f"<Finding(root_domain='{self.root_domain}', subdomain='{self.subdomain}', source='{self.source}')>" 