"""
Database models for storing plugin results and findings.

This module defines SQLAlchemy models for storing:
- Scan sessions
- Plugin results
- Findings (centralized table for all findings)
"""

from datetime import datetime, UTC
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, 
    JSON, Boolean, Enum, Text, Float, Table, Index
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    """Base class for all database models."""
    pass

class ScanSession(Base):
    """Represents a complete scan session."""
    __tablename__ = 'scan_sessions'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    start_time: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # running, completed, failed
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # Scan configuration
    summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # Scan summary statistics
    
    # Relationships
    plugin_results: Mapped[list["PluginResult"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<ScanSession(target='{self.target}', status='{self.status}')>"

class PluginResult(Base):
    """Represents results from a single plugin execution."""
    __tablename__ = 'plugin_results'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey('scan_sessions.id'), nullable=False)
    plugin_name: Mapped[str] = mapped_column(String(100), nullable=False)
    start_time: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # running, completed, failed
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Error message if failed
    data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # Raw plugin output
    
    # Relationships
    session: Mapped["ScanSession"] = relationship(back_populates="plugin_results")
    findings: Mapped[list["Finding"]] = relationship(back_populates="plugin_result", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<PluginResult(plugin='{self.plugin_name}', status='{self.status}')>"

class Finding(Base):
    """Centralized table for all findings."""
    __tablename__ = 'findings'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    plugin_result_id: Mapped[int] = mapped_column(ForeignKey('plugin_results.id'), nullable=False)
    root_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    subdomain: Mapped[str] = mapped_column(String(255), nullable=False)
    ipv4: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv4 address
    ipv6: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv6 address
    open_ports: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # List of open ports
    services: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # Map of port to service info
    tls_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # TLS/SSL status
    vuln_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # Vulnerability status
    web_tech: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # Web technologies
    headers: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # HTTP headers
    cookies: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # Cookies
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # Source of the finding
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)  # Confidence score
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    extra_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True, default=dict, comment="Additional extra metadata (e.g. extra details, extra info)")
    stage: Mapped[str] = mapped_column(String(50), nullable=False)  # recon, vuln, etc.
    status: Mapped[str] = mapped_column(String(50), nullable=False, default='active')  # active, inactive, fixed, etc.
    
    # Relationships
    plugin_result: Mapped["PluginResult"] = relationship(back_populates="findings")
    
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