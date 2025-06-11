"""
Database connection and session management module.

This module provides:
- Database connection management
- Session handling
- Connection pooling
- Transaction management
"""

import os
import logging
from contextlib import contextmanager
from typing import Generator, Any, Callable, Optional
from functools import wraps

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError

from bbf.core.database.config import db_config
from bbf.core.database.models import Base

# Configure logging
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages database connections and sessions."""
    
    def __init__(self):
        """Initialize the database manager."""
        self._engine = None
        self._session_factory = None
        self._is_initialized = False
    
    @property
    def engine(self):
        """Get the database engine."""
        if not self._engine:
            self._initialize()
        return self._engine
    
    @property
    def session_factory(self):
        """Get the session factory."""
        if not self._session_factory:
            self._initialize()
        return self._session_factory
    
    def _get_connection_url(self) -> str:
        """Get the database connection URL."""
        if os.getenv("BBF_TESTING") == "true":
            # Use SQLite for testing
            return "sqlite:///:memory:"
        
        # Use PostgreSQL for production
        host = os.getenv("BBF_DB_HOST", "localhost")
        port = os.getenv("BBF_DB_PORT", "5432")
        user = os.getenv("BBF_DB_USER", "postgres")
        password = os.getenv("BBF_DB_PASSWORD", "postgres")
        database = os.getenv("BBF_DB_NAME", "bug_bounty_framework")
        
        return f"postgresql://{user}:{password}@{host}:{port}/{database}"
    
    def _initialize(self):
        """Initialize the database connection."""
        if self._is_initialized:
            return
        
        try:
            connection_url = self._get_connection_url()
            logger.info(f"Initializing database connection to {connection_url}")
            
            self._engine = create_engine(
                connection_url,
                echo=os.getenv("BBF_DB_ECHO", "false").lower() == "true",
                pool_pre_ping=True,
                pool_recycle=3600
            )
            
            self._session_factory = sessionmaker(
                bind=self._engine,
                expire_on_commit=False
            )
            
            self._is_initialized = True
            logger.info("Database connection initialized successfully")
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def create_tables(self) -> None:
        """Create all database tables."""
        try:
            logger.info("Creating database tables")
            Base.metadata.create_all(self.engine)
            logger.info("Database tables created successfully")
        except SQLAlchemyError as e:
            logger.error(f"Failed to create database tables: {e}")
            raise
            
    def drop_tables(self) -> None:
        """Drop all database tables."""
        try:
            Base.metadata.drop_all(self.engine)
            logger.info("Database tables dropped successfully")
        except SQLAlchemyError as e:
            logger.error(f"Failed to drop database tables: {e}")
            raise
            
    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Get a database session context manager.
        
        Yields:
            Session: A SQLAlchemy session object.
            
        Example:
            with db_manager.get_session() as session:
                result = session.query(Model).all()
        """
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
            
    def execute_in_transaction(self, func: Callable) -> Callable:
        """Decorator to execute a function within a database transaction.
        
        Args:
            func: The function to execute within a transaction.
            
        Returns:
            Callable: The wrapped function.
            
        Example:
            @db_manager.execute_in_transaction
            def create_user(session: Session, name: str) -> User:
                return User(name=name)
        """
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            with self.get_session() as session:
                # Replace any session argument with our managed session
                if args and isinstance(args[0], Session):
                    args = (session,) + args[1:]
                elif 'session' in kwargs:
                    kwargs['session'] = session
                return func(*args, **kwargs)
        return wrapper
        
    def check_connection(self) -> bool:
        """Check if the database connection is working.
        
        Returns:
            bool: True if the connection is working, False otherwise.
        """
        try:
            with self.get_session() as session:
                session.execute("SELECT 1")
            return True
        except SQLAlchemyError as e:
            logger.error(f"Database connection check failed: {e}")
            return False
            
    def get_connection_info(self) -> dict:
        """Get database connection information.
        
        Returns:
            dict: Connection information including host, port, database name,
                 and connection pool status.
        """
        return {
            'host': db_config.host,
            'port': db_config.port,
            'database': db_config.database,
            'user': db_config.user,
            'pool_size': db_config.pool_size,
            'max_overflow': db_config.max_overflow,
            'pool_timeout': db_config.pool_timeout,
            'pool_recycle': db_config.pool_recycle,
            'ssl_mode': db_config.ssl_mode
        }

    def close(self):
        """Close the database connection."""
        if self._engine:
            self._engine.dispose()
            self._is_initialized = False
            logger.info("Database connection closed")

# Create a global database manager instance
db_manager = DatabaseManager()

# (Removed: Only create tables if not in test mode) 