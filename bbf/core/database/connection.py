"""
Database connection and session management module.

This module provides:
- Database connection management
- Session handling
- Connection pooling
- Transaction management
"""

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
    """Database connection and session manager."""
    
    def __init__(self):
        """Initialize the database manager."""
        self.engine = create_engine(
            db_config.connection_url,
            **db_config.engine_options
        )
        self.Session = sessionmaker(
            bind=self.engine,
            expire_on_commit=False
        )
        
    def create_tables(self) -> None:
        """Create all database tables."""
        try:
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
        session = self.Session()
        try:
            yield session
            session.commit()
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
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

# Create database manager instance
db_manager = DatabaseManager()

# Create tables on import
try:
    db_manager.create_tables()
except SQLAlchemyError as e:
    logger.error(f"Failed to initialize database: {e}")
    raise 