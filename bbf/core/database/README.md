# Database Module

This module provides database functionality for the Bug Bounty Framework, including:
- Database models for storing scan results and findings
- Connection management and session handling
- Repository pattern for data access
- Service layer for business logic
- Database migrations using Alembic

## Structure

```
database/
├── __init__.py
├── config.py           # Database configuration
├── connection.py       # Connection and session management
├── models.py          # SQLAlchemy models
├── repository.py      # Repository pattern implementation
├── service.py         # Service layer
└── migrations/        # Alembic migrations
    ├── env.py         # Migration environment
    ├── versions/      # Migration scripts
    └── script.py.mako # Migration template
```

## Models

The database models represent the core entities of the framework:

- `ScanSession`: Represents a complete scan session
- `PluginResult`: Results from a single plugin execution
- `SubdomainFinding`: Discovered subdomains
- `PortScanResult`: Open ports and services
- `WebTechnologyFinding`: Detected web technologies
- `DirectoryFinding`: Discovered directories and files
- `VulnerabilityFinding`: Discovered vulnerabilities

## Configuration

Database configuration is handled through environment variables:

```bash
# Required
DB_NAME=bug_bounty_framework
DB_USER=postgres
DB_PASSWORD=your_password

# Optional (with defaults)
DB_HOST=localhost
DB_PORT=5432
DB_POOL_SIZE=5
DB_MAX_OVERFLOW=10
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=3600
DB_SSL_MODE=prefer
DB_ECHO=false
```

## Usage

### Connection Management

```python
from bbf.core.database.connection import db_manager

# Get a session
with db_manager.get_session() as session:
    # Use the session
    result = session.query(Model).all()

# Execute in transaction
@db_manager.execute_in_transaction
def create_record(session, data):
    return Model(**data)
```

### Repository Pattern

```python
from bbf.core.database.repository import scan_session_repo

# Create a new scan session
session = scan_session_repo.create(
    session,
    target="example.com",
    start_time=datetime.utcnow(),
    status="running"
)

# Get active sessions
active_sessions = scan_session_repo.get_active_sessions(session)
```

### Service Layer

```python
from bbf.core.database.service import scan_service, finding_service

# Create a new scan session
session = scan_service.create_scan_session(
    session,
    target="example.com",
    config={"plugins": ["subdomain", "port_scan"]}
)

# Add findings
findings = finding_service.add_subdomain_findings(
    session,
    plugin_result_id=1,
    findings=[{"subdomain": "test.example.com", "ip": "1.2.3.4"}]
)
```

### Migrations

The database schema is managed using Alembic migrations:

```bash
# Create a new migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback migrations
alembic downgrade -1
```

## Security Considerations

1. **Connection Security**:
   - Use SSL/TLS for database connections
   - Configure appropriate SSL modes based on your security requirements
   - Store sensitive credentials in environment variables

2. **Access Control**:
   - Use a dedicated database user with minimal required privileges
   - Implement row-level security if needed
   - Regularly audit database access

3. **Data Protection**:
   - Encrypt sensitive data at rest
   - Implement proper data retention policies
   - Regular backups with encryption

4. **Connection Pooling**:
   - Configure appropriate pool sizes
   - Implement connection timeouts
   - Monitor connection usage

## Development

### Adding New Models

1. Add the model class in `models.py`
2. Create a repository class in `repository.py`
3. Add service methods in `service.py`
4. Generate and run migrations:
   ```bash
   alembic revision --autogenerate -m "add new model"
   alembic upgrade head
   ```

### Testing

1. Use a separate test database
2. Implement database fixtures
3. Clean up test data after each test
4. Test both successful and error cases
5. Verify transaction handling

### Monitoring

1. Monitor database connection pool usage
2. Track query performance
3. Set up alerts for connection issues
4. Log database operations appropriately
5. Monitor disk space usage

## Contributing

1. Follow the existing code style
2. Add appropriate docstrings
3. Write tests for new functionality
4. Update documentation
5. Create migrations for schema changes
6. Review security implications 