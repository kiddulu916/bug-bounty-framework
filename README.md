# Bug Bounty Framework (BBF)

A modular, extensible framework for automating bug bounty and security testing tasks. The framework is designed to be flexible, allowing security researchers to easily add new plugins and customize the testing workflow.

## Features

- **Modular Architecture**: Easily extendable with custom plugins
- **Asynchronous Execution**: Built on asyncio for efficient I/O operations
- **Stage-based Workflow**: Organized into logical stages (Recon, Scan, Test, Report)
- **Plugin System**: Simple plugin registration and discovery
- **State Management**: Tracks progress and maintains state between stages
- **Error Handling**: Comprehensive error handling and recovery
- **Configuration**: Flexible configuration system
- **Logging**: Detailed logging with multiple log levels
- **Parallel Execution**: Run multiple plugins in parallel
- **Result Aggregation**: Collect and analyze results from multiple sources

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/bug-bounty-framework.git
   cd bug-bounty-framework
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

1. Create a configuration file (`config.yaml`):
   ```yaml
   target: example.com
   output_dir: reports
   log_level: INFO
   
   stages:
     recon:
       enabled: true
       plugins:
         - subdomain_enumeration
     scan:
       enabled: true
       plugins:
         - port_scanning
     test:
       enabled: true
       plugins: []
     report:
       enabled: true
   
   plugins:
     subdomain_enumeration:
       max_workers: 20
       timeout: 5
       rate_limit: 0.1
       use_search_engines: true
       use_cert_transparency: true
     port_scanning:
       ports: '1-1024,8080,8443'
       scan_technique: 'syn'  # syn, connect, or ack
       timeout: 5
       max_retries: 2
       rate_limit: 100
   ```

2. Run the framework:
   ```bash
   python -m bbf.cli --config config.yaml
   ```

## Project Structure

```
bug-bounty-framework/
├── bbf/                       # Main package
│   ├── core/                   # Core framework components
│   │   ├── __init__.py
│   │   ├── exceptions.py       # Custom exceptions
│   │   ├── framework.py        # Main framework class
│   │   ├── plugin.py           # Plugin base class and registry
│   │   └── state.py            # State management
│   │
│   ├── plugins/              # Plugins directory
│   │   ├── __init__.py
│   │   ├── base_plugin.py      # Base plugin class
│   │   └── example_plugins/    # Example plugins
│   │       ├── __init__.py
│   │       ├── subdomain_enumeration.py
│   │       └── port_scanning.py
│   │
│   └── stages/               # Stage implementations
│       ├── __init__.py
│       ├── base_stage.py       # Base stage class
│       ├── recon.py            # Reconnaissance stage
│       ├── scan.py             # Scanning stage
│       ├── test.py             # Testing stage
│       └── report.py           # Reporting stage
│
├── examples/                 # Example scripts
│   └── basic_usage.py
│
├── tests/                   # Unit and integration tests
│   ├── __init__.py
│   ├── test_plugins.py
│   └── test_stages.py
│
├── .gitignore
├── LICENSE
├── README.md
├── pyproject.toml
└── requirements.txt
```

## Creating Plugins

Plugins are the core components of the framework. Each plugin should inherit from `BasePlugin` and implement the required methods.

### Example Plugin

```python
from bbf.plugins import BasePlugin, plugin

@plugin
class ExamplePlugin(BasePlugin):
    """Example plugin that demonstrates the plugin interface."""
    
    name = "example"
    description = "An example plugin"
    version = "1.0.0"
    
    DEFAULT_CONFIG = {
        'option1': 'default_value',
        'option2': 42,
    }
    
    def __init__(self, config=None):
        super().__init__(config or {})
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
    
    async def execute(self, target, **kwargs):
        """Execute the plugin's main functionality."""
        self.logger.info(f"Running example plugin on {target}")
        
        # Plugin logic goes here
        result = {
            'target': target,
            'option1': self.config['option1'],
            'option2': self.config['option2'],
            'timestamp': self._current_timestamp(),
        }
        
        # Save results
        self.add_result('example_result', result)
        return result
    
    async def cleanup(self):
        """Clean up any resources used by the plugin."""
        self.logger.debug("Cleaning up example plugin")
```

## Configuration

The framework can be configured using a YAML file or a Python dictionary. The following options are available:

### Global Configuration

- `target`: The target to scan (required)
- `output_dir`: Directory to save reports (default: 'reports')
- `log_level`: Logging level (default: 'INFO')
- `state_file`: Path to the state file (default: '.bbf_state.json')
- `max_workers`: Maximum number of concurrent workers (default: 10)

### Stage Configuration

Each stage can be configured with the following options:

- `enabled`: Whether the stage is enabled (default: true)
- `plugins`: List of plugins to run in this stage
- `timeout`: Maximum time to wait for the stage to complete (in seconds)
- `continue_on_error`: Whether to continue to the next stage if an error occurs (default: false)

### Plugin Configuration

Each plugin can have its own configuration options. Refer to the plugin's documentation for available options.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch for your feature or bugfix
3. Write tests for your changes
4. Run the test suite
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by various open-source security tools and frameworks
- Thanks to all contributors who have helped improve this project
