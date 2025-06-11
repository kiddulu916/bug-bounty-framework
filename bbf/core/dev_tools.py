"""
Plugin Development Tools

This module provides tools and utilities for plugin development, including:
- Plugin project scaffolding
- Plugin testing utilities
- Plugin documentation generation
- Plugin packaging and distribution
- Plugin development environment management
"""

import ast
import importlib
import inspect
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

import click
import jinja2
import pdoc
import pytest
from cookiecutter.main import cookiecutter

from bbf.core.exceptions import (
    DevToolsError,
    PluginValidationError,
    PluginTestError,
)
from bbf.core.plugin import PluginRegistry
from bbf.core.validation import validate_plugin

logger = logging.getLogger(__name__)

class PluginProject:
    """Manages a plugin development project."""
    
    def __init__(
        self,
        name: str,
        path: str,
        registry: Optional[PluginRegistry] = None
    ):
        self.name = name
        self.path = os.path.abspath(path)
        self.registry = registry
        self._plugin_class = None
        self._metadata = None

    @property
    def plugin_class(self) -> type:
        """Get the plugin class."""
        if not self._plugin_class:
            self._load_plugin()
        return self._plugin_class

    @property
    def metadata(self) -> Dict:
        """Get the plugin metadata."""
        if not self._metadata:
            self._load_metadata()
        return self._metadata

    def _load_plugin(self) -> None:
        """Load the plugin class from the project."""
        # Add project directory to Python path
        sys.path.insert(0, self.path)
        try:
            # Import plugin module
            module = importlib.import_module(self.name)
            
            # Find plugin class
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type) and
                    hasattr(attr, 'run') and
                    hasattr(attr, 'execute')
                ):
                    self._plugin_class = attr
                    break
            
            if not self._plugin_class:
                raise DevToolsError(
                    f"No plugin class found in {self.name}"
                )
        finally:
            # Remove project directory from Python path
            sys.path.pop(0)

    def _load_metadata(self) -> None:
        """Load plugin metadata from project."""
        metadata_path = os.path.join(self.path, 'plugin.json')
        if not os.path.exists(metadata_path):
            raise DevToolsError(
                f"Plugin metadata not found at {metadata_path}"
            )
        
        with open(metadata_path) as f:
            self._metadata = json.load(f)

    def validate(self) -> None:
        """Validate the plugin project."""
        try:
            # Validate plugin class
            validate_plugin(self.plugin_class)
            
            # Validate metadata
            if not self.metadata.get('name'):
                raise PluginValidationError("Plugin name not found in metadata")
            if not self.metadata.get('version'):
                raise PluginValidationError("Plugin version not found in metadata")
            if not self.metadata.get('description'):
                raise PluginValidationError("Plugin description not found in metadata")
            
            # Validate project structure
            required_files = [
                'plugin.json',
                'README.md',
                'requirements.txt',
                'tests/',
                'tests/__init__.py',
                'tests/test_plugin.py'
            ]
            for file in required_files:
                path = os.path.join(self.path, file)
                if not os.path.exists(path):
                    raise PluginValidationError(
                        f"Required file/directory not found: {file}"
                    )
            
        except Exception as e:
            raise PluginValidationError(f"Plugin validation failed: {str(e)}")

    def test(self, coverage: bool = False) -> None:
        """Run plugin tests."""
        try:
            # Run pytest
            args = ['pytest', '-v']
            if coverage:
                args.extend(['--cov', self.name, '--cov-report', 'term-missing'])
            
            result = subprocess.run(
                args,
                cwd=self.path,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                raise PluginTestError(
                    f"Tests failed:\n{result.stdout}\n{result.stderr}"
                )
            
        except Exception as e:
            raise PluginTestError(f"Test execution failed: {str(e)}")

    def generate_docs(self, output_dir: Optional[str] = None) -> None:
        """Generate plugin documentation."""
        try:
            # Set up output directory
            if not output_dir:
                output_dir = os.path.join(self.path, 'docs')
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate API documentation
            pdoc.pdoc(
                self.name,
                output_directory=output_dir,
                template_directory=None,
                template_format='html'
            )
            
            # Generate README
            readme_path = os.path.join(self.path, 'README.md')
            if not os.path.exists(readme_path):
                template = jinja2.Template('''
# {{ name }}

{{ description }}

## Installation

```bash
pip install {{ name }}
```

## Usage

```python
from {{ name }} import {{ class_name }}

plugin = {{ class_name }}()
plugin.run()
```

## Configuration

{{ configuration }}

## Development

1. Clone the repository
2. Install development dependencies: `pip install -e ".[dev]"`
3. Run tests: `pytest`
4. Generate documentation: `python -m bbf.dev_tools generate-docs`

## License

{{ license }}
''')
                
                with open(readme_path, 'w') as f:
                    f.write(template.render(
                        name=self.name,
                        description=self.metadata.get('description', ''),
                        class_name=self.plugin_class.__name__,
                        configuration=self.metadata.get('configuration', ''),
                        license=self.metadata.get('license', 'MIT')
                    ))
            
        except Exception as e:
            raise DevToolsError(f"Documentation generation failed: {str(e)}")

    def package(self, output_dir: Optional[str] = None) -> str:
        """Package the plugin for distribution."""
        try:
            # Set up output directory
            if not output_dir:
                output_dir = os.path.join(self.path, 'dist')
            os.makedirs(output_dir, exist_ok=True)
            
            # Build package
            subprocess.run(
                ['python', 'setup.py', 'sdist', 'bdist_wheel'],
                cwd=self.path,
                check=True
            )
            
            # Find built package
            dist_dir = os.path.join(self.path, 'dist')
            packages = [
                f for f in os.listdir(dist_dir)
                if f.endswith('.whl') or f.endswith('.tar.gz')
            ]
            if not packages:
                raise DevToolsError("No package files found")
            
            # Copy package to output directory
            package_path = os.path.join(dist_dir, packages[0])
            output_path = os.path.join(output_dir, packages[0])
            shutil.copy2(package_path, output_path)
            
            return output_path
            
        except Exception as e:
            raise DevToolsError(f"Package creation failed: {str(e)}")

class DevTools:
    """Provides plugin development tools and utilities."""
    
    def __init__(self, registry: Optional[PluginRegistry] = None):
        self.registry = registry
        self._template_dir = os.path.join(
            os.path.dirname(__file__),
            'templates',
            'plugin_template'
        )

    def create_project(
        self,
        name: str,
        path: str,
        description: str,
        author: str,
        license: str = 'MIT',
        template: Optional[str] = None
    ) -> PluginProject:
        """Create a new plugin project."""
        try:
            # Set up cookiecutter context
            context = {
                'plugin_name': name,
                'plugin_description': description,
                'author': author,
                'license': license,
                'year': datetime.now().year
            }
            
            # Create project
            cookiecutter(
                template or self._template_dir,
                no_input=True,
                extra_context=context,
                output_dir=path
            )
            
            # Create project instance
            project_path = os.path.join(path, name)
            return PluginProject(name, project_path, self.registry)
            
        except Exception as e:
            raise DevToolsError(f"Project creation failed: {str(e)}")

    def load_project(self, path: str) -> PluginProject:
        """Load an existing plugin project."""
        try:
            # Get project name from directory
            name = os.path.basename(os.path.abspath(path))
            
            # Create project instance
            return PluginProject(name, path, self.registry)
            
        except Exception as e:
            raise DevToolsError(f"Project loading failed: {str(e)}")

@click.group()
def cli():
    """Plugin development tools."""
    pass

@cli.command()
@click.argument('name')
@click.option('--path', '-p', default='.', help='Project path')
@click.option('--description', '-d', help='Plugin description')
@click.option('--author', '-a', help='Plugin author')
@click.option('--license', '-l', default='MIT', help='License')
@click.option('--template', '-t', help='Custom template path')
def create(name, path, description, author, license, template):
    """Create a new plugin project."""
    try:
        tools = DevTools()
        project = tools.create_project(
            name=name,
            path=path,
            description=description or f"{name} plugin",
            author=author or "Unknown",
            license=license,
            template=template
        )
        click.echo(f"Created plugin project at {project.path}")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('path')
@click.option('--coverage/--no-coverage', default=False, help='Run with coverage')
def test(path, coverage):
    """Run plugin tests."""
    try:
        tools = DevTools()
        project = tools.load_project(path)
        project.test(coverage=coverage)
        click.echo("Tests passed")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('path')
@click.option('--output', '-o', help='Output directory')
def generate_docs(path, output):
    """Generate plugin documentation."""
    try:
        tools = DevTools()
        project = tools.load_project(path)
        project.generate_docs(output_dir=output)
        click.echo(f"Generated documentation at {output or os.path.join(path, 'docs')}")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('path')
@click.option('--output', '-o', help='Output directory')
def package(path, output):
    """Package plugin for distribution."""
    try:
        tools = DevTools()
        project = tools.load_project(path)
        package_path = project.package(output_dir=output)
        click.echo(f"Created package at {package_path}")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli() 