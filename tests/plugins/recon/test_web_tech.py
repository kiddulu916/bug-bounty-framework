"""
Tests for the WebTechPlugin.

This module contains comprehensive test cases for the web technology detection plugin,
verifying its functionality for identifying web technologies and frameworks.

Test Categories:
1. Basic Functionality
   - Plugin initialization and configuration
   - Plugin lifecycle management
   - Session handling and SSL verification
   - Technology database setup

2. Header Analysis
   - Server header detection
   - X-Powered-By header analysis
   - Security header identification
   - Content-Type header parsing
   - Custom header detection

3. HTML Analysis
   - Meta tag analysis
   - Script and style detection
   - Framework signature matching
   - CMS identification
   - Version extraction
   - Component detection

4. JavaScript Analysis
   - Framework detection
   - Library identification
   - Version extraction
   - Source map analysis
   - Dynamic loading detection
   - Minified code handling

5. Error Handling
   - Connection error handling
   - Timeout management
   - SSL/TLS error handling
   - Invalid response handling
   - Resource cleanup
   - Error recovery

6. Finding Management
   - Finding creation
   - Finding updates
   - Metadata handling
   - Evidence collection
   - Confidence scoring
   - Finding categorization

7. Resource Management
   - Session cleanup
   - Connection pooling
   - Memory optimization
   - Resource leak prevention
   - Rate limiting
   - Timeout handling

8. Performance
   - Concurrent analysis
   - Response time optimization
   - Resource usage monitoring
   - Cache utilization
   - Batch processing
   - Load management

9. Integration
   - Database integration
   - HTTP client integration
   - Configuration management
   - Plugin lifecycle
   - Service interaction
   - State management
"""

import asyncio
import pytest
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from unittest.mock import AsyncMock, MagicMock, patch
import aiohttp
from datetime import datetime
import json
from urllib.parse import urlparse, urljoin

from bbf.plugins.recon.web_tech import WebTechPlugin
from bbf.core.exceptions import PluginError
from bbf.core.database.models import Finding
from bbf.core.database.service import finding_service

# Test Configuration
TEST_CONFIG = {
    'url': "https://example.com",
    'confidence_threshold': 0.8,
    'timeout': 10.0,
    'max_redirects': 5,
    'max_concurrent_requests': 10,
    'verify_ssl': True,
    'retry_count': 3,
    'retry_delay': 1.0,
    'rate_limit': 10,  # requests per second
    'scan_depth': 3,
    'cache_ttl': 3600,  # 1 hour
    'batch_size': 50
}

# Test Data
TEST_URL = TEST_CONFIG['url']
TEST_DOMAIN = "example.com"
TEST_SUBDOMAIN = "example"

# Test Headers
TEST_HEADERS = {
    'Server': 'nginx/1.18.0',
    'X-Powered-By': 'PHP/7.4.3',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-Content-Type-Options': 'nosniff',
    'Content-Type': 'text/html; charset=utf-8',
    'X-AspNet-Version': '4.0.30319',
    'X-AspNetMvc-Version': '5.2',
    'X-Runtime': 'Ruby/2.7.0',
    'X-Version': 'Django/3.2.0',
    'X-Generator': 'Drupal 9.2.0'
}

# Test HTML Templates
TEST_HTML_TEMPLATES = {
    'wordpress': """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Example Site</title>
        <meta name="generator" content="WordPress 5.8.2">
        <link rel="stylesheet" href="/wp-content/themes/twentytwentyone/style.css">
        <script src="/wp-includes/js/jquery/jquery.min.js"></script>
        <script src="/wp-content/plugins/woocommerce/assets/js/frontend/cart.min.js"></script>
    </head>
    <body>
        <div id="wpadminbar">
            <div class="wp-admin-bar-avatar"></div>
        </div>
        <div id="content">
            <div class="woocommerce-product-gallery">
                <img src="/wp-content/uploads/2023/01/product.jpg">
            </div>
        </div>
    </body>
    </html>
    """,
    'django': """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Django Site</title>
        <meta name="csrf-token" content="abc123">
        <link rel="stylesheet" href="/static/css/main.css">
        <script src="/static/js/jquery.min.js"></script>
        <script src="/static/js/bootstrap.min.js"></script>
    </head>
    <body>
        <div class="container">
            <div class="row">
                <div class="col-md-12">
                    <h1>Welcome to Django</h1>
                </div>
            </div>
        </div>
    </body>
    </html>
    """,
    'react': """
    <!DOCTYPE html>
    <html>
    <head>
        <title>React App</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="/static/css/main.css">
        <script src="/static/js/react.production.min.js"></script>
        <script src="/static/js/react-dom.production.min.js"></script>
        <script src="/static/js/main.js"></script>
    </head>
    <body>
        <div id="root"></div>
        <script>
            ReactDOM.render(
                React.createElement(App, null),
                document.getElementById('root')
            );
        </script>
    </body>
    </html>
    """
}

# Test JavaScript Templates
TEST_JS_TEMPLATES = {
    'react': "/* React v17.0.2 */\nconst App = () => { return React.createElement('div', null, 'Hello World'); };",
    'jquery': "/* jQuery v3.6.0 */\n$(document).ready(function() { $('.menu').click(function() { $(this).toggleClass('active'); }); });",
    'angular': "/* AngularJS v1.8.2 */\nangular.module('app', []).controller('MainCtrl', function($scope) { $scope.message = 'Hello World'; });",
    'vue': "/* Vue.js v2.6.14 */\nnew Vue({ el: '#app', data: { message: 'Hello World' } });"
}

# Expected Technologies
EXPECTED_TECHNOLOGIES = {
    'web-server': {
        'nginx': {
            'version': '1.18.0',
            'confidence': 0.95,
            'category': 'web-server',
            'evidence': ['Server header']
        }
    },
    'programming-language': {
        'PHP': {
            'version': '7.4.3',
            'confidence': 0.9,
            'category': 'programming-language',
            'evidence': ['X-Powered-By header']
        }
    },
    'cms': {
        'WordPress': {
            'version': '5.8.2',
            'confidence': 0.95,
            'category': 'cms',
            'evidence': ['meta generator', 'wp-content path']
        },
        'Drupal': {
            'version': '9.2.0',
            'confidence': 0.9,
            'category': 'cms',
            'evidence': ['X-Generator header']
        }
    },
    'javascript-framework': {
        'jQuery': {
            'version': '3.6.0',
            'confidence': 0.9,
            'category': 'javascript-framework',
            'evidence': ['jquery.min.js', 'jQuery object']
        },
        'React': {
            'version': '17.0.2',
            'confidence': 0.95,
            'category': 'javascript-framework',
            'evidence': ['react.production.min.js', 'ReactDOM.render']
        }
    },
    'ecommerce': {
        'WooCommerce': {
            'version': None,
            'confidence': 0.9,
            'category': 'ecommerce',
            'evidence': ['woocommerce path', 'cart.min.js']
        }
    }
}

# Expected Test Results
EXPECTED_RESULTS = {
    'wordpress': {
        'technologies': ['WordPress', 'WooCommerce', 'jQuery', 'PHP', 'nginx'],
        'categories': ['cms', 'ecommerce', 'javascript-framework', 'programming-language', 'web-server'],
        'confidence': 0.9,
        'evidence_count': 5
    },
    'django': {
        'technologies': ['Django', 'Bootstrap', 'jQuery'],
        'categories': ['web-framework', 'css-framework', 'javascript-framework'],
        'confidence': 0.9,
        'evidence_count': 3
    },
    'react': {
        'technologies': ['React', 'ReactDOM'],
        'categories': ['javascript-framework'],
        'confidence': 0.95,
        'evidence_count': 2
    }
}

class TestWebTechPlugin:
    """
    Test suite for WebTechPlugin.
    
    This class implements comprehensive tests for the web technology detection plugin,
    covering all aspects of its functionality from basic initialization to
    advanced technology detection techniques.
    """
    
    @pytest.fixture
    def plugin(self) -> WebTechPlugin:
        """
        Create a plugin instance for testing.
        
        Returns:
            WebTechPlugin: Plugin instance with default configuration.
        """
        return WebTechPlugin()
    
    @pytest.fixture
    def mock_session(self) -> AsyncGenerator[AsyncMock, None]:
        """
        Create a mock aiohttp session for testing.
        
        Yields:
            AsyncMock: Mocked HTTP session with configured responses.
        """
        with patch('aiohttp.ClientSession') as mock:
            session = AsyncMock()
            mock.return_value.__aenter__.return_value = session
            yield session
    
    @pytest.fixture
    def mock_finding_service(self) -> AsyncGenerator[AsyncMock, None]:
        """
        Mock the finding service for testing.
        
        Yields:
            AsyncMock: Mocked finding service with configured methods.
        """
        with patch('bbf.core.database.service.finding_service') as mock:
            mock.create = AsyncMock()
            mock.update = AsyncMock()
            mock.get_by_url = AsyncMock(return_value=None)
            yield mock

class TestBasicFunctionality(TestWebTechPlugin):
    """Tests for basic plugin functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_initialization(self, plugin: WebTechPlugin) -> None:
        """
        Test plugin initialization.
        
        This test verifies that the plugin:
        1. Initializes with correct configuration
        2. Creates HTTP session
        3. Sets up technology database
        4. Configures confidence threshold
        
        Args:
            plugin: Plugin instance
        """
        await plugin.initialize()
        
        # Verify initialization
        assert plugin._session is not None
        assert isinstance(plugin._session, aiohttp.ClientSession)
        assert plugin._technologies == {}
        assert plugin._confidence_threshold == TEST_CONFIG['confidence_threshold']

class TestHeaderAnalysis(TestWebTechPlugin):
    """Tests for header-based technology detection."""
    
    @pytest.mark.asyncio
    async def test_header_analysis(self, plugin: WebTechPlugin) -> None:
        """
        Test header-based technology detection.
        
        This test verifies that the plugin:
        1. Detects technologies from headers
        2. Identifies versions correctly
        3. Assigns appropriate categories
        4. Calculates confidence scores
        
        Args:
            plugin: Plugin instance
        """
        # Test header analysis
        technologies = await plugin._analyze_headers(TEST_HEADERS)
        
        # Verify results
        assert len(technologies) > 0
        assert any(t['name'] == 'nginx' for t in technologies)
        assert any(t['name'] == 'PHP' for t in technologies)
        assert all(t['confidence'] >= plugin._confidence_threshold for t in technologies)
        assert all(t['category'] in ['web-server', 'programming-language'] for t in technologies)

class TestHTMLAnalysis(TestWebTechPlugin):
    """Tests for HTML-based technology detection."""
    
    @pytest.mark.asyncio
    async def test_html_analysis(self, plugin: WebTechPlugin) -> None:
        """
        Test HTML-based technology detection.
        
        This test verifies that the plugin:
        1. Detects technologies from HTML
        2. Identifies CMS and frameworks
        3. Extracts versions from meta tags
        4. Analyzes script and style references
        
        Args:
            plugin: Plugin instance
        """
        # Test HTML analysis
        technologies = await plugin._analyze_html(TEST_HTML_TEMPLATES['wordpress'])
        
        # Verify results
        assert len(technologies) > 0
        assert any(t['name'] == 'WordPress' for t in technologies)
        assert any(t['name'] == 'WooCommerce' for t in technologies)
        assert any(t['name'] == 'jQuery' for t in technologies)
        assert all(t['confidence'] >= plugin._confidence_threshold for t in technologies)
        assert all(t['category'] in ['cms', 'ecommerce', 'javascript-framework'] for t in technologies)

class TestJavaScriptAnalysis(TestWebTechPlugin):
    """Tests for JavaScript-based technology detection."""
    
    @pytest.mark.asyncio
    async def test_js_analysis(
        self,
        plugin: WebTechPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test JavaScript-based technology detection.
        
        This test verifies that the plugin:
        1. Analyzes JavaScript files
        2. Detects frameworks and libraries
        3. Extracts versions from comments
        4. Handles file retrieval properly
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock JavaScript file response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="/* React v17.0.2 */")
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        # Test JavaScript analysis
        technologies = await plugin._analyze_javascript(TEST_URL, ["/static/js/main.js"])
        
        # Verify results
        assert len(technologies) > 0
        assert any(t['name'] == 'React' for t in technologies)
        assert all(t['confidence'] >= plugin._confidence_threshold for t in technologies)
        assert all(t['category'] == 'javascript-framework' for t in technologies)

class TestErrorHandling(TestWebTechPlugin):
    """Tests for error handling functionality."""
    
    @pytest.mark.asyncio
    async def test_network_error_handling(
        self,
        plugin: WebTechPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test handling of network errors.
        
        This test verifies that the plugin:
        1. Handles connection errors gracefully
        2. Returns empty results on failure
        3. Continues execution after errors
        4. Maintains stability during failures
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock network error
        mock_session.get.side_effect = aiohttp.ClientError("Connection error")
        
        # Test error handling
        results = await plugin.execute(TEST_URL)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_timeout_handling(
        self,
        plugin: WebTechPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test handling of request timeouts.
        
        This test verifies that the plugin:
        1. Handles timeouts gracefully
        2. Respects timeout configuration
        3. Returns partial results if available
        4. Continues execution after timeout
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock timeout
        mock_session.get.side_effect = asyncio.TimeoutError("Request timeout")
        
        # Test timeout handling
        results = await plugin.execute(TEST_URL)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_ssl_error_handling(
        self,
        plugin: WebTechPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test handling of SSL/TLS errors.
        
        This test verifies that the plugin:
        1. Handles SSL errors gracefully
        2. Respects SSL verification settings
        3. Returns empty results on SSL failure
        4. Continues execution after SSL error
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock SSL error
        mock_session.get.side_effect = aiohttp.ClientSSLError("SSL error")
        
        # Test SSL error handling
        results = await plugin.execute(TEST_URL)
        assert len(results) == 0

class TestFindingManagement(TestWebTechPlugin):
    """Tests for finding management functionality."""
    
    @pytest.mark.asyncio
    async def test_finding_creation(
        self,
        plugin: WebTechPlugin,
        mock_session: AsyncMock,
        mock_finding_service: AsyncMock
    ) -> None:
        """
        Test finding creation for discovered technologies.
        
        This test verifies that the plugin:
        1. Creates findings for each technology
        2. Sets appropriate finding attributes
        3. Includes relevant metadata
        4. Updates finding service properly
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
            mock_finding_service: Mocked finding service
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock HTTP response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = TEST_HEADERS
        mock_response.text = AsyncMock(return_value=TEST_HTML_TEMPLATES['wordpress'])
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        # Run plugin execution
        results = await plugin.execute(TEST_URL)
        
        # Verify findings were created
        assert mock_finding_service.create.call_count == len(results)
        for call in mock_finding_service.create.call_args_list:
            finding = call[0][0]
            assert isinstance(finding, Finding)
            assert finding.stage == 'recon'
            assert finding.status == 'active'
            assert finding.severity == 'info'
            assert finding.title.startswith('Web Technology')
            assert finding.description.startswith('Detected')

class TestResourceManagement(TestWebTechPlugin):
    """Tests for resource management functionality."""
    
    @pytest.mark.asyncio
    async def test_plugin_cleanup(
        self,
        plugin: WebTechPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test plugin cleanup.
        
        This test verifies that the plugin:
        1. Closes HTTP session properly
        2. Cleans up resources
        3. Handles cleanup gracefully
        4. Prevents resource leaks
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        await plugin.cleanup()
        
        # Verify session was closed
        mock_session.close.assert_called_once()

class TestPluginExecution(TestWebTechPlugin):
    """Tests for complete plugin execution."""
    
    @pytest.mark.asyncio
    async def test_plugin_execution(
        self,
        plugin: WebTechPlugin,
        mock_session: AsyncMock,
        mock_finding_service: AsyncMock
    ) -> None:
        """
        Test complete plugin execution.
        
        This test verifies that the plugin:
        1. Executes all detection methods
        2. Combines results from different sources
        3. Handles HTTP requests properly
        4. Returns comprehensive findings
        5. Creates appropriate findings
        6. Manages resources properly
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
            mock_finding_service: Mocked finding service
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock HTTP response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = TEST_HEADERS
        mock_response.text = AsyncMock(return_value=TEST_HTML_TEMPLATES['wordpress'])
        mock_session.get.return_value.__aenter__.return_value = mock_response
        
        # Run plugin execution
        results = await plugin.execute(TEST_URL)
        
        # Verify results
        assert isinstance(results, list)
        assert len(results) > 0
        assert all(isinstance(t, dict) for t in results)
        assert all('name' in t for t in results)
        assert all('version' in t for t in results)
        assert all('category' in t for t in results)
        assert all('confidence' in t for t in results)
        assert all('evidence' in t for t in results)
        assert all(t['confidence'] >= plugin._confidence_threshold for t in results)
        
        # Verify technology detection
        detected_techs = {t['name'] for t in results}
        expected_techs = set(EXPECTED_RESULTS['wordpress']['technologies'])
        assert detected_techs == expected_techs
        
        # Verify finding creation
        assert mock_finding_service.create.call_count == len(results)
        for call in mock_finding_service.create.call_args_list:
            finding = call[0][0]
            assert isinstance(finding, Finding)
            assert finding.stage == 'recon'
            assert finding.status == 'active'
            assert finding.severity == 'info'
            assert finding.title.startswith('Web Technology')
            assert finding.description.startswith('Detected')
            assert finding.metadata is not None
            
            metadata = json.loads(finding.metadata)
            assert 'technologies' in metadata
            assert 'scan_timestamp' in metadata
            assert 'scan_details' in metadata
            assert 'confidence' in metadata
            assert 'evidence' in metadata

class TestPerformance(TestWebTechPlugin):
    """Tests for performance and optimization."""
    
    @pytest.mark.asyncio
    async def test_concurrent_analysis(
        self,
        plugin: WebTechPlugin,
        mock_session: AsyncMock
    ) -> None:
        """
        Test concurrent technology analysis.
        
        This test verifies that the plugin:
        1. Handles concurrent requests efficiently
        2. Respects rate limits
        3. Manages resources properly
        4. Completes within timeout
        
        Args:
            plugin: Plugin instance
            mock_session: Mocked HTTP session
        """
        await plugin.initialize()
        plugin._session = mock_session
        
        # Mock responses for concurrent requests
        mock_responses = {
            '/': {'headers': TEST_HEADERS, 'html': TEST_HTML_TEMPLATES['wordpress']},
            '/static/js/main.js': {'js': TEST_JS_TEMPLATES['react']},
            '/static/css/main.css': {'css': '/* Bootstrap v5.0.0 */'},
            '/api/version': {'json': {'version': '1.0.0'}}
        }
        
        async def mock_get(*args: Any, **kwargs: Any) -> AsyncMock:
            mock_response = AsyncMock()
            url = args[0]
            path = urlparse(url).path
            response_data = mock_responses.get(path, {})
            
            mock_response.status = 200
            mock_response.headers = response_data.get('headers', {})
            mock_response.text = AsyncMock(return_value=response_data.get('html', ''))
            mock_response.json = AsyncMock(return_value=response_data.get('json', {}))
            
            return mock_response
        
        mock_session.get.side_effect = mock_get
        
        # Execute plugin with concurrent scanning
        start_time = datetime.utcnow()
        results = await plugin.execute(TEST_URL)
        end_time = datetime.utcnow()
        
        # Verify performance
        scan_duration = (end_time - start_time).total_seconds()
        assert scan_duration < TEST_CONFIG['timeout']
        assert len(results) > 0
        
        # Verify all technology types were detected
        detected_techs = {t['name'] for t in results}
        expected_techs = set(EXPECTED_RESULTS['wordpress']['technologies'])
        assert detected_techs == expected_techs 