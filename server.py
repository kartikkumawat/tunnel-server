#!/usr/bin/env python3
"""
Universal Tunnel Server - Handles WebSocket, SSE, HTTP for ALL frameworks
Works with React, Python, Go, Node.js, PHP, etc. - Zero version dependencies!
"""

import asyncio
import json
import logging
import random
import string
import time
import ssl
import os
import re
from typing import Dict, Optional, Set, Any, Union, List
import uuid
from aiohttp import web, ClientSession, ClientTimeout
from aiohttp.web_request import Request
from aiohttp.web_response import Response, StreamResponse
import aiohttp_cors
from urllib.parse import urlparse, parse_qs
from aiohttp.web_ws import WebSocketResponse, WSMsgType
import base64
import signal
import sys
from datetime import datetime, timedelta, timezone

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)

class UniversalTunnelServer:
    def __init__(self, host='0.0.0.0', port=8080, domain='localhost',
                ssl_cert=None, ssl_key=None, auto_detect_ssl=True,
                max_tunnels=1000, request_timeout=120):

        self.host = host
        self.port = port
        self.domain = domain
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.auto_detect_ssl = auto_detect_ssl
        self.max_tunnels = max_tunnels
        self.request_timeout = request_timeout

        # Auto-detect SSL configuration
        self.use_ssl = self._detect_ssl_setup()
        self.protocol = 'https' if self.use_ssl else 'http'
        self.ws_protocol = 'wss' if self.use_ssl else 'ws'

        # Enhanced storage for all connection types
        self.tunnels: Dict[str, dict] = {}
        self.websocket_to_tunnel: Dict[WebSocketResponse, str] = {}
        self.subdomain_to_tunnel_id: Dict[str, str] = {}
        self.port_to_subdomain: Dict[int, str] = {}
        self.used_subdomains: Set[str] = set()
        self.special_paths = {'status', 'health', 'metrics', 'ws', 'favicon.ico', 'robots.txt'}

        # Universal connection tracking
        self.websocket_sessions: Dict[str, WebSocketResponse] = {}
        self.sse_connections: Dict[str, StreamResponse] = {}
        self.pending_requests: Dict[str, dict] = {}

        # Enhanced framework detection patterns with Socket.IO
        self.framework_patterns = {
            'react': [r'socket\.io', r'ws://', r'wss://', r'react-hot-loader', r'__webpack'],
            'vue': [r'vue-hot-reload', r'ws://', r'wss://', r'vue-cli'],
            'socketio': [r'/socket\.io/', r'EIO=', r'transport=', r'socket\.io'],
            'flask-socketio': [r'flask-socketio', r'/socket\.io/', r'eventlet', r'gevent'],
            'fastapi': [r'/ws', r'websockets', r'uvicorn'],
            'django': [r'channels', r'asgi', r'websocket'],
            'express-socketio': [r'socket\.io', r'express', r'node'],
            'go': [r'gorilla/websocket', r'gin-gonic', r'echo'],
            'php': [r'ratchet', r'reactphp', r'swoole'],
            'aspnet': [r'signalr', r'asp\.net', r'blazor']
        }

        # Statistics
        self.start_time = time.time()
        self.total_requests = 0
        self.total_websockets = 0
        self.total_sse = 0
        self.total_bytes_transferred = 0
        self.failed_requests = 0

        self.running = False
        logger.info(f"🚀 Universal Tunnel Server with Socket.IO Support Initializing")
        logger.info(f"SSL: {'Enabled' if self.use_ssl else 'Disabled'}")
        logger.info(f"Protocol: {self.protocol}")

    def _detect_ssl_setup(self) -> bool:
        """Enhanced SSL detection for any platform"""
        if not self.auto_detect_ssl:
            return False

        # Platform detection
        platform_indicators = [
            'RENDER', 'HEROKU', 'VERCEL', 'NETLIFY', 'RAILWAY',
            'AWS_LAMBDA', 'AZURE_FUNCTIONS', 'GOOGLE_CLOUD',
            'DIGITALOCEAN_APP', 'FLY_IO'
        ]

        if any(os.environ.get(indicator) for indicator in platform_indicators):
            logger.info("SSL enabled - deployment platform detected")
            return True

        ssl_env_vars = ['HTTPS', 'USE_SSL', 'SSL_ENABLED', 'FORCE_HTTPS', 'TLS']
        for var in ssl_env_vars:
            value = os.environ.get(var, '').lower()
            if value in ('true', '1', 'yes', 'on', 'enabled'):
                logger.info(f"SSL enabled via {var}")
                return True

        if self.ssl_cert and self.ssl_key:
            return True

        return self.port == 443

    def _is_socket_io_request(self, request: Request) -> bool:
        """Enhanced Socket.IO detection"""
        path = request.path.lower()
        query_string = str(request.query_string)

        # Direct Socket.IO path detection
        if '/socket.io/' in path:
            return True

        # Socket.IO query parameters
        socketio_params = ['eio=', 'transport=', 'sid=']
        if any(param in query_string.lower() for param in socketio_params):
            return True

        # Socket.IO specific headers
        origin = request.headers.get('origin', '').lower()
        if 'socket.io' in origin:
            return True

        return False

    def _is_websocket_request(self, request: Request) -> bool:
        """Universal WebSocket detection including Socket.IO WebSocket upgrade"""
        connection = request.headers.get('connection', '').lower()
        upgrade = request.headers.get('upgrade', '').lower()
        ws_key = request.headers.get('sec-websocket-key')
        ws_version = request.headers.get('sec-websocket-version')

        # Standard WebSocket upgrade
        if ('upgrade' in connection and upgrade == 'websocket' and ws_key and ws_version):
            return True

        # Socket.IO WebSocket upgrade (happens after initial polling)
        if self._is_socket_io_request(request) and 'websocket' in str(request.query.get('transport', '')):
            return True

        # Common WebSocket paths
        ws_paths = ['/ws', '/websocket', '/socket', '/realtime', '/live']
        if any(ws_path in request.path.lower() for ws_path in ws_paths):
            return True

        return False

    def _detect_framework_type(self, headers: Dict[str, str], path: str, body: str = '') -> str:
        """Enhanced framework detection with Socket.IO priority"""
        user_agent = headers.get('user-agent', '').lower()
        origin = headers.get('origin', '').lower()
        content_type = headers.get('content-type', '').lower()

        # Combine all text for analysis
        combined_text = f"{user_agent} {origin} {path} {body}".lower()

        # Priority check for Socket.IO
        if '/socket.io/' in path or 'eio=' in path or 'transport=' in path:
            if 'flask' in combined_text:
                return 'flask-socketio'
            elif 'express' in combined_text or 'node' in combined_text:
                return 'express-socketio'
            else:
                return 'socketio'

        framework_scores = {}
        for framework, patterns in self.framework_patterns.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    score += 1
            if score > 0:
                framework_scores[framework] = score

        if framework_scores:
            detected = max(framework_scores, key=framework_scores.get)
            logger.info(f"🔍 Framework detected: {detected.upper()}")
            return detected

        return 'unknown'

    async def handle_http_request(self, request: Request) -> Response:
        """Enhanced HTTP request handler with Socket.IO support"""
        start_time = time.time()
        host = request.headers.get('host', '')
        path = request.path.strip('/')

        # Handle server paths first
        if path in self.special_paths:
            return await self._handle_server_path(path, request)

        # Special handling for Socket.IO requests
        if self._is_socket_io_request(request):
            logger.info(f"🔌 Socket.IO request detected: {request.method} {request.path_qs}")

            # Check if it's a WebSocket upgrade request
            if self._is_websocket_request(request):
                return await self.handle_websocket_proxy(request)
            else:
                # Handle Socket.IO HTTP polling
                return await self.handle_socketio_polling(request)

        # Check for other connection types
        if self._is_websocket_request(request):
            return await self.handle_websocket_proxy(request)
        elif self._is_sse_request(request):
            return await self.handle_sse_proxy(request)

        # Handle regular HTTP tunnel traffic
        subdomain = self._extract_subdomain(host)
        if not subdomain:
            return await self.not_found_handler(request)

        tunnel_data, tunnel_id = self._find_tunnel_by_subdomain(subdomain)
        if not tunnel_data:
            logger.warning(f"No tunnel found for subdomain: {subdomain}")
            return web.Response(
                text=f"Tunnel for '{subdomain}' not found or not connected.",
                status=404
            )

        if tunnel_data['websocket'].closed:
            self.cleanup_tunnel(tunnel_id)
            return web.Response(
                text="Tunnel connection is closed. Please restart your client.",
                status=503
            )

        try:
            # Detect framework
            body = await request.read()
            framework = self._detect_framework_type(dict(request.headers), request.path, body.decode('utf-8', errors='ignore'))
            tunnel_data['detected_frameworks'].add(framework)

            response = await self._forward_http_request(request, tunnel_data, tunnel_id, body)
            duration = time.time() - start_time

            logger.info(f"🔄 {request.method} {request.path_qs} -> {subdomain} "
                       f"({response.status}) [{duration:.3f}s] [{framework}]")

            # Update statistics
            tunnel_data['request_count'] += 1
            self.total_requests += 1

            if hasattr(response, 'body') and response.body:
                body_size = len(response.body)
                tunnel_data['bytes_transferred'] += body_size
                self.total_bytes_transferred += body_size

            return response

        except asyncio.TimeoutError:
            self.failed_requests += 1
            logger.error(f"Request timeout for {subdomain}")
            return web.Response(text="Request timeout", status=504)
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"Error forwarding request: {e}", exc_info=True)
            return web.Response(text="Internal server error", status=500)

    async def handle_socketio_polling(self, request: Request) -> Response:
        """Handle Socket.IO HTTP polling requests"""
        subdomain = self._extract_subdomain(request.headers.get('host', ''))
        if not subdomain:
            return web.Response(text="Invalid subdomain for Socket.IO", status=400)

        tunnel_data, tunnel_id = self._find_tunnel_by_subdomain(subdomain)
        if not tunnel_data or tunnel_data['websocket'].closed:
            return web.Response(text=f"Socket.IO tunnel '{subdomain}' not found", status=503)

        # Enable Socket.IO support if not already enabled
        service_types = tunnel_data.get('service_types', {})
        local_port = self._extract_local_port_from_subdomain(subdomain)
        supported_types = service_types.get(local_port, ['http'])

        if 'socketio' not in supported_types and 'ws' not in supported_types:
            logger.info(f"Auto-enabling Socket.IO for {subdomain}")
            supported_types.extend(['socketio', 'ws'])
            service_types[local_port] = supported_types

        # Framework detection
        framework = self._detect_framework_type(dict(request.headers), request.path)
        tunnel_data['detected_frameworks'].add(framework)

        logger.info(f"🔌 Socket.IO polling: {request.method} {request.path_qs} -> {subdomain} [{framework}]")

        try:
            body = await request.read()
            response = await self._forward_http_request(request, tunnel_data, tunnel_id, body)

            # Add CORS headers for Socket.IO
            if hasattr(response, 'headers'):
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Access-Control-Allow-Credentials'] = 'true'
                response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = '*'

            return response

        except Exception as e:
            logger.error(f"Socket.IO polling error: {e}")
            return web.Response(text="Socket.IO polling failed", status=500)

    def _is_websocket_request(self, request: Request) -> bool:
        """Universal WebSocket detection"""
        connection = request.headers.get('connection', '').lower()
        upgrade = request.headers.get('upgrade', '').lower()
        ws_key = request.headers.get('sec-websocket-key')
        ws_version = request.headers.get('sec-websocket-version')

        # Standard WebSocket upgrade
        if ('upgrade' in connection and upgrade == 'websocket' and ws_key and ws_version):
            return True

        # Socket.IO detection
        if 'socket.io' in request.path.lower():
            return True

        # Common WebSocket paths
        ws_paths = ['/ws', '/websocket', '/socket', '/realtime', '/live']
        if any(ws_path in request.path.lower() for ws_path in ws_paths):
            return True

        return False

    def _is_sse_request(self, request: Request) -> bool:
        """Universal SSE detection"""
        accept = request.headers.get('accept', '').lower()
        cache_control = request.headers.get('cache-control', '').lower()

        # Standard SSE request
        if 'text/event-stream' in accept:
            return True

        # Common SSE patterns
        if 'no-cache' in cache_control and 'stream' in request.path.lower():
            return True

        # Common SSE paths
        sse_paths = ['/events', '/stream', '/live', '/sse', '/updates']
        if any(sse_path in request.path.lower() for sse_path in sse_paths):
            return True

        return False

    def generate_unique_subdomain(self, local_port: int, service_type: str = 'http') -> str:
        """Generate unique subdomain with service type support"""
        if service_type == 'ws':
            candidate = f"ws{local_port}"
        elif service_type == 'sse':
            candidate = f"sse{local_port}"
        else:
            candidate = f"port{local_port}"

        if candidate not in self.used_subdomains:
            return candidate

        # Fallback to random
        for _ in range(100):
            suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            candidate = f"{service_type}{local_port}-{suffix}"
            if candidate not in self.used_subdomains:
                return candidate

        return f"tunnel-{int(time.time())}"

    def get_public_url(self, subdomain: str, secure: bool = None) -> str:
        """Get public URL with protocol flexibility"""
        domain = self._normalize_domain(self.domain)

        if subdomain in self.special_paths:
            return f"{self.protocol}://{domain}/{subdomain}"

        # Determine protocol
        if secure is None:
            protocol = self.protocol
        else:
            protocol = 'https' if secure else 'http'

        if self._is_deployment_platform():
            return f"{protocol}://{subdomain}.{domain}"
        else:
            port_str = f":{self.port}" if self.port not in [80, 443] else ""
            return f"{protocol}://{subdomain}.{domain}{port_str}"

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain"""
        if domain.startswith(('http://', 'https://')):
            return urlparse(domain).netloc
        return domain

    def _is_deployment_platform(self) -> bool:
        """Check if on deployment platform"""
        indicators = [
            'RENDER', 'HEROKU', 'VERCEL', 'NETLIFY', 'RAILWAY',
            'AWS_LAMBDA', 'AZURE_FUNCTIONS', 'GOOGLE_CLOUD'
        ]
        return any(os.environ.get(indicator) for indicator in indicators)

    async def handle_websocket_connection(self, websocket: WebSocketResponse, request: Request):
        """Enhanced WebSocket control connection handler"""
        client_ip = request.remote or "unknown"
        logger.info(f"🔌 New WebSocket control connection from {client_ip}")

        tunnel_id = str(uuid.uuid4())
        self.websocket_to_tunnel[websocket] = tunnel_id

        if len(self.tunnels) >= self.max_tunnels:
            await websocket.send_json({
                'type': 'error',
                'message': f'Server at capacity. Max {self.max_tunnels} connections allowed.'
            })
            await websocket.close()
            return

        try:
            async for msg in websocket:
                if msg.type == web.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._process_control_message(data, websocket, client_ip)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON from {client_ip}")
                    except Exception as e:
                        logger.error(f"Error processing message: {e}", exc_info=True)
                elif msg.type == web.WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {websocket.exception()}")
                    break
        except Exception as e:
            logger.error(f"WebSocket handler error: {e}", exc_info=True)
        finally:
            tunnel_id = self.websocket_to_tunnel.get(websocket)
            if tunnel_id and tunnel_id in self.tunnels:
                self.cleanup_tunnel(tunnel_id)
            self.websocket_to_tunnel.pop(websocket, None)
            logger.info(f"WebSocket connection closed for {client_ip}")

    async def _process_control_message(self, data: dict, websocket: WebSocketResponse, client_ip: str):
        """Process control channel messages with universal support"""
        msg_type = data.get('type')
        tunnel_id = self.websocket_to_tunnel.get(websocket)

        if msg_type == 'register':
            await self._handle_registration(data, websocket, client_ip)
        elif msg_type == 'response' and tunnel_id:
            await self._handle_http_response(data)
        elif msg_type == 'ws_data' and tunnel_id:
            await self._handle_websocket_data(data, tunnel_id)
        elif msg_type == 'ws_closed' and tunnel_id:
            await self._handle_websocket_closed(data)
        elif msg_type == 'sse_data' and tunnel_id:
            await self._handle_sse_data(data, tunnel_id)
        elif msg_type == 'sse_closed' and tunnel_id:
            await self._handle_sse_closed(data)
        elif msg_type == 'heartbeat' and tunnel_id:
            await self._handle_heartbeat(tunnel_id, websocket)
        else:
            logger.warning(f"Unknown message type: {msg_type}")

    async def _handle_registration(self, data: dict, websocket: WebSocketResponse, client_ip: str):
        """Enhanced registration with universal service type support"""
        local_port = data.get('local_port')
        service_types = data.get('service_types', ['http'])  # Can be ['http', 'ws', 'sse']

        if not isinstance(local_port, int) or not (1 <= local_port <= 65535):
            await websocket.send_json({
                'type': 'error',
                'message': 'Invalid local_port. Must be between 1-65535.'
            })
            return

        if local_port in self.port_to_subdomain:
            existing_subdomain = self.port_to_subdomain[local_port]
            await websocket.send_json({
                'type': 'error',
                'message': f'Port {local_port} already tunneled to {self.get_public_url(existing_subdomain)}'
            })
            return

        tunnel_id = self.websocket_to_tunnel.get(websocket)
        if tunnel_id not in self.tunnels:
            self.tunnels[tunnel_id] = {
                'websocket': websocket,
                'client_ip': client_ip,
                'last_seen': time.time(),
                'created_at': time.time(),
                'exposed_ports': {},
                'request_count': 0,
                'websocket_count': 0,
                'sse_count': 0,
                'bytes_transferred': 0,
                'service_types': {},
                'detected_frameworks': set()
            }

        # Generate subdomain for primary service type
        primary_service = service_types[0] if service_types else 'http'
        subdomain = self.generate_unique_subdomain(local_port, primary_service)

        # Store the mapping
        self.tunnels[tunnel_id]['exposed_ports'][local_port] = subdomain
        self.tunnels[tunnel_id]['service_types'][local_port] = service_types
        self.subdomain_to_tunnel_id[subdomain] = tunnel_id
        self.port_to_subdomain[local_port] = subdomain
        self.used_subdomains.add(subdomain)

        # Generate URLs for all supported protocols
        urls = {}
        for service_type in service_types:
            if service_type == 'ws':
                base_url = self.get_public_url(subdomain)
                urls['websocket'] = base_url.replace('http://', 'ws://').replace('https://', 'wss://')
            elif service_type == 'sse':
                urls['sse'] = self.get_public_url(subdomain)
            else:
                urls['http'] = self.get_public_url(subdomain)

        await websocket.send_json({
            'type': 'registered',
            'tunnel_id': tunnel_id,
            'local_port': local_port,
            'subdomain': subdomain,
            'service_types': service_types,
            'urls': urls,
            'server_info': {
                'version': '3.0',
                'features': [
                    'universal-websocket', 'server-sent-events', 'all-http-methods',
                    'framework-agnostic', 'auto-detection', 'binary-support'
                ]
            }
        })

        services_str = ', '.join(service_types).upper()
        logger.info(f"✅ Universal Tunnel: {urls} -> localhost:{local_port} ({services_str})")

    async def websocket_handler(self, request: Request) -> WebSocketResponse:
        """WebSocket upgrade handler"""
        ws = WebSocketResponse(heartbeat=30, max_msg_size=500 * 1024 * 1024)
        await ws.prepare(request)
        await self.handle_websocket_connection(ws, request)
        return ws

    async def handle_http_request(self, request: Request) -> Response:
        """Universal HTTP request handler"""
        start_time = time.time()
        host = request.headers.get('host', '')
        path = request.path.strip('/')

        # Handle server paths first
        if path in self.special_paths:
            return await self._handle_server_path(path, request)

        # Check connection type
        if self._is_websocket_request(request):
            return await self.handle_websocket_proxy(request)
        elif self._is_sse_request(request):
            return await self.handle_sse_proxy(request)

        # Handle regular HTTP tunnel traffic
        subdomain = self._extract_subdomain(host)
        if not subdomain:
            return await self.not_found_handler(request)

        tunnel_data, tunnel_id = self._find_tunnel_by_subdomain(subdomain)
        if not tunnel_data:
            logger.warning(f"No tunnel found for subdomain: {subdomain}")
            return web.Response(
                text=f"Tunnel for '{subdomain}' not found or not connected.",
                status=404
            )

        if tunnel_data['websocket'].closed:
            self.cleanup_tunnel(tunnel_id)
            return web.Response(
                text="Tunnel connection is closed. Please restart your client.",
                status=503
            )

        try:
            # Detect framework
            body = await request.read()
            framework = self._detect_framework_type(dict(request.headers), path, body.decode('utf-8', errors='ignore'))
            tunnel_data['detected_frameworks'].add(framework)

            response = await self._forward_http_request(request, tunnel_data, tunnel_id, body)
            duration = time.time() - start_time

            logger.info(f"🔄 {request.method} {request.path_qs} -> {subdomain} "
                       f"({response.status}) [{duration:.3f}s] [{framework}]")

            # Update statistics
            tunnel_data['request_count'] += 1
            self.total_requests += 1

            if hasattr(response, 'body') and response.body:
                body_size = len(response.body)
                tunnel_data['bytes_transferred'] += body_size
                self.total_bytes_transferred += body_size

            return response

        except asyncio.TimeoutError:
            self.failed_requests += 1
            logger.error(f"Request timeout for {subdomain}")
            return web.Response(text="Request timeout", status=504)
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"Error forwarding request: {e}", exc_info=True)
            return web.Response(text="Internal server error", status=500)

    async def handle_websocket_proxy(self, request: Request) -> WebSocketResponse:
        """Universal WebSocket proxy handler"""
        subdomain = self._extract_subdomain(request.headers.get('host', ''))
        if not subdomain:
            return web.Response(text="Invalid subdomain for WebSocket", status=400)

        tunnel_data, tunnel_id = self._find_tunnel_by_subdomain(subdomain)
        if not tunnel_data or tunnel_data['websocket'].closed:
            return web.Response(text=f"WebSocket tunnel '{subdomain}' not found", status=503)

        # Check if WebSocket is supported for this tunnel
        service_types = tunnel_data.get('service_types', {})
        local_port = self._extract_local_port_from_subdomain(subdomain)
        supported_types = service_types.get(local_port, ['http'])

        if 'ws' not in supported_types and 'websocket' not in [t.lower() for t in supported_types]:
            logger.info(f"Auto-enabling WebSocket for {subdomain}")
            supported_types.append('ws')
            service_types[local_port] = supported_types

        public_ws = WebSocketResponse(heartbeat=30, max_msg_size=500 * 1024 * 1024)
        await public_ws.prepare(request)

        session_id = str(uuid.uuid4())
        self.websocket_sessions[session_id] = public_ws

        # Detect framework from WebSocket handshake
        framework = self._detect_framework_type(dict(request.headers), request.path)
        tunnel_data['detected_frameworks'].add(framework)

        logger.info(f"🔌 WebSocket session {session_id} started for {subdomain} [{framework}]")
        tunnel_data['websocket_count'] += 1
        self.total_websockets += 1

        try:
            # Notify client to establish local WebSocket connection
            await tunnel_data['websocket'].send_json({
                'type': 'ws_initiate',
                'websocket_session_id': session_id,
                'path': request.path_qs,
                'headers': dict(request.headers),
                'framework': framework
            })

            # Relay messages from public client to tunnel
            async for msg in public_ws:
                if msg.type == WSMsgType.TEXT:
                    await tunnel_data['websocket'].send_json({
                        'type': 'ws_data',
                        'websocket_session_id': session_id,
                        'ws_message_type': 'text',
                        'ws_data': msg.data
                    })
                elif msg.type == WSMsgType.BINARY:
                    encoded_data = base64.b64encode(msg.data).decode('utf-8')
                    await tunnel_data['websocket'].send_json({
                        'type': 'ws_data',
                        'websocket_session_id': session_id,
                        'ws_message_type': 'binary',
                        'ws_data': encoded_data
                    })
                elif msg.type in [WSMsgType.CLOSE, WSMsgType.ERROR]:
                    break

        except Exception as e:
            logger.error(f"WebSocket proxy error: {e}")
        finally:
            self.websocket_sessions.pop(session_id, None)
            if not public_ws.closed:
                await public_ws.close()

            # Notify client that session ended
            if tunnel_id in self.tunnels:
                try:
                    await tunnel_data['websocket'].send_json({
                        'type': 'ws_close',
                        'websocket_session_id': session_id
                    })
                except Exception:
                    pass

        return public_ws

    async def handle_sse_proxy(self, request: Request) -> StreamResponse:
        """Universal Server-Sent Events proxy handler"""
        subdomain = self._extract_subdomain(request.headers.get('host', ''))
        if not subdomain:
            return web.Response(text="Invalid subdomain for SSE", status=400)

        tunnel_data, tunnel_id = self._find_tunnel_by_subdomain(subdomain)
        if not tunnel_data or tunnel_data['websocket'].closed:
            return web.Response(text=f"SSE tunnel '{subdomain}' not found", status=503)

        # Check if SSE is supported for this tunnel
        service_types = tunnel_data.get('service_types', {})
        local_port = self._extract_local_port_from_subdomain(subdomain)
        supported_types = service_types.get(local_port, ['http'])

        if 'sse' not in supported_types:
            logger.info(f"Auto-enabling SSE for {subdomain}")
            supported_types.append('sse')
            service_types[local_port] = supported_types

        # Create SSE response
        response = StreamResponse(
            status=200,
            reason='OK',
            headers={
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Cache-Control'
            }
        )
        await response.prepare(request)

        session_id = str(uuid.uuid4())
        self.sse_connections[session_id] = response

        # Detect framework
        framework = self._detect_framework_type(dict(request.headers), request.path)
        tunnel_data['detected_frameworks'].add(framework)

        logger.info(f"📡 SSE session {session_id} started for {subdomain} [{framework}]")
        tunnel_data['sse_count'] += 1
        self.total_sse += 1

        try:
            # Notify client to establish local SSE connection
            await tunnel_data['websocket'].send_json({
                'type': 'sse_initiate',
                'sse_session_id': session_id,
                'path': request.path_qs,
                'headers': dict(request.headers),
                'framework': framework
            })

            # Keep connection alive
            while not response.task.done():
                await asyncio.sleep(30)  # Send keep-alive every 30 seconds
                try:
                    await response.write(b': keep-alive\n\n')
                except Exception:
                    break

        except Exception as e:
            logger.error(f"SSE proxy error: {e}")
        finally:
            self.sse_connections.pop(session_id, None)

            # Notify client that session ended
            if tunnel_id in self.tunnels:
                try:
                    await tunnel_data['websocket'].send_json({
                        'type': 'sse_close',
                        'sse_session_id': session_id
                    })
                except Exception:
                    pass

        return response

    async def _handle_websocket_data(self, data: dict, tunnel_id: str):
        """Handle WebSocket data from client"""
        session_id = data.get('websocket_session_id')
        msg_type = data.get('ws_message_type')
        payload = data.get('ws_data')

        if session_id not in self.websocket_sessions:
            return

        public_ws = self.websocket_sessions[session_id]
        if public_ws.closed:
            self.websocket_sessions.pop(session_id, None)
            return

        try:
            if msg_type == 'text':
                await public_ws.send_str(payload)
            elif msg_type == 'binary':
                decoded_data = base64.b64decode(payload)
                await public_ws.send_bytes(decoded_data)

            # Update stats
            if tunnel_id in self.tunnels:
                self.tunnels[tunnel_id]['bytes_transferred'] += len(payload.encode('utf-8'))

        except Exception as e:
            logger.error(f"Error sending WebSocket data: {e}")
            self.websocket_sessions.pop(session_id, None)

    async def _handle_sse_data(self, data: dict, tunnel_id: str):
        """Handle SSE data from client"""
        session_id = data.get('sse_session_id')
        event_type = data.get('event_type', 'message')
        event_data = data.get('event_data', '')
        event_id = data.get('event_id')

        if session_id not in self.sse_connections:
            return

        sse_response = self.sse_connections[session_id]
        if sse_response.task.done():
            self.sse_connections.pop(session_id, None)
            return

        try:
            # Format SSE event
            sse_message = f"event: {event_type}\n"
            if event_id:
                sse_message += f"id: {event_id}\n"
            sse_message += f"data: {event_data}\n\n"

            await sse_response.write(sse_message.encode('utf-8'))

            # Update stats
            if tunnel_id in self.tunnels:
                self.tunnels[tunnel_id]['bytes_transferred'] += len(sse_message.encode('utf-8'))

        except Exception as e:
            logger.error(f"Error sending SSE data: {e}")
            self.sse_connections.pop(session_id, None)

    async def _handle_websocket_closed(self, data: dict):
        """Handle WebSocket close from client"""
        session_id = data.get('websocket_session_id')
        if session_id in self.websocket_sessions:
            ws = self.websocket_sessions.pop(session_id)
            if not ws.closed:
                await ws.close()

    async def _handle_sse_closed(self, data: dict):
        """Handle SSE close from client"""
        session_id = data.get('sse_session_id')
        if session_id in self.sse_connections:
            sse_response = self.sse_connections.pop(session_id)
            if not sse_response.task.done():
                sse_response.force_close()

    def _extract_subdomain(self, host: str) -> Optional[str]:
        """Extract subdomain from host header"""
        if not host:
            return None

        host_without_port = host.split(':')[0]
        domain = self._normalize_domain(self.domain)

        if host_without_port.endswith(domain):
            subdomain_part = host_without_port[:-len(domain)].strip('.')
            if self._is_deployment_platform():
                return subdomain_part.split('.')[0]
            return subdomain_part

        return None

    def _extract_local_port_from_subdomain(self, subdomain: str) -> Optional[int]:
        """Extract local port from subdomain"""
        patterns = [
            r'port(\d+)', r'ws(\d+)', r'sse(\d+)',
            r'(\d+)', r'.*?(\d+)'
        ]

        for pattern in patterns:
            match = re.search(pattern, subdomain)
            if match:
                try:
                    return int(match.group(1))
                except (ValueError, IndexError):
                    continue

        return None

    def _find_tunnel_by_subdomain(self, subdomain: str) -> tuple[Optional[dict], Optional[str]]:
        """Find tunnel by subdomain"""
        tunnel_id = self.subdomain_to_tunnel_id.get(subdomain)
        if tunnel_id and tunnel_id in self.tunnels:
            return self.tunnels[tunnel_id], tunnel_id
        return None, None

    async def _forward_http_request(self, request: Request, tunnel: dict, tunnel_id: str, body: bytes = None) -> Response:
        """Enhanced HTTP request forwarding"""
        request_id = str(uuid.uuid4())

        if body is None:
            try:
                body = await request.read()
            except Exception as e:
                logger.error(f"Failed to read request body: {e}")
                body = b''

        request_data = {
            'type': 'request',
            'request_id': request_id,
            'method': request.method,
            'path': request.path_qs,
            'headers': dict(request.headers),
            'body': base64.b64encode(body).decode('utf-8') if body else None,
        }

        future = asyncio.Future()
        self.pending_requests[request_id] = {
            'future': future,
            'timeout': time.time() + self.request_timeout,
            'tunnel_id': tunnel_id
        }

        try:
            await tunnel['websocket'].send_json(request_data)
            response_data = await asyncio.wait_for(future, timeout=self.request_timeout)
            return self._create_response(response_data)
        except asyncio.TimeoutError:
            self.pending_requests.pop(request_id, None)
            raise
        except Exception as e:
            self.pending_requests.pop(request_id, None)
            raise e

    def _create_response(self, response_data: dict) -> Response:
        """Create HTTP response with proper encoding handling"""
        status = response_data.get('status', 200)
        headers = response_data.get('headers', {})
        body_data = response_data.get('body', '')
        body_encoding = response_data.get('body_encoding', 'base64')

        # Handle response body based on encoding type
        if body_data:
            try:
                if body_encoding == 'base64':
                    body_bytes = base64.b64decode(body_data)
                elif body_encoding == 'utf-8':
                    body_bytes = body_data.encode('utf-8')
                else:
                    try:
                        body_bytes = base64.b64decode(body_data)
                    except Exception:
                        body_bytes = body_data.encode('utf-8')
            except Exception as e:
                logger.error(f"Error decoding response body: {e}")
                body_bytes = b''
        else:
            body_bytes = b''

        # Clean problematic headers
        problematic_headers = {
            'transfer-encoding', 'content-length', 'content-encoding',
            'accept-encoding', 'connection', 'upgrade'
        }

        cleaned_headers = {}
        for k, v in headers.items():
            if k.lower() not in problematic_headers:
                cleaned_headers[k] = v

        # Set proper content-length
        if body_bytes:
            cleaned_headers['Content-Length'] = str(len(body_bytes))

        return web.Response(body=body_bytes, status=status, headers=cleaned_headers)

    async def _handle_http_response(self, data: dict):
        """Handle HTTP response from client"""
        request_id = data.get('request_id')
        if request_id in self.pending_requests:
            future = self.pending_requests.pop(request_id)['future']
            if not future.done():
                future.set_result(data)

    async def _handle_heartbeat(self, tunnel_id: str, websocket: WebSocketResponse):
        """Handle heartbeat"""
        if tunnel_id in self.tunnels:
            self.tunnels[tunnel_id]['last_seen'] = time.time()
            await websocket.send_json({'type': 'heartbeat_ack'})

    def cleanup_tunnel(self, tunnel_id: str):
        """Clean up tunnel resources"""
        if tunnel_id not in self.tunnels:
            return

        tunnel_data = self.tunnels.pop(tunnel_id)
        exposed_ports = tunnel_data.get('exposed_ports', {})

        for local_port, subdomain in exposed_ports.items():
            self.used_subdomains.discard(subdomain)
            self.port_to_subdomain.pop(local_port, None)
            self.subdomain_to_tunnel_id.pop(subdomain, None)

        # Clean up WebSocket sessions
        sessions_to_close = [
            sid for sid, ws in list(self.websocket_sessions.items())
            if hasattr(ws, '_tunnel_id') and ws._tunnel_id == tunnel_id
        ]

        for session_id in sessions_to_close:
            ws = self.websocket_sessions.pop(session_id)
            if not ws.closed:
                asyncio.create_task(ws.close())

        # Clean up SSE connections
        sse_to_close = [
            sid for sid, resp in list(self.sse_connections.items())
            if hasattr(resp, '_tunnel_id') and resp._tunnel_id == tunnel_id
        ]

        for session_id in sse_to_close:
            resp = self.sse_connections.pop(session_id)
            if not resp.task.done():
                resp.force_close()

        logger.info(f"🧹 Cleaned up tunnel: {tunnel_id}")

    async def _handle_server_path(self, path: str, request: Request) -> Response:
        """Handle server-specific paths"""
        if path == 'status':
            return await self.status_handler(request)
        elif path == 'health':
            return await self.health_handler(request)
        elif path == 'metrics':
            return await self.metrics_handler(request)
        elif path == 'favicon.ico':
            return web.Response(status=204)
        elif path == 'robots.txt':
            return web.Response(text="User-agent: *\nDisallow: /", content_type='text/plain')
        else:
            return await self.not_found_handler(request)

    async def status_handler(self, request: Request) -> Response:
        """Enhanced status endpoint with framework detection"""
        uptime = time.time() - self.start_time
        tunnels_info = []

        for tid, tdata in self.tunnels.items():
            ports_info = []
            for port, subdomain in tdata.get('exposed_ports', {}).items():
                service_types = tdata.get('service_types', {}).get(port, ['http'])
                ports_info.append({
                    'local_port': port,
                    'subdomain': subdomain,
                    'public_url': self.get_public_url(subdomain),
                    'service_types': service_types,
                    'websocket_url': self.get_public_url(subdomain).replace('http://', 'ws://').replace('https://', 'wss://') if 'ws' in service_types else None,
                    'sse_url': self.get_public_url(subdomain) if 'sse' in service_types else None
                })

            tunnels_info.append({
                'tunnel_id': tid,
                'client_ip': tdata['client_ip'],
                'uptime': time.time() - tdata['created_at'],
                'last_seen': tdata['last_seen'],
                'exposed_ports': ports_info,
                'request_count': tdata.get('request_count', 0),
                'websocket_count': tdata.get('websocket_count', 0),
                'sse_count': tdata.get('sse_count', 0),
                'bytes_transferred': tdata.get('bytes_transferred', 0),
                'detected_frameworks': list(tdata.get('detected_frameworks', set()))
            })

        status = {
            'server_status': 'running',
            'version': '3.0',
            'uptime_seconds': uptime,
            'active_tunnels': len(self.tunnels),
            'max_tunnels': self.max_tunnels,
            'total_requests': self.total_requests,
            'total_websockets': self.total_websockets,
            'total_sse': self.total_sse,
            'total_bytes_transferred': self.total_bytes_transferred,
            'failed_requests': self.failed_requests,
            'pending_requests': len(self.pending_requests),
            'active_websocket_sessions': len(self.websocket_sessions),
            'active_sse_connections': len(self.sse_connections),
            'tunnels': tunnels_info,
            'features': [
                'universal-websocket', 'server-sent-events', 'all-http-methods',
                'framework-detection', 'auto-protocol-upgrade', 'binary-support',
                'react-support', 'vue-support', 'flask-support', 'fastapi-support',
                'go-support', 'node-support', 'php-support', 'aspnet-support'
            ]
        }

        return web.json_response(status)

    async def health_handler(self, request: Request) -> Response:
        """Health check endpoint"""
        return web.json_response({
            'status': 'healthy',
            'timestamp': time.time(),
            'active_tunnels': len(self.tunnels),
            'version': '3.0'
        })

    async def metrics_handler(self, request: Request) -> Response:
        """Enhanced Prometheus metrics"""
        metrics = [
            f"# HELP tunnel_server_uptime_seconds Server uptime in seconds",
            f"tunnel_server_uptime_seconds {time.time() - self.start_time}",
            f"# HELP tunnel_server_active_tunnels Number of active tunnels",
            f"tunnel_server_active_tunnels {len(self.tunnels)}",
            f"# HELP tunnel_server_total_requests Total HTTP requests processed",
            f"tunnel_server_total_requests {self.total_requests}",
            f"# HELP tunnel_server_total_websockets Total WebSocket connections",
            f"tunnel_server_total_websockets {self.total_websockets}",
            f"# HELP tunnel_server_total_sse Total SSE connections",
            f"tunnel_server_total_sse {self.total_sse}",
            f"# HELP tunnel_server_failed_requests Total failed requests",
            f"tunnel_server_failed_requests {self.failed_requests}",
            f"# HELP tunnel_server_bytes_transferred Total bytes transferred",
            f"tunnel_server_bytes_transferred {self.total_bytes_transferred}",
            f"# HELP tunnel_server_pending_requests Current pending requests",
            f"tunnel_server_pending_requests {len(self.pending_requests)}",
            f"# HELP tunnel_server_websocket_sessions Current WebSocket sessions",
            f"tunnel_server_websocket_sessions {len(self.websocket_sessions)}",
            f"# HELP tunnel_server_sse_connections Current SSE connections",
            f"tunnel_server_sse_connections {len(self.sse_connections)}",
        ]

        return web.Response(text='\n'.join(metrics), content_type='text/plain')

    async def favicon_handler(self, request: Request) -> Response:
        """Handle favicon requests"""
        return web.Response(status=204)

    async def robots_handler(self, request: Request) -> Response:
        """Handle robots.txt requests"""
        return web.Response(text="User-agent: *\nDisallow: /", content_type='text/plain')

    async def not_found_handler(self, request: Request) -> Response:
        """Custom 404 handler"""
        message = f"🚀 Universal Tunnel Server v3.0 is running!\n\n"
        message += f"No resource found at: {request.path}\n\n"
        message += f"📊 Server Status: {self.get_public_url('status')}\n"
        message += f"🔧 Health Check: {self.get_public_url('health')}\n"
        message += f"📈 Metrics: {self.get_public_url('metrics')}\n\n"
        message += f"Supports: WebSocket, SSE, HTTP for ANY framework!"

        return web.Response(text=message, status=404, content_type='text/plain')

    def setup_app(self, app):
        """Setup application routes and CORS configuration"""
        cors = aiohttp_cors.setup(app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })

        # Add specific routes first
        cors.add(app.router.add_get('/ws', self.websocket_handler))
        cors.add(app.router.add_get('/status', self.status_handler))
        cors.add(app.router.add_get('/health', self.health_handler))
        cors.add(app.router.add_get('/metrics', self.metrics_handler))
        cors.add(app.router.add_get('/favicon.ico', self.favicon_handler))
        cors.add(app.router.add_get('/robots.txt', self.robots_handler))

        # Handle the catch-all resource for tunneling
        resource = app.router.add_resource('/{path:.*}')

        # Add handlers for all HTTP methods
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD']:
            resource.add_route(method, self.handle_http_request)

        # Apply CORS to the catch-all resource
        cors.add(resource)

    async def start_server(self):
        """Start the universal tunnel server with Socket.IO support"""
        self.running = True
        app = web.Application()
        self.setup_app(app)

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, self.host, self.port)
        await site.start()

        domain = self._normalize_domain(self.domain)
        base_url = f"{self.protocol}://{domain}"

        if self.port not in [80, 443]:
            base_url += f":{self.port}"

        logger.info("🎉 Universal Tunnel Server with Socket.IO Support Started!")
        logger.info(f"📡 Listening: {self.host}:{self.port}")
        logger.info(f"🌐 Public Domain: {base_url}")
        logger.info(f"🔗 WebSocket Control: {base_url}/ws")
        logger.info(f"📊 Status: {base_url}/status")
        logger.info(f"🔌 Socket.IO Support: ENABLED")
        logger.info(f"✅ Universal Support: WebSocket, SSE, HTTP, Socket.IO for ALL frameworks")

        return runner

# Entry point
async def main():
    import argparse

    parser = argparse.ArgumentParser(description='Universal Tunnel Server v3.0')
    parser.add_argument('--host', default=os.environ.get('HOST', '0.0.0.0'))
    parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', 8080)))
    parser.add_argument('--domain', default=os.environ.get('DOMAIN', 'localhost'))
    parser.add_argument('--max-tunnels', type=int, default=1000)
    parser.add_argument('--request-timeout', type=int, default=120)

    args = parser.parse_args()

    server = UniversalTunnelServer(
        host=args.host,
        port=args.port,
        domain=args.domain,
        max_tunnels=args.max_tunnels,
        request_timeout=args.request_timeout
    )

    runner = None
    try:
        runner = await server.start_server()
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("👋 Shutdown signal received")
    finally:
        if runner:
            await runner.cleanup()

if __name__ == '__main__':
    asyncio.run(main())
