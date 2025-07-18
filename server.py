#!/usr/bin/env python3
"""
Enhanced Flask Tunnel Server - Single Port Version
Runs both HTTP and WebSocket servers on the same port for better compatibility with cloud platforms
Compatible with latest library versions and handles common deployment issues
"""

import asyncio
import json
import logging
import random
import string
import time
import socket
import ssl
import os
import threading
from typing import Dict, Optional, Set, Any
import uuid
import websockets
from websockets.server import WebSocketServerProtocol
from aiohttp import web, ClientSession, ClientTimeout
from aiohttp.web_request import Request
from aiohttp.web_response import Response
import aiohttp_cors
from urllib.parse import urlparse
from aiohttp.web_ws import WebSocketResponse
import base64
from flask import Flask, jsonify, request as flask_request
import signal
import sys
from datetime import datetime, timedelta
import weakref

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress verbose logging from dependencies
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logging.getLogger('websockets').setLevel(logging.WARNING)

class TunnelServer:
    def __init__(self, host='0.0.0.0', port=8080, domain='yourdomain.com',
                 ssl_cert=None, ssl_key=None, auto_detect_ssl=True,
                 max_tunnels=100, request_timeout=60):
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

        # Store active tunnels with weak references to avoid memory leaks
        self.tunnels: Dict[str, dict] = {}
        self.pending_requests: Dict[str, dict] = {}
        self.used_subdomains: Set[str] = set()
        self.port_to_subdomain: Dict[int, str] = {}

        # Statistics
        self.start_time = time.time()
        self.total_requests = 0
        self.total_bytes_transferred = 0
        self.failed_requests = 0

        # Cleanup intervals
        self.cleanup_interval = 120  # seconds
        self.heartbeat_timeout = 600  # 5 minutes
        self.request_cleanup_interval = 60  # seconds

        # Rate limiting
        self.rate_limit_window = 60  # 1 minute
        self.rate_limit_max_requests = 1000  # per minute per tunnel
        self.rate_limit_tracking = {}

        # Server state
        self.running = False
        self.cleanup_tasks = []

        logger.info(f"SSL Detection: {'Enabled' if self.use_ssl else 'Disabled'}")
        logger.info(f"Protocol: {self.protocol}")
        logger.info(f"WebSocket Protocol: {self.ws_protocol}")
        logger.info(f"Max Tunnels: {self.max_tunnels}")
        logger.info(f"Request Timeout: {self.request_timeout}s")

    def _detect_ssl_setup(self) -> bool:
        """Enhanced SSL detection with better environment variable support"""
        if not self.auto_detect_ssl:
            return False

        # Check for explicit SSL environment variables
        ssl_env_vars = [
            'HTTPS', 'USE_SSL', 'SSL_ENABLED', 'FORCE_HTTPS',
            'HTTPS_ENABLED', 'TLS_ENABLED', 'SSL_MODE'
        ]

        for var in ssl_env_vars:
            value = os.environ.get(var, '').lower()
            if value in ('true', '1', 'yes', 'on', 'enabled'):
                logger.info(f"SSL enabled via environment variable: {var}={value}")
                return True

        # Check for deployment platform environments
        platform_indicators = [
            'RENDER',           # Render.com
            'HEROKU',           # Heroku
            'VERCEL',           # Vercel
            'NETLIFY',          # Netlify
            'RAILWAY',          # Railway
            'FLYIO',            # Fly.io
            'DETA',             # Deta
            'REPLIT',           # Replit
        ]

        for indicator in platform_indicators:
            if os.environ.get(indicator):
                logger.info(f"SSL enabled - detected {indicator} environment")
                return True

        # Check for certificate files
        if self.ssl_cert and self.ssl_key:
            if os.path.exists(self.ssl_cert) and os.path.exists(self.ssl_key):
                logger.info("SSL enabled via certificate files")
                return True
            else:
                logger.warning("SSL certificate files specified but not found")

        # Check for common certificate locations
        cert_locations = [
            ('/etc/ssl/certs/server.crt', '/etc/ssl/private/server.key'),
            ('/etc/letsencrypt/live/*/fullchain.pem', '/etc/letsencrypt/live/*/privkey.pem'),
            ('./ssl/cert.pem', './ssl/key.pem'),
            ('./cert.pem', './key.pem'),
            ('./certs/cert.pem', './certs/key.pem'),
        ]

        for cert_path, key_path in cert_locations:
            if os.path.exists(cert_path) and os.path.exists(key_path):
                self.ssl_cert = cert_path
                self.ssl_key = key_path
                logger.info(f"SSL enabled - found certificates at {cert_path} and {key_path}")
                return True

        # Check if running on standard HTTPS port
        if self.port == 443:
            logger.info("SSL enabled - running on port 443")
            return True

        # Check if domain suggests HTTPS
        https_domains = [
            '.onrender.com', '.herokuapp.com', '.netlify.app', '.vercel.app',
            '.railway.app', '.fly.dev', '.deta.app', '.replit.app',
            '.github.io', '.gitlab.io', '.surge.sh', '.now.sh'
        ]

        for https_domain in https_domains:
            if https_domain in self.domain:
                logger.info(f"SSL enabled - detected HTTPS-enabled domain: {self.domain}")
                return True

        logger.info("SSL disabled - no SSL configuration detected")
        return False

    def get_public_websocket_url(self) -> str:
        """Get the public WebSocket URL for clients"""
        domain = self._normalize_domain(self.domain)

        # Handle deployment platforms
        if self._is_deployment_platform(domain):
            return f"wss://{domain}/ws"

        # Handle custom domains
        if self.use_ssl:
            if self.port != 443:
                return f"wss://{domain}:{self.port}/ws"
            return f"wss://{domain}/ws"
        else:
            if self.port != 80:
                return f"ws://{domain}:{self.port}/ws"
            return f"ws://{domain}/ws"

    def get_public_http_url(self, subdomain: str) -> str:
        """Get the public HTTP URL for a subdomain"""
        domain = self._normalize_domain(self.domain)

        # Handle deployment platforms
        if self._is_deployment_platform(domain):
            return f"https://{subdomain}-{domain}"

        # Handle custom domains
        if self.use_ssl:
            if self.port != 443:
                return f"https://{subdomain}.{domain}:{self.port}"
            return f"https://{subdomain}.{domain}"
        else:
            if self.port != 80:
                return f"http://{subdomain}.{domain}:{self.port}"
            return f"http://{subdomain}.{domain}"

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain by removing protocol and extracting netloc"""
        if domain.startswith('http://') or domain.startswith('https://'):
            parsed = urlparse(domain)
            return parsed.netloc
        return domain

    def _is_deployment_platform(self, domain: str) -> bool:
        """Check if domain belongs to a deployment platform"""
        platforms = [
            '.onrender.com', '.herokuapp.com', '.netlify.app', '.vercel.app',
            '.railway.app', '.fly.dev', '.deta.app', '.replit.app'
        ]
        return any(platform in domain for platform in platforms)

    def generate_unique_subdomain(self, local_port: int) -> str:
        """Generate a unique subdomain with collision detection"""
        max_attempts = 100

        # Try port-based subdomain first
        candidates = [
            f"port{local_port}",
            f"app{local_port}",
            f"tunnel{local_port}",
            f"p{local_port}"
        ]

        for candidate in candidates:
            if candidate not in self.used_subdomains:
                return candidate

        # Generate random subdomains
        for attempt in range(max_attempts):
            subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            if subdomain not in self.used_subdomains:
                return subdomain

        # Fallback with timestamp
        timestamp = str(int(time.time()))[-8:]
        return f"t{timestamp}"

    def generate_tunnel_id(self) -> str:
        """Generate a unique tunnel ID"""
        return str(uuid.uuid4())

    def generate_request_id(self) -> str:
        """Generate a unique request ID"""
        return str(uuid.uuid4())

    def check_rate_limit(self, tunnel_id: str) -> bool:
        """Check if tunnel is within rate limits"""
        current_time = time.time()

        if tunnel_id not in self.rate_limit_tracking:
            self.rate_limit_tracking[tunnel_id] = []

        # Clean old entries
        cutoff_time = current_time - self.rate_limit_window
        self.rate_limit_tracking[tunnel_id] = [
            req_time for req_time in self.rate_limit_tracking[tunnel_id]
            if req_time > cutoff_time
        ]

        # Check rate limit
        if len(self.rate_limit_tracking[tunnel_id]) >= self.rate_limit_max_requests:
            return False

        # Add current request
        self.rate_limit_tracking[tunnel_id].append(current_time)
        return True

    def cleanup_tunnel(self, tunnel_id: str):
        """Clean up tunnel resources with proper error handling"""
        try:
            if tunnel_id in self.tunnels:
                tunnel_data = self.tunnels[tunnel_id]
                subdomain = tunnel_data.get('subdomain')
                local_port = tunnel_data.get('local_port')

                # Remove from tracking sets
                if subdomain:
                    self.used_subdomains.discard(subdomain)
                if local_port and local_port in self.port_to_subdomain:
                    del self.port_to_subdomain[local_port]

                # Clean up rate limiting
                if tunnel_id in self.rate_limit_tracking:
                    del self.rate_limit_tracking[tunnel_id]

                # Remove tunnel
                del self.tunnels[tunnel_id]

                public_url = self.get_public_http_url(subdomain) if subdomain else "unknown"
                logger.info(f"Tunnel cleaned up: {tunnel_id} ({public_url})")

        except Exception as e:
            logger.error(f"Error cleaning up tunnel {tunnel_id}: {e}")

    async def handle_websocket_connection(self, websocket: WebSocketResponse, request: Request):
        """Enhanced WebSocket connection handler with better error handling"""
        tunnel_id = None
        client_ip = request.remote or "unknown"

        try:
            logger.info(f"New WebSocket connection from {client_ip}")

            if len(self.tunnels) >= self.max_tunnels:
                await websocket.send_str(json.dumps({
                    'type': 'error',
                    'message': f'Server at capacity. Maximum {self.max_tunnels} tunnels allowed.'
                }))
                return

            async for msg in websocket:
                if msg.type == web.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._handle_websocket_message(data, websocket, client_ip, tunnel_id)

                        if data.get('type') == 'register' and not tunnel_id:
                            for tid, tunnel_data in self.tunnels.items():
                                if tunnel_data.get('websocket') == websocket:
                                    tunnel_id = tid
                                    break

                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON from {client_ip}: {e}")
                    except Exception as e:
                        logger.error(f"Error processing message from {client_ip}: {e}")

                elif msg.type == web.WSMsgType.ERROR:
                    error = websocket.exception()
                    # Don't cleanup tunnel for message size errors immediately
                    if "Message size" in str(error):
                        logger.warning(f"Large message from {client_ip}: {error}")
                        await websocket.send_str(json.dumps({
                            'type': 'error',
                            'message': 'Message too large, please split large responses'
                        }))
                    else:
                        logger.error(f"WebSocket error from {client_ip}: {error}")
                        break
                elif msg.type == web.WSMsgType.CLOSE:
                    logger.info(f"WebSocket closed by client {client_ip}")
                    break

        except Exception as e:
            logger.error(f"Unexpected error in WebSocket handler for {client_ip}: {e}")
        finally:
            if tunnel_id:
                self.cleanup_tunnel(tunnel_id)

    async def _handle_websocket_message(self, data: dict, websocket: WebSocketResponse, client_ip: str, tunnel_id: Optional[str]):
        """Handle individual WebSocket message types"""
        message_type = data.get('type')

        if message_type == 'register':
            await self._handle_registration(data, websocket, client_ip)
        elif message_type == 'response':
            await self._handle_response(data, client_ip)
        elif message_type == 'heartbeat':
            await self._handle_heartbeat(data, websocket, client_ip, tunnel_id)
        else:
            logger.warning(f"Unknown message type '{message_type}' from {client_ip}")

    async def _handle_registration(self, data: dict, websocket: WebSocketResponse, client_ip: str):
        """Handle tunnel registration"""
        try:
            # Validate registration data
            local_port = data.get('local_port')
            if not local_port or not isinstance(local_port, int) or local_port <= 0 or local_port > 65535:
                await websocket.send_str(json.dumps({
                    'type': 'error',
                    'message': 'Invalid local_port. Must be a valid port number (1-65535)'
                }))
                return

            # Check if port is already being tunneled
            if local_port in self.port_to_subdomain:
                existing_subdomain = self.port_to_subdomain[local_port]
                await websocket.send_str(json.dumps({
                    'type': 'error',
                    'message': f'Port {local_port} is already being tunneled to {self.get_public_http_url(existing_subdomain)}'
                }))
                return

            # Generate unique identifiers
            tunnel_id = self.generate_tunnel_id()
            subdomain = self.generate_unique_subdomain(local_port)

            # Register tunnel
            self.tunnels[tunnel_id] = {
                'websocket': websocket,
                'subdomain': subdomain,
                'local_port': local_port,
                'last_seen': time.time(),
                'client_ip': client_ip,
                'created_at': time.time(),
                'request_count': 0,
                'bytes_transferred': 0,
                'client_info': data.get('client_info', {})
            }

            # Track used resources
            self.used_subdomains.add(subdomain)
            self.port_to_subdomain[local_port] = subdomain

            # Get public URL
            public_url = self.get_public_http_url(subdomain)

            # Send registration response
            await websocket.send_str(json.dumps({
                'type': 'registered',
                'tunnel_id': tunnel_id,
                'public_url': public_url,
                'subdomain': subdomain,
                'local_port': local_port,
                'protocol': self.protocol,
                'websocket_url': self.get_public_websocket_url(),
                'server_info': {
                    'version': '2.0',
                    'max_tunnels': self.max_tunnels,
                    'request_timeout': self.request_timeout
                }
            }))

            logger.info(f"Tunnel registered: {tunnel_id} -> {public_url} -> localhost:{local_port} (client: {client_ip})")

        except Exception as e:
            logger.error(f"Error registering tunnel for {client_ip}: {e}")
            await websocket.send_str(json.dumps({
                'type': 'error',
                'message': f'Registration failed: {str(e)}'
            }))

    async def _handle_response(self, data: dict, client_ip: str):
        """Handle response from client"""
        try:
            request_id = data.get('request_id')
            if not request_id:
                logger.error(f"Missing request_id in response from {client_ip}")
                return

            if request_id in self.pending_requests:
                future = self.pending_requests[request_id]['future']
                if not future.done():
                    future.set_result(data)
                del self.pending_requests[request_id]
            else:
                logger.warning(f"Received response for unknown request_id: {request_id}")

        except Exception as e:
            logger.error(f"Error handling response from {client_ip}: {e}")

    async def _handle_heartbeat(self, data: dict, websocket: WebSocketResponse, client_ip: str, tunnel_id: Optional[str]):
        """Handle heartbeat from client"""
        try:
            # Find tunnel_id if not provided
            if not tunnel_id:
                for tid, tunnel_data in self.tunnels.items():
                    if tunnel_data.get('websocket') == websocket:
                        tunnel_id = tid
                        break

            if tunnel_id and tunnel_id in self.tunnels:
                self.tunnels[tunnel_id]['last_seen'] = time.time()
                await websocket.send_str(json.dumps({'type': 'heartbeat_ack'}))
            else:
                logger.warning(f"Heartbeat from unregistered tunnel: {client_ip}")

        except Exception as e:
            logger.error(f"Error handling heartbeat from {client_ip}: {e}")

    async def websocket_handler(self, request: Request) -> WebSocketResponse:
        """Handle WebSocket upgrade requests with increased message size limit"""
        ws = WebSocketResponse(
            protocols=('chat',),
            heartbeat=30,
            timeout=120,  # Increased timeout
            max_msg_size=90 * 1024 * 1024,  # 50MB limit instead of 4MB
            compress=False
        )
        await ws.prepare(request)
        await self.handle_websocket_connection(ws, request)
        return ws

    async def handle_http_request(self, request: Request) -> Response:
        """Enhanced HTTP request handler with better error handling and logging"""
        client_ip = request.remote or "unknown"
        host = request.headers.get('host', '')
        start_time = time.time()

        try:
            self.total_requests += 1

            # Validate host header
            if not host:
                logger.warning(f"Missing host header from {client_ip}")
                self.failed_requests += 1
                return web.Response(
                    text="Missing host header",
                    status=400,
                    headers={'Content-Type': 'text/plain'}
                )

            # Extract subdomain
            subdomain = self._extract_subdomain(host)
            if not subdomain:
                logger.warning(f"Could not extract subdomain from host '{host}' from {client_ip}")
                self.failed_requests += 1
                return web.Response(
                    text=f"Invalid subdomain format. Expected format: subdomain.{self.domain}",
                    status=400,
                    headers={'Content-Type': 'text/plain'}
                )

            # Find tunnel
            tunnel, tunnel_id = self._find_tunnel_by_subdomain(subdomain)
            if not tunnel:
                logger.warning(f"No tunnel found for subdomain '{subdomain}' from {client_ip}")
                self.failed_requests += 1
                return web.Response(
                    text=f"Tunnel not found for subdomain '{subdomain}'\n\nMake sure your tunnel client is running and connected.",
                    status=404,
                    headers={'Content-Type': 'text/plain'}
                )

            # Check tunnel health
            if tunnel['websocket'].closed:
                logger.warning(f"Tunnel websocket closed for {subdomain}")
                self.cleanup_tunnel(tunnel_id)
                self.failed_requests += 1
                return web.Response(
                    text=f"Tunnel connection closed for subdomain '{subdomain}'\n\nPlease restart your tunnel client.",
                    status=503,
                    headers={'Content-Type': 'text/plain'}
                )

            # Check rate limits
            if not self.check_rate_limit(tunnel_id):
                logger.warning(f"Rate limit exceeded for tunnel {tunnel_id} from {client_ip}")
                self.failed_requests += 1
                return web.Response(
                    text="Rate limit exceeded. Please try again later.",
                    status=429,
                    headers={'Content-Type': 'text/plain'}
                )

            # Forward request
            response = await self._forward_request(request, tunnel, tunnel_id, client_ip)

            # Update statistics
            if response.status < 400:
                tunnel['request_count'] += 1
                if hasattr(response, 'body') and response.body:
                    body_size = len(response.body)
                    tunnel['bytes_transferred'] += body_size
                    self.total_bytes_transferred += body_size

            # Log successful request
            duration = time.time() - start_time
            logger.info(f"{request.method} {request.path_qs} -> {subdomain} ({response.status}) [{duration:.3f}s]")

            return response

        except Exception as e:
            self.failed_requests += 1
            logger.error(f"Unexpected error handling HTTP request from {client_ip}: {e}")
            return web.Response(
                text="Internal server error",
                status=500,
                headers={'Content-Type': 'text/plain'}
            )

    def _extract_subdomain(self, host: str) -> Optional[str]:
        """Extract subdomain from host header"""
        try:
            # Remove port if present
            host_without_port = host.split(':')[0]

            # Handle deployment platforms (subdomain-domain.platform.com)
            if self._is_deployment_platform(host_without_port):
                parts = host_without_port.split('-')
                if len(parts) > 1:
                    return parts[0]
            else:
                # Handle traditional subdomains (subdomain.domain.com)
                parts = host_without_port.split('.')
                if len(parts) > 2:  # At least subdomain.domain.tld
                    return parts[0]
                elif len(parts) == 2 and parts[0] != self.domain.split('.')[0]:
                    return parts[0]

            return None
        except Exception as e:
            logger.error(f"Error extracting subdomain from host '{host}': {e}")
            return None

    def _find_tunnel_by_subdomain(self, subdomain: str) -> tuple[Optional[dict], Optional[str]]:
        """Find tunnel by subdomain"""
        for tunnel_id, tunnel_data in self.tunnels.items():
            if tunnel_data.get('subdomain') == subdomain:
                return tunnel_data, tunnel_id
        return None, None

    async def _forward_request(self, request: Request, tunnel: dict, tunnel_id: str, client_ip: str) -> Response:
        """Forward HTTP request to tunnel client with better timeout handling"""
        request_id = self.generate_request_id()

        try:
            # Prepare request data
            headers = dict(request.headers)

            # Read request body with size limit
            body = None
            if request.content_length:
                if request.content_length > 50 * 1024 * 1024:  # 50MB limit
                    return web.Response(
                        text="Request body too large (max 50MB)",
                        status=413,
                        headers={'Content-Type': 'text/plain'}
                    )
                try:
                    body = await request.read()
                    if body:
                        body = body.decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.warning(f"Error reading request body: {e}")

            request_data = {
                'type': 'request',
                'request_id': request_id,
                'method': request.method,
                'path': request.path_qs,
                'headers': headers,
                'body': body,
                'client_ip': client_ip,
                'timestamp': time.time()
            }

            # Determine timeout based on request type
            timeout = self.request_timeout
            if request.path_qs.endswith(('.js', '.css', '.html', '.json')):
                timeout = 60  # Longer timeout for static files
            elif request.content_length and request.content_length > 1024 * 1024:
                timeout = 120  # Even longer for large uploads

            # Create future for response
            future = asyncio.Future()
            self.pending_requests[request_id] = {
                'future': future,
                'timeout': time.time() + timeout,
                'tunnel_id': tunnel_id
            }

            try:
                # Send request to client
                await tunnel['websocket'].send_str(json.dumps(request_data))

                # Wait for response with dynamic timeout
                response_data = await asyncio.wait_for(future, timeout=timeout)

                return self._create_response(response_data)

            except asyncio.TimeoutError:
                logger.error(f"Request timeout for {tunnel['subdomain']} (request_id: {request_id}, timeout: {timeout}s)")
                return web.Response(
                    text=f"Request timeout - the tunneled service did not respond within {timeout} seconds",
                    status=504,
                    headers={'Content-Type': 'text/plain'}
                )
            finally:
                self.pending_requests.pop(request_id, None)

        except Exception as e:
            logger.error(f"Error forwarding request to {tunnel['subdomain']}: {e}")
            return web.Response(
                text="Internal server error while forwarding request",
                status=500,
                headers={'Content-Type': 'text/plain'}
            )

    def _create_response(self, response_data: dict) -> Response:
        """Create aiohttp Response with chunked transfer for large content"""
        try:
            status = response_data.get('status', 200)
            headers = response_data.get('headers', {}).copy()
            body_encoding = response_data.get('body_encoding', 'utf-8')
            raw_body = response_data.get('body', '')

            # Remove problematic headers
            headers.pop('Transfer-Encoding', None)
            headers.pop('transfer-encoding', None)
            content_encoding = headers.pop('Content-Encoding', None) or headers.pop('content-encoding', None)

            # Handle body encoding
            if body_encoding == 'base64':
                try:
                    body_bytes = base64.b64decode(raw_body)

                    # For large responses, use chunked transfer
                    if len(body_bytes) > 1024 * 1024:  # 1MB threshold
                        headers['Transfer-Encoding'] = 'chunked'

                    if content_encoding:
                        try:
                            if content_encoding.lower() == 'gzip':
                                import gzip
                                gzip.decompress(body_bytes)
                                headers['Content-Encoding'] = content_encoding
                            elif content_encoding.lower() == 'deflate':
                                import zlib
                                zlib.decompress(body_bytes)
                                headers['Content-Encoding'] = content_encoding
                        except Exception:
                            pass

                    return web.Response(
                        body=body_bytes,
                        status=status,
                        headers=headers
                    )
                except Exception as e:
                    logger.error(f"Error decoding base64 body: {e}")
                    return web.Response(
                        text="Error decoding response body",
                        status=500,
                        headers={'Content-Type': 'text/plain'}
                    )
            else:
                return web.Response(
                    text=raw_body,
                    status=status,
                    headers=headers
                )

        except Exception as e:
            logger.error(f"Error creating response: {e}")
            return web.Response(
                text="Error creating response",
                status=500,
                headers={'Content-Type': 'text/plain'}
            )

    async def cleanup_pending_requests(self):
        """Clean up expired pending requests"""
        while self.running:
            try:
                current_time = time.time()
                expired_requests = []

                for request_id, request_data in self.pending_requests.items():
                    if current_time > request_data['timeout']:
                        expired_requests.append(request_id)

                for request_id in expired_requests:
                    if request_id in self.pending_requests:
                        future = self.pending_requests[request_id]['future']
                        if not future.done():
                            future.set_exception(asyncio.TimeoutError("Request timeout"))
                        del self.pending_requests[request_id]

                if expired_requests:
                    logger.debug(f"Cleaned up {len(expired_requests)} expired requests")

                await asyncio.sleep(self.request_cleanup_interval)

            except Exception as e:
                logger.error(f"Request cleanup error: {e}")
                await asyncio.sleep(self.request_cleanup_interval)

    async def cleanup_dead_tunnels(self):
        """Clean up tunnels that haven't sent heartbeat"""
        while self.running:
            try:
                current_time = time.time()
                dead_tunnels = []

                for tunnel_id, tunnel_data in self.tunnels.items():
                    if current_time - tunnel_data['last_seen'] > self.heartbeat_timeout:
                        dead_tunnels.append(tunnel_id)

                for tunnel_id in dead_tunnels:
                    logger.info(f"Cleaning up dead tunnel: {tunnel_id}")
                    self.cleanup_tunnel(tunnel_id)

                await asyncio.sleep(self.cleanup_interval)

            except Exception as e:
                logger.error(f"Dead tunnel cleanup error: {e}")
                await asyncio.sleep(self.cleanup_interval)

    async def status_handler(self, request: Request) -> Response:
        """Enhanced status handler with comprehensive server statistics"""
        try:
            uptime = time.time() - self.start_time
            active_tunnels = []

            for tunnel_id, tunnel_data in self.tunnels.items():
                tunnel_info = {
                    'tunnel_id': tunnel_id,
                    'subdomain': tunnel_data['subdomain'],
                    'local_port': tunnel_data['local_port'],
                    'public_url': self.get_public_http_url(tunnel_data['subdomain']),
                    'client_ip': tunnel_data['client_ip'],
                    'connected': not tunnel_data['websocket'].closed,
                    'created_at': tunnel_data['created_at'],
                    'last_seen': tunnel_data['last_seen'],
                    'request_count': tunnel_data['request_count'],
                    'bytes_transferred': tunnel_data['bytes_transferred'],
                    'client_info': tunnel_data.get('client_info', {})
                }
                active_tunnels.append(tunnel_info)

            status_data = {
                'server': {
                    'version': '2.0',
                    'status': 'running',
                    'uptime': uptime,
                    'uptime_human': str(timedelta(seconds=int(uptime))),
                    'protocol': self.protocol,
                    'websocket_protocol': self.ws_protocol,
                    'ssl_enabled': self.use_ssl,
                    'host': self.host,
                    'port': self.port,
                    'domain': self.domain,
                    'max_tunnels': self.max_tunnels,
                    'request_timeout': self.request_timeout
                },
                'tunnels': {
                    'active': len(active_tunnels),
                    'max': self.max_tunnels,
                    'details': active_tunnels
                },
                'statistics': {
                    'total_requests': self.total_requests,
                    'failed_requests': self.failed_requests,
                    'success_rate': ((self.total_requests - self.failed_requests) / self.total_requests * 100) if self.total_requests > 0 else 0,
                    'total_bytes_transferred': self.total_bytes_transferred,
                    'total_bytes_human': self._format_bytes(self.total_bytes_transferred),
                    'pending_requests': len(self.pending_requests)
                },
                'system': {
                    'timestamp': time.time(),
                    'timestamp_human': datetime.now().isoformat(),
                    'rate_limit_window': self.rate_limit_window,
                    'rate_limit_max_requests': self.rate_limit_max_requests
                }
            }

            return web.json_response(status_data, dumps=self._json_encoder)

        except Exception as e:
            logger.error(f"Error generating status: {e}")
            return web.json_response({
                'error': 'Failed to generate status',
                'message': str(e)
            }, status=500)

    def _format_bytes(self, bytes_count: int) -> str:
        """Format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.2f} PB"

    def _json_encoder(self, obj):
        """Custom JSON encoder for datetime objects"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    async def health_handler(self, request: Request) -> Response:
        """Simple health check endpoint"""
        return web.json_response({
            'status': 'healthy',
            'timestamp': time.time(),
            'active_tunnels': len(self.tunnels),
            'uptime': time.time() - self.start_time
        })

    async def metrics_handler(self, request: Request) -> Response:
        """Prometheus-style metrics endpoint"""
        metrics = []

        # Server metrics
        metrics.append(f"tunnel_server_uptime_seconds {time.time() - self.start_time}")
        metrics.append(f"tunnel_server_active_tunnels {len(self.tunnels)}")
        metrics.append(f"tunnel_server_max_tunnels {self.max_tunnels}")
        metrics.append(f"tunnel_server_total_requests {self.total_requests}")
        metrics.append(f"tunnel_server_failed_requests {self.failed_requests}")
        metrics.append(f"tunnel_server_bytes_transferred {self.total_bytes_transferred}")
        metrics.append(f"tunnel_server_pending_requests {len(self.pending_requests)}")

        # Per-tunnel metrics
        for tunnel_id, tunnel_data in self.tunnels.items():
            labels = f'tunnel_id="{tunnel_id}",subdomain="{tunnel_data["subdomain"]}",local_port="{tunnel_data["local_port"]}"'
            metrics.append(f"tunnel_requests_total{{{labels}}} {tunnel_data['request_count']}")
            metrics.append(f"tunnel_bytes_transferred{{{labels}}} {tunnel_data['bytes_transferred']}")
            metrics.append(f"tunnel_connected{{{labels}}} {0 if tunnel_data['websocket'].closed else 1}")

        return web.Response(
            text='\n'.join(metrics) + '\n',
            content_type='text/plain; version=0.0.4; charset=utf-8'
        )

    async def favicon_handler(self, request: Request) -> Response:
        """Handle favicon requests"""
        return web.Response(status=204)

    async def robots_handler(self, request: Request) -> Response:
        """Handle robots.txt requests"""
        robots_txt = """User-agent: *
Disallow: /
"""
        return web.Response(text=robots_txt, content_type='text/plain')

    async def not_found_handler(self, request: Request) -> Response:
        """Handle 404 errors with helpful information"""
        host = request.headers.get('host', '')
        subdomain = self._extract_subdomain(host)

        if subdomain:
            available_tunnels = list(self.tunnels.keys())
            message = f"""Tunnel not found for subdomain '{subdomain}'

Available tunnels:
{chr(10).join([f"- {data['subdomain']}.{self.domain} -> localhost:{data['local_port']}" for data in self.tunnels.values()])}

To create a tunnel for this subdomain, run your tunnel client and connect to:
{self.get_public_websocket_url()}
"""
        else:
            message = f"""Invalid subdomain format

Expected format: subdomain.{self.domain}

Available tunnels:
{chr(10).join([f"- {data['subdomain']}.{self.domain} -> localhost:{data['local_port']}" for data in self.tunnels.values()])}

Server Status: {self.get_public_http_url('status')}
"""

        return web.Response(
            text=message,
            status=404,
            headers={'Content-Type': 'text/plain'}
        )

    def create_ssl_context(self):
        """Create SSL context for HTTPS"""
        if not self.use_ssl:
            return None

        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

            if self.ssl_cert and self.ssl_key:
                context.load_cert_chain(self.ssl_cert, self.ssl_key)
            else:
                # Create self-signed certificate for development
                logger.warning("No SSL certificates provided, using self-signed certificate")
                context = self._create_self_signed_context()

            return context
        except Exception as e:
            logger.error(f"Failed to create SSL context: {e}")
            return None

    def _create_self_signed_context(self):
        """Create self-signed SSL context for development"""
        try:
            import tempfile
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime

            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.domain),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(self.domain),
                    x509.DNSName(f"*.{self.domain}"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())

            # Create temporary files
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as cert_file:
                cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
                cert_path = cert_file.name

            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as key_file:
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                key_path = key_file.name

            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_path, key_path)

            return context

        except ImportError:
            logger.error("cryptography package not installed, cannot create self-signed certificate")
            return None
        except Exception as e:
            logger.error(f"Failed to create self-signed certificate: {e}")
            return None

    def setup_routes(self, app):
        """Setup application routes"""
        # WebSocket route
        app.router.add_get('/ws', self.websocket_handler)

        # API routes
        app.router.add_get('/status', self.status_handler)
        app.router.add_get('/health', self.health_handler)
        app.router.add_get('/metrics', self.metrics_handler)

        # Static file routes
        app.router.add_get('/favicon.ico', self.favicon_handler)
        app.router.add_get('/robots.txt', self.robots_handler)

        # Catch-all route for tunnel traffic - MUST BE LAST
        # Use a more specific pattern to avoid conflicts
        app.router.add_route('*', '/{path:.*}', self.handle_http_request)


    def setup_cors(self, app):
        """Setup CORS configuration"""
        cors = aiohttp_cors.setup(app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })

        # Add CORS to all routes except the catch-all
        for route in list(app.router.routes()):
            try:
                cors.add(route)
            except ValueError:
                # Skip routes that can't have CORS added
                pass

    def setup_middlewares(self, app):
        """Setup application middlewares"""

        @web.middleware
        async def error_middleware(request, handler):
            try:
                response = await handler(request)
                return response
            except web.HTTPException as ex:
                return ex
            except Exception as ex:
                logger.error(f"Unhandled error: {ex}")
                return web.Response(
                    text="Internal Server Error",
                    status=500,
                    headers={'Content-Type': 'text/plain'}
                )

        app.middlewares.append(error_middleware)

    async def start_server(self):
        """Start the tunnel server"""
        try:
            self.running = True

            # Create aiohttp application
            app = web.Application(
                client_max_size=10 * 1024 * 1024,  # 10MB max request size
                middlewares=[]
            )

            # Setup application components
            self.setup_middlewares(app)
            self.setup_routes(app)
            self.setup_cors(app)

            # Create SSL context
            ssl_context = self.create_ssl_context()

            # Start cleanup tasks
            self.cleanup_tasks = [
                asyncio.create_task(self.cleanup_dead_tunnels()),
                asyncio.create_task(self.cleanup_pending_requests())
            ]

            # Create and start server
            runner = web.AppRunner(app)
            await runner.setup()

            # Create site with compatible socket options
            site_kwargs = {
                'ssl_context': ssl_context,
                'reuse_address': True,
            }

            # Only add reuse_port if supported
            try:
                # Test if reuse_port is supported
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                test_socket.close()
                site_kwargs['reuse_port'] = True
                logger.info("Socket reuse_port: Enabled")
            except (OSError, AttributeError):
                logger.info("Socket reuse_port: Not supported, skipping")

            site = web.TCPSite(
                runner,
                self.host,
                self.port,
                **site_kwargs
            )

            await site.start()

            logger.info(f"🚀 Tunnel Server started!")
            logger.info(f"   Server URL: {self.protocol}://{self.host}:{self.port}")
            logger.info(f"   Public URL: {self.get_public_http_url('your-subdomain')}")
            logger.info(f"   WebSocket URL: {self.get_public_websocket_url()}")
            logger.info(f"   Status Page: {self.get_public_http_url('status')}")
            logger.info(f"   Health Check: {self.get_public_http_url('health')}")
            logger.info(f"   Metrics: {self.get_public_http_url('metrics')}")
            logger.info(f"   SSL: {'Enabled' if self.use_ssl else 'Disabled'}")
            logger.info(f"   Max Tunnels: {self.max_tunnels}")
            logger.info(f"   Request Timeout: {self.request_timeout}s")

            # Keep server running
            return runner

        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise

    async def stop_server(self):
        """Stop the tunnel server"""
        try:
            self.running = False

            # Cancel cleanup tasks
            for task in self.cleanup_tasks:
                task.cancel()

            # Wait for cleanup tasks to complete
            if self.cleanup_tasks:
                await asyncio.gather(*self.cleanup_tasks, return_exceptions=True)

            # Clean up all tunnels
            for tunnel_id in list(self.tunnels.keys()):
                self.cleanup_tunnel(tunnel_id)

            # Cancel pending requests
            for request_id, request_data in self.pending_requests.items():
                future = request_data['future']
                if not future.done():
                    future.cancel()

            self.pending_requests.clear()

            logger.info("🛑 Tunnel Server stopped")

        except Exception as e:
            logger.error(f"Error stopping server: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)

async def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Enhanced Flask Tunnel Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('--domain', default='tunnel-server-decm.onrender.com', help='Public domain')
    parser.add_argument('--ssl-cert', help='SSL certificate file')
    parser.add_argument('--ssl-key', help='SSL key file')
    parser.add_argument('--no-ssl', action='store_true', help='Disable SSL auto-detection')
    parser.add_argument('--max-tunnels', type=int, default=100, help='Maximum number of tunnels')
    parser.add_argument('--request-timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])

    args = parser.parse_args()

    # Configure logging
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    # Create server
    server = TunnelServer(
        host=args.host,
        port=args.port,
        domain=args.domain,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        auto_detect_ssl=not args.no_ssl,
        max_tunnels=args.max_tunnels,
        request_timeout=args.request_timeout
    )

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Start server
        runner = await server.start_server()

        # Keep running until interrupted
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")

    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
    finally:
        # Stop server
        await server.stop_server()
        if 'runner' in locals():
            await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
