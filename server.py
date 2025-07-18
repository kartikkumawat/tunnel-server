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
from datetime import datetime, timedelta, timezone

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
        self.special_paths = {'status', 'health', 'metrics', 'ws', 'favicon.ico', 'robots.txt'}

        # Statistics
        self.start_time = time.time()
        self.total_requests = 0
        self.total_bytes_transferred = 0
        self.failed_requests = 0

        # Cleanup intervals
        self.cleanup_interval = 120  # seconds
        self.heartbeat_timeout = 600  # 10 minutes
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

    def _is_deployment_platform(self) -> bool:
        """Check if running on a known deployment platform."""
        platform_indicators = [
            'RENDER', 'HEROKU', 'VERCEL', 'NETLIFY', 'RAILWAY',
            'FLYIO', 'DETA', 'REPLIT'
        ]
        return any(os.environ.get(indicator) for indicator in platform_indicators)

    def _detect_ssl_setup(self) -> bool:
        """Enhanced SSL detection with better environment variable support"""
        if not self.auto_detect_ssl:
            return False

        if self._is_deployment_platform():
            logger.info("SSL enabled - deployment platform detected.")
            return True

        ssl_env_vars = ['HTTPS', 'USE_SSL', 'SSL_ENABLED', 'FORCE_HTTPS']
        for var in ssl_env_vars:
            value = os.environ.get(var, '').lower()
            if value in ('true', '1', 'yes', 'on'):
                logger.info(f"SSL enabled via environment variable: {var}={value}")
                return True

        if self.ssl_cert and self.ssl_key and os.path.exists(self.ssl_cert) and os.path.exists(self.ssl_key):
            logger.info("SSL enabled via certificate files")
            return True

        if self.port == 443:
            logger.info("SSL enabled - running on port 443")
            return True

        logger.info("SSL disabled - no specific SSL configuration detected")
        return False

    def get_base_domain(self) -> str:
        """Get the base domain, stripping protocol and www."""
        domain = self._normalize_domain(self.domain)
        if self._is_deployment_platform() and '-' in domain:
            # Handle render-like domains: my-app-abcdef.onrender.com -> onrender.com
            parts = domain.split('.')
            if len(parts) > 2 and parts[-2] == 'onrender':
                 # Re-join all but the service name part
                return '.'.join(parts[1:])
        return domain


    def get_public_url(self, path_or_subdomain: str) -> str:
        """Get a public URL, correctly formatting for paths vs subdomains."""
        domain = self._normalize_domain(self.domain)

        # For special server routes, use path-based URLs
        if path_or_subdomain in self.special_paths:
             return f"{self.protocol}://{domain}/{path_or_subdomain}"

        # For tunnels, use subdomain-based URLs
        if self._is_deployment_platform():
            # e.g., https://mysubdomain.my-app.onrender.com
            return f"https://{path_or_subdomain}.{domain}"
        else:
            port_str = f":{self.port}" if self.port not in [80, 443] else ""
            return f"{self.protocol}://{path_or_subdomain}.{domain}{port_str}"


    def get_public_websocket_url(self) -> str:
        """Get the public WebSocket URL for clients"""
        domain = self._normalize_domain(self.domain)
        port_str = f":{self.port}" if self.port not in [80, 443] else ""
        if self._is_deployment_platform():
            return f"wss://{domain}/ws"
        return f"{self.ws_protocol}://{domain}{port_str}/ws"


    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain by removing protocol and extracting netloc"""
        if domain.startswith(('http://', 'https://')):
            return urlparse(domain).netloc
        return domain

    def generate_unique_subdomain(self, local_port: int) -> str:
        """Generate a unique subdomain with collision detection"""
        max_attempts = 100
        candidate = f"port{local_port}"
        if candidate not in self.used_subdomains:
            return candidate

        for _ in range(max_attempts):
            subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            if subdomain not in self.used_subdomains:
                return subdomain

        return f"tunnel-{int(time.time())}"

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

        self.rate_limit_tracking[tunnel_id] = [t for t in self.rate_limit_tracking[tunnel_id] if t > current_time - self.rate_limit_window]

        if len(self.rate_limit_tracking[tunnel_id]) >= self.rate_limit_max_requests:
            return False

        self.rate_limit_tracking[tunnel_id].append(current_time)
        return True

    def cleanup_tunnel(self, tunnel_id: str):
        """Clean up tunnel resources."""
        if tunnel_id in self.tunnels:
            tunnel_data = self.tunnels.pop(tunnel_id)
            subdomain = tunnel_data.get('subdomain')
            local_port = tunnel_data.get('local_port')

            if subdomain:
                self.used_subdomains.discard(subdomain)
            if local_port:
                self.port_to_subdomain.pop(local_port, None)

            self.rate_limit_tracking.pop(tunnel_id, None)

            public_url = self.get_public_url(subdomain) if subdomain else "unknown"
            logger.info(f"Tunnel cleaned up: {tunnel_id} ({public_url})")


    async def handle_websocket_connection(self, websocket: WebSocketResponse, request: Request):
        """Enhanced WebSocket connection handler with better error handling"""
        tunnel_id = None
        client_ip = request.remote or "unknown"
        logger.info(f"New WebSocket connection from {client_ip}")

        if len(self.tunnels) >= self.max_tunnels:
            await websocket.send_json({'type': 'error', 'message': f'Server at capacity. Maximum {self.max_tunnels} tunnels allowed.'})
            await websocket.close()
            return

        try:
            async for msg in websocket:
                if msg.type == web.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        msg_type = data.get('type')

                        if msg_type == 'register':
                            # Assign tunnel_id upon successful registration
                            new_tunnel_id = await self._handle_registration(data, websocket, client_ip)
                            if new_tunnel_id:
                                tunnel_id = new_tunnel_id
                        elif msg_type == 'response' and tunnel_id:
                            await self._handle_response(data, client_ip)
                        elif msg_type == 'heartbeat' and tunnel_id:
                            await self._handle_heartbeat(tunnel_id, websocket)
                        else:
                            logger.warning(f"Unknown or out-of-sequence message type '{msg_type}' from {client_ip}")

                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON from {client_ip}")
                    except Exception as e:
                        logger.error(f"Error processing message from {client_ip}: {e}", exc_info=True)

                elif msg.type == web.WSMsgType.ERROR:
                    logger.error(f"WebSocket error from {client_ip}: {websocket.exception()}")
                    break

        except Exception as e:
            logger.error(f"Unexpected error in WebSocket handler for {client_ip}: {e}", exc_info=True)
        finally:
            if tunnel_id:
                self.cleanup_tunnel(tunnel_id)
            logger.info(f"WebSocket connection closed for {client_ip}")


    async def _handle_registration(self, data: dict, websocket: WebSocketResponse, client_ip: str) -> Optional[str]:
        """Handle tunnel registration."""
        local_port = data.get('local_port')
        if not isinstance(local_port, int) or not (0 < local_port < 65536):
            await websocket.send_json({'type': 'error', 'message': 'Invalid local_port specified.'})
            return None

        if local_port in self.port_to_subdomain:
            existing_subdomain = self.port_to_subdomain[local_port]
            await websocket.send_json({'type': 'error', 'message': f'Port {local_port} is already tunneled to {self.get_public_url(existing_subdomain)}'})
            return None

        tunnel_id = self.generate_tunnel_id()
        subdomain = self.generate_unique_subdomain(local_port)

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
        self.used_subdomains.add(subdomain)
        self.port_to_subdomain[local_port] = subdomain

        public_url = self.get_public_url(subdomain)

        await websocket.send_json({
            'type': 'registered',
            'tunnel_id': tunnel_id,
            'public_url': public_url,
            'subdomain': subdomain,
            'server_info': {'version': '2.1'}
        })
        logger.info(f"Tunnel registered: {tunnel_id} | {public_url} -> localhost:{local_port} (Client: {client_ip})")
        return tunnel_id


    async def _handle_response(self, data: dict, client_ip: str):
        """Handle response from client."""
        request_id = data.get('request_id')
        if not request_id or request_id not in self.pending_requests:
            logger.warning(f"Received response for unknown/expired request_id: {request_id}")
            return

        future = self.pending_requests.pop(request_id)['future']
        if not future.done():
            future.set_result(data)

    async def _handle_heartbeat(self, tunnel_id: str, websocket: WebSocketResponse):
        """Handle heartbeat from client."""
        if tunnel_id in self.tunnels:
            self.tunnels[tunnel_id]['last_seen'] = time.time()
            await websocket.send_json({'type': 'heartbeat_ack'})
        else:
            logger.warning(f"Heartbeat from unknown tunnel: {tunnel_id}")


    async def websocket_handler(self, request: Request) -> WebSocketResponse:
        """Handle WebSocket upgrade requests."""
        ws = WebSocketResponse(heartbeat=30, max_msg_size=50 * 1024 * 1024)
        await ws.prepare(request)
        await self.handle_websocket_connection(ws, request)
        return ws


    async def handle_http_request(self, request: Request) -> Response:
        """Main HTTP request handler, routing to tunnels or server endpoints."""
        start_time = time.time()
        host = request.headers.get('host', '')

        # Route server-specific paths
        if request.path.strip('/') in self.special_paths:
            # This is handled by dedicated route handlers, this is a fallback
            return await self.not_found_handler(request)

        # Route tunnel traffic
        subdomain = self._extract_subdomain(host)
        if not subdomain:
            return await self.not_found_handler(request)

        tunnel, tunnel_id = self._find_tunnel_by_subdomain(subdomain)
        if not tunnel:
            logger.warning(f"No tunnel found for subdomain '{subdomain}'")
            return web.Response(text=f"Tunnel for '{subdomain}' not found or is not connected.", status=404)

        if tunnel['websocket'].closed:
            self.cleanup_tunnel(tunnel_id)
            return web.Response(text="Tunnel connection is closed. Please restart your client.", status=503)

        if not self.check_rate_limit(tunnel_id):
            return web.Response(text="Rate limit exceeded.", status=429)

        try:
            response = await self._forward_request(request, tunnel, tunnel_id)
            duration = time.time() - start_time
            logger.info(f"{request.method} {request.path_qs} -> {subdomain} ({response.status}) [{duration:.3f}s]")

            # Update stats
            self.total_requests += 1
            tunnel['request_count'] += 1
            if hasattr(response, 'body') and response.body:
                 body_size = len(response.body)
                 tunnel['bytes_transferred'] += body_size
                 self.total_bytes_transferred += body_size

            return response
        except asyncio.TimeoutError:
             self.failed_requests += 1
             logger.error(f"Request timeout for {subdomain}")
             return web.Response(text="Request timed out. The local service did not respond in time.", status=504)
        except Exception as e:
            self.failed_requests += 1
            logger.error(f"Error forwarding request to {subdomain}: {e}", exc_info=True)
            return web.Response(text="Internal server error while forwarding request.", status=500)


    def _extract_subdomain(self, host: str) -> Optional[str]:
        """Extract subdomain from host header."""
        host_without_port = host.split(':')[0]
        base_domain = self.get_base_domain()

        if host_without_port.endswith(base_domain):
            subdomain_part = host_without_port[:-len(base_domain)].strip('.')
            # On Render, the host might be my-app-xyz.onrender.com, and a tunnel
            # would be mysub.my-app-xyz.onrender.com.
            # We must ensure the extracted part is not part of the service name.
            if self._is_deployment_platform():
                # Split by '.' and take the first part
                return subdomain_part.split('.')[0]
            return subdomain_part
        return None


    def _find_tunnel_by_subdomain(self, subdomain: str) -> tuple[Optional[dict], Optional[str]]:
        """Find tunnel by subdomain."""
        for tunnel_id, tunnel_data in self.tunnels.items():
            if tunnel_data.get('subdomain') == subdomain:
                return tunnel_data, tunnel_id
        return None, None


    async def _forward_request(self, request: Request, tunnel: dict, tunnel_id: str) -> Response:
        """Forward HTTP request to the tunnel client."""
        request_id = self.generate_request_id()
        body = await request.read()

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

        await tunnel['websocket'].send_json(request_data)

        response_data = await asyncio.wait_for(future, timeout=self.request_timeout)

        return self._create_response(response_data)


    def _create_response(self, response_data: dict) -> Response:
        """Create aiohttp Response from client's response data."""
        status = response_data.get('status', 200)
        headers = response_data.get('headers', {})
        raw_body = response_data.get('body', '')

        # Body is expected to be base64 encoded
        body_bytes = base64.b64decode(raw_body) if raw_body else b''

        # Clean up headers that shouldn't be passed through
        headers.pop('Transfer-Encoding', None)
        headers.pop('Content-Length', None)

        return web.Response(body=body_bytes, status=status, headers=headers)


    async def cleanup_pending_requests(self):
        """Clean up expired pending requests."""
        while self.running:
            await asyncio.sleep(self.request_cleanup_interval)
            now = time.time()
            expired_ids = [rid for rid, r in self.pending_requests.items() if now > r['timeout']]
            for rid in expired_ids:
                if rid in self.pending_requests:
                    future = self.pending_requests.pop(rid)['future']
                    if not future.done():
                        future.set_exception(asyncio.TimeoutError("Server-side request timeout"))
            if expired_ids:
                logger.debug(f"Cleaned up {len(expired_ids)} expired requests.")


    async def cleanup_dead_tunnels(self):
        """Clean up tunnels that haven't sent a heartbeat."""
        while self.running:
            await asyncio.sleep(self.cleanup_interval)
            now = time.time()
            dead_ids = [tid for tid, t in self.tunnels.items() if now - t['last_seen'] > self.heartbeat_timeout]
            for tid in dead_ids:
                logger.warning(f"Cleaning up dead tunnel due to heartbeat timeout: {tid}")
                self.cleanup_tunnel(tid)


    async def status_handler(self, request: Request) -> Response:
        """Enhanced status handler with comprehensive server statistics"""
        uptime = time.time() - self.start_time
        active_tunnels_info = []
        for tid, t in self.tunnels.items():
             active_tunnels_info.append({
                'tunnel_id': tid,
                'subdomain': t['subdomain'],
                'public_url': self.get_public_url(t['subdomain']),
                'local_port': t['local_port'],
                'client_ip': t['client_ip'],
                'connected_duration': time.time() - t['created_at'],
                'request_count': t['request_count'],
                'bytes_transferred': t['bytes_transferred'],
             })

        status_data = {
            'server_status': 'running',
            'uptime_seconds': uptime,
            'active_tunnels': len(self.tunnels),
            'max_tunnels': self.max_tunnels,
            'total_requests_processed': self.total_requests,
            'total_bytes_transferred': self.total_bytes_transferred,
            'pending_http_requests': len(self.pending_requests),
            'tunnel_details': active_tunnels_info,
        }
        return web.json_response(status_data)


    async def health_handler(self, request: Request) -> Response:
        """Simple health check endpoint"""
        return web.json_response({'status': 'healthy', 'timestamp': time.time()})


    async def metrics_handler(self, request: Request) -> Response:
        """Prometheus-style metrics endpoint"""
        metrics = [
            f"tunnel_server_uptime_seconds {time.time() - self.start_time}",
            f"tunnel_server_active_tunnels {len(self.tunnels)}",
            f"tunnel_server_total_requests {self.total_requests}",
            f"tunnel_server_bytes_transferred {self.total_bytes_transferred}",
            f"tunnel_server_pending_requests {len(self.pending_requests)}",
        ]
        for tid, t in self.tunnels.items():
            labels = f'tunnel_id="{tid}",subdomain="{t["subdomain"]}"'
            metrics.append(f"tunnel_requests_total{{{labels}}} {t['request_count']}")
            metrics.append(f"tunnel_bytes_transferred_total{{{labels}}} {t['bytes_transferred']}")

        return web.Response(text='\n'.join(metrics), content_type='text/plain')


    async def favicon_handler(self, request: Request) -> Response:
        """Handle favicon requests with a 204 No Content response."""
        return web.Response(status=204)

    async def robots_handler(self, request: Request) -> Response:
        """Handle robots.txt requests, disallowing all indexing."""
        return web.Response(text="User-agent: *\nDisallow: /", content_type='text/plain')


    async def not_found_handler(self, request: Request) -> Response:
        """Custom 404 handler."""
        message = f"Tunnel Server is running.\n\n"
        message += f"No resource found at the requested path: {request.path}\n"
        message += f"Visit {self.get_public_url('status')} for server status and a list of active tunnels."
        return web.Response(text=message, status=404)

    def create_ssl_context(self):
        """Create SSL context only if not on a platform with external SSL termination."""
        if not self.use_ssl or self._is_deployment_platform():
            # On Render/Heroku etc., SSL is terminated by the load balancer.
            # The app runs on HTTP internally, so we don't need a context.
            return None

        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            if self.ssl_cert and self.ssl_key:
                context.load_cert_chain(self.ssl_cert, self.ssl_key)
            else:
                # This part will now be skipped on Render, avoiding the warning.
                logger.warning("No SSL certs provided; falling back to self-signed (NOT for production).")
                return self._create_self_signed_context()
            return context
        except Exception as e:
            logger.error(f"Failed to create SSL context: {e}")
            # Critical error if SSL is expected but fails.
            raise

    def _create_self_signed_context(self):
        """Creates a self-signed SSL context for local development."""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import tempfile

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.domain)])

            # Use timezone-aware datetime objects
            now = datetime.now(timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(self.domain), x509.DNSName(f"*.{self.domain}")]))
                .sign(private_key, hashes.SHA256())
            )

            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as cert_file, \
                 tempfile.NamedTemporaryFile(delete=False, mode='wb') as key_file:
                cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
                cert_path, key_path = cert_file.name, key_file.name

            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_path, key_path)
            return context

        except ImportError:
            logger.error("`cryptography` package is required to create self-signed certificates.")
            return None
        except Exception as e:
            logger.error(f"Error creating self-signed certificate: {e}")
            return None


    def setup_app(self, app):
        """Setup application routes and CORS configuration."""
        cors = aiohttp_cors.setup(app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                # Using "*" tells CORS to allow any method in the preflight response
                allow_methods="*")
        })

        # Add specific routes and apply CORS to them
        cors.add(app.router.add_get('/ws', self.websocket_handler))
        cors.add(app.router.add_get('/status', self.status_handler))
        cors.add(app.router.add_get('/health', self.health_handler))
        cors.add(app.router.add_get('/metrics', self.metrics_handler))
        cors.add(app.router.add_get('/favicon.ico', self.favicon_handler))
        cors.add(app.router.add_get('/robots.txt', self.robots_handler))

        # Handle the catch-all resource for tunneling
        resource = app.router.add_resource('/{path:.*}')

        # Add handlers for all common methods. This avoids the conflicting '*' method.
        # aiohttp-cors will add its own OPTIONS handler without conflict.
        resource.add_route('GET', self.handle_http_request)
        resource.add_route('POST', self.handle_http_request)
        resource.add_route('PUT', self.handle_http_request)
        resource.add_route('DELETE', self.handle_http_request)
        resource.add_route('PATCH', self.handle_http_request)
        resource.add_route('HEAD', self.handle_http_request)

        # Apply CORS settings to the entire catch-all resource
        cors.add(resource)

    async def start_server(self):
        """Start the tunnel server"""
        self.running = True
        app = web.Application()

        # Setup routes and CORS using the new corrected method
        self.setup_app(app)

        ssl_context = self.create_ssl_context()

        self.cleanup_tasks = [
            asyncio.create_task(self.cleanup_dead_tunnels()),
            asyncio.create_task(self.cleanup_pending_requests())
        ]

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, self.host, self.port, ssl_context=ssl_context)
        await site.start()

        # Corrected logging messages
        base_url = f"{self.protocol}://{self._normalize_domain(self.domain)}"
        if self.port not in [80, 443] and not self._is_deployment_platform():
            base_url += f":{self.port}"

        logger.info(f"🚀 Tunnel Server started!")
        logger.info(f"   Listening on: {self.host}:{self.port}")
        logger.info(f"   Public Domain: {base_url}")
        logger.info(f"   WebSocket URL: {self.get_public_websocket_url()}")
        logger.info(f"   Status Page: {base_url}/status")
        logger.info(f"   Health Check: {base_url}/health")
        logger.info(f"   Metrics: {base_url}/metrics")
        logger.info(f"   SSL: {'Enabled' if self.use_ssl else 'Disabled'} {'(Platform-provided)' if self._is_deployment_platform() else ''}")

        return runner

    async def stop_server(self):
        """Stop the tunnel server"""
        self.running = False
        for task in self.cleanup_tasks:
            task.cancel()
        await asyncio.gather(*self.cleanup_tasks, return_exceptions=True)

        for tunnel_id in list(self.tunnels.keys()):
            self.cleanup_tunnel(tunnel_id)

        logger.info("🛑 Tunnel Server stopped")


async def main():
    """Main entry point for the server application."""
    import argparse
    parser = argparse.ArgumentParser(description='Enhanced Tunnel Server')
    parser.add_argument('--host', default=os.environ.get('HOST', '0.0.0.0'), help='Host to bind to')
    parser.add_argument('--port', type=int, default=os.environ.get('PORT', 8080), help='Port to bind to')
    parser.add_argument('--domain', default=os.environ.get('DOMAIN', 'localhost'), help='Public domain name')
    parser.add_argument('--ssl-cert', help='SSL certificate file')
    parser.add_argument('--ssl-key', help='SSL key file')
    parser.add_argument('--max-tunnels', type=int, default=100)
    parser.add_argument('--request-timeout', type=int, default=30)
    args = parser.parse_args()

    server = TunnelServer(
        host=args.host,
        port=args.port,
        domain=args.domain,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        max_tunnels=args.max_tunnels,
        request_timeout=args.request_timeout
    )

    runner = None
    try:
        runner = await server.start_server()
        # Keep the server running until a KeyboardInterrupt (Ctrl+C) is received
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutdown signal received, cleaning up...")
    finally:
        if runner:
            await server.stop_server()
            await runner.cleanup()
        logger.info("Server has been shut down gracefully.")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # This handles the case where Ctrl+C is pressed before the asyncio loop starts
        logger.info("Server execution stopped.")
