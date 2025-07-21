#!/usr/bin/env python3

"""
Ultra High-Performance Tunnel Server with SSL Support - Unlimited Capacity
Supports unlimited timeout, unlimited connections, 100TB+ data transfers
No limits on HTTP/HTTPS/WebSocket/SSE services with SSL auto-detection
"""

import asyncio
import json
import logging
import random
import string
import time
import os
import sys
import uuid
import base64
import ssl
import socket
from typing import Dict, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from urllib.parse import urlparse

import aiohttp
from aiohttp import web, ClientSession, ClientTimeout
from aiohttp.web_request import Request
from aiohttp.web_response import Response, StreamResponse
from aiohttp.web_ws import WebSocketResponse
import aiohttp_cors

# Cloud-optimized logging - no file output, no emojis, Windows compatible
class CloudFormatter(logging.Formatter):
    """Cloud platform formatter - no emojis, no file I/O"""
    def format(self, record):
        try:
            # Clean any problematic Unicode characters
            if hasattr(record, 'msg') and record.msg:
                # Replace emojis with readable text
                msg_str = str(record.msg)
                msg_str = msg_str.replace('🚀', '[START]')
                msg_str = msg_str.replace('✅', '[OK]')
                msg_str = msg_str.replace('❌', '[ERROR]')
                msg_str = msg_str.replace('⚠️', '[WARNING]')
                msg_str = msg_str.replace('🔌', '[CONNECT]')
                msg_str = msg_str.replace('📝', '[REGISTER]')
                msg_str = msg_str.replace('🔄', '[FORWARD]')
                msg_str = msg_str.replace('🧹', '[CLEANUP]')
                msg_str = msg_str.replace('🛑', '[STOP]')
                msg_str = msg_str.replace('💓', '[HEARTBEAT]')
                record.msg = msg_str.encode('ascii', errors='replace').decode('ascii')
            return super().format(record)
        except (UnicodeError, UnicodeEncodeError, UnicodeDecodeError):
            # Ultimate fallback for any Unicode issues
            record.msg = str(record.msg).encode('ascii', errors='replace').decode('ascii')
            return super().format(record)

# Configure cloud logging - stdout only, no files
def setup_cloud_logging():
    """Setup logging optimized for cloud platforms"""
    # Clear all existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Create console handler only
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(CloudFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))

    # Configure root logger
    logging.root.addHandler(console_handler)
    logging.root.setLevel(logging.INFO)

    # Suppress verbose logging from dependencies
    for logger_name in ['aiohttp.access', 'aiohttp.server', 'websockets', 'asyncio']:
        logging.getLogger(logger_name).setLevel(logging.WARNING)

# Initialize cloud logging
setup_cloud_logging()
logger = logging.getLogger(__name__)

class PerformanceMetrics:
    """Ultra high-performance metrics collection - memory only"""
    def __init__(self):
        self.start_time = time.time()
        self.request_count = 0
        self.bytes_transferred = 0
        self.error_count = 0
        self.active_connections = 0
        self.response_times = deque(maxlen=10000)  # Increased buffer
        self.throughput_samples = deque(maxlen=1000)  # Increased buffer

    def record_request(self, duration: float, bytes_size: int, success: bool):
        """Record request metrics with minimal overhead"""
        self.request_count += 1
        self.bytes_transferred += bytes_size
        self.response_times.append(duration)
        if not success:
            self.error_count += 1

    def get_throughput(self) -> float:
        """Calculate current throughput in MB/s"""
        if len(self.throughput_samples) < 2:
            return 0.0
        time_diff = self.throughput_samples[-1][0] - self.throughput_samples[0][0]
        bytes_diff = sum(sample[1] for sample in self.throughput_samples)
        return (bytes_diff / (1024 * 1024)) / max(time_diff, 0.001)

class TunnelRegistry:
    """Ultra high-performance tunnel registry with unlimited capacity"""
    def __init__(self):
        self.tunnels: Dict[str, dict] = {}  # tunnel_id -> tunnel_data
        self.subdomain_to_tunnel: Dict[str, str] = {}  # subdomain -> tunnel_id
        self.client_to_tunnel: Dict[str, str] = {}  # client_id -> tunnel_id
        self.company_subdomains: Dict[str, Set[str]] = defaultdict(set)
        self.used_subdomains: Set[str] = set()

    def register_tunnel(self, tunnel_id: str, client_id: str, company: str,
                       subdomain: str, websocket: WebSocketResponse,
                       local_port: int, client_ip: str) -> dict:
        """Register new tunnel with O(1) performance - unlimited capacity"""
        tunnel_data = {
            'tunnel_id': tunnel_id,
            'client_id': client_id,
            'company': company,
            'subdomain': subdomain,
            'websocket': websocket,
            'local_port': local_port,
            'client_ip': client_ip,
            'created_at': time.time(),
            'last_seen': time.time(),
            'request_count': 0,
            'bytes_transferred': 0,
            'active_requests': 0
        }

        self.tunnels[tunnel_id] = tunnel_data
        self.subdomain_to_tunnel[subdomain] = tunnel_id
        self.client_to_tunnel[client_id] = tunnel_id
        self.company_subdomains[company].add(subdomain)
        self.used_subdomains.add(subdomain)

        return tunnel_data

    def get_tunnel_by_subdomain(self, subdomain: str) -> Optional[dict]:
        """O(1) tunnel lookup by subdomain"""
        tunnel_id = self.subdomain_to_tunnel.get(subdomain)
        return self.tunnels.get(tunnel_id) if tunnel_id else None

    def get_tunnel_by_client(self, client_id: str) -> Optional[dict]:
        """O(1) tunnel lookup by client ID"""
        tunnel_id = self.client_to_tunnel.get(client_id)
        return self.tunnels.get(tunnel_id) if tunnel_id else None

    def unregister_tunnel(self, tunnel_id: str):
        """Remove tunnel with cleanup"""
        if tunnel_id not in self.tunnels:
            return

        tunnel_data = self.tunnels.pop(tunnel_id)
        subdomain = tunnel_data['subdomain']
        client_id = tunnel_data['client_id']
        company = tunnel_data['company']

        self.subdomain_to_tunnel.pop(subdomain, None)
        self.client_to_tunnel.pop(client_id, None)
        self.company_subdomains[company].discard(subdomain)
        self.used_subdomains.discard(subdomain)

    def generate_company_subdomain(self, company: str, client_id: str) -> str:
        """Generate company-namespaced subdomain with collision handling"""
        # Try the preferred name first
        preferred = f"{company}"
        if preferred not in self.used_subdomains:
            return preferred

        # Generate with random suffix
        for _ in range(100):  # Increased attempts
            suffix = ''.join(random.choices(string.digits, k=6))  # Longer suffix
            candidate = f"{company}{suffix}"
            if candidate not in self.used_subdomains:
                return candidate

        # Fallback with timestamp and UUID
        return f"{company}{int(time.time())}{str(uuid.uuid4())[:8]}"

class UltraHighPerformanceTunnelServer:
    """Main tunnel server optimized for unlimited capacity and performance with SSL"""

    def __init__(self, host='0.0.0.0', port=8080, domain='localhost',
                 ssl_cert=None, ssl_key=None, auto_detect_ssl=True):
        self.host = host
        self.port = port
        self.domain = self._normalize_domain(domain)
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.auto_detect_ssl = auto_detect_ssl

        # UNLIMITED SETTINGS - No limits on anything
        self.max_tunnels = None  # Unlimited tunnels
        self.request_timeout = None  # No timeout
        self.max_body_size = None  # Unlimited body size (100TB+)

        # Ultra high-performance components - memory only
        self.registry = TunnelRegistry()
        self.metrics = PerformanceMetrics()
        self.pending_requests: Dict[str, asyncio.Future] = {}

        # SSL detection and configuration
        self.use_ssl = self._detect_ssl_setup()
        self.ssl_context = self._create_ssl_context() if self.use_ssl else None
        self.protocol = 'https' if self.use_ssl else 'http'
        self.ws_protocol = 'wss' if self.use_ssl else 'ws'

        # NO RATE LIMITING - Unlimited requests
        self.rate_limiters: Dict[str, dict] = {}
        self.rate_limit_requests = float('inf')  # Unlimited
        self.rate_limit_window = 1  # Minimal window
        self.running = False
        self.cleanup_tasks = []

        logger.info("[INIT] Ultra High-Performance Tunnel Server with SSL initialized")
        logger.info("[INIT] UNLIMITED MODE: No timeouts, no connection limits, 100TB+ support")
        logger.info(f"[INIT] SSL: {'Enabled' if self.use_ssl else 'Disabled'}")
        if self.use_ssl and self.ssl_cert:
            logger.info(f"[INIT] SSL Certificate: {self.ssl_cert}")
        logger.info(f"[INIT] Protocol: {self.protocol} | WebSocket: {self.ws_protocol}")

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain by removing protocol"""
        if domain.startswith(('http://', 'https://')):
            return urlparse(domain).netloc
        return domain

    def _detect_ssl_setup(self) -> bool:
        """Auto-detect SSL configuration based on environment and certificates"""
        if not self.auto_detect_ssl:
            logger.info("[SSL] Auto-detection disabled")
            return False

        # Check for environment variables (common in deployment platforms)
        if os.environ.get('HTTPS') == 'true' or os.environ.get('USE_SSL') == 'true':
            logger.info("[SSL] Enabled via environment variables")
            return True

        # Check for cloud platform specific environments
        cloud_indicators = ['RENDER', 'HEROKU', 'RAILWAY', 'VERCEL', 'NETLIFY', 'FLY_IO']
        detected_platform = None
        for indicator in cloud_indicators:
            if os.environ.get(indicator):
                detected_platform = indicator
                break

        if detected_platform:
            logger.info(f"[SSL] Enabled - detected {detected_platform} environment")
            return True

        # Check for certificate files
        if self.ssl_cert and self.ssl_key:
            if os.path.exists(self.ssl_cert) and os.path.exists(self.ssl_key):
                logger.info("[SSL] Enabled via certificate files")
                return True
            else:
                logger.warning("[SSL] Certificate files specified but not found")

        # Check for common certificate locations
        common_cert_paths = [
            '/etc/ssl/certs/server.crt',
            '/etc/letsencrypt/live/*/fullchain.pem',
            './ssl/cert.pem',
            './cert.pem',
            'fullchain.pem'
        ]

        common_key_paths = [
            '/etc/ssl/private/server.key',
            '/etc/letsencrypt/live/*/privkey.pem',
            './ssl/key.pem',
            './key.pem',
            'privkey.pem'
        ]

        for cert_path in common_cert_paths:
            for key_path in common_key_paths:
                if os.path.exists(cert_path) and os.path.exists(key_path):
                    self.ssl_cert = cert_path
                    self.ssl_key = key_path
                    logger.info(f"[SSL] Enabled - found certificates at {cert_path} and {key_path}")
                    return True

        # Check if running on standard HTTPS port
        if self.port == 443:
            logger.info("[SSL] Enabled - running on port 443")
            return True

        # Check if domain suggests HTTPS
        https_domains = ['.onrender.com', '.herokuapp.com', '.netlify.app', '.vercel.app',
                        '.railway.app', '.fly.dev']
        for https_domain in https_domains:
            if https_domain in self.domain:
                logger.info(f"[SSL] Enabled - detected HTTPS-enabled domain: {self.domain}")
                return True

        logger.info("[SSL] Disabled - no SSL configuration detected")
        return False

    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Create SSL context if certificates are available"""
        try:
            if not self.ssl_cert or not self.ssl_key:
                logger.info("[SSL] No certificates specified, relying on reverse proxy SSL")
                return None

            if not (os.path.exists(self.ssl_cert) and os.path.exists(self.ssl_key)):
                logger.warning("[SSL] Certificate files not found, SSL context not created")
                return None

            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(self.ssl_cert, self.ssl_key)
            logger.info("[SSL] SSL context created successfully")
            return context

        except Exception as e:
            logger.error(f"[SSL] Error creating SSL context: {e}")
            return None

    def check_port_availability(self, port: int) -> bool:
        """Check if a port is available for binding"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, port))
                return True
        except OSError:
            return False

    def get_public_url(self, subdomain: str) -> str:
        """Generate public URL for subdomain with SSL support"""
        # Handle the case where domain includes protocol
        domain = self.domain
        if domain.startswith('http://') or domain.startswith('https://'):
            parsed = urlparse(domain)
            domain = parsed.netloc
            if parsed.port:
                domain = f"{parsed.hostname}:{parsed.port}"

        # For deployment platforms, use the provided domain directly
        if any(platform in domain for platform in ['.onrender.com', '.herokuapp.com', '.netlify.app', '.vercel.app']):
            return f"https://{subdomain}-{domain}"

        # For custom domains with subdomains
        port_str = ""
        if (self.use_ssl and self.port != 443) or (not self.use_ssl and self.port != 80):
            port_str = f":{self.port}"

        return f"{self.protocol}://{subdomain}.{domain}{port_str}"

    def get_public_websocket_url(self) -> str:
        """Get the public WebSocket URL for clients"""
        domain = self.domain
        if domain.startswith('http://') or domain.startswith('https://'):
            parsed = urlparse(domain)
            domain = parsed.netloc
            if parsed.port:
                domain = f"{parsed.hostname}:{parsed.port}"

        # For deployment platforms
        if any(platform in domain for platform in ['.onrender.com', '.herokuapp.com']):
            return f"wss://{domain}/ws"

        # For custom domains
        port_str = ""
        if (self.use_ssl and self.port != 443) or (not self.use_ssl and self.port != 80):
            port_str = f":{self.port}"

        return f"{self.ws_protocol}://{domain}{port_str}/ws"

    def _extract_subdomain(self, host: str) -> Optional[str]:
        """Extract subdomain from Host header with high performance"""
        if not host:
            return None

        host_clean = host.split(':')[0].lower()

        # For deployment platforms like Render (subdomain-domain.onrender.com)
        if any(platform in host_clean for platform in ['.onrender.com', '.herokuapp.com']):
            parts = host_clean.split('-')
            if len(parts) > 1:
                return parts[0]
        else:
            # For traditional subdomains (subdomain.domain.com)
            domain_suffix = f".{self.domain}"
            if not host_clean.endswith(domain_suffix):
                return None
            subdomain = host_clean[:-len(domain_suffix)]
            return subdomain if subdomain else None

        return None

    def check_rate_limit(self, tunnel_id: str) -> bool:
        """NO RATE LIMITING - Always allow"""
        return True  # Unlimited requests always allowed

    async def websocket_handler(self, request: Request) -> WebSocketResponse:
        """Ultra WebSocket handler - unlimited capacity with SSL support"""
        # UNLIMITED WebSocket settings
        ws = WebSocketResponse(
            heartbeat=None,  # No heartbeat timeout
            max_msg_size=None,  # Unlimited message size (100TB+)
            compress=False,  # Disabled to prevent encoding issues
            timeout=None  # No timeout
        )

        await ws.prepare(request)
        tunnel_id = None
        client_ip = request.remote or "unknown"

        try:
            self.metrics.active_connections += 1
            logger.info(f"[WS] New unlimited WebSocket connection from {client_ip} (SSL: {self.use_ssl})")

            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        msg_type = data.get('type')

                        if msg_type == 'register':
                            tunnel_id = await self._handle_registration(data, ws, client_ip)
                        elif msg_type == 'response' and tunnel_id:
                            await self._handle_response(data)
                        elif msg_type == 'heartbeat' and tunnel_id:
                            await self._handle_heartbeat(tunnel_id, ws)
                        else:
                            logger.debug(f"[WS] Message type: {msg_type}")
                    except json.JSONDecodeError:
                        logger.error(f"[WS] Invalid JSON from {client_ip}")
                    except Exception as e:
                        logger.error(f"[WS] Message processing error: {e}")
                elif msg.type == web.WSMsgType.ERROR:
                    logger.error(f"[WS] WebSocket error: {ws.exception()}")
                    break
        except Exception as e:
            logger.error(f"[WS] WebSocket handler error: {e}")
        finally:
            self.metrics.active_connections -= 1
            if tunnel_id:
                self.registry.unregister_tunnel(tunnel_id)
                logger.info(f"[WS] Tunnel {tunnel_id} disconnected")

        return ws

    async def _handle_registration(self, data: dict, ws: WebSocketResponse,
                                 client_ip: str) -> Optional[str]:
        """Handle tunnel registration - unlimited capacity with SSL URLs"""
        local_port = data.get('local_port')
        company = data.get('company', 'default')
        client_id = data.get('client_id')

        # Validate input
        if not isinstance(local_port, int) or not (1 <= local_port <= 65535):
            await ws.send_json({'type': 'error', 'message': 'Invalid local_port'})
            return None

        # NO CAPACITY LIMITS - Accept unlimited tunnels
        # Generate or reuse client ID
        if not client_id:
            client_id = str(uuid.uuid4())

        # Check if client already has a tunnel
        existing_tunnel = self.registry.get_tunnel_by_client(client_id)
        if existing_tunnel:
            subdomain = existing_tunnel['subdomain']
        else:
            subdomain = self.registry.generate_company_subdomain(company, client_id)

        tunnel_id = str(uuid.uuid4())

        # Register the tunnel
        tunnel_data = self.registry.register_tunnel(
            tunnel_id, client_id, company, subdomain, ws, local_port, client_ip
        )

        public_url = self.get_public_url(subdomain)
        websocket_url = self.get_public_websocket_url()

        # Include client_id in response with SSL info
        await ws.send_json({
            'type': 'registered',
            'tunnel_id': tunnel_id,
            'client_id': client_id,
            'public_url': public_url,
            'subdomain': subdomain,
            'company': company,
            'websocket_url': websocket_url,
            'protocol': self.protocol,
            'ssl_enabled': self.use_ssl,
            'server_info': {
                'version': '3.0',
                'platform': 'unlimited',
                'ssl_support': True
            }
        })

        logger.info(f"[REGISTER] Unlimited tunnel registered: {public_url} -> localhost:{local_port} (SSL: {self.use_ssl})")
        return tunnel_id

    async def _handle_response(self, data: dict):
        """Handle response from client with minimal latency"""
        request_id = data.get('request_id')
        if request_id in self.pending_requests:
            future = self.pending_requests.pop(request_id)
            if not future.done():
                future.set_result(data)

    async def _handle_heartbeat(self, tunnel_id: str, ws: WebSocketResponse):
        """Handle heartbeat with performance tracking"""
        if tunnel_id in self.registry.tunnels:
            self.registry.tunnels[tunnel_id]['last_seen'] = time.time()
            await ws.send_json({'type': 'heartbeat_ack'})

    async def http_handler(self, request: Request) -> Response:
        """Ultra high-performance HTTP handler - unlimited capacity with SSL"""
        start_time = time.time()
        host = request.headers.get('host', '')

        # Extract subdomain with performance optimization
        subdomain = self._extract_subdomain(host)
        if not subdomain:
            return await self._handle_server_route(request)

        # Get tunnel with O(1) lookup
        tunnel = self.registry.get_tunnel_by_subdomain(subdomain)
        if not tunnel:
            return web.Response(
                text=f"Tunnel '{subdomain}' not found",
                status=404,
                headers={'Content-Type': 'text/plain'}
            )

        # Check if WebSocket is still alive
        if tunnel['websocket'].closed:
            self.registry.unregister_tunnel(tunnel['tunnel_id'])
            return web.Response(
                text="Tunnel connection closed",
                status=503,
                headers={'Content-Type': 'text/plain'}
            )

        # NO RATE LIMITING - Accept all requests
        try:
            # Forward request with unlimited streaming support
            response = await self._forward_request(request, tunnel)

            # Update metrics
            duration = time.time() - start_time
            body_size = len(response.body) if hasattr(response, 'body') and response.body else 0
            self.metrics.record_request(duration, body_size, True)
            tunnel['request_count'] += 1
            tunnel['bytes_transferred'] += body_size

            logger.debug(f"[HTTP] {request.method} {request.path_qs} -> {subdomain} ({response.status}) [{duration:.3f}s] SSL: {self.use_ssl}")
            return response

        except Exception as e:
            self.metrics.record_request(time.time() - start_time, 0, False)
            logger.error(f"[HTTP] Forwarding error: {e}")
            return web.Response(text="Internal Server Error", status=500)

    async def _handle_server_route(self, request: Request) -> Response:
        """Handle server management routes"""
        path = request.path.strip('/')

        if path == 'status':
            return await self._status_handler(request)
        elif path == 'health':
            return web.json_response({
                'status': 'healthy',
                'timestamp': time.time(),
                'platform': 'unlimited',
                'ssl_enabled': self.use_ssl,
                'protocol': self.protocol
            })
        elif path == 'metrics':
            return await self._metrics_handler(request)
        else:
            return web.Response(
                text=f"Ultra Tunnel Server - UNLIMITED MODE with SSL\n"
                     f"Protocol: {self.protocol}\n"
                     f"SSL: {'Enabled' if self.use_ssl else 'Disabled'}\n"
                     f"Visit /status for active tunnels",
                status=404,
                headers={'Content-Type': 'text/plain'}
            )

    async def _forward_request(self, request: Request, tunnel: dict) -> Response:
        """Forward HTTP request - unlimited capacity (100TB+)"""
        request_id = str(uuid.uuid4())

        # Read body with UNLIMITED size
        try:
            body = await request.read()
            # NO SIZE LIMIT - Accept 100TB+ bodies
        except Exception as e:
            logger.error(f"[FORWARD] Error reading body: {e}")
            body = b''

        # Prepare request data
        request_data = {
            'type': 'request',
            'request_id': request_id,
            'method': request.method,
            'path': request.path_qs,
            'headers': dict(request.headers),
            'body': base64.b64encode(body).decode('utf-8') if body else None
        }

        # Create future for response
        future = asyncio.Future()
        self.pending_requests[request_id] = future
        tunnel['active_requests'] += 1

        try:
            # Send request to client
            await tunnel['websocket'].send_json(request_data)

            # Wait for response with NO TIMEOUT (unlimited wait)
            response_data = await future

            # Create response with proper encoding
            status = response_data.get('status', 200)
            headers = response_data.get('headers', {})
            body_b64 = response_data.get('body', '')

            # Decode body safely
            try:
                response_body = base64.b64decode(body_b64) if body_b64 else b''
            except Exception as e:
                logger.error(f"[FORWARD] Base64 decode error: {e}")
                response_body = b''

            # Clean problematic headers
            clean_headers = {}
            skip_headers = {
                'content-length', 'transfer-encoding', 'content-encoding',
                'connection', 'upgrade', 'keep-alive'
            }

            for key, value in headers.items():
                if key.lower() not in skip_headers:
                    try:
                        clean_headers[key] = str(value)
                    except:
                        continue

            # Set proper Content-Length
            if response_body:
                clean_headers['Content-Length'] = str(len(response_body))

            return web.Response(
                body=response_body,
                status=status,
                headers=clean_headers
            )

        finally:
            tunnel['active_requests'] -= 1
            self.pending_requests.pop(request_id, None)

    async def _status_handler(self, request: Request) -> Response:
        """Status endpoint with comprehensive metrics including SSL info"""
        uptime = time.time() - self.metrics.start_time

        tunnels_info = []
        for tunnel in self.registry.tunnels.values():
            tunnels_info.append({
                'company': tunnel['company'],
                'subdomain': tunnel['subdomain'],
                'public_url': self.get_public_url(tunnel['subdomain']),
                'local_port': tunnel['local_port'],
                'client_ip': tunnel['client_ip'],
                'uptime': time.time() - tunnel['created_at'],
                'requests': tunnel['request_count'],
                'bytes_transferred': tunnel['bytes_transferred'],
                'active_requests': tunnel['active_requests'],
                'ssl_enabled': self.use_ssl
            })

        status_data = {
            'status': 'running',
            'platform': 'unlimited',
            'mode': 'UNLIMITED_CAPACITY_SSL',
            'ssl_info': {
                'enabled': self.use_ssl,
                'protocol': self.protocol,
                'websocket_protocol': self.ws_protocol,
                'certificate_path': self.ssl_cert if self.ssl_cert else None,
                'auto_detection': self.auto_detect_ssl
            },
            'uptime_seconds': uptime,
            'active_tunnels': len(self.registry.tunnels),
            'active_connections': self.metrics.active_connections,
            'total_requests': self.metrics.request_count,
            'total_bytes': self.metrics.bytes_transferred,
            'error_rate': self.metrics.error_count / max(self.metrics.request_count, 1),
            'avg_response_time': sum(self.metrics.response_times) / max(len(self.metrics.response_times), 1),
            'throughput_mbps': self.metrics.get_throughput(),
            'limits': {
                'max_tunnels': 'UNLIMITED',
                'request_timeout': 'UNLIMITED',
                'max_body_size': 'UNLIMITED (100TB+)',
                'rate_limit': 'DISABLED'
            },
            'urls': {
                'websocket': self.get_public_websocket_url(),
                'base': f"{self.protocol}://{self.domain}:{self.port}" if self.port not in [80, 443] else f"{self.protocol}://{self.domain}"
            },
            'tunnels': tunnels_info
        }

        return web.json_response(status_data)

    async def _metrics_handler(self, request: Request) -> Response:
        """Prometheus-compatible metrics endpoint"""
        metrics_text = f"""# HELP tunnel_server_uptime_seconds Server uptime
tunnel_server_uptime_seconds {time.time() - self.metrics.start_time}

# HELP tunnel_server_active_tunnels Number of active tunnels
tunnel_server_active_tunnels {len(self.registry.tunnels)}

# HELP tunnel_server_requests_total Total requests processed
tunnel_server_requests_total {self.metrics.request_count}

# HELP tunnel_server_bytes_transferred_total Total bytes transferred
tunnel_server_bytes_transferred_total {self.metrics.bytes_transferred}

# HELP tunnel_server_error_rate Request error rate
tunnel_server_error_rate {self.metrics.error_count / max(self.metrics.request_count, 1)}

# HELP tunnel_server_ssl_enabled SSL status
tunnel_server_ssl_enabled {1 if self.use_ssl else 0}

# HELP tunnel_server_mode Server operation mode
tunnel_server_mode{{mode="unlimited"}} 1
"""
        return web.Response(text=metrics_text, content_type='text/plain')

    async def _cleanup_stale_connections(self):
        """Clean up stale connections - very generous timeouts"""
        while self.running:
            await asyncio.sleep(300)  # Run every 5 minutes
            current_time = time.time()

            # Clean up very stale tunnels (no heartbeat for 24 hours)
            stale_tunnels = [
                tid for tid, tunnel in self.registry.tunnels.items()
                if current_time - tunnel['last_seen'] > 86400  # 24 hours
            ]

            for tunnel_id in stale_tunnels:
                self.registry.unregister_tunnel(tunnel_id)
                logger.info(f"[CLEANUP] Cleaned up stale tunnel: {tunnel_id}")

    async def start_server(self):
        """Start the ultra high-performance tunnel server with SSL"""
        self.running = True

        # Check if port is available
        if not self.check_port_availability(self.port):
            logger.error(f"[START] Port {self.port} is already in use")
            raise RuntimeError(f"Port {self.port} is already in use")

        # Create aiohttp application with UNLIMITED settings
        app = web.Application(
            client_max_size=None  # UNLIMITED body size (100TB+)
        )

        # Setup CORS without conflicts
        cors = aiohttp_cors.setup(app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
            )
        })

        # Add WebSocket route
        ws_route = app.router.add_get('/ws', self.websocket_handler)
        cors.add(ws_route)

        # Add specific server routes
        status_route = app.router.add_get('/status', self._status_handler)
        health_route = app.router.add_get('/health', lambda r: web.json_response({
            'status': 'healthy',
            'timestamp': time.time(),
            'platform': 'unlimited',
            'ssl_enabled': self.use_ssl,
            'protocol': self.protocol
        }))
        metrics_route = app.router.add_get('/metrics', self._metrics_handler)

        cors.add(status_route)
        cors.add(health_route)
        cors.add(metrics_route)

        # Add catch-all route for tunnel traffic
        methods_to_register = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD']
        for method in methods_to_register:
            route = app.router.add_route(method, '/{path:.*}', self.http_handler)
            cors.add(route)

        # Start cleanup task
        self.cleanup_tasks.append(asyncio.create_task(self._cleanup_stale_connections()))

        # Create and start server with SSL support
        runner = web.AppRunner(app)
        await runner.setup()

        # Use PORT environment variable if available (for cloud platforms)
        port = int(os.environ.get('PORT', self.port))

        # Create TCP site with SSL context if available
        site = web.TCPSite(
            runner,
            self.host,
            port,
            ssl_context=self.ssl_context
        )
        await site.start()

        base_url = f"{self.protocol}://{self.domain}"
        if port not in [80, 443]:
            base_url += f":{port}"

        websocket_url = self.get_public_websocket_url()

        logger.info("[START] " + "=" * 80)
        logger.info("[START] ULTRA HIGH-PERFORMANCE TUNNEL SERVER WITH SSL STARTED!")
        logger.info("[START] MODE: UNLIMITED CAPACITY - NO TIMEOUTS - 100TB+ SUPPORT")
        logger.info(f"[START] Server: {self.host}:{port}")
        logger.info(f"[START] SSL: {'Enabled' if self.use_ssl else 'Disabled'}")
        logger.info(f"[START] Protocol: {self.protocol}")
        logger.info(f"[START] Domain: {base_url}")
        logger.info(f"[START] WebSocket: {websocket_url}")
        logger.info(f"[START] Status: {base_url}/status")
        if self.ssl_cert:
            logger.info(f"[START] SSL Certificate: {self.ssl_cert}")
        logger.info("[START] " + "=" * 80)

        return runner

    async def stop_server(self):
        """Stop server gracefully"""
        self.running = False

        # Cancel cleanup tasks
        for task in self.cleanup_tasks:
            task.cancel()

        # Close all tunnels
        for tunnel_id in list(self.registry.tunnels.keys()):
            self.registry.unregister_tunnel(tunnel_id)

        logger.info("[STOP] Ultra tunnel server with SSL stopped gracefully")

async def main():
    """Main server entry point with SSL support"""
    import argparse

    parser = argparse.ArgumentParser(description='Ultra High-Performance Tunnel Server with SSL')
    parser.add_argument('--host', default=os.environ.get('HOST', '0.0.0.0'),
                       help='Host to bind to')
    parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', 8080)),
                       help='Port to bind to')
    parser.add_argument('--domain', default=os.environ.get('DOMAIN', 'localhost'),
                       help='Public domain name')
    parser.add_argument('--ssl-cert', default=os.environ.get('SSL_CERT'),
                       help='Path to SSL certificate file')
    parser.add_argument('--ssl-key', default=os.environ.get('SSL_KEY'),
                       help='Path to SSL private key file')
    parser.add_argument('--no-auto-ssl', action='store_true',
                       help='Disable automatic SSL detection')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    server = UltraHighPerformanceTunnelServer(
        host=args.host,
        port=args.port,
        domain=args.domain,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        auto_detect_ssl=not args.no_auto_ssl
    )

    runner = None
    try:
        runner = await server.start_server()
        # Keep running until interrupted
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("[MAIN] Shutdown signal received")
    finally:
        if runner:
            await server.stop_server()
            await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[MAIN] Server stopped by user")
