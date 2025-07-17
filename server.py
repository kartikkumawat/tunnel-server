#!/usr/bin/env python3
"""
Enhanced Tunnel Server - Single Port Version
Runs both HTTP and WebSocket servers on the same port for better compatibility with cloud platforms
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
from typing import Dict, Optional, Set
import uuid
import websockets
from websockets.server import WebSocketServerProtocol
from aiohttp import web, ClientSession, ClientTimeout
from aiohttp.web_request import Request
from aiohttp.web_response import Response
import aiohttp_cors
from urllib.parse import urlparse
from aiohttp.web_ws import WebSocketResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TunnelServer:
    def __init__(self, host='0.0.0.0', port=8080, domain='yourdomain.com', 
                 ssl_cert=None, ssl_key=None, auto_detect_ssl=True):
        self.host = host
        self.port = port
        self.domain = domain
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.auto_detect_ssl = auto_detect_ssl
        
        # Auto-detect SSL configuration
        self.use_ssl = self._detect_ssl_setup()
        self.protocol = 'https' if self.use_ssl else 'http'
        self.ws_protocol = 'wss' if self.use_ssl else 'ws'

        # Store active tunnels: {tunnel_id: {'websocket': ws, 'subdomain': subdomain, 'local_port': port}}
        self.tunnels: Dict[str, dict] = {}

        # Store pending requests: {request_id: {'future': future, 'timeout': timestamp}}
        self.pending_requests: Dict[str, dict] = {}

        # Keep track of used subdomains and port mappings
        self.used_subdomains: Set[str] = set()
        self.port_to_subdomain: Dict[int, str] = {}

        # Cleanup interval
        self.cleanup_interval = 60  # seconds

        logger.info(f"SSL Detection: {'Enabled' if self.use_ssl else 'Disabled'}")
        logger.info(f"Protocol: {self.protocol}")
        logger.info(f"WebSocket Protocol: {self.ws_protocol}")

    def _detect_ssl_setup(self) -> bool:
        """Auto-detect SSL configuration based on environment and certificates"""
        if not self.auto_detect_ssl:
            return False
            
        # Check for environment variables (common in deployment platforms)
        if os.environ.get('HTTPS') == 'true' or os.environ.get('USE_SSL') == 'true':
            logger.info("SSL enabled via environment variables")
            return True
            
        # Check for Render.com specific environment
        if os.environ.get('RENDER'):
            logger.info("SSL enabled - detected Render.com environment")
            return True
            
        # Check for certificate files
        if self.ssl_cert and self.ssl_key:
            if os.path.exists(self.ssl_cert) and os.path.exists(self.ssl_key):
                logger.info("SSL enabled via certificate files")
                return True
            else:
                logger.warning("SSL certificate files specified but not found")
                
        # Check for common certificate locations
        common_cert_paths = [
            '/etc/ssl/certs/server.crt',
            '/etc/letsencrypt/live/*/fullchain.pem',
            './ssl/cert.pem',
            './cert.pem'
        ]
        
        common_key_paths = [
            '/etc/ssl/private/server.key',
            '/etc/letsencrypt/live/*/privkey.pem',
            './ssl/key.pem',
            './key.pem'
        ]
        
        for cert_path in common_cert_paths:
            for key_path in common_key_paths:
                if os.path.exists(cert_path) and os.path.exists(key_path):
                    self.ssl_cert = cert_path
                    self.ssl_key = key_path
                    logger.info(f"SSL enabled - found certificates at {cert_path} and {key_path}")
                    return True
                    
        # Check if running on standard HTTPS port
        if self.port == 443:
            logger.info("SSL enabled - running on port 443")
            return True
            
        # Check if domain suggests HTTPS (like render.com, herokuapp.com, etc.)
        https_domains = ['.onrender.com', '.herokuapp.com', '.netlify.app', '.vercel.app']
        for https_domain in https_domains:
            if https_domain in self.domain:
                logger.info(f"SSL enabled - detected HTTPS-enabled domain: {self.domain}")
                return True
                
        logger.info("SSL disabled - no SSL configuration detected")
        return False

    def get_public_websocket_url(self) -> str:
        """Get the public WebSocket URL for clients"""
        # Handle the case where domain includes protocol
        domain = self.domain
        if domain.startswith('http://') or domain.startswith('https://'):
            parsed = urlparse(domain)
            domain = parsed.netloc
            if parsed.port:
                domain = f"{parsed.hostname}:{parsed.port}"
        
        # For deployment platforms, use the provided domain directly
        if '.onrender.com' in domain or '.herokuapp.com' in domain:
            return f"wss://{domain}/ws"
        
        # For custom domains, include port if not standard
        if self.use_ssl and self.port != 443:
            return f"wss://{domain}:{self.port}/ws"
        elif not self.use_ssl and self.port != 80:
            return f"ws://{domain}:{self.port}/ws"
        else:
            return f"{self.ws_protocol}://{domain}/ws"

    def get_public_http_url(self, subdomain: str) -> str:
        """Get the public HTTP URL for a subdomain"""
        # Handle the case where domain includes protocol
        domain = self.domain
        if domain.startswith('http://') or domain.startswith('https://'):
            parsed = urlparse(domain)
            domain = parsed.netloc
            if parsed.port:
                domain = f"{parsed.hostname}:{parsed.port}"
        
        # For deployment platforms, use the provided domain directly
        if '.onrender.com' in domain or '.herokuapp.com' in domain:
            return f"https://{subdomain}-{domain}"
        
        # For custom domains with subdomains
        if self.use_ssl and self.port != 443:
            return f"https://{subdomain}.{domain}:{self.port}"
        elif not self.use_ssl and self.port != 80:
            return f"http://{subdomain}.{domain}:{self.port}"
        else:
            return f"{self.protocol}://{subdomain}.{domain}"

    def generate_unique_subdomain(self, local_port: int) -> str:
        """Generate a unique subdomain, preferably based on port"""
        max_attempts = 100

        # First try to use port-based subdomain
        port_based = f"port{local_port}"
        if port_based not in self.used_subdomains:
            return port_based

        # If port-based subdomain is taken, generate random ones
        for attempt in range(max_attempts):
            subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            if subdomain not in self.used_subdomains:
                return subdomain

        # Fallback: use timestamp-based subdomain
        timestamp = str(int(time.time()))[-6:]  # Last 6 digits of timestamp
        return f"tunnel{timestamp}"

    def generate_tunnel_id(self) -> str:
        """Generate a unique tunnel ID"""
        return str(uuid.uuid4())

    def generate_request_id(self) -> str:
        """Generate a unique request ID"""
        return str(uuid.uuid4())

    def cleanup_tunnel(self, tunnel_id: str):
        """Clean up tunnel resources"""
        if tunnel_id in self.tunnels:
            tunnel_data = self.tunnels[tunnel_id]
            subdomain = tunnel_data['subdomain']
            local_port = tunnel_data['local_port']

            # Remove from tracking sets
            self.used_subdomains.discard(subdomain)
            if local_port in self.port_to_subdomain:
                del self.port_to_subdomain[local_port]

            # Remove tunnel
            del self.tunnels[tunnel_id]
            logger.info(f"Tunnel cleaned up: {tunnel_id} ({self.get_public_http_url(subdomain)})")

    async def handle_websocket_connection(self, websocket: WebSocketResponse):
        """Handle WebSocket connections from clients using aiohttp WebSocket"""
        tunnel_id = None
        client_address = "unknown"

        try:
            logger.info(f"New WebSocket connection from {client_address}")

            async for msg in websocket:
                if msg.type == web.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON from {client_address}: {e}")
                        await websocket.send_str(json.dumps({
                            'type': 'error',
                            'message': 'Invalid JSON format'
                        }))
                        continue

                    if data['type'] == 'register':
                        try:
                            # Validate registration data
                            local_port = data.get('local_port')
                            if not local_port or not isinstance(local_port, int) or local_port <= 0 or local_port > 65535:
                                await websocket.send_str(json.dumps({
                                    'type': 'error',
                                    'message': 'Invalid local_port. Must be a valid port number (1-65535)'
                                }))
                                continue

                            # Check if port is already being tunneled
                            if local_port in self.port_to_subdomain:
                                existing_subdomain = self.port_to_subdomain[local_port]
                                await websocket.send_str(json.dumps({
                                    'type': 'error',
                                    'message': f'Port {local_port} is already being tunneled to {self.get_public_http_url(existing_subdomain)}'
                                }))
                                continue

                            # Generate unique identifiers
                            tunnel_id = self.generate_tunnel_id()
                            subdomain = self.generate_unique_subdomain(local_port)

                            # Register tunnel
                            self.tunnels[tunnel_id] = {
                                'websocket': websocket,
                                'subdomain': subdomain,
                                'local_port': local_port,
                                'last_seen': time.time(),
                                'client_address': client_address
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
                                'websocket_url': self.get_public_websocket_url()
                            }))

                            logger.info(f"Tunnel registered: {tunnel_id} -> {public_url} -> localhost:{local_port} (client: {client_address})")

                        except Exception as e:
                            logger.error(f"Error registering tunnel for {client_address}: {e}")
                            await websocket.send_str(json.dumps({
                                'type': 'error',
                                'message': 'Registration failed'
                            }))

                    elif data['type'] == 'response':
                        try:
                            # Handle response from client
                            request_id = data.get('request_id')
                            if not request_id:
                                logger.error(f"Missing request_id in response from {client_address}")
                                continue

                            if request_id in self.pending_requests:
                                future = self.pending_requests[request_id]['future']
                                if not future.done():
                                    future.set_result(data)
                                del self.pending_requests[request_id]
                            else:
                                logger.warning(f"Received response for unknown request_id: {request_id}")

                        except Exception as e:
                            logger.error(f"Error handling response from {client_address}: {e}")

                    elif data['type'] == 'heartbeat':
                        try:
                            # Update last seen time
                            if tunnel_id and tunnel_id in self.tunnels:
                                self.tunnels[tunnel_id]['last_seen'] = time.time()
                                await websocket.send_str(json.dumps({'type': 'heartbeat_ack'}))
                            else:
                                logger.warning(f"Heartbeat from unregistered tunnel: {client_address}")

                        except Exception as e:
                            logger.error(f"Error handling heartbeat from {client_address}: {e}")

                    else:
                        logger.warning(f"Unknown message type '{data.get('type')}' from {client_address}")

                elif msg.type == web.WSMsgType.ERROR:
                    logger.error(f"WebSocket error from {client_address}: {websocket.exception()}")
                    break

        except Exception as e:
            logger.error(f"Unexpected error handling WebSocket from {client_address}: {e}")
        finally:
            # Clean up tunnel when connection closes
            if tunnel_id:
                self.cleanup_tunnel(tunnel_id)

    async def websocket_handler(self, request: Request) -> WebSocketResponse:
        """Handle WebSocket upgrade requests"""
        ws = WebSocketResponse(
            protocols=('chat',),
            heartbeat=30,
            timeout=30
        )
        await ws.prepare(request)
        
        # Handle the WebSocket connection
        await self.handle_websocket_connection(ws)
        
        return ws

    async def handle_http_request(self, request: Request) -> Response:
        """Handle HTTP requests and forward them to appropriate tunnel"""
        client_ip = request.remote
        host = request.headers.get('host', '')

        try:
            # Validate host header
            if not host:
                logger.warning(f"Missing host header from {client_ip}")
                return web.Response(
                    text="Missing host header",
                    status=400,
                    headers={'Content-Type': 'text/plain'}
                )

            # Extract subdomain - handle different domain formats
            subdomain = None
            
            # For deployment platforms like Render (subdomain-domain.onrender.com)
            if '.onrender.com' in host or '.herokuapp.com' in host:
                parts = host.split('-')
                if len(parts) > 1:
                    subdomain = parts[0]
            else:
                # For traditional subdomains (subdomain.domain.com)
                if '.' in host:
                    subdomain = host.split('.')[0]

            if not subdomain:
                logger.warning(f"Could not extract subdomain from host '{host}' from {client_ip}")
                return web.Response(
                    text="Invalid subdomain format",
                    status=400,
                    headers={'Content-Type': 'text/plain'}
                )

            # Find tunnel for this subdomain
            tunnel = None
            tunnel_id = None
            for tid, tunnel_data in self.tunnels.items():
                if tunnel_data['subdomain'] == subdomain:
                    tunnel = tunnel_data
                    tunnel_id = tid
                    break

            if not tunnel:
                logger.warning(f"No tunnel found for subdomain '{subdomain}' from {client_ip}")
                return web.Response(
                    text=f"Tunnel not found for subdomain '{subdomain}'",
                    status=404,
                    headers={'Content-Type': 'text/plain'}
                )

            # Check if tunnel connection is still alive
            if tunnel['websocket'].closed:
                logger.warning(f"Tunnel websocket closed for {subdomain}")
                self.cleanup_tunnel(tunnel_id)
                return web.Response(
                    text=f"Tunnel connection closed for subdomain '{subdomain}'",
                    status=503,
                    headers={'Content-Type': 'text/plain'}
                )

            # Forward request to client
            request_id = self.generate_request_id()

            # Prepare request data
            headers = dict(request.headers)

            # Read request body safely
            try:
                body = await request.read()
                body_str = body.decode('utf-8', errors='ignore') if body else None
            except Exception as e:
                logger.error(f"Error reading request body: {e}")
                body_str = None

            request_data = {
                'type': 'request',
                'request_id': request_id,
                'method': request.method,
                'path': request.path_qs,
                'headers': headers,
                'body': body_str
            }

            # Create future for response
            future = asyncio.Future()
            self.pending_requests[request_id] = {
                'future': future,
                'timeout': time.time() + 30  # 30 second timeout
            }

            try:
                # Send request to client
                await tunnel['websocket'].send_str(json.dumps(request_data))
                logger.debug(f"Forwarded {request.method} {request.path_qs} to {subdomain} (request_id: {request_id})")

                # Wait for response
                response_data = await asyncio.wait_for(future, timeout=30)

                # Validate response data
                if not isinstance(response_data, dict):
                    raise ValueError("Invalid response format")

                # Return response
                return web.Response(
                    text=response_data.get('body', ''),
                    status=response_data.get('status', 200),
                    headers=response_data.get('headers', {}),
                    content_type=response_data.get('content_type', 'text/html')
                )

            except asyncio.TimeoutError:
                logger.error(f"Request timeout for {subdomain} (request_id: {request_id})")
                return web.Response(
                    text="Request timeout - the tunneled service did not respond in time",
                    status=504,
                    headers={'Content-Type': 'text/plain'}
                )
            except Exception as e:
                logger.error(f"Error forwarding request to {subdomain}: {e}")
                return web.Response(
                    text="Internal server error while forwarding request",
                    status=500,
                    headers={'Content-Type': 'text/plain'}
                )

        except Exception as e:
            logger.error(f"Unexpected error handling HTTP request from {client_ip}: {e}")
            return web.Response(
                text="Internal server error",
                status=500,
                headers={'Content-Type': 'text/plain'}
            )

    async def cleanup_pending_requests(self):
        """Clean up expired pending requests"""
        while True:
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
                            future.set_exception(asyncio.TimeoutError())
                        del self.pending_requests[request_id]

                if expired_requests:
                    logger.info(f"Cleaned up {len(expired_requests)} expired requests")

                await asyncio.sleep(self.cleanup_interval)

            except Exception as e:
                logger.error(f"Cleanup error: {e}")
                await asyncio.sleep(self.cleanup_interval)

    async def cleanup_dead_tunnels(self):
        """Clean up tunnels that haven't sent heartbeat in a while"""
        while True:
            try:
                current_time = time.time()
                dead_tunnels = []

                for tunnel_id, tunnel_data in self.tunnels.items():
                    # If no heartbeat for 5 minutes, consider it dead
                    if current_time - tunnel_data['last_seen'] > 300:
                        dead_tunnels.append(tunnel_id)

                for tunnel_id in dead_tunnels:
                    logger.info(f"Cleaning up dead tunnel: {tunnel_id}")
                    self.cleanup_tunnel(tunnel_id)

                await asyncio.sleep(self.cleanup_interval)

            except Exception as e:
                logger.error(f"Dead tunnel cleanup error: {e}")
                await asyncio.sleep(self.cleanup_interval)

    async def status_handler(self, request: Request) -> Response:
        """Handle status requests"""
        try:
            status = {
                'server_info': {
                    'domain': self.domain,
                    'port': self.port,
                    'protocol': self.protocol,
                    'websocket_protocol': self.ws_protocol,
                    'ssl_enabled': self.use_ssl,
                    'websocket_url': self.get_public_websocket_url(),
                    'uptime': time.time()
                },
                'statistics': {
                    'active_tunnels': len(self.tunnels),
                    'pending_requests': len(self.pending_requests),
                    'used_subdomains': len(self.used_subdomains)
                },
                'tunnels': {
                    tunnel_id: {
                        'subdomain': data['subdomain'],
                        'local_port': data['local_port'],
                        'public_url': self.get_public_http_url(data['subdomain']),
                        'last_seen': data['last_seen'],
                        'client_address': data.get('client_address', 'unknown'),
                        'connected': not data['websocket'].closed
                    }
                    for tunnel_id, data in self.tunnels.items()
                }
            }
            return web.json_response(status)
        except Exception as e:
            logger.error(f"Error generating status: {e}")
            return web.json_response({'error': 'Status generation failed'}, status=500)

    def check_port_availability(self, port: int) -> bool:
        """Check if a port is available for binding"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, port))
                return True
        except OSError:
            return False

    async def start_server(self):
        """Start the tunnel server"""
        try:
            # Check if port is available
            if not self.check_port_availability(self.port):
                logger.error(f"Port {self.port} is already in use")
                raise RuntimeError(f"Port {self.port} is already in use")

            # Create HTTP application
            app = web.Application(client_max_size=1024*1024*10)  # 10MB max request size

            # Add routes (order matters!)
            same_head = app.router.add_get('/status', self.status_handler)
            app.router.add_get('/ws', self.websocket_handler)  # WebSocket endpoint

            # Add CORS support
            cors = aiohttp_cors.setup(app, defaults={
                "*": aiohttp_cors.ResourceOptions(
                    allow_credentials=True,
                    expose_headers="*",
                    allow_headers="*",
                    allow_methods="*"
                )
            })

            # Add CORS to status route
            cors.add(same_head)

            # Add catch-all route for tunnel traffic
            app.router.add_route('*', '/{path:.*}', self.handle_http_request)

            # Start cleanup tasks
            cleanup_task = asyncio.create_task(self.cleanup_pending_requests())
            dead_tunnel_task = asyncio.create_task(self.cleanup_dead_tunnels())

            # Start server
            runner = web.AppRunner(app)
            await runner.setup()
            
            # Use PORT environment variable if available (for Render.com)
            port = int(os.environ.get('PORT', self.port))
            
            site = web.TCPSite(runner, self.host, port)
            await site.start()

            logger.info(f"Tunnel server started successfully:")
            logger.info(f"  Server: {self.protocol}://{self.host}:{port}")
            logger.info(f"  Domain: {self.domain}")
            logger.info(f"  WebSocket endpoint: {self.get_public_websocket_url()}")
            logger.info(f"  Status endpoint: {self.protocol}://{self.host}:{port}/status")

            # Keep server running
            try:
                await asyncio.gather(
                    cleanup_task,
                    dead_tunnel_task
                )
            except KeyboardInterrupt:
                logger.info("Shutting down gracefully...")
            finally:
                # Cleanup
                logger.info("Cleaning up resources...")
                cleanup_task.cancel()
                dead_tunnel_task.cancel()
                await runner.cleanup()
                logger.info("Server shutdown complete")

        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Enhanced Tunnel Server - Single Port Version')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', 8080)), help='Port to bind to')
    parser.add_argument('--domain', default='tunnel-server-latest.onrender.com', help='Your domain name')
    parser.add_argument('--ssl-cert', help='Path to SSL certificate file')
    parser.add_argument('--ssl-key', help='Path to SSL private key file')
    parser.add_argument('--no-auto-ssl', action='store_true', help='Disable automatic SSL detection')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='Log level')

    args = parser.parse_args()

    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    server = TunnelServer(
        host=args.host,
        port=args.port,
        domain=args.domain,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        auto_detect_ssl=not args.no_auto_ssl
    )

    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        logger.info("Server stopped by user.")
    except Exception as e:
        logger.error(f"Server failed: {e}")
        exit(1)