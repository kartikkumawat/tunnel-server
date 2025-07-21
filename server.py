#!/usr/bin/env python3
"""
Universal Tunnel Server with PostgreSQL, Multi-Service Support & Web UI
"""
import asyncio
import json
import logging
import time
import os
import re
from typing import Dict, Optional, Set, Any, List
from datetime import datetime, timedelta
import uuid
import base64

from aiohttp import web, ClientTimeout, WSMsgType
from aiohttp.web_request import Request
from aiohttp.web_response import Response, StreamResponse
from aiohttp.web_ws import WebSocketResponse
import aiohttp_cors
from sqlalchemy import select, update, delete, func
from sqlalchemy.exc import IntegrityError

from models import (
    DatabaseManager, TunnelClient, TunnelService,
    ActiveConnection, RequestLog, ServerStats
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UniversalTunnelServer:
    def __init__(self, host='0.0.0.0', port=8080, domain='localhost'):
        self.host = host
        self.port = port
        self.domain = self._normalize_domain(domain)

        # Database
        self.db = DatabaseManager()

        # In-memory connection tracking
        self.websocket_connections: Dict[str, WebSocketResponse] = {}
        self.sse_connections: Dict[str, StreamResponse] = {}
        self.pending_requests: Dict[str, asyncio.Future] = {}
        self.active_sessions: Dict[str, dict] = {}

        # Universal service configurations per subdomain
        self.service_configs: Dict[str, dict] = {}

        # SSL detection
        self.use_ssl = self._detect_ssl()
        self.protocol = 'https' if self.use_ssl else 'http'

        logger.info(f"🚀 Universal Tunnel Server - Domain: {self.domain}")

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

    def _detect_ssl(self) -> bool:
        """Smart SSL detection"""
        platforms = ['RENDER', 'HEROKU', 'VERCEL', 'NETLIFY', 'RAILWAY']
        return (
            any(os.getenv(p) for p in platforms) or
            self.port == 443 or
            os.getenv('SSL_ENABLED', '').lower() == 'true'
        )

    def _normalize_domain(self, domain: str) -> str:
        return domain.replace('http://', '').replace('https://', '').split(':')[0]

    async def websocket_handler(self, request: Request) -> WebSocketResponse:
        """Enhanced WebSocket control handler"""
        ws = WebSocketResponse(heartbeat=30, max_msg_size=100*1024*1024)
        await ws.prepare(request)

        client_id = None
        client_ip = request.remote or "unknown"

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    if data.get('type') == 'register':
                        client_id = await self._handle_registration(data, ws, client_ip)
                    elif client_id and data.get('type') == 'service_config':
                        await self._handle_service_config(data, client_id)
                    elif client_id:
                        await self._handle_control_message(data, client_id)

        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            if client_id:
                await self._cleanup_client(client_id)

        return ws

    async def _handle_registration(self, data: dict, ws: WebSocketResponse, client_ip: str) -> str:
        """Handle client registration with multi-service support"""
        async with self.db.get_session() as session:
            # Create or update client
            client_id = data.get('client_id') or str(uuid.uuid4())

            # Check existing client
            result = await session.execute(
                select(TunnelClient).where(TunnelClient.id == client_id)
            )
            client = result.scalar_one_or_none()

            if not client:
                client = TunnelClient(
                    id=client_id,
                    client_ip=client_ip,
                    user_agent=data.get('user_agent', ''),
                    client_info=data.get('client_info', {})
                )
                session.add(client)
            else:
                client.last_seen = datetime.utcnow()
                client.is_active = True

            await session.commit()

            # Store WebSocket connection
            self.websocket_connections[client_id] = ws

            # Send registration response
            await ws.send_str(json.dumps({
                'type': 'registered',
                'client_id': client_id,
                'server_version': '4.0',
                'features': ['multi-service', 'universal-proxy', 'smart-routing']
            }))

            logger.info(f"✅ Client registered: {client_id[:8]} from {client_ip}")
            return client_id

    async def _handle_service_config(self, data: dict, client_id: str):
        """Handle service configuration for multi-service support"""
        async with self.db.get_session() as session:
            local_port = data.get('local_port')
            service_types = data.get('service_types', ['http'])
            service_configs = data.get('service_configs', {})
            preferred_subdomain = data.get('preferred_subdomain')

            # Generate unique subdomain
            subdomain = await self._generate_subdomain(session, local_port, preferred_subdomain)

            # Create or update service
            service = TunnelService(
                client_id=client_id,
                subdomain=subdomain,
                local_port=local_port,
                local_host=data.get('local_host', 'localhost'),
                service_types=service_types,
                service_configs=service_configs,
                detected_framework=data.get('detected_framework', 'unknown')
            )

            try:
                session.add(service)
                await session.commit()

                # Store service config in memory for quick access
                self.service_configs[subdomain] = {
                    'client_id': client_id,
                    'service_id': service.id,
                    'local_port': local_port,
                    'local_host': service.local_host,
                    'service_types': service_types,
                    'service_configs': service_configs
                }

                # Build URLs
                urls = self._build_service_urls(subdomain, service_types, service_configs)

                # Send response
                ws = self.websocket_connections.get(client_id)
                if ws:
                    await ws.send_str(json.dumps({
                        'type': 'service_configured',
                        'service_id': service.id,
                        'subdomain': subdomain,
                        'urls': urls
                    }))

                logger.info(f"🔧 Service configured: {subdomain} -> {local_port}")

            except IntegrityError:
                await session.rollback()
                logger.error(f"❌ Subdomain {subdomain} already exists")

    def _build_service_urls(self, subdomain: str, service_types: List[str], configs: dict) -> dict:
        """Build URLs for different service types with custom paths"""
        base_url = f"{self.protocol}://{subdomain}.{self.domain}"
        if self.port not in [80, 443]:
            base_url += f":{self.port}"

        urls = {}

        for service_type in service_types:
            if service_type == 'http':
                urls['http'] = base_url
                # Add custom HTTP paths if configured
                if 'http_paths' in configs:
                    urls['http_paths'] = {
                        path: f"{base_url}{path}"
                        for path in configs['http_paths']
                    }

            elif service_type == 'ws':
                ws_path = configs.get('websocket_path', '/ws')
                urls['websocket'] = f"{base_url.replace('http', 'ws')}{ws_path}"

            elif service_type == 'sse':
                sse_path = configs.get('sse_path', '/events')
                urls['sse'] = f"{base_url}{sse_path}"

        return urls

    async def _generate_subdomain(self, session, local_port: int, preferred: str = None) -> str:
        """Generate unique subdomain"""
        if preferred:
            result = await session.execute(
                select(TunnelService).where(TunnelService.subdomain == preferred)
            )
            if not result.scalar_one_or_none():
                return preferred

        # Generate based on port and random suffix
        import random, string
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"port{local_port}-{suffix}"

    async def handle_request(self, request: Request) -> Response:
        """Universal request handler with smart routing"""
        start_time = time.time()

        # Extract subdomain and determine service type
        host = request.headers.get('host', '').split(':')[0]
        subdomain = self._extract_subdomain(host)

        if not subdomain or subdomain not in self.service_configs:
            return await self._handle_server_request(request)

        service_config = self.service_configs[subdomain]

        # Determine connection type and route accordingly
        if self._is_websocket_request(request):
            return await self._handle_websocket_proxy(request, service_config)
        elif self._is_sse_request(request):
            return await self._handle_sse_proxy(request, service_config)
        else:
            return await self._handle_http_proxy(request, service_config, start_time)

    def _is_websocket_request(self, request: Request) -> bool:
        """Universal WebSocket detection"""[3]
        connection = request.headers.get('connection', '').lower()
        upgrade = request.headers.get('upgrade', '').lower()
        return (
            'upgrade' in connection and upgrade == 'websocket' or
            'socket.io' in request.path.lower() or
            any(ws_path in request.path.lower() for ws_path in ['/ws', '/websocket', '/socket'])
        )

    def _is_sse_request(self, request: Request) -> bool:
        """Universal SSE detection"""[5]
        accept = request.headers.get('accept', '').lower()
        return (
            'text/event-stream' in accept or
            any(sse_path in request.path.lower() for sse_path in ['/events', '/stream', '/sse'])
        )

    async def _handle_websocket_proxy(self, request: Request, service_config: dict):
        """Universal WebSocket proxy with framework agnostic handling"""[7]
        ws = WebSocketResponse(heartbeat=30, max_msg_size=100*1024*1024)
        await ws.prepare(request)

        session_id = str(uuid.uuid4())
        client_id = service_config['client_id']

        # Store connection
        self.active_sessions[session_id] = {
            'type': 'websocket',
            'client_id': client_id,
            'service_config': service_config,
            'ws': ws
        }

        # Get custom WebSocket configuration
        ws_config = service_config.get('service_configs', {})
        local_port = service_config['local_port']
        local_host = service_config['local_host']

        # Build local WebSocket URL with custom path
        ws_path = ws_config.get('websocket_path', request.path)
        local_ws_url = f"ws://{local_host}:{local_port}{ws_path}"

        # Notify client to establish connection
        control_ws = self.websocket_connections.get(client_id)
        if control_ws:
            await control_ws.send_str(json.dumps({
                'type': 'websocket_initiate',
                'session_id': session_id,
                'local_url': local_ws_url,
                'headers': dict(request.headers),
                'query_params': dict(request.query)
            }))

        # Relay messages
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    await control_ws.send_str(json.dumps({
                        'type': 'websocket_data',
                        'session_id': session_id,
                        'message_type': 'text',
                        'data': msg.data
                    }))
                elif msg.type == WSMsgType.BINARY:
                    await control_ws.send_str(json.dumps({
                        'type': 'websocket_data',
                        'session_id': session_id,
                        'message_type': 'binary',
                        'data': base64.b64encode(msg.data).decode()
                    }))
        except Exception as e:
            logger.error(f"WebSocket proxy error: {e}")
        finally:
            self.active_sessions.pop(session_id, None)

        return ws

    async def _handle_sse_proxy(self, request: Request, service_config: dict):
        """Universal SSE proxy with custom paths"""[9]
        response = StreamResponse(
            status=200,
            headers={
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*'
            }
        )
        await response.prepare(request)

        session_id = str(uuid.uuid4())
        client_id = service_config['client_id']

        # Store connection
        self.active_sessions[session_id] = {
            'type': 'sse',
            'client_id': client_id,
            'service_config': service_config,
            'response': response
        }

        # Get custom SSE configuration
        sse_config = service_config.get('service_configs', {})
        local_port = service_config['local_port']
        local_host = service_config['local_host']

        # Build local SSE URL with custom path
        sse_path = sse_config.get('sse_path', request.path)
        local_sse_url = f"http://{local_host}:{local_port}{sse_path}"

        # Notify client
        control_ws = self.websocket_connections.get(client_id)
        if control_ws:
            await control_ws.send_str(json.dumps({
                'type': 'sse_initiate',
                'session_id': session_id,
                'local_url': local_sse_url,
                'headers': dict(request.headers)
            }))

        # Keep connection alive
        try:
            while not response.task.done():
                await asyncio.sleep(30)
                await response.write(b': keepalive\n\n')
        except Exception as e:
            logger.error(f"SSE proxy error: {e}")
        finally:
            self.active_sessions.pop(session_id, None)

        return response

    async def _handle_http_proxy(self, request: Request, service_config: dict, start_time: float):
        """Enhanced HTTP proxy with routing support"""[12]
        request_id = str(uuid.uuid4())
        body = await request.read()
        client_id = service_config['client_id']

        # Get custom HTTP configuration
        http_config = service_config.get('service_configs', {})
        local_port = service_config['local_port']
        local_host = service_config['local_host']

        # Handle path routing
        local_path = request.path
        if 'path_mappings' in http_config:
            for mapping in http_config['path_mappings']:
                if request.path.startswith(mapping['public_path']):
                    local_path = request.path.replace(
                        mapping['public_path'],
                        mapping['local_path'], 1
                    )
                    break

        # Build local URL
        local_url = f"http://{local_host}:{local_port}{local_path}"
        if request.query_string:
            local_url += f"?{request.query_string}"

        # Create future for response
        future = asyncio.Future()
        self.pending_requests[request_id] = future

        # Send request to client
        control_ws = self.websocket_connections.get(client_id)
        if control_ws:
            await control_ws.send_str(json.dumps({
                'type': 'http_request',
                'request_id': request_id,
                'method': request.method,
                'local_url': local_url,
                'headers': dict(request.headers),
                'body': base64.b64encode(body).decode() if body else ''
            }))

        try:
            # Wait for response
            response_data = await asyncio.wait_for(future, timeout=30.0)

            # Log request
            duration = (time.time() - start_time) * 1000
            asyncio.create_task(self._log_request(
                service_config['service_id'], request, response_data, duration
            ))

            # Build response
            return web.Response(
                body=base64.b64decode(response_data.get('body', '')),
                status=response_data.get('status', 200),
                headers=response_data.get('headers', {})
            )

        except asyncio.TimeoutError:
            return web.Response(text="Request timeout", status=504)
        finally:
            self.pending_requests.pop(request_id, None)

    async def _log_request(self, service_id: str, request: Request, response_data: dict, duration: float):
        """Log request for analytics"""
        async with self.db.get_session() as session:
            log_entry = RequestLog(
                service_id=service_id,
                method=request.method,
                path=request.path,
                status_code=response_data.get('status', 200),
                response_time=duration,
                bytes_received=len(await request.read()) if hasattr(request, 'read') else 0,
                bytes_sent=len(response_data.get('body', '')),
                remote_ip=request.remote,
                user_agent=request.headers.get('user-agent', '')
            )
            session.add(log_entry)
            await session.commit()

    def _extract_subdomain(self, host: str) -> Optional[str]:
        """Extract subdomain from host"""
        if not host.endswith(self.domain):
            return None
        subdomain_part = host[:-len(self.domain)-1]
        return subdomain_part if subdomain_part else None

    async def _handle_server_request(self, request: Request) -> Response:
        """Handle server management requests"""
        path = request.path.strip('/')

        if path == 'status':
            return await self._status_handler(request)
        elif path == 'ui' or path == '':
            return await self._ui_handler(request)
        elif path.startswith('api/'):
            return await self._api_handler(request)
        else:
            return web.Response(text="Universal Tunnel Server v4.0", status=404)

    async def _status_handler(self, request: Request) -> Response:
        """Enhanced status with database stats"""
        async with self.db.get_session() as session:
            # Get active clients count
            clients_result = await session.execute(
                select(func.count(TunnelClient.id)).where(TunnelClient.is_active == True)
            )
            active_clients = clients_result.scalar()

            # Get active services count
            services_result = await session.execute(
                select(func.count(TunnelService.id)).where(TunnelService.is_active == True)
            )
            active_services = services_result.scalar()

            # Get request stats
            requests_result = await session.execute(
                select(func.count(RequestLog.id))
            )
            total_requests = requests_result.scalar()

            status = {
                'server_status': 'running',
                'version': '4.0',
                'active_clients': active_clients,
                'active_services': active_services,
                'total_requests': total_requests,
                'active_websockets': len([s for s in self.active_sessions.values() if s['type'] == 'websocket']),
                'active_sse': len([s for s in self.active_sessions.values() if s['type'] == 'sse']),
                'features': ['postgresql', 'multi-service', 'universal-proxy', 'web-ui']
            }

            return web.json_response(status)

    async def _ui_handler(self, request: Request) -> Response:
        """Serve web UI"""
        ui_html = await self._generate_ui_html()
        return web.Response(text=ui_html, content_type='text/html')

    async def _generate_ui_html(self) -> str:
        """Generate management UI HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Universal Tunnel Server v4.0</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-center mb-8 text-blue-600">
            🚀 Universal Tunnel Server v4.0
        </h1>

        <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold text-gray-700">Active Clients</h3>
                <p id="active-clients" class="text-3xl font-bold text-blue-600">-</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold text-gray-700">Active Services</h3>
                <p id="active-services" class="text-3xl font-bold text-green-600">-</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold text-gray-700">Total Requests</h3>
                <p id="total-requests" class="text-3xl font-bold text-purple-600">-</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold text-gray-700">Active Connections</h3>
                <p id="active-connections" class="text-3xl font-bold text-red-600">-</p>
            </div>
        </div>

        <!-- Services Table -->
        <div class="bg-white rounded-lg shadow mb-8">
            <div class="px-6 py-4 border-b">
                <h2 class="text-xl font-semibold text-gray-800">Active Services</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Subdomain</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Local Port</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Services</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Requests</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="services-table" class="bg-white divide-y divide-gray-200">
                        <!-- Services will be loaded here -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Charts -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-white rounded-lg shadow p-6" style=" height: 400px;">
                <h3 class="text-lg font-semibold text-gray-700 mb-4">Request Traffic</h3>
                <canvas id="traffic-chart"  height="400"></canvas>
            </div>
            <div class="bg-white rounded-lg shadow p-6" style=" height: 400px;">
                <h3 class="text-lg font-semibold text-gray-700 mb-4">Connection Types</h3>
                <canvas id="connections-chart"  height="400"></canvas>
            </div>
        </div>
    </div>

    <script>
        // Dashboard functionality
        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();

                document.getElementById('active-clients').textContent = data.active_clients;
                document.getElementById('active-services').textContent = data.active_services;
                document.getElementById('total-requests').textContent = data.total_requests;
                document.getElementById('active-connections').textContent =
                    data.active_websockets + data.active_sse;

                loadServicesTable(data.services);
                updateCharts(data);
            } catch (error) {
                console.error('Failed to load stats:', error);
            }
        }

        function loadServicesTable(services) {
            const tbody = document.getElementById('services-table');
            tbody.innerHTML = services.map(service => `
                <tr>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        <a href="https://${service.subdomain}.${window.location.hostname}"
                           target="_blank" class="text-blue-600 hover:underline">
                            ${service.subdomain}
                        </a>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${service.local_port}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        <span class="inline-flex space-x-1">
                            ${service.service_types.map(type =>
                                `<span class="px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">${type}</span>`
                            ).join('')}
                        </span>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${service.request_count || 0}</td>
                    <td class="px-6 py-4 whitespace-nowrap">
                        <span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            service.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                        }">
                            ${service.is_active ? 'Active' : 'Inactive'}
                        </span>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <button onclick="testService('${service.subdomain}')"
                                class="text-blue-600 hover:text-blue-900 mr-3">Test</button>
                        <button onclick="viewLogs('${service.id}')"
                                class="text-green-600 hover:text-green-900">Logs</button>
                    </td>
                </tr>
            `).join('');
        }

        function updateCharts(data) {
            // Traffic chart
            const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
            new Chart(trafficCtx, {
                type: 'line',
                data: {
                    labels: ['1h', '2h', '3h', '4h', '5h', '6h'],
                    datasets: [{
                        label: 'Requests',
                        data: [12, 19, 3, 5, 2, 3],
                        borderColor: 'rgb(59, 130, 246)',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.4
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false }
            });

            // Connections chart
            const connCtx = document.getElementById('connections-chart').getContext('2d');
            new Chart(connCtx, {
                type: 'doughnut',
                data: {
                    labels: ['HTTP', 'WebSocket', 'SSE'],
                    datasets: [{
                        data: [data.total_requests || 0, data.active_websockets || 0, data.active_sse || 0],
                        backgroundColor: ['#3B82F6', '#10B981', '#F59E0B']
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false }
            });
        }

        async function testService(subdomain) {
            try {
                const url = `https://${subdomain}.${window.location.hostname}`;
                const response = await fetch(url);
                alert(`Service test: ${response.status} ${response.statusText}`);
            } catch (error) {
                alert(`Service test failed: ${error.message}`);
            }
        }

        function viewLogs(serviceId) {
            window.open(`/api/logs/${serviceId}`, '_blank');
        }

        // Auto-refresh every 5 seconds
        loadStats();
        setInterval(loadStats, 5000);
    </script>
</body>
</html>
"""

    async def _api_handler(self, request: Request) -> Response:
        """Handle API requests"""
        path = request.path[5:]  # Remove '/api/'

        if path == 'stats':
            return await self._api_stats(request)
        elif path.startswith('logs/'):
            service_id = path[5:]
            return await self._api_logs(request, service_id)
        else:
            return web.json_response({'error': 'Not found'}, status=404)

    async def _api_stats(self, request: Request) -> Response:
        """API endpoint for stats"""
        async with self.db.get_session() as session:
            # Get detailed service information
            services_result = await session.execute(
                select(TunnelService).where(TunnelService.is_active == True)
            )
            services = services_result.scalars().all()

            services_data = []
            for service in services:
                services_data.append({
                    'id': service.id,
                    'subdomain': service.subdomain,
                    'local_port': service.local_port,
                    'service_types': service.service_types,
                    'request_count': service.request_count,
                    'is_active': service.is_active,
                    'detected_framework': service.detected_framework
                })

            return web.json_response({
                'active_clients': len(self.websocket_connections),
                'active_services': len(services),
                'total_requests': sum(s.request_count for s in services),
                'active_websockets': len([s for s in self.active_sessions.values() if s['type'] == 'websocket']),
                'active_sse': len([s for s in self.active_sessions.values() if s['type'] == 'sse']),
                'services': services_data
            })

    async def _api_logs(self, request: Request, service_id: str) -> Response:
        """API endpoint for service logs"""
        async with self.db.get_session() as session:
            logs_result = await session.execute(
                select(RequestLog)
                .where(RequestLog.service_id == service_id)
                .order_by(RequestLog.timestamp.desc())
                .limit(100)
            )
            logs = logs_result.scalars().all()

            logs_data = []
            for log in logs:
                logs_data.append({
                    'timestamp': log.timestamp.isoformat(),
                    'method': log.method,
                    'path': log.path,
                    'status_code': log.status_code,
                    'response_time': log.response_time,
                    'remote_ip': log.remote_ip
                })

            return web.json_response({'logs': logs_data})

    async def _cleanup_client(self, client_id: str):
        """Cleanup client resources"""
        self.websocket_connections.pop(client_id, None)

        # Clean up active sessions
        sessions_to_remove = [
            sid for sid, session in self.active_sessions.items()
            if session['client_id'] == client_id
        ]
        for session_id in sessions_to_remove:
            self.active_sessions.pop(session_id, None)

        # Update database
        async with self.db.get_session() as session:
            await session.execute(
                update(TunnelClient)
                .where(TunnelClient.id == client_id)
                .values(is_active=False)
            )
            await session.commit()

    def setup_routes(self):
        """Setup routes with CORS - FIXED MIDDLEWARE"""
        app = web.Application()

        # FIXED CORS middleware with correct signature
        @web.middleware
        async def cors_middleware(request, handler):
            if request.method == 'OPTIONS':
                response = web.Response()
            else:
                try:
                    response = await handler(request)
                except web.HTTPException as ex:
                    response = web.Response(
                        text=str(ex),
                        status=ex.status,
                        headers={'Content-Type': 'text/plain'}
                    )

            # Add CORS headers
            response.headers.update({
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS',
                'Access-Control-Allow-Headers': '*',
                'Access-Control-Allow-Credentials': 'true',
                'Access-Control-Expose-Headers': '*'
            })
            return response

        app.middlewares.append(cors_middleware)

        # Add specific routes
        app.router.add_get('/ws', self.websocket_handler)
        app.router.add_get('/status', self.status_handler)
        app.router.add_get('/health', self.health_handler)
        app.router.add_get('/metrics', self.metrics_handler)
        app.router.add_get('/favicon.ico', self.favicon_handler)
        app.router.add_get('/robots.txt', self.robots_handler)

        # Add catch-all for all HTTP methods
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD']
        for method in methods:
            app.router.add_route(method, '/{path:.*}', self.handle_request)

        return app


    async def start(self):
        """Start server - FIXED"""
        self.running = True
        app = self.setup_routes()  # This now calls the fixed setup_routes method

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, self.host, self.port)
        await site.start()

        domain = self._normalize_domain(self.domain)
        base_url = f"{self.protocol}://{domain}"
        if self.port not in [80, 443]:
            base_url += f":{self.port}"

        logger.info("🎉 Universal Tunnel Server v3.0 Started!")
        logger.info(f"📡 Listening: {self.host}:{self.port}")
        logger.info(f"🌐 Public Domain: {base_url}")
        logger.info(f"🔗 WebSocket Control: {base_url}/ws")
        logger.info(f"📊 Status: {base_url}/status")
        logger.info(f"✅ Universal Support: WebSocket, SSE, HTTP for ALL frameworks")

        return runner

async def main():
    import argparse
    parser = argparse.ArgumentParser(description='Universal Tunnel Server v4.0')
    parser.add_argument('--host', default=os.getenv('HOST', '0.0.0.0'))
    parser.add_argument('--port', type=int, default=int(os.getenv('PORT', 8080)))
    parser.add_argument('--domain', default=os.getenv('DOMAIN', 'localhost'))
    args = parser.parse_args()

    server = UniversalTunnelServer(args.host, args.port, args.domain)
    runner = None

    try:
        runner = await server.start()
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("👋 Shutting down...")
    finally:
        if runner:
            await runner.cleanup()
        await server.db.close()

if __name__ == '__main__':
    asyncio.run(main())
