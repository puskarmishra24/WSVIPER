import os
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import time
import threading
from websocket import create_connection, WebSocketException, WebSocket
import logging
from base64 import b64encode
import socket
import ssl
import http.client
from urllib.parse import urlparse
from termcolor import colored
import struct
import random
import string
import binascii
import requests
from hashlib import sha1
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def attack_website(websocket_urls):
    """Main function to handle WebSocket attack logic."""
    websocket_payloads = [
    {"name": "Malformed JSON", "payload": '{"type": "invalid_json", "data": "unclosed bracket'},
    {"name": "XSS Attempt", "payload": "<script>alert('XSS')</script>"},
    {"name": "Large Payload for DoS (JSON)", "payload": {"type": "large_payload", "data": "A" * 1000000}},
    {"name": "Invalid Binary Frame", "payload": b"\x00\xFF\xFE\xFD"},
    {"name": "Command Injection Simulation", "payload": {"command": "whoami; ls"}},
    {"name": "SQL Injection Simulation", "payload": {"query": "SELECT * FROM users WHERE id = '1' OR '1'='1'"}},
    {"name": "Expression Evaluation Injection", "payload": "${{7*7}}"},
    {"name": "Null Bytes in JSON String", "payload": b'{"data": "\\0\\0\\0"}'},
    {"name": "Unicode Characters in Payload", "payload": {"data": "🚀🌟💥"}},
    {"name": "Oversized DoS Message (JSON)", "payload": {"message": "B" * 2000000}},
    {"name": "Path Traversal Simulation", "payload": {"path": "/../../etc/passwd"}},
    {"name": "PostMessage Abuse Simulation", "payload": {"message": "window.postMessage('malicious','*')"}}
]
    print(colored("Starting WebSocket tests...", "yellow"))
    vulnerabilities = perform_websocket_tests(websocket_urls, websocket_payloads)
    return vulnerabilities

def send_raw_handshake(host, port, request_headers, scheme="ws", timeout=10):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        if scheme == "wss":
            ssl_context = ssl.create_default_context()
            s = ssl_context.wrap_socket(s, server_hostname=host)

        s.connect((host, port))
        s.send(request_headers.encode())

        response = b""
        while b"\r\n\r\n" not in response:
            try:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break

        # Truncate response after header
        header_end = response.find(b"\r\n\r\n")
        if header_end != -1:
            response = response[:header_end + 4]  # Include the \r\n\r\n

        
        return response.decode(errors="ignore")

    except Exception as e:
        logging.info(f"Handshake failed for {host}:{port}: {e}")
        return None
    finally:
        try:
            s.close()
        except:
            pass

def test_working_websocket(url_list):
    """Ensure invalid websockets are not being tested on."""
    cleaned_urls = []
    for url in url_list:
        # 1. Remove everything after an angle bracket (`<`, `>`)
        url = re.split(r'[<>]', url)[0]
        url = re.sub(r'&lt;|&gt;|&amp;', '', url)
        # 2. Remove trailing HTML-like fragments such as `</code>`, `<span`, etc.
        url = re.sub(r'</?\w+[^>]*>', '', url)
        url = url.split('?')[0]
        # 3. Remove everything after unexpected trailing characters like `,` or stray quotes
        url = re.split(r'[,"\')\]]', url)[0]

        # 4. Remove whitespace from beginning and end
        url = url.strip()

        # 5. Remove trailing slash
        if url.endswith('/'):
            url = url[:-1]

        # 6. Validate WebSocket URL format (must start with ws:// or wss:// and have at least host)
        if re.match(r'^wss?://[^/\s]+(?:/[^\s]*)?$', url):
            cleaned_urls.append(url)

    # Remove duplicates
    unique_urls = list(set(cleaned_urls))

    return unique_urls

def send_custom_frame(ws_url, frame_data):
    """Send a custom WebSocket frame (binary) and return the server's response."""
    try:
        ws = WebSocket()
        ws.connect(ws_url, timeout=5)

        ws.send_binary(frame_data)
        response = ws.recv()

        ws.close()
        return response

    except WebSocketException as e:
        return None

    except Exception as e:
        print(colored(f"[EXCEPTION] Unexpected error for {ws_url}: {e}", "red"))
        return None

def test_origin_check(ws_url):
    """Test for missing or weak origin checks."""
    try:
        ws = WebSocket()
        ws.connect(ws_url, origin="http://malicious-site.com", timeout=5)
        ws.send("ping")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Missing Origin Check',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts connections from unauthorized origin 'http://malicious-site.com'.",
            'solution': 'Implement strict Origin header validation (whitelist allowed domains).',
            'affected_url': ws_url,
            'impact': 'Allows cross-origin attacks, potentially leading to data theft or session hijacking.'
        }
    except WebSocketException as e:
        logging.info(f"Origin check test for {ws_url}: {e}")
        return {'name':'Missing Origin Check','risk':'No'}

def test_authentication(ws_url):
    """Test for missing or weak authentication."""
    try:
        ws = WebSocket()
        ws.connect(ws_url, timeout=5)
        ws.send("whoami")
        response = ws.recv()
        ws.close()
        if response and len(response) > 0:
            return {
                'name': 'Missing Authentication',
                'risk': 'High',
                'description': f"WebSocket at {ws_url} allows unauthenticated connections and responds with data.",
                'solution': 'Require authentication (e.g., JWT, API keys) for WebSocket connections.',
                'affected_url': ws_url,
                'impact': 'Unauthorized access to sensitive data or functionality.'
            }
        return {'name':'Missing Authentication','risk':'No'}
    except WebSocketException as e:
        return {'name':'Missing Authentication','risk':'No'}

def test_fuzzing(ws_url, payload, name):
    """Perform protocol fuzzing with payloads."""
    try:
        ws = WebSocket()
        ws.connect(ws_url, timeout=5)

        if isinstance(payload, dict):
            payload = json.dumps(payload)
        elif isinstance(payload, bytes):
            pass  # send raw
        else:
            payload = str(payload)

        ws.send(payload)

        try:
            response = ws.recv()
            ws.close()
            if response:
                return {
                    'name': 'Protocol Fuzzing',
                    'risk': 'Medium',
                    'description': f"WebSocket at {ws_url} responded to malformed payload type: {name}.",
                    'solution': 'Implement robust input validation and reject malformed messages.',
                    'affected_url': ws_url,
                    'impact': 'Malformed messages may lead to unsafe behavior or data leaks.'
                }
            else:
                return {
                    'name': 'Protocol Fuzzing',
                    'risk': 'No'
                }
        except WebSocketException:
            ws.close()
            return {
                'name': 'Protocol Fuzzing',
                'risk': 'Low',
                'description': f"WebSocket at {ws_url} closed connection on malformed payload: {name}.",
                'solution': 'Ensure server logs and rejects invalid frames correctly.',
                'affected_url': ws_url,
                'impact': 'Likely a safe defensive measure, but review logs to confirm.'
            }
    except (WebSocketException, ConnectionError, OSError, ssl.SSLError, socket.error):
        # Connection could not be established or was reset by the server.
        return {
            'name': 'Protocol Fuzzing',
            'risk': 'No'
        }
    except Exception:
        return {
            'name': 'Protocol Fuzzing',
            'risk': 'No'
        }
  
def test_omit_sec_websocket_key(host, port, path="/", scheme="ws"):
    """Test omitting Sec-WebSocket-Key header (Vuln #3)."""
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Omit Sec-WebSocket-Key', 'risk': 'No'}
        return {
            'name': 'Omit Sec-WebSocket-Key',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake without Sec-WebSocket-Key.",
            'solution': 'Require Sec-WebSocket-Key header for WebSocket handshake.',
            'affected_host': f"{host}:{port}",
            'impact': 'Bypassing handshake validation can allow unauthorized connections.'
        } if response and "101 Switching Protocols" in response else {'name': 'Omit Sec-WebSocket-Key', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_omit_sec_websocket_key for {host}:{port}: {e}")
        return {'name': 'Omit Sec-WebSocket-Key', 'risk': 'No'}
    
def test_non_base64_sec_websocket_key(host, port, path="/", scheme="ws"):
    """Test non-base64 Sec-WebSocket-Key header (Vuln #2)."""
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: NotBase64!!\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme=scheme)
        if response is None:
            return {'name': 'Non-Base64 Sec-WebSocket-Key', 'risk': 'No'}
        return {
            'name': 'Non-Base64 Sec-WebSocket-Key',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted non-base64 Sec-WebSocket-Key.",
            'solution': 'Validate Sec-WebSocket-Key as base64-encoded.',
            'affected_host': f"{host}:{port}",
            'impact': 'Improper key validation can lead to handshake vulnerabilities.'
        } if response and "101 Switching Protocols" in response else {'name': 'Non-Base64 Sec-WebSocket-Key', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_non_base64_sec_websocket_key for {host}:{port}: {e}")
        return {'name': 'Non-Base64 Sec-WebSocket-Key', 'risk': 'No'}
    
def test_oversized_sec_websocket_key(host, port, path="/", scheme="ws"):
    """Test oversized Sec-WebSocket-Key header (Vuln #3)."""
    big_key = b64encode(b"A" * 1024).decode()  # 1KB key
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {big_key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Oversized Sec-WebSocket-Key', 'risk': 'No'}
        return {
            'name': 'Oversized Sec-WebSocket-Key',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted oversized Sec-WebSocket-Key (1KB).",
            'solution': 'Limit Sec-WebSocket-Key size to prevent resource exhaustion.',
            'affected_host': f"{host}:{port}",
            'impact': 'Large keys can cause server resource exhaustion.'
        } if "101 Switching Protocols" in response else {'name': 'Oversized Sec-WebSocket-Key', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_oversized_sec_websocket_key for {host}:{port}: {e}")
        return {'name': 'Oversized Sec-WebSocket-Key', 'risk': 'No'}
    
def test_duplicate_sec_websocket_key(host, port, path="/", scheme="ws"):
    """Test duplicate Sec-WebSocket-Key headers (Vuln #4)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    f"Sec-WebSocket-Key: {key}duplicate\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Duplicate Sec-WebSocket-Key', 'risk': 'No'}
        
        return {
            'name': 'Duplicate Sec-WebSocket-Key',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted duplicate Sec-WebSocket-Key headers.",
            'solution': 'Reject requests with multiple Sec-WebSocket-Key headers.',
            'affected_host': f"{host}:{port}",
            'impact': 'Duplicate headers can confuse handshake processing.'
        } if "101 Switching Protocols" in response else {'name': 'Duplicate Sec-WebSocket-Key', 'risk': 'No'}
    
    except Exception as e:
        logging.info(f"Error in test_duplicate_sec_websocket_key for {host}:{port}: {e}")
        return {'name': 'Duplicate Sec-WebSocket-Key', 'risk': 'No'}
   
def test_missing_sec_websocket_version(host, port, path="/", scheme="ws"):
    """Test missing Sec-WebSocket-Version header (Vuln #5)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Missing Sec-WebSocket-Version', 'risk': 'No'}
        return {
            'name': 'Missing Sec-WebSocket-Version',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake without Sec-WebSocket-Version.",
            'solution': 'Require Sec-WebSocket-Version header for WebSocket handshake.',
            'affected_host': f"{host}:{port}",
            'impact': 'Missing version header can allow incompatible connections.'
        } if "101 Switching Protocols" in response else {'name': 'Missing Sec-WebSocket-Version', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_missing_sec_websocket_version for {host}:{port}: {e}")
        return {'name': 'Missing Sec-WebSocket-Version', 'risk': 'No'}
    
def test_invalid_sec_websocket_version(host, port, path="/", scheme="ws"):
    """Test invalid Sec-WebSocket-Version header (Vuln #6)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 999\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Invalid Sec-WebSocket-Version', 'risk': 'No'}
        return {
            'name': 'Invalid Sec-WebSocket-Version',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted invalid Sec-WebSocket-Version.",
            'solution': 'Validate Sec-WebSocket-Version (e.g., 13) for WebSocket handshake.',
            'affected_host': f"{host}:{port}",
            'impact': 'Invalid versions can lead to protocol mismatches.'
        } if "101 Switching Protocols" in response else {'name': 'Invalid Sec-WebSocket-Version', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_invalid_sec_websocket_version for {host}:{port}: {e}")
        return {'name': 'Invalid Sec-WebSocket-Version', 'risk': 'No'}
    
def test_conflicting_sec_websocket_version(host, port, path="/", scheme="ws"):
    """Test conflicting Sec-WebSocket-Version headers (Vuln #7)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Version: 8\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Conflicting Sec-WebSocket-Version', 'risk': 'No'}
        return {
            'name': 'Conflicting Sec-WebSocket-Version',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted conflicting Sec-WebSocket-Version headers.",
            'solution': 'Reject requests with multiple Sec-WebSocket-Version headers.',
            'affected_host': f"{host}:{port}",
            'impact': 'Conflicting versions can cause protocol errors.'
        } if "101 Switching Protocols" in response else {'name': 'Conflicting Sec-WebSocket-Version', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_conflicting_sec_websocket_version for {host}:{port}: {e}")
        return {'name': 'Conflicting Sec-WebSocket-Version', 'risk': 'No'}

def test_wrong_upgrade_header(host, port, path="/", scheme="ws"):
    """Test wrong Upgrade header (Vuln #8)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocketty\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Wrong Upgrade Header', 'risk': 'No'}
        return {
            'name': 'Wrong Upgrade Header',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake with wrong Upgrade header.",
            'solution': 'Enforce strict Upgrade header validation.',
            'affected_host': f"{host}:{port}",
            'impact': 'Incorrect headers can bypass protocol validation.'
        } if "101 Switching Protocols" in response else {'name': 'Wrong Upgrade Header', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_wrong_upgrade_header for {host}:{port}: {e}")
        return {'name': 'Wrong Upgrade Header', 'risk': 'No'}

def test_missing_connection_header(host, port, path="/", scheme="ws"):
    """Test missing Connection header (Vuln #9)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Missing Connection Header', 'risk': 'No'}
        return {
            'name': 'Missing Connection Header',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake without Connection header.",
            'solution': 'Require Connection: Upgrade header for security.',
            'affected_host': f"{host}:{port}",
            'impact': 'Missing headers can allow improper connections.'
        } if "101 Switching Protocols" in response else {'name': 'Missing Connection Header', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_missing_connection_header for {host}:{port}: {e}")
        return {'name': 'Missing Connection Header', 'risk': 'No'}

def test_case_sensitive_headers(host, port, path="/", scheme="ws"):
    """Test case-sensitive headers (Vuln #10)."""
    key = b64encode(b"1234567890123456").decode()
    req = f"""GET {path} HTTP/1.1\r\n
Host: {host}\r\n
uPgradE: websocket\r\n
cOnneCtion: Upgrade\r\n
sEc-websocKet-key: {key}\r\n
Sec-WebSocket-Version: 13\r\n
\r\n"""
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "uPgradE: websocket\r\n"
    "cOnneCtion: Upgrade\r\n"
    f"sEc-websocKet-key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Case-Sensitive Headers', 'risk': 'No'}
        return {
            'name': 'Case-Sensitive Headers',
            'risk': 'Low',
            'description': f"Server at {host}:{port} accepted case-sensitive headers.",
            'solution': 'Ensure case-insensitive header parsing as per RFC.',
            'affected_host': f"{host}:{port}",
            'impact': 'Inconsistent header parsing can lead to security bypasses.'
        } if "101 Switching Protocols" in response else {'name': 'Case-Sensitive Headers', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_case_sensitive_headers for {host}:{port}: {e}")
        return {'name': 'Case-Sensitive Headers', 'risk': 'No'}

def test_non_get_method(host, port, path="/", scheme="ws"):
    """Test non-GET method for handshake (Vuln #11)."""
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"POST {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Non-GET Method', 'risk': 'No'}
        return {
            'name': 'Non-GET Method',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted non-GET method (POST) for handshake.",
            'solution': 'Restrict WebSocket handshakes to GET method.',
            'affected_host': f"{host}:{port}",
            'impact': 'Non-GET methods can bypass standard handshake validation.'
        } if "101 Switching Protocols" in response else {'name': 'Non-GET Method', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_non_get_method for {host}:{port}: {e}")
        return {'name': 'Non-GET Method', 'risk': 'No'}

def test_fake_http_status(host, port, path="/", scheme="ws"):
    """Test fake HTTP status code (Vuln #12)."""
    key = b64encode(b"1234567890123456").decode()

    # Proper WebSocket handshake
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )

    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Fake HTTP Status', 'risk': 'No'}

        # Extract the first status line from the response
        status_line = response.split("\r\n", 1)[0].strip()

        if status_line != "HTTP/1.1 101 Switching Protocols":
            return {
                'name': 'Fake HTTP Status',
                'risk': 'High',
                'description': f"Server at {host}:{port} returned unexpected status: {status_line}",
                'solution': 'Ensure server returns "HTTP/1.1 101 Switching Protocols" for valid handshakes.',
                'affected_host': f"{host}:{port}",
                'impact': 'Clients may be tricked into accepting invalid upgrades or downgrade attacks.'
            }

        # Server responded correctly — no issue
        return {'name': 'Fake HTTP Status', 'risk': 'No'}

    except Exception as e:
        logging.info(f"Error in test_fake_http_status for {host}:{port}: {e}")
        return {'name': 'Fake HTTP Status', 'risk': 'No'}

    
def test_wrong_sec_websocket_accept(host, port, path="/", scheme="ws"):
    """Test wrong Sec-WebSocket-Accept value from server (Vuln #13)."""

    key = b64encode(b"1234567890123456").decode()

    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Wrong Sec-WebSocket-Accept', 'risk': 'No'}

        # Parse response headers
        lines = response.split("\r\n")
        accept_header = [line.strip() for line in lines if line.lower().startswith("sec-websocket-accept:")]

        if not accept_header:
            return {
                'name': 'Wrong Sec-WebSocket-Accept',
                'risk': 'Medium',
                'description': f"Server at {host}:{port} did not return a Sec-WebSocket-Accept header.",
                'solution': 'Ensure server follows RFC 6455 and sends correct Sec-WebSocket-Accept header.',
                'affected_host': f"{host}:{port}",
                'impact': 'Clients may accept invalid or spoofed handshakes.'
            }

        server_accept = accept_header[0].split(":", 1)[1].strip()

        # Compute expected Sec-WebSocket-Accept value
        GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        expected_accept = b64encode(sha1((key + GUID).encode()).digest()).decode()

        if server_accept != expected_accept:
            return {
                'name': 'Wrong Sec-WebSocket-Accept',
                'risk': 'Medium',
                'description': f"Server at {host}:{port} returned invalid Sec-WebSocket-Accept: {server_accept}",
                'solution': 'Fix server to generate correct Sec-WebSocket-Accept header as per RFC 6455.',
                'affected_host': f"{host}:{port}",
                'impact': 'Clients may accept spoofed or malformed handshakes, risking data leakage.'
            }

        # All good — no issue found
        return {'name': 'Wrong Sec-WebSocket-Accept', 'risk': 'No'}

    except Exception as e:
        logging.info(f"Error in test_wrong_sec_websocket_accept for {host}:{port}: {e}")
        return {'name': 'Wrong Sec-WebSocket-Accept', 'risk': 'No'}

    
def test_oversized_headers(host, port, path="/", scheme="ws"):
    """Test oversized headers (Vuln #14)."""
    big_value = "A" * 8000
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    f"X-Big-Header: {big_value}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Oversized Headers', 'risk': 'No'}
        return {
            'name': 'Oversized Headers',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted handshake with oversized headers.",
            'solution': 'Set limits for header size to prevent resource exhaustion.',
            'affected_host': f"{host}:{port}",
            'impact': 'Oversized headers can cause denial-of-service attacks.'
        } if "101 Switching Protocols" in response else {'name': 'Oversized Headers', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_oversized_headers for {host}:{port}: {e}")
        return {'name': 'Oversized Headers', 'risk': 'No'}
    
def test_missing_host_header(host, port, path="/", scheme="ws"):
    """Test missing Host header (Vuln #15)."""
    key = b64encode(b"1234567890123456").decode()
    req = (
    f"GET {path} HTTP/1.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Missing Host Header', 'risk': 'No'}
        return {
            'name': 'Missing Host Header',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake without Host header.",
            'solution': 'Enforce Host header validation.',
            'affected_host': f"{host}:{port}",
            'impact': 'Missing Host header can allow domain spoofing.'
        } if "101 Switching Protocols" in response else {'name': 'Missing Host Header', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_missing_host_header for {host}:{port}: {e}")
        return {'name': 'Missing Host Header', 'risk': 'No'}

def test_fake_host_header(host, port, path="/", scheme="ws"):
    """Test fake Host header (Vuln #16)."""
    key = b64encode(b"1234567890123456").decode()
    req = (
    f"GET {path} HTTP/1.1\r\n"
    "Host: fake.example.com\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Fake Host Header', 'risk': 'No'}
        return {
            'name': 'Fake Host Header',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake with incorrect Host header.",
            'solution': 'Validate Host header to match expected server domain.',
            'affected_host': f"{host}:{port}",
            'impact': 'Fake Host headers can enable domain spoofing attacks.'
        } if "101 Switching Protocols" in response else {'name': 'Fake Host Header', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_fake_host_header for {host}:{port}: {e}")
        return {'name': 'Fake Host Header', 'risk': 'No'}

def test_multiple_host_headers(host, port, path="/", scheme="ws"):
    """Test multiple Host headers (Vuln #17)."""
    key = b64encode(b"1234567890123456").decode()
    req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: real.example.com\r\n"
    f"Host: fake.example.com\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Multiple Host Headers', 'risk': 'No'}
        return {
            'name': 'Multiple Host Headers',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted handshake with multiple Host headers.",
            'solution': 'Reject requests with duplicate Host headers.',
            'affected_host': f"{host}:{port}",
            'impact': 'Multiple Host headers can confuse server routing.'
        } if "101 Switching Protocols" in response else {'name': 'Multiple Host Headers', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_multiple_host_headers for {host}:{port}: {e}")
        return {'name': 'Multiple Host Headers', 'risk': 'No'}

def test_long_url_path(host, port, path="/", scheme="ws"):
    """Test long URL path (Vuln #18)."""
    long_path = "/" + "a" * 2048
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {long_path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Long URL Path', 'risk': 'No'}
        return {
            'name': 'Long URL Path',
            'risk': 'Low',
            'description': f"Server at {host}:{port} accepted handshake with long URL path (2KB).",
            'solution': 'Limit URL path length to prevent resource exhaustion.',
            'affected_host': f"{host}:{port}",
            'impact': 'Long URLs can cause server overload or crashes.'
        } if "101 Switching Protocols" in response else {'name': 'Long URL Path', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_long_url_path for {host}:{port}: {e}")
        return {'name': 'Long URL Path', 'risk': 'No'}

def test_unicode_url(host, port, path="/", scheme="ws"):
    """Test Unicode URL (Vuln #19)."""
    unicode_path = "/%F0%9F%98%80"  # Smiling emoji
    key = b64encode(b"1234567890123456").decode()
    
    req = (
    f"GET {unicode_path} HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
    try:
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'Unicode URL', 'risk': 'No'}
        return {
            'name': 'Unicode URL',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted handshake with Unicode URL.",
            'solution': 'Sanitize and validate URL paths to handle Unicode correctly.',
            'affected_host': f"{host}:{port}",
            'impact': 'Improper Unicode handling can lead to parsing errors or bypasses.'
        } if "101 Switching Protocols" in response else {'name': 'Unicode URL', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_unicode_url for {host}:{port}: {e}")
        return {'name': 'Unicode URL', 'risk': 'No'}

def test_http_0_9_handshake(host, port, path="/", scheme="ws"):
    """Test HTTP/0.9 handshake (Vuln #20)."""
    req = f"""GET {path}\r\n"""
    try:
        # HTTP/0.9 doesn't use headers
        response = send_raw_handshake(host, port, req, scheme)
        if response is None:
            return {'name': 'HTTP/0.9 Handshake', 'risk': 'No'}
        return {
            'name': 'HTTP/0.9 Handshake',
            'risk': 'High',
            'description': f"Server at {host}:{port} accepted HTTP/0.9 handshake.",
            'solution': 'Require HTTP/1.1 or higher for WebSocket handshakes.',
            'affected_host': f"{host}:{port}",
            'impact': 'HTTP/0.9 lacks headers, enabling downgrade attacks.'
        } if "101 Switching Protocols" in response else {'name': 'HTTP/0.9 Handshake', 'risk': 'No'}
    except Exception as e:
        logging.info(f"Error in test_http_0_9_handshake for {host}:{port}: {e}")
        return {'name': 'HTTP/0.9 Handshake', 'risk': 'No'}
    

def test_invalid_port(ws_url):
    """Test if WebSocket properly rejects connections on invalid ports (Vuln #21)."""
    try:
        parsed_url = urlparse(ws_url)
        invalid_port_url = f"{parsed_url.scheme}://{parsed_url.hostname}:99999{parsed_url.path}"

        # Attempt to connect to an invalid port — this should raise an error
        ws = WebSocket()
        ws.connect(invalid_port_url, timeout=5)
        ws.close()

        # If it connects successfully, that's suspicious
        return {
            'name': 'Invalid Port',
            'risk': 'Medium',
            'description': f"WebSocket accepted connection on invalid port 99999 at {invalid_port_url}.",
            'solution': 'Ensure server validates port numbers and rejects those outside the 0–65535 range.',
            'affected_url': invalid_port_url,
            'impact': 'Invalid port acceptance can indicate improper input validation and may cause undefined behavior.'
        }

    except Exception as e:
        return {'name':'Invalid Port','risk':'No'}
    
def test_non_ws_scheme(ws_url):
    """Test if WebSocket accepts non-WebSocket schemes (Vuln #22)."""
    try:
        parsed_url = urlparse(ws_url)
        # Check if the scheme is invalid (not ws:// or wss://)
        if parsed_url.scheme not in ['ws', 'wss']:
            return {
                'name': 'Non-WebSocket Scheme',
                'risk': 'High',
                'description': f"WebSocket URL {ws_url} could be accessed with a non-WebSocket scheme 'http', which should be rejected by the server.",
                'solution': 'Reject connections with non-WebSocket schemes (only allow ws:// or wss://).',
                'affected_url': ws_url,
                'impact': 'Non-WebSocket schemes can lead to protocol misuse if not handled properly.'
            }
        # If the scheme is valid, this test isn't applicable
        return {'name': 'Non-WS Scheme', 'risk': 'No'}
    except Exception as e:
        return {'name': 'Non-WS Scheme', 'risk': 'No'}

def test_undefined_opcode(ws_url):
    """Test undefined opcode (Vuln #23)."""
    try:
        payload = b"test"
        payload_len = len(payload)

        # Create masking key (4 bytes)
        masking_key = os.urandom(4)

        # Mask the payload
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        # Build frame with undefined opcode 0x3 (binary + 1)
        fin_opcode = 0x80 | 0x3  # FIN=1, Opcode=0x3
        mask_len = 0x80 | payload_len  # MASK=1, payload length

        frame = struct.pack("!BB", fin_opcode, mask_len) + masking_key + masked_payload

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Undefined Opcode',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepted frame with undefined opcode 0x3.",
            'solution': 'Reject frames with undefined opcodes.',
            'affected_url': ws_url,
            'impact': 'Undefined opcodes can cause unexpected server behavior.'
        } if response else {'name': 'Undefined Opcode', 'risk': 'No'}

    except Exception as e:
        # You could log e here if needed
        return {'name': 'Undefined Opcode', 'risk': 'No'}
    
def test_reserved_opcode(ws_url):
    """Test reserved opcode (Vuln #24)."""
    try:
        payload = b"test"
        payload_len = len(payload)

        # Generate 4-byte masking key
        masking_key = os.urandom(4)

        # Apply masking
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        # FIN = 1, opcode = 0xB (reserved)
        fin_opcode = 0x80 | 0x0B
        mask_payload_len = 0x80 | payload_len  # MASK bit set + length

        # Full frame: [header][masking key][masked payload]
        frame = struct.pack("!BB", fin_opcode, mask_payload_len) + masking_key + masked_payload

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Reserved Opcode',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepted frame with reserved opcode 0xB.",
            'solution': 'Reject frames with reserved opcodes (0x3-0x7, 0xB-0xF).',
            'affected_url': ws_url,
            'impact': 'Reserved opcodes can lead to protocol errors.'
        } if response else {'name': 'Reserved Opcode', 'risk': 'No'}

    except Exception as e:
        return {'name': 'Reserved Opcode', 'risk': 'No'}
  
def test_zero_length_fragment(ws_url):
    """Test zero-length fragments (Vuln #25)."""
    try:
        # Prepare a list of zero-length FIN=0 fragments with opcode=0x1 (text)
        # All frames are masked and follow RFC6455

        results = []
        for _ in range(3):  # Send 3 zero-length fragments
            fin_opcode = 0x01  # FIN=0, Opcode=0x1 (text frame)
            mask_len = 0x80 | 0x00  # MASK=1, Payload len = 0
            masking_key = os.urandom(4)
            frame = struct.pack("!BB", fin_opcode, mask_len) + masking_key

            response = send_custom_frame(ws_url, frame)
            results.append(response)

            time.sleep(0.5)  # Give server time to process/buffer

        if any(results):
            return {
                'name': 'Zero-Length Fragment',
                'risk': 'Low',
                'description': f"WebSocket at {ws_url} accepted zero-length fragments and responded unexpectedly.",
                'solution': 'Reject or limit incomplete fragmented messages.',
                'affected_url': ws_url,
                'impact': 'Zero-length fragments can cause server confusion or buffer exhaustion.'
            }

        # If server gave no response to any zero-length fragment, it likely handled it safely
        return {'name': 'Zero-Length Fragment', 'risk': 'No'}

    except Exception:
        return {'name': 'Zero-Length Fragment', 'risk': 'No'}
    
def test_invalid_payload_length(ws_url):
    """Test invalid payload length (Vuln #26)."""
    try:
        payload = b"test"  # 4 bytes only
        fake_len = 10  # Declare 10 bytes
        masking_key = os.urandom(4)

        # Mask only 4 bytes of data
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        # FIN=1, Opcode=0x1 (text); MASK=1, PayloadLen=10
        fin_opcode = 0x81
        mask_payload_len = 0x80 | fake_len

        frame = struct.pack("!BB", fin_opcode, mask_payload_len) + masking_key + masked_payload

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Invalid Payload Length',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepted frame with declared payload length 10 but sent only 4 bytes.",
            'solution': 'Validate payload length matches actual data.',
            'affected_url': ws_url,
            'impact': 'Invalid lengths can cause buffer overflows or crashes.'
        } if response else {'name': 'Invalid Payload Length', 'risk': 'No'}

    except Exception:
        return {'name': 'Invalid Payload Length', 'risk': 'No'}

def test_negative_payload_length(ws_url):
    """Test forged negative payload length (Vuln #27)."""
    try:
        payload = b"test"
        masking_key = os.urandom(4)
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        fin_opcode = 0x81  # FIN=1, text
        payload_len = 127  # 127 means: next 8 bytes is extended length (64-bit)

        # Forge extended payload length: set MSB to simulate "negative" in signed logic
        # Example: 0x8000000000000001
        forged_len_bytes = struct.pack("!Q", 0x8000000000000001)

        frame = (
            struct.pack("!BB", fin_opcode, 0xFF) +  # 0xFF = 127
            forged_len_bytes +
            masking_key +
            masked_payload
        )

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Negative Payload Length',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepted forged extended payload length (0x8000000000000001).",
            'solution': 'Validate payload length fields and reject extreme or invalid values.',
            'affected_url': ws_url,
            'impact': 'Signed overflows in length handling can lead to crashes or memory corruption.'
        } if response else {'name': 'Negative Payload Length', 'risk': 'No'}

    except Exception:
        return {'name': 'Negative Payload Length', 'risk': 'No'}


def test_mismatched_payload(ws_url):
    """Test mismatched payload (Vuln #28)."""
    try:
        # 🧪 Test 1: Declared length = 4, sent 8 bytes
        declared_len = 4
        actual_payload = b"testtest"  # 8 bytes
        masking_key_1 = os.urandom(4)
        masked_payload_1 = bytes(b ^ masking_key_1[i % 4] for i, b in enumerate(actual_payload))
        frame1 = (
            struct.pack("!BB", 0x81, 0x80 | declared_len) +  # FIN=1, text; MASK=1
            masking_key_1 +
            masked_payload_1
        )
        response1 = send_custom_frame(ws_url, frame1)
        
        if response1:
            return {
                'name': 'Mismatched Payload',
                'risk': 'Medium',
                'description': f"WebSocket at {ws_url} accepted frames with mismatched lengths.",
                'solution': 'Ensure payload lengths match.',
                'affected_url': ws_url,
                'impact': 'Can lead to parsing errors, decoder crashes, or type confusion.'
            }

        return {'name': 'Mismatched Payload', 'risk': 'No'}

    except Exception:
        return {'name': 'Mismatched Payload', 'risk': 'No'}


def test_invalid_masking_key(ws_url):
    """Test invalid masking key variations (Vuln #29)."""
    try:
        payload = b"test"
        responses = []

        test_keys = {
            "All-zero": b"\x00\x00\x00\x00",
            "Repeating FF": b"\xFF\xFF\xFF\xFF",
            "Too short (3 bytes)": b"\x01\x02\x03",
            "Too long (5 bytes)": b"\x01\x02\x03\x04\x05"
        }

        for label, key in test_keys.items():
            # XOR masking — truncate or repeat key if needed
            masked_payload = bytes(p ^ key[i % len(key)] for i, p in enumerate(payload))

            fin_opcode = 0x81  # FIN=1, text frame
            mask_payload_len = 0x80 | len(payload)  # MASK=1, length=4

            frame = (
                struct.pack("!BB", fin_opcode, mask_payload_len) +
                key +
                masked_payload
            )

            response = send_custom_frame(ws_url, frame)
            responses.append((label, response))

        for label, resp in responses:
            if resp:
                return {
                    'name': 'Invalid Masking Key',
                    'risk': 'High',
                    'description': f"WebSocket at {ws_url} accepted a frame with invalid masking key pattern: {label}.",
                    'solution': 'Enforce strict validation of client masking keys per RFC 6455.',
                    'affected_url': ws_url,
                    'impact': 'Improper masking validation may cause data integrity issues or security flaws.'
                }

        return {'name': 'Invalid Masking Key', 'risk': 'No'}

    except Exception:
        return {'name': 'Invalid Masking Key', 'risk': 'No'}


def test_unmasked_client_frame(ws_url):
    """Test unmasked client frame (Vuln #30)."""
    try:
        payload = b"test"
        fin_opcode = 0x81  # FIN=1, text frame
        payload_len = len(payload)
        mask_bit_off = payload_len  # MASK=0

        frame = struct.pack("!BB", fin_opcode, mask_bit_off) + payload

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Unmasked Client Frame',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepted an unmasked client frame.",
            'solution': 'Require masking for all client-to-server frames per RFC 6455.',
            'affected_url': ws_url,
            'impact': 'Unmasked frames can be intercepted or misused in shared environments.'
        } if response else {'name': 'Unmasked Client Frame', 'risk': 'No'}

    except Exception:
        return {'name': 'Unmasked Client Frame', 'risk': 'No'}


def test_invalid_rsv_bits(ws_url):
    """Test invalid RSV bits (Vuln #31)."""
    try:
        payload = b"test"
        masked_payload = None
        masking_key = os.urandom(4)
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        results = []

        rsv_labels = {
            "RSV1": 0x40,
            "RSV2": 0x20,
            "RSV3": 0x10
        }

        for label, bit in rsv_labels.items():
            fin_opcode = 0x80 | bit | 0x1  # FIN=1, RSVx=1, Opcode=0x1 (text)
            payload_len = 0x80 | len(payload)  # MASK=1 + 4 bytes

            frame = (
                struct.pack("!BB", fin_opcode, payload_len) +
                masking_key +
                masked_payload
            )

            response = send_custom_frame(ws_url, frame)
            results.append((label, response))

        for label, resp in results:
            if resp:
                return {
                    'name': 'Invalid RSV Bits',
                    'risk': 'Medium',
                    'description': f"WebSocket at {ws_url} accepted a frame with invalid {label} bit set.",
                    'solution': 'Reject non-zero RSV bits unless explicitly negotiated via extension.',
                    'affected_url': ws_url,
                    'impact': 'May trigger unintended behaviors, desyncs, or extension misinterpretation.'
                }

        return {'name': 'Invalid RSV Bits', 'risk': 'No'}

    except Exception:
        return {'name': 'Invalid RSV Bits', 'risk': 'No'}


def test_oversized_control_frame(ws_url):
    """Test oversized control frame (Vuln #32)."""
    try:
        payload = b"A" * 126  # 1 byte over limit
        masking_key = os.urandom(4)
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        fin_opcode = 0x89  # FIN=1, Opcode=0x9 (ping)
        # Payload len = 126, so use extended 2-byte length + MASK=1
        frame = (
            struct.pack("!BBH", fin_opcode, 0xFE, 126) +  # 0xFE = MASK=1 + payload len=126
            masking_key +
            masked_payload
        )

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Oversized Control Frame',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} accepted a ping control frame with 126-byte payload.",
            'solution': 'Reject control frames larger than 125 bytes as per RFC 6455.',
            'affected_url': ws_url,
            'impact': 'Oversized control frames can crash or desync the server.'
        } if response else {'name': 'Oversized Control Frame', 'risk': 'No'}

    except Exception:
        return {'name': 'Oversized Control Frame', 'risk': 'No'}


def test_non_utf8_text(ws_url):
    """Test non-UTF-8 payload in text frame (Vuln #33)."""
    try:
        invalid_utf8 = b"\xFF\xFF"  # clearly invalid UTF-8 sequence
        masking_key = os.urandom(4)
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(invalid_utf8))

        fin_opcode = 0x81  # FIN=1, Opcode=0x1 (text)
        payload_len = 0x80 | len(invalid_utf8)  # MASK=1 + len=2

        frame = (
            struct.pack("!BB", fin_opcode, payload_len) +
            masking_key +
            masked_payload
        )

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Non-UTF-8 Text',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepted a text frame with invalid UTF-8 bytes.",
            'solution': 'Ensure strict UTF-8 validation of text frames.',
            'affected_url': ws_url,
            'impact': 'Improper decoding may cause crashes, parser confusion, or security flaws.'
        } if response else {'name': 'Non-UTF-8 Text', 'risk': 'No'}

    except Exception:
        return {'name': 'Non-UTF-8 Text', 'risk': 'No'}


def test_null_bytes_in_text(ws_url):
    """Test null bytes in text frame (Vuln #34)."""
    try:
        payload = b"te\x00st"
        masking_key = os.urandom(4)
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        fin_opcode = 0x81  # FIN=1, text frame
        payload_len = 0x80 | len(payload)  # MASK=1 + length=5

        frame = (
            struct.pack("!BB", fin_opcode, payload_len) +
            masking_key +
            masked_payload
        )

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Null Bytes in Text',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} accepted a text frame containing null bytes.",
            'solution': 'Validate and sanitize text frames for embedded nulls. Avoid C-style string truncation risks.',
            'affected_url': ws_url,
            'impact': 'Null bytes may cause truncation, spoofing, or parsing logic issues in downstream systems.'
        } if response else {'name': 'Null Bytes in Text', 'risk': 'No'}

    except Exception:
        return {'name': 'Null Bytes in Text', 'risk': 'No'}


def test_binary_as_text(ws_url):
    """Test binary data sent as a text frame (Vuln #35)."""
    try:
        payload = b"\x00\xFF\x00\xFF"  # Clearly not valid UTF-8
        masking_key = os.urandom(4)
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        fin_opcode = 0x81  # FIN=1, Opcode=0x1 (text frame)
        payload_len = 0x80 | len(payload)  # MASK=1 + len=4

        frame = (
            struct.pack("!BB", fin_opcode, payload_len) +
            masking_key +
            masked_payload
        )

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Binary as Text',
            'risk': 'Low',
            'description': f"WebSocket at {ws_url} accepted a text frame with non-UTF-8 binary data.",
            'solution': 'Validate UTF-8 compliance in all text frames as per RFC 6455.',
            'affected_url': ws_url,
            'impact': 'Binary data in text frames can crash UTF-8 decoders or lead to logic bugs in logging, auth, or sanitization layers.'
        } if response else {'name': 'Binary as Text', 'risk': 'No'}

    except Exception:
        return {'name': 'Binary as Text', 'risk': 'No'}


def test_text_as_binary(ws_url):
    """Test UTF-8 text sent as binary frame (Vuln #36)."""
    try:
        payload = b"text"  # Valid UTF-8 string
        masking_key = os.urandom(4)
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        fin_opcode = 0x82  # FIN=1, Opcode=0x2 (binary)
        payload_len = 0x80 | len(payload)  # MASK=1 + 4

        frame = (
            struct.pack("!BB", fin_opcode, payload_len) +
            masking_key +
            masked_payload
        )

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Text as Binary',
            'risk': 'Low',
            'description': f"WebSocket at {ws_url} accepted UTF-8 text sent in a binary frame.",
            'solution': 'Handle binary and text frames with separate logic as per RFC 6455.',
            'affected_url': ws_url,
            'impact': 'Frame type confusion may lead to parsing errors, logging bugs, or misrouted messages.'
        } if response else {'name': 'Text as Binary', 'risk': 'No'}

    except Exception:
        return {'name': 'Text as Binary', 'risk': 'No'}


def test_invalid_close_code(ws_url):
    """Test invalid close code in close frame (Vuln #37)."""
    try:
        code = 999  # Not allowed by RFC 6455
        reason = b"OK"
        payload = struct.pack("!H", code) + reason

        masking_key = os.urandom(4)
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        fin_opcode = 0x88  # FIN=1, Opcode=0x8 (close)
        payload_len = 0x80 | len(payload)  # MASK=1 + len=4

        frame = (
            struct.pack("!BB", fin_opcode, payload_len) +
            masking_key +
            masked_payload
        )

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Invalid Close Code',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} accepted a close frame with invalid code 999.",
            'solution': 'Close codes must conform to RFC 6455 (valid: 1000-1015, 3000-4999).',
            'affected_url': ws_url,
            'impact': 'Invalid codes may cause parser errors or incorrect shutdown logic.'
        } if response else {'name': 'Invalid Close Code', 'risk': 'No'}

    except Exception:
        return {'name': 'Invalid Close Code', 'risk': 'No'}


def test_early_close_frame(ws_url):
    """Test early close frame immediately after handshake (Vuln #38)."""
    try:
        ws = WebSocket()
        ws.connect(ws_url, timeout=5)

        close_code = 1000  # Normal closure
        payload = struct.pack("!H", close_code)

        masking_key = os.urandom(4)
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        fin_opcode = 0x88  # FIN=1, Opcode=8 (close)
        payload_len = 0x80 | len(payload)  # MASK=1 + length

        frame = (
            struct.pack("!BB", fin_opcode, payload_len) +
            masking_key +
            masked_payload
        )

        ws.send(frame)  # Send raw frame directly

        try:
            response = ws.recv()
        except Exception:
            response = None

        ws.close()

        return {
            'name': 'Early Close Frame',
            'risk': 'Low',
            'description': f"WebSocket at {ws_url} accepted an early close frame before any data was exchanged.",
            'solution': 'Gracefully handle close frames sent immediately after handshake.',
            'affected_url': ws_url,
            'impact': 'Unexpected early closes may cause resource leaks or state desyncs if not handled correctly.'
        } if response else {'name': 'Early Close Frame', 'risk': 'No'}

    except WebSocketException:
        return {'name': 'Early Close Frame', 'risk': 'No'}


def test_no_close_frame(ws_url):
    """Test connection closed without sending a WebSocket close frame (Vuln #39)."""
    try:
        # Step 1: Connect and abruptly close
        ws1 = WebSocket()
        ws1.connect(ws_url, timeout=5)
        try:
            ws1.sock.close()  # Close TCP connection directly (no WebSocket close frame)
        except Exception as e:
            print(colored(f"[WARN] TCP close on ws1 may have failed silently: {e}", "yellow"))
        time.sleep(2)

        # Step 2: Reconnect and test if server is in a clean state
        ws2 = WebSocket()
        ws2.connect(ws_url, timeout=5)
        ws2.send("test")  # normal masked text message
        response = ws2.recv()
        ws2.close()

        return {
            'name': 'No Close Frame',
            'risk': 'Low',
            'description': f"WebSocket at {ws_url} handled abrupt TCP closure and allowed clean reconnection.",
            'solution': 'Ensure that server detects and cleans up on ungraceful disconnects.',
            'affected_url': ws_url,
            'impact': 'Abrupt closures (without a close frame) may leave sessions open or leak memory.'
        } if response else {'name': 'No Close Frame', 'risk': 'No'}

    except WebSocketException:
        return {'name': 'No Close Frame', 'risk': 'No'}

def test_long_close_reason(ws_url):
    """Test long close reason (max allowed by spec — 123 bytes) (Vuln #40)."""
    try:
        reason = "A" * 123  # Max allowed reason length
        payload = struct.pack("!H", 1000) + reason.encode()  # 2-byte close code + reason

        masking_key = os.urandom(4)
        masked_payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

        fin_opcode = 0x88  # FIN=1, Opcode=8 (close)
        payload_len = 0x80 | len(payload)  # MASK=1 + payload length

        frame = (
            struct.pack("!BB", fin_opcode, payload_len) +
            masking_key +
            masked_payload
        )

        response = send_custom_frame(ws_url, frame)

        return {
            'name': 'Long Close Reason',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} accepted close frame with long reason ({len(reason)} bytes).",
            'solution': 'Enforce strict limits on close reason size (≤123 bytes).',
            'affected_url': ws_url,
            'impact': 'Overly long reasons may stress server logs, cause parsing failures, or lead to DoS.'
        } if response else {'name': 'Long Close Reason', 'risk': 'No'}

    except WebSocketException:
        return {'name': 'Long Close Reason', 'risk': 'No'}


def test_no_session_cookie(ws_url):
    """Test if WebSocket accepts connections without a session cookie (Vuln #41)."""
    try:
        # Omit the Cookie header completely
        headers = [
        "Origin: http://malicious.com" # Optional: simulate untrusted origin
        ]
        ws = create_connection(ws_url, header=headers, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
        'name': 'No Session Cookie',
        'risk': 'High',
        'description': f"WebSocket at {ws_url} accepts connections without a session cookie.",
        'solution': 'Require valid session cookies (or tokens) to authenticate WebSocket clients.',
        'affected_url': ws_url,
        'impact': 'Unauthenticated users can establish WebSocket sessions, exposing sensitive data.'
        }
    except WebSocketException:
        return {'name': 'No Session Cookie', 'risk': 'No'}
    except Exception as e:
        return {'name': 'No Session Cookie', 'risk': 'No'}

def test_expired_cookie(ws_url):
    """Test if WebSocket accepts connections with an expired session cookie (Vuln #42)."""
    try:
        # Simulate expired cookie using Max-Age and Expires
        headers = [
        "Cookie: session=expired_cookie_value; Max-Age=-1",
        "Origin: http://malicious.com" # Optional: simulates cross-origin if needed
        ]
        ws = create_connection(ws_url, header=headers, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
        'name': 'Expired Cookie',
        'risk': 'Medium',
        'description': f"WebSocket at {ws_url} accepts connections with an expired session cookie.",
        'solution': 'Validate cookie expiration on the server side and reject expired tokens.',
        'affected_url': ws_url,
        'impact': 'Expired sessions may be reused by attackers, leading to unauthorized access.'
        }
    except WebSocketException:
        return {'name': 'Expired Cookie', 'risk': 'No'}
    except Exception as e:
        return {'name': 'Expired Cookie', 'risk': 'No'}

def test_fake_token(ws_url):
    """Test if WebSocket accepts connections with a fake authentication token (Vuln #43)."""
    try:
        headers = [
            "Authorization: Bearer fake_token_123"
        ]
        ws = create_connection(ws_url, header=headers, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()

        return {
            'name': 'Fake Token',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts connections with a fake authentication token.",
            'solution': 'Implement robust token validation (e.g., JWT signature verification, token expiry check, audience validation).',
            'affected_url': ws_url,
            'impact': 'Fake tokens can lead to unauthorized access, impersonation, or escalation.'
        }

    except WebSocketException:
        return {'name': 'Fake Token', 'risk': 'No'}

def test_http_session_reuse(ws_url):
    """Test if HTTP session cookie is reused for WebSocket without revalidation (Vuln #44)."""
    try:
        # 1. Derive equivalent HTTP URL
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"

        # 2. Start HTTP session and extract cookies
        session = requests.Session()
        response = session.get(http_url, timeout=5)
        cookies = session.cookies.get_dict()
        if not cookies:
            return {'name': 'HTTP Session Reuse', 'risk': 'No'}

        # 3. Convert cookies to WebSocket-compatible header
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        headers = [f"Cookie: {cookie_str}"]

        # 4. Connect to WebSocket using same cookies
        ws = create_connection(ws_url, header=headers, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()

        # 5. Report success (session accepted)
        return {
            'name': 'HTTP Session Reuse',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} reused HTTP session cookie without revalidation.",
            'solution': 'Require revalidation or token-based auth for WebSockets even if HTTP session exists.',
            'affected_url': ws_url,
            'impact': 'Reused sessions may allow impersonation or privilege escalation if the HTTP session is hijacked.'
        }

    except (WebSocketException, requests.RequestException) as e:
        return {'name': 'HTTP Session Reuse', 'risk': 'No'}

def test_stale_session_reconnect(ws_url):
    """Test if WebSocket allows reconnection with a stale session (Vuln #45)."""
    try:
        stale_cookie = "session=stale_session_id_123"
        headers = [
            f"Cookie: {stale_cookie}"
        ]

        # First connection
        ws1 = create_connection(ws_url, header=headers, timeout=5)
        ws1.send("initial connection")
        ws1.recv()
        ws1.close()

        # Simulate session aging
        time.sleep(5)  # Not true expiration, but delay

        # Second connection with same cookie
        ws2 = create_connection(ws_url, header=headers, timeout=5)
        ws2.send("reconnect with stale session")
        response = ws2.recv()
        ws2.close()

        return {
            'name': 'Stale Session Reconnect',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} allows reconnection with same stale session cookie.",
            'solution': 'Invalidate old session IDs on WebSocket reconnect. Require fresh authentication or refresh token.',
            'affected_url': ws_url,
            'impact': 'Attackers can reuse stolen or outdated session tokens for unauthorized access.'
        }

    except WebSocketException as e:
        return {'name': 'Stale Session Reconnect', 'risk': 'No'}

def test_cross_site_cookie_hijack(ws_url):
    """Test if WebSocket accepts cookies from a different origin (Vuln #46)."""
    try:
        # Craft malicious headers
        headers = [
            "Origin: http://malicious.com",
            "Cookie: session=cross_site_session; Domain=malicious.com"
        ]

        # Establish connection
        ws = create_connection(ws_url, header=headers, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()

        return {
            'name': 'Cross-Site Cookie Hijack',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepted cross-origin cookies and origin header.",
            'solution': 'Set SameSite=Strict on cookies and validate the Origin header server-side.',
            'affected_url': ws_url,
            'impact': 'Attackers could hijack sessions via forged WebSocket connections from malicious origins.'
        }

    except WebSocketException as e:
        return {'name': 'Cross-Site Cookie Hijack', 'risk': 'No'}
    
def test_invalid_subprotocol(ws_url):
    """Test if WebSocket accepts an invalid subprotocol (Vuln #47)."""
    try:
        ws = create_connection(ws_url, subprotocols=["invalid..protocol"], timeout=5)
        
        # Use the correct attribute and safely handle None
        selected = getattr(ws, 'subprotocol', None)

        ws.send("test")
        _ = ws.recv()
        ws.close()

        if selected == "invalid..protocol":
            return {
                'name': 'Invalid Subprotocol',
                'risk': 'Medium',
                'description': f"WebSocket at {ws_url} negotiated invalid subprotocol: '{selected}'.",
                'solution': 'Reject malformed or unsupported subprotocol values during handshake.',
                'affected_url': ws_url,
                'impact': 'Invalid subprotocols can lead to parser confusion, downgrade attacks, or misbehavior.'
            }
        else:
            return {'name': 'Invalid Subprotocol', 'risk': 'No'}  # No vulnerability: server ignored the invalid subprotocol

    except WebSocketException:
        return {'name': 'Invalid Subprotocol', 'risk': 'No'}

from websocket import create_connection, WebSocketException

def test_conflicting_subprotocols(ws_url):
    """Test if WebSocket server accepts conflicting or duplicate subprotocols (Vuln #48)."""
    try:
        # Pass multiple distinct subprotocols (with a duplicate)
        ws = create_connection(ws_url, subprotocols=["chat", "stream", "chat"], timeout=5)
        
        # Use safe access
        selected = getattr(ws, 'subprotocol', None)

        ws.send("test")
        _ = ws.recv()
        ws.close()

        if selected not in ["chat", "stream", None]:
            return {
                'name': 'Conflicting Subprotocols',
                'risk': 'Medium',
                'description': f"WebSocket at {ws_url} accepted conflicting subprotocols: {selected}.",
                'solution': 'Ensure only one valid subprotocol is negotiated and reject duplicates.',
                'affected_url': ws_url,
                'impact': 'Conflicting subprotocols can cause logic confusion or downgrade vulnerabilities.'
            }

        return {'name': 'Conflicting Subprotocols', 'risk': 'No'}

    except WebSocketException:
        return {'name': 'Conflicting Subprotocols', 'risk': 'No'}


from websocket import create_connection, WebSocketException

def test_unaccepted_subprotocol(ws_url):
    """Test if WebSocket server accepts an unadvertised subprotocol (Vuln #49)."""
    try:
        ws = create_connection(ws_url, subprotocols=["unadvertised_protocol"], timeout=5)

        # Use safe attribute
        negotiated = getattr(ws, 'subprotocol', None)

        ws.send("test")
        _ = ws.recv()
        ws.close()

        if negotiated == "unadvertised_protocol":
            return {
                'name': 'Unaccepted Subprotocol',
                'risk': 'Medium',
                'description': f"WebSocket at {ws_url} negotiated unadvertised subprotocol 'unadvertised_protocol'.",
                'solution': 'Only negotiate subprotocols explicitly supported by the server.',
                'affected_url': ws_url,
                'impact': 'Unadvertised subprotocols can allow unintended parsing or behavior (e.g., logic injection).'
            }
        else:
            return {'name': 'Unaccepted Subprotocol', 'risk': 'No'}

    except WebSocketException:
        return {'name': 'Unaccepted Subprotocol', 'risk': 'No'}


def test_fake_extension(host, port, path="/"):
    """Test if WebSocket accepts a fake extension (Vuln #50)."""

    key = b64encode(b"1234567890123456").decode()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Extensions: permessage-hackz; param=true\r\n"
        f"\r\n"
    )

    try:
        sock = socket.create_connection((host, port), timeout=5)
        if port == 443:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.sendall(request.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()

        if "101 Switching Protocols" in response:
            return {
                'name': 'Fake Extension',
                'risk': 'High',
                'description': f"Server at {host}:{port} accepted spoofed extension.",
                'solution': 'Validate Sec-WebSocket-Extensions header against supported values.',
                'affected_host': f"{host}:{port}{path}",
                'impact': 'Fake extensions can lead to parser confusion or misbehavior.'
            }
        return {'name': 'Fake Extension', 'risk': 'No'}
    except Exception as e:
        print(f"[!] Fake extension test failed for {host}:{port}: {e}")
        return {'name': 'Fake Extension', 'risk': 'No'}

def test_conflicting_extensions(host, port, path="/"):
    """Test if WebSocket accepts conflicting extensions (Vuln #51)."""
    key = b64encode(b"1234567890123456").decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        "Host: fake.example.com\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate; permessage-deflate\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )

    response = send_raw_handshake(host, port, req)

    if response and "101 Switching Protocols" in response:
        return {
            'name': 'Conflicting Extensions',
            'risk': 'Medium',
            'description': f"Server at {host}:{port} accepted conflicting extensions.",
            'solution': 'Reject requests with duplicate or conflicting extensions.',
            'affected_host': f"{host}:{port}",
            'impact': 'Conflicting extensions can cause protocol errors.'
        }

    return {'name': 'Conflicting Extensions', 'risk': 'No'}

def test_spoofed_connection_header(host, port, path="/"):
    """Test if WebSocket accepts a spoofed Connection header (Vuln #52)."""
    try:
        key = b64encode(b"1234567890123456").decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: keep-alive, Upgrade, evil\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )

        sock = socket.create_connection((host, port), timeout=5)
        if port == 443:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.sendall(request.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()

        if "101 Switching Protocols" in response:
            return {
                'name': 'Spoofed Connection Header',
                'risk': 'High',
                'description': f"Server at {host}:{port} accepted spoofed Connection header.",
                'solution': 'Strictly validate Connection header to be exactly "Upgrade".',
                'affected_host': f"{host}:{port}{path}",
                'impact': 'Spoofed headers can bypass upgrade validation or confuse reverse proxies.'
            }

        return {'name': 'Spoofed Connection Header', 'risk': 'No'}
    except Exception as e:
                return {'name': 'Spoofed Connection Header', 'risk': 'No'}

def test_http_1_0_downgrade(host, port, path="/"):
    """Test if WebSocket accepts HTTP/1.0 handshake (Vuln #53)."""
    try:
        key = b64encode(b"1234567890123456").decode()
        request = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )

        # Create socket connection
        sock = socket.create_connection((host, port), timeout=5)
        if port == 443:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.sendall(request.encode())
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()

        if "101 Switching Protocols" in response:
            return {
                'name': 'HTTP/1.0 Downgrade',
                'risk': 'High',
                'description': f"Server at {host}:{port} accepted HTTP/1.0 WebSocket handshake.",
                'solution': 'Only allow WebSocket upgrades over HTTP/1.1 or newer.',
                'affected_host': f"{host}:{port}{path}",
                'impact': 'Accepting HTTP/1.0 WebSocket handshakes can lead to protocol confusion and security issues.'
            }

        return {'name': 'HTTP/1.0 Downgrade', 'risk': 'No'}

    except Exception as e:
                return {'name': 'HTTP/1.0 Downgrade', 'risk': 'No'}

def test_tls_downgrade(ws_url):
    """Test if WebSocket allows downgrade to insecure TLS versions (Vuln #54)."""
    try:
        parsed_url = urlparse(ws_url)
        if parsed_url.scheme != 'wss':
            return {'name': 'TLS Downgrade', 'risk': 'No'}  # Only applicable to wss:// URLs
        
        # Check if TLS 1.0 is supported
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # Force TLS 1.0 (insecure)
        except ValueError as e:
                        return {'name': 'TLS Downgrade', 'risk': 'No'}

        context.verify_mode = ssl.CERT_NONE
        ws = WebSocket(sslopt={"context": context})
        ws.connect(ws_url, timeout=5)
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'TLS Downgrade',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} allows downgrade to insecure TLS version (TLS 1.0).",
            'solution': 'Enforce modern TLS versions (e.g., TLS 1.2 or 1.3) and disable older versions.',
            'affected_url': ws_url,
            'impact': 'Insecure TLS versions are vulnerable to attacks like POODLE.'
        }
    except WebSocketException as e:
                return {'name': 'TLS Downgrade', 'risk': 'No'}
    except ssl.SSLError as e:
                return {'name': 'TLS Downgrade', 'risk': 'No'}
    except Exception as e:
                return {'name': 'TLS Downgrade', 'risk': 'No'}
    
def test_insecure_cipher(ws_url):
    """Test if WebSocket accepts insecure ciphers (Vuln #38: Weak TLS Ciphers)."""
    try:
        parsed_url = urlparse(ws_url)
        if parsed_url.scheme != 'wss':
            return {'name': 'Weak TLS Ciphers', 'risk': 'No'}  # Only applies to wss://

        insecure_ciphers = [
            "RC4-MD5",
            "RC4-SHA",
            "DES-CBC-SHA",
            "EXP-RC4-MD5",
            "EXP-DES-CBC-SHA",
            "NULL-MD5"
        ]

        supported_cipher = None
        for cipher in insecure_ciphers:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.set_ciphers(cipher)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                ws = WebSocket(sslopt={"context": context})
                ws.connect(ws_url, timeout=5)
                ws.send("test")
                _ = ws.recv()
                ws.close()

                supported_cipher = cipher
                break  # Stop at first successful connection with a weak cipher

            except Exception:
                continue  # Try next cipher

        if supported_cipher:
            return {
                'name': 'Insecure Cipher',
                'risk': 'High',
                'description': f"WebSocket at {ws_url} accepts insecure TLS cipher: {supported_cipher}.",
                'solution': 'Disable weak ciphers like RC4, NULL, EXPORT, and DES-CBC-SHA. Use modern TLS ciphers only.',
                'affected_url': ws_url,
                'impact': 'Weak ciphers enable downgrade attacks and session compromise.'
            }

        else:
            return {'name': 'Weak TLS Ciphers', 'risk': 'No'}

    except Exception:
        return {'name': 'Weak TLS Ciphers', 'risk': 'No'}
    
def test_certificate_mismatch(ws_url):
    """Test if WebSocket endpoint's certificate matches the domain (Vuln #56)."""
    try:
        parsed_url = urlparse(ws_url)
        if parsed_url.scheme != 'wss':
            return {'name': 'Certificate Mismatch', 'risk': 'No'}  # Only applicable to wss:// URLs
        host = parsed_url.hostname
        port = parsed_url.port or 443
        # Create a default SSL context to verify the certificate
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # Check if the certificate matches the hostname
                ssl.match_hostname(cert, host)
        return {'name': 'Certificate Mismatch', 'risk': 'No'}  # If no exception, certificate is valid
    except ssl.SSLCertVerificationError as e:
        return {
            'name': 'Certificate Mismatch',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} has a certificate mismatch: {e}.",
            'solution': 'Ensure the SSL certificate matches the domain and is issued by a trusted CA.',
            'affected_url': ws_url,
            'impact': 'Certificate mismatches can allow man-in-the-middle attacks.'
        }
    except Exception:
        return {'name': 'Certificate Mismatch', 'risk': 'No'}
    
def test_connection_flood(ws_url):
    """Test if WebSocket server handles rapid concurrent connection flooding (Vuln #56)."""
    successful = 0
    failed = 0
    threads = []
    lock = threading.Lock()

    def open_and_close():
        nonlocal successful, failed
        try:
            ws = WebSocket()
            ws.connect(ws_url, timeout=5)
            ws.close()
            with lock:
                successful += 1
        except Exception:
            with lock:
                failed += 1

    start = time.time()
    for _ in range(100):  # Try 100 connections in parallel
        t = threading.Thread(target=open_and_close)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()
    elapsed = time.time() - start

    if successful >= 90:  # Server handled them all
        return {
            'name': 'Connection Flood',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} allowed {successful} concurrent connections in {elapsed:.2f}s.",
            'solution': 'Enforce per-IP connection limits and rate limiting to prevent abuse.',
            'affected_url': ws_url,
            'impact': 'Connection floods can exhaust server memory and sockets, causing DoS.'
        }
    else:
                return {'name': 'Connection Flood', 'risk': 'No'}

def test_oversized_message(ws_url):
    """Test if WebSocket accepts oversized messages (Vuln #57)."""
    ws = None
    try:
        ws = WebSocket()
        ws.connect(ws_url, timeout=5)
        payload = "A" * 10_000_000  # 10MB message
        ws.send(payload)
        try:
            response = ws.recv()
            echoed = len(response)
        except Exception:
            echoed = 0  # server didn't reply
        return {
            'name': 'Oversized Message',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepted a 10MB message.",
            'solution': 'Set a reasonable max message size limit (e.g., 1MB) to prevent buffer overflows.',
            'affected_url': ws_url,
            'impact': f"Large payloads like 10MB can cause memory exhaustion or DoS. Server echoed {echoed} bytes.",
        }
    except (WebSocketException, ssl.SSLError, socket.error) as e:
                return {'name': 'Oversized Message', 'risk': 'No'}
    finally:
        try:
            if ws:
                ws.close()
        except:
            pass

def test_max_connections(ws_url):
    """Test if WebSocket server enforces maximum connections limit (Vuln #58)."""
    connections = []
    max_attempts = 100
    success_count = 0
    try:
        for i in range(max_attempts):
            ws = WebSocket()
            ws.connect(ws_url, timeout=5)
            connections.append(ws)
            success_count += 1
    except (WebSocketException, ssl.SSLError, socket.error) as e:
        return {'name': 'Max Connections', 'risk': 'No'}
    finally:
        for ws in connections:
            try:
                ws.close()
            except:
                pass

    if success_count >= max_attempts:
        return {
            'name': 'Max Connections',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} allows {max_attempts} simultaneous connections without restriction.",
            'solution': 'Enforce a maximum connection limit per client to prevent resource exhaustion.',
            'affected_url': ws_url,
            'impact': 'Excessive connections can lead to server overload and DoS.',
            'notes': f"{success_count} connections opened successfully. No limit detected."
        }
    else:
        return {'name': 'Max Connections', 'risk': 'No'}

def test_idle_timeout_abuse(ws_url):
    """Test if WebSocket server allows idle connections to persist (Vuln #60)."""
    ws = None
    try:
    # Optional SSL bypass (you may remove 'sslopt' if certificate validation is required)
        sslopt = {"cert_reqs": ssl.CERT_NONE} if ws_url.startswith("wss://") else None
        ws = create_connection(ws_url, timeout=5, sslopt=sslopt)
        time.sleep(60)  # Remain idle for 60 seconds
        ws.send("test")
        response = ws.recv()
        ws.close()
        return {
            'name': 'Idle Timeout Abuse',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} allows idle connections to persist for 60 seconds.",
            'solution': 'Implement an idle timeout policy to close inactive connections.',
            'affected_url': ws_url,
            'impact': 'Idle connections can tie up server resources, enabling DoS.'
        }
    except WebSocketException as e:
                return {'name': 'Idle Timeout Abuse', 'risk': 'No'}
    except Exception as e:
                return {'name': 'Idle Timeout Abuse', 'risk': 'No'}
    finally:
        try:
            if ws:
                ws.close()
        except:
            pass


def test_no_compression_negotiation(ws_url):
    """Test if WebSocket server handles compression without proper negotiation (Vuln #61)."""
    try:
        # Intentionally omit 'Sec-WebSocket-Extensions' header
        ws = WebSocket()
        ws.connect(ws_url, timeout=5)

        # Send repetitive compressible data (should not be decompressed by server)
        payload = "A" * 1000
        ws.send(payload)
        response = ws.recv()
        ws.close()

        return {
            'name': 'No Compression Negotiation',
            'risk': 'Medium',
            'description': f"WebSocket at {ws_url} may mishandle compression without proper negotiation.",
            'solution': 'Ensure the server only decompresses messages when permessage-deflate was negotiated.',
            'affected_url': ws_url,
            'impact': 'Improper handling can cause parser crashes or CPU overhead.'
        }

    except (WebSocketException, ssl.SSLError, socket.error) as e:
        return {'name': 'No Compression Negotiation', 'risk': 'No'}
    except:
        return {'name': 'No Compression Negotiation', 'risk': 'No'}

def test_high_compression_ratio(ws_url):
    """Test if WebSocket server handles high compression ratio messages (Vuln #62)."""
    try:
        ws = WebSocket()
        ws.connect(ws_url, header=["Sec-WebSocket-Extensions: permessage-deflate"], timeout=5)

        payload = "A" * 1_000_000  # 1MB of highly compressible data
        ws.send(payload)

        try:
            response = ws.recv()
        except Exception:
            response = None  # Some servers close the connection silently

        ws.close()

        return {
            'name': 'High Compression Ratio',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepts highly compressible messages (1MB of 'A').",
            'solution': 'Limit allowed compression ratio or message size on the server.',
            'affected_url': ws_url,
            'impact': 'May allow decompression bombs causing memory/CPU exhaustion (DoS vector).'
        }

    except (WebSocketException, ssl.SSLError, socket.error, ConnectionResetError, BrokenPipeError) as e:
                return {'name': 'High Compression Ratio', 'risk': 'No'}
    
def test_large_payload_leak(ws_url):
    """Test if server accepts large repeated messages without closing (Part of Resource Leak)."""
    try:
        ws = WebSocket()
        ws.connect(ws_url, timeout=5)
        for _ in range(10):  # 10 messages of 1MB each
            ws.send("A" * 1_000_000)
            time.sleep(0.1)
        ws.close()

        return {
            'name': 'Large Payload Resource Leak',
            'risk': 'High',
            'description': f"WebSocket at {ws_url} accepted repeated large messages without closing.",
            'solution': 'Set server-side limits for message size and rate. Monitor memory usage.',
            'affected_url': ws_url,
            'impact': 'Excessive memory allocation can exhaust server RAM over time.'
        }
    except Exception:
        return {'name': 'Large Payload Resource Leak', 'risk': 'No'}


def test_socket_leak_on_half_open(ws_url):
    """Test if server allows hanging sockets without timeouts (Part of Resource Leak)."""
    parsed = urlparse(ws_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'wss' else 80)

    for _ in range(5):  # 5 sockets opened without completing handshake
        try:
            sock = socket.create_connection((hostname, port), timeout=5)
            if parsed.scheme == 'wss':
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=hostname)
            time.sleep(0.5)  # Simulate hanging socket
            sock.close()
        except ssl.SSLError as e:
            return {'name':'TCP Half-Open Resource Leak','risk':'No'}  # Expected for incomplete handshake

    return {
        'name': 'TCP Half-Open Resource Leak',
        'risk': 'High',
        'description': f"WebSocket at {ws_url} accepted hanging TCP connections without timeout.",
        'solution': 'Use TCP keep-alive and server-side timeout policies.',
        'affected_url': ws_url,
        'impact': 'Leaked descriptors may degrade server over time or cause exhaustion.'
    }

def test_no_timeout_policy(ws_url):
    """Test if WebSocket server lacks a connection timeout policy (Vuln #64)."""
    ws = None
    try:
        ws = WebSocket()
        ws.connect(ws_url, timeout=5)
        time.sleep(60)  # Simulate idle period

        try:
            ws.send("test")  # Try to send data after being idle
            response = ws.recv()
            return {
                'name': 'No Timeout Policy',
                'risk': 'High',
                'description': f"WebSocket at {ws_url} remained open and active after 120 seconds of idleness.",
                'solution': 'Implement idle timeout to close inactive connections.',
                'affected_url': ws_url,
                'impact': 'Idle connections can consume server resources (threads, memory).'
            }
        except (WebSocketException, ssl.SSLError, socket.error) as e:
            # Server closed connection = GOOD (has timeout)
                        return {'name': 'No Timeout Policy', 'risk': 'No'}

    except (WebSocketException, ssl.SSLError, socket.error) as e:
                return {'name': 'No Timeout Policy', 'risk': 'No'}
    finally:
        try:
            if ws:
                ws.close()
                return {'name': 'No Timeout Policy', 'risk': 'No'}
        except:
            return {'name': 'No Timeout Policy', 'risk': 'No'}

# Cross-Origin & Mixed Content (Vuln #65-69)

def test_missing_cors_headers(ws_url):
    """Test if WebSocket endpoint lacks CORS headers (Vuln #65)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        headers = {"Origin": "http://malicious.com"}
        response = requests.get(http_url, headers=headers, timeout=5)

        # Check for missing or misconfigured Access-Control-Allow-Origin
        cors_header = response.headers.get("Access-Control-Allow-Origin", "")
        if not cors_header or cors_header != "http://malicious.com":
            return {
                'name': 'Missing CORS Headers',
                'risk': 'High',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) lacks proper CORS headers.",
                'solution': 'Implement proper CORS headers to restrict cross-origin access.',
                'affected_url': http_url,
                'impact': 'Missing or misconfigured CORS headers can lead to unauthorized cross-origin requests.'
            }
        return  {'name': 'Missing CORS Headers', 'risk': 'No'}
    except requests.RequestException as e:
                return  {'name': 'Missing CORS Headers', 'risk': 'No'}

def test_cross_origin_iframe(ws_url):
    """Test if WebSocket endpoint allows cross-origin iframe embedding (Vuln #66)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5)

        headers = response.headers
        xfo = headers.get("X-Frame-Options", "").lower()
        csp = headers.get("Content-Security-Policy", "").lower()

        if (
        "deny" not in xfo and
        "sameorigin" not in xfo and
        "frame-ancestors" not in csp
        ):
            return {
            'name': 'Cross-Origin Iframe',
            'risk': 'High',
            'description': f"{ws_url} allows itself to be embedded in cross-origin iframes (missing X-Frame-Options / CSP).",
            'solution': 'Set X-Frame-Options: DENY or SAMEORIGIN, or CSP frame-ancestors directive.',
            'affected_url': http_url,
            'impact': 'Lack of iframe restrictions enables clickjacking and session abuse via embedded WebSocket clients.'
            }

        return {'name': 'Cross-Origin Iframe', 'risk': 'No'}

    except requests.RequestException as e:
                return {'name': 'Cross-Origin Iframe', 'risk': 'No'}

def test_mixed_content(ws_url):
    """Test if WebSocket frontend loads insecure ws:// connections inside an https:// page (Vuln #67)."""
    try:
        parsed_url = urlparse(ws_url)

    # We only test if the site uses HTTPS (relevant for mixed content)
        if parsed_url.scheme != 'wss':
            return {'name': 'Mixed Content', 'risk': 'No'}

        https_url = f"https://{parsed_url.netloc}/"
        response = requests.get(https_url, timeout=5, allow_redirects=True)

        if response.status_code == 200:
            # Scan page content for insecure WebSocket connections
            if "ws://" in response.text.lower():
                return {
                'name': 'Mixed Content',
                'risk': 'High',
                'description': f"The HTTPS page at {https_url} includes insecure WebSocket connections (ws://).",
                'solution': 'Replace ws:// with wss:// in all frontend scripts loaded over HTTPS.',
                'affected_url': https_url,
                'impact': 'Mixed content exposes users to downgrade/MITM attacks and breaks secure context assumptions.'
                }

        return {'name': 'Mixed Content', 'risk': 'No'}

    except Exception:
        return {'name': 'Mixed Content', 'risk': 'No'}

def test_postmessage_abuse(ws_url):
    """Test if WebSocket endpoint is vulnerable to postMessage abuse (Vuln #68)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5)
        # Check for HTML content that might include postMessage listeners
        if "text/html" in response.headers.get("Content-Type", "").lower():
            content = response.text.lower()
            if "postmessage" in content and "origin" not in content:
                return {
                    'name': 'PostMessage Abuse',
                    'risk': 'High',
                    'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) may be vulnerable to postMessage abuse.",
                    'solution': 'Validate the origin of postMessage events in client-side code.',
                    'affected_url': http_url,
                    'impact': 'PostMessage abuse can allow cross-origin data leakage or script execution.'
                }
        return {'name': 'PostMessage Abuse', 'risk': 'No'}
    except requests.RequestException as e:
                return {'name': 'PostMessage Abuse', 'risk': 'No'}

def test_spoofed_url(ws_url):
    """Test if WebSocket endpoint allows spoofed URLs (Vuln #69)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        headers = {"Referer": "http://malicious.com"}
        response = requests.get(http_url, headers=headers, timeout=5)

        # Check if the referer is reflected in the response body (indicating reflection)
        if response.status_code == 200 and "malicious.com" in response.text.lower():
            return {
                'name': 'Spoofed URL',
                'risk': 'High',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) reflects spoofed Referer URL.",
                'solution': 'Sanitize and validate Referer headers; avoid reflecting untrusted input.',
                'affected_url': http_url,
                'impact': 'Spoofed URLs can be used for phishing or redirection attacks.'
            }
        return {'name': 'Spoofed URL', 'risk': 'No'}
    except requests.RequestException as e:
                return {'name': 'Spoofed URL', 'risk': 'No'}


# Other Vulnerabilities (Vuln #70-75)

def test_error_message_leak(ws_url):
    """Test if WebSocket server leaks sensitive error messages (Vuln #70)."""
    try:
        ws = create_connection(ws_url, timeout=5)
        ws.send("\x00" * 1000)  # Malformed input to trigger error
        response = ws.recv()
        ws.close()
        if any(keyword in response.lower() for keyword in ["stack trace", "exception", "sql", "database", "error at"]):
            return {
                'name': 'Error Message Leak',
                'risk': 'Medium',
                'description': f"WebSocket at {ws_url} leaks sensitive error messages: {response}.",
                'solution': 'Avoid exposing detailed error messages in production; use generic error responses.',
                'affected_url': ws_url,
                'impact': 'Error message leaks can expose server details to attackers.'
            }
        return {'name': 'Error Message Leak', 'risk': 'No'}
    except WebSocketException as e:
                return {'name': 'Error Message Leak', 'risk': 'No'}

def test_server_disclosure(ws_url):
    """Test if WebSocket server discloses platform/framework/version info (Vuln #71)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5)


        leaked = []
        keywords = {
        "Server": ["nginx", "apache", "iis", "tomcat", "gunicorn", "caddy"],
        "X-Powered-By": ["express", "php", "django", "rails", "spring"],
        "X-AspNet-Version": [],
        }

        for header, values in keywords.items():
            raw = response.headers.get(header, "")
            if raw:
                if not values or any(v in raw.lower() for v in values):
                    leaked.append(f"{header}: {raw}")

        if leaked:
            return {
            'name': 'Server Disclosure',
            'risk': 'Medium',
            'description': f"WebSocket HTTP interface discloses: {', '.join(leaked)}.",
            'solution': 'Disable or obscure headers like Server, X-Powered-By, and X-AspNet-Version.',
            'affected_url': http_url,
            'impact': 'Disclosed server info enables attackers to craft tech-specific exploits.'
            }
        return {'name': 'Server Disclosure', 'risk': 'No'}

    except requests.RequestException as e:
                return {'name': 'Server Disclosure', 'risk': 'No'}

def test_invalid_content_type(ws_url):
    """Test if WebSocket endpoint serves invalid Content-Type (Vuln #72)."""
    try:
        parsed_url = urlparse(ws_url)
        http_url = f"{'https' if parsed_url.scheme == 'wss' else 'http'}://{parsed_url.netloc}/"
        response = requests.get(http_url, timeout=5)
        content_type = response.headers.get("Content-Type", "").lower()

        if content_type and "text/html" in content_type and "upgrade" not in response.headers.get("Connection", "").lower():
            return {
                'name': 'Invalid Content-Type',
                'risk': 'Medium',
                'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) serves invalid Content-Type: {content_type}.",
                'solution': 'Ensure WebSocket endpoints return appropriate Content-Type or upgrade headers.',
                'affected_url': http_url,
                'impact': 'Invalid Content-Type can confuse clients or enable XSS attacks.'
            }
        return {'name': 'Invalid Content-Type', 'risk': 'No'}
    except requests.RequestException as e:
                return {'name': 'Invalid Content-Type', 'risk': 'No'}

def test_missing_security_headers(ws_url):
    """Test if WebSocket endpoint lacks key security headers (Vuln #73)."""
    try:
        parsed_url = urlparse(ws_url)
        # Convert ws/wss to http/https
        http_scheme = 'https' if parsed_url.scheme == 'wss' else 'http'
        http_url = f"{http_scheme}://{parsed_url.netloc}{parsed_url.path or '/'}"

        response = requests.get(http_url, timeout=5)

        # List of important security headers to check (not their values, just presence)
        required_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        # You can add: "Referrer-Policy", "Permissions-Policy" if needed
        ]

        missing_headers = [h for h in required_headers if h not in response.headers]

        if missing_headers:
            return {
            'name': 'Missing Security Headers',
            'risk': 'Medium',
            'description': f"WebSocket endpoint {ws_url} (HTTP equivalent) lacks the following headers: {', '.join(missing_headers)}.",
            'solution': 'Add missing security headers such as Content-Security-Policy, X-Frame-Options, and Strict-Transport-Security.',
            'affected_url': http_url,
            'impact': 'Missing security headers can allow framing attacks, downgrade vulnerabilities, or mixed content issues.'
            }
        return {'name': 'Missing Security Headers', 'risk': 'No'}

    except requests.RequestException as e:
                return {'name': 'Missing Security Headers', 'risk': 'No'}

def test_url_path_traversal(ws_url):
    """Test for path traversal by manipulating WebSocket path (Vuln #74)."""
    try:
        parsed = urlparse(ws_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        payload_url = base + "/ws/../admin/socket"
        ws = create_connection(payload_url, timeout=5)
        ws.close()
        return {
            'name': 'URL Path Traversal',
            'risk': 'High',
            'description': f"WebSocket endpoint allows path traversal via: {payload_url}",
            'solution': 'Validate and normalize paths to prevent traversal.',
            'affected_url': payload_url,
            'impact': 'May allow unauthorized access to internal/admin WebSocket paths.'
        }
    except Exception as e:
        return {'name': 'URL Path Traversal', 'risk': 'No'}
    
def compact_url(url):
    if "?" not in url:
        return url
    base = url.split("?", 1)[0]
    num_params = url.count("&") + 1
    return f"{base}?[{num_params} params]"

    
def test_query_parameter_flood(ws_url):
    """Test if WebSocket endpoint handles query parameter flooding (Vuln #75)."""
    try:
        parsed = urlparse(ws_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = "&".join([f"param{i}=value{i}" for i in range(1000)])
        flood_url = f"{base}?{params}"
        compacted = compact_url(flood_url)
        ws = create_connection(flood_url, timeout=5)
        ws.close()
        return {
            'name': 'Query Parameter Flood',
            'risk': 'High',
            'description': f"WebSocket endpoint {compacted} accepts 1000 query parameters.",
            'solution': 'Limit query parameters and implement strict validation.',
            'affected_url': compacted,
            'impact': 'May cause resource exhaustion and DoS conditions.'
        }
    except Exception as e:
                return {'name': 'Query Parameter Flood', 'risk': 'No'}
    
# 🔒 Handshake & Protocol Validation
handshake_tests = [
    test_omit_sec_websocket_key,                # 3
    test_non_base64_sec_websocket_key,          # 4
    test_oversized_sec_websocket_key,           # 5
    test_duplicate_sec_websocket_key,           # 6
    test_missing_sec_websocket_version,         # 7
    test_invalid_sec_websocket_version,         # 8
    test_conflicting_sec_websocket_version,     # 9
    test_wrong_upgrade_header,      # 10
    test_missing_connection_header, # 11
    test_case_sensitive_headers,    # 12
    test_non_get_method,            # 13
    test_fake_http_status,          # 14
    test_wrong_sec_websocket_accept,# 15 
    test_oversized_headers,         # 16
    test_missing_host_header,       # 17
    test_fake_host_header,          # 18
    test_multiple_host_headers,     # 19
    test_long_url_path,             # 20
    test_unicode_url,               # 21
    test_http_0_9_handshake,        # 22
]
# 🔓 Authentication, Sessions & Identity Control
auth_session_tests = [
    test_no_session_cookie,         # 23
    test_expired_cookie,            # 24
    test_fake_token,                # 25
    test_http_session_reuse,        # 26
    test_stale_session_reconnect,   # 27
    test_cross_site_cookie_hijack,  # 28
    test_authentication             # 29
]
# 🗂 Subprotocol & Extension Negotiation
ws_subprotocol_tests = [
    test_invalid_subprotocol,       # 30
    test_conflicting_subprotocols,  # 31
    test_unaccepted_subprotocol,    # 32
]
subprotocol_tests = [
    test_fake_extension,            # 33
    test_conflicting_extensions,    # 34
]
# ⚡ Transport Security & Encryption
security_tests = [
    test_spoofed_connection_header, # 35
    test_http_1_0_downgrade,        # 36
]
ws_security_tests = [
    test_tls_downgrade,             # 37
    test_insecure_cipher,           # 38
    test_certificate_mismatch,      # 39
]
# 📦 Payload Handling & Fragmentation
payload_tests = [
    test_undefined_opcode,          # 40
    test_reserved_opcode,           # 41
    test_zero_length_fragment,      # 42
    test_invalid_payload_length,    # 43
    test_negative_payload_length,   # 44
    test_mismatched_payload,        # 45
    test_invalid_masking_key,       # 46
    test_unmasked_client_frame,     # 47
    test_invalid_rsv_bits,          # 48
    test_oversized_control_frame,   # 49
    test_non_utf8_text,             # 50
    test_null_bytes_in_text,        # 51
    test_binary_as_text,            # 52
    test_text_as_binary,            # 53
    test_invalid_close_code,        # 54
    test_early_close_frame,         # 55
    test_no_close_frame,            # 56
    test_long_close_reason,         # 57
]
# 🌍 Cross-Origin Policy & Browser-Side Risks
cross_origin_tests = [
    test_missing_cors_headers,      # 58
    test_cross_origin_iframe,       # 59
    test_mixed_content,             # 60
    test_postmessage_abuse,         # 61
    test_spoofed_url,               # 62
    test_origin_check               # 63
]
# 🛡 Application-Layer Vulnerabilities
ws_app_tests = [
    test_error_message_leak,        # 64
    test_server_disclosure,         # 65
    test_invalid_content_type,      # 66
    test_missing_security_headers,  # 67
    test_url_path_traversal,        # 68
    test_query_parameter_flood,     # 69
]
# ⚠ DoS, Compression & Resource Limits
ws_dos_tests = [
    test_connection_flood,          # 70
    test_oversized_message,         # 71
    test_max_connections,           # 72
    test_idle_timeout_abuse,        # 73
    test_high_compression_ratio,    # 74
    test_large_payload_leak,        # 75
    test_socket_leak_on_half_open,  # 76
    test_no_compression_negotiation,# 77
    test_no_timeout_policy,         # 78
]

def perform_websocket_tests(websocket_urls, payloads):
    """Perform WebSocket security tests concurrently, one thread per WebSocket."""
    ws_report = {}
    di1 = {
        "Handshake & Upgrade Validation":0,
        "Authentication & Session Control":0,
        "Subprotocols & Extension Handling":0,
        "Transport Security & Encryption":0,
        "Payload Framing & Messaging Semantics":0,
        "Origin Policy & Cross-Origin Enforcement":0,
        "Application-Layer Logic & Misconfigurations":0,
        "DoS, Compression & Resource Limits":0,
        "Protocol Fuzzing":0
    }
    valid_ws = websocket_urls

    
    def test_one_websocket(ws_url, payloads):
        """Test a single WebSocket URL and return vulnerabilities and category counts."""
        vulnerabilities = []
        local_di = {k: 0 for k in di1.keys()}

        def append_result(category, result):
            if not isinstance(result, dict):
                return
            vulnerabilities.append(result)
            if category and result.get("risk") != "No":
                local_di[category] += 1

        def run_safe(test_name, func, args, category):
            try:
                result = func(*args)
                append_result(category, result)
            except Exception as e:
                
                print(f"[!] {ws_url} -> {test_name} failed: {e}")

        try:
            parsed_url = urlparse(ws_url)
            host = parsed_url.hostname
            scheme = parsed_url.scheme
            port = parsed_url.port or (443 if scheme == 'wss' else 80)
            path = parsed_url.path or "/"

            run_safe("test_invalid_port", test_invalid_port, (ws_url,), "Handshake & Upgrade Validation")
            run_safe("test_non_ws_scheme", test_non_ws_scheme, (ws_url,), "Handshake & Upgrade Validation")

            for test_func in handshake_tests:
                run_safe(f"{test_func.__name__}", test_func, (host, port, path, scheme), "Handshake & Upgrade Validation")

            for test_func in auth_session_tests:
                run_safe(f"{test_func.__name__}", test_func, (ws_url,), "Authentication & Session Control")

            for test_func in ws_subprotocol_tests:
                run_safe(f"{test_func.__name__}", test_func, (ws_url,), "Subprotocols & Extension Handling")

            for test_func in subprotocol_tests:
                run_safe(f"{test_func.__name__}", test_func, (host, port, path), "Subprotocols & Extension Handling")

            for test_func in security_tests:
                run_safe(f"{test_func.__name__}", test_func, (host, port, path), "Transport Security & Encryption")

            for test_func in ws_security_tests:
                run_safe(f"{test_func.__name__}", test_func, (ws_url,), "Transport Security & Encryption")

            for test_func in payload_tests:
                run_safe(f"{test_func.__name__}", test_func, (ws_url,), "Payload Framing & Messaging Semantics")

            for test_func in cross_origin_tests:
                run_safe(f"{test_func.__name__}", test_func, (ws_url,), "Origin Policy & Cross-Origin Enforcement")

            for test_func in ws_app_tests:
                run_safe(f"{test_func.__name__}", test_func, (ws_url,), "Application-Layer Logic & Misconfigurations")

            for test_func in ws_dos_tests:
                run_safe(f"{test_func.__name__}", test_func, (ws_url,), "DoS, Compression & Resource Limits")

            for idx, item in enumerate(payloads, 1):
                test_name = item.get("name", f"Protocol Fuzzing #{idx}")
                try:
                    res = test_fuzzing(ws_url, item["payload"], test_name)
                    if isinstance(res, dict):
                        res = dict(res)
                        res["name"] = test_name
                    append_result(test_name, res)
                except Exception as e:
                    print(f"[!] {ws_url} -> {test_name} failed: {e}")
        except Exception as e:
           
            print(f"[!] Error while testing {ws_url}: {e}")
        finally:
            print(f"[{ws_url}] Tests finished. Collected {len(vulnerabilities)} result entries.")

        return ws_url, vulnerabilities, local_di
    #Run threads for each WebSocket URL
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(test_one_websocket, ws, payloads): ws for ws in valid_ws}
        for future in as_completed(futures):
            try:
                ws_url, vulns, local_di = future.result()
                ws_report[ws_url] = vulns
                for k in di1:
                    di1[k] += local_di.get(k, 0)
            except Exception as e:
                print(f"[!] Error testing {futures[future]}: {e}")
                ws_report.setdefault(futures[future], [])
                print(ws_report)
    return ws_report, di1

        
