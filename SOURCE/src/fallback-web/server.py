#!/usr/bin/env python3
# Managed by sbox-manager
"""SBOX Personal Cloud: hardened, loopback-only, read-only HTTPS static site.

Used only as the *self-hosted* REALITY fallback. Ordinary (non-REALITY) TLS
connections that reach the public REALITY listener are forwarded by sing-box to
this local listener, so a browser sees a real multi-page website served with
the owner's own trusted certificate.

Security boundary (see docs/reality-fallback.md):
  * binds only to 127.0.0.1 or ::1; any other address is refused at start-up;
  * serves regular files below one read-only site root; no directory listing,
    no dotfiles, no symlinks, no path traversal, no uploads, no CGI;
  * GET and HEAD only; every other method answers 405; request bodies are
    rejected; header, line and connection counts/time are bounded;
  * strict security headers; no third-party scripts, fonts or analytics;
  * never touches SBOX state, credentials, the WebUI or the admin API.

Python standard library only. Python >= 3.10.
"""
import argparse
import email.utils
import errno
import http.server
import ipaddress
import json
import os
import signal
import socket
import ssl
import stat
import sys
import threading
import time
import urllib.parse

SITE_MARKER = '<meta name="generator" content="sbox-personal-cloud">'
LOOPBACK = {'127.0.0.1', '::1'}
MAX_PATH = 512
MAX_REQUEST_LINE = 2048
MAX_HEADERS = 48
MAX_FILE = 16 * 1024 * 1024
DEFAULT_CONNECTIONS = 32
# REALITY relays every ClientHello on its port here, authenticated users
# included, and needs this site's TLS handshake to finish theirs. Handshakes
# therefore get their own, larger bound with a short timeout; the HTTP-serving
# bound above applies only after TLS. See docs/reality-fallback.md.
DEFAULT_HANDSHAKES = 192
DEFAULT_HANDSHAKE_TIMEOUT = 5.0
BUSY_RESPONSE = (b'HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n'
                 b'Content-Length: 12\r\nRetry-After: 5\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n'
                 b'Server busy\n')
TYPES = {
    '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
    '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp',
    '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8', '.csv': 'text/csv; charset=utf-8',
    '.md': 'text/markdown; charset=utf-8', '.pdf': 'application/pdf', '.json': 'application/json',
}
# Only curated library files are offered as downloads.
DOWNLOAD_PREFIX = '/library/'
CSP = ("default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
       "img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'none'; object-src 'none'")
SECURITY_HEADERS = (
    ('Content-Security-Policy', CSP),
    ('X-Content-Type-Options', 'nosniff'),
    ('Referrer-Policy', 'no-referrer'),
    ('X-Frame-Options', 'DENY'),
    ('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()'),
    ('Cross-Origin-Opener-Policy', 'same-origin'),
    ('Cross-Origin-Resource-Policy', 'same-origin'),
    ('Strict-Transport-Security', 'max-age=15552000'),
)


class Refused(Exception):
    """Configuration that must never be served."""


def loopback_only(address):
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        raise Refused('listen address must be a literal IP address') from None
    if str(parsed) not in LOOPBACK:
        raise Refused('listen address must be 127.0.0.1 or ::1, not ' + str(parsed))
    return str(parsed)


def valid_hostname(name):
    if not isinstance(name, str) or not 1 <= len(name) <= 253 or name.endswith('.'):
        return False
    labels = name.split('.')
    return len(labels) >= 2 and all(
        1 <= len(x) <= 63 and x[0] != '-' and x[-1] != '-' and all(c.isascii() and (c.isalnum() or c == '-') for c in x)
        for x in labels)


def resolve(root_fd, root_real, url_path):
    """Map a decoded URL path to an open regular file descriptor or None.

    The walk uses openat-style lookups relative to the root descriptor with
    O_NOFOLLOW at every component, so a symlink anywhere below the root (or a
    swapped component) is refused rather than followed."""
    if len(url_path) > MAX_PATH or '\x00' in url_path or '\\' in url_path or not url_path.startswith('/'):
        return None, 'bad'
    parts = [p for p in url_path.split('/') if p != '']
    for part in parts:
        if part in ('.', '..') or part.startswith('.') or part.startswith('~'):
            return None, 'hidden'
    directory_request = url_path.endswith('/') or not parts
    if directory_request:
        parts = parts + ['index.html']
    name = parts[-1]
    ext = os.path.splitext(name)[1].lower()
    if ext not in TYPES:
        # A directory without trailing slash is redirected; anything else is absent.
        return None, 'type'
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    dir_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                nxt = os.open(part, flags | os.O_DIRECTORY, dir_fd=dir_fd)
            except OSError:
                return None, 'missing'
            os.close(dir_fd)
            dir_fd = nxt
        try:
            fd = os.open(parts[-1], flags | getattr(os, 'O_NONBLOCK', 0), dir_fd=dir_fd)
        except OSError:
            return None, 'missing'
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
            os.close(fd)
            return None, 'missing'
        # Defence in depth: the resolved file must still live below the root.
        real = os.path.realpath('/proc/self/fd/%d' % fd) if os.path.exists('/proc/self/fd') else None
        if real is not None and not (real == root_real or real.startswith(root_real + os.sep)):
            os.close(fd)
            return None, 'escape'
        return fd, ext
    finally:
        os.close(dir_fd)


def is_directory(root_fd, url_path):
    parts = [p for p in url_path.split('/') if p]
    if not parts or any(p.startswith('.') or p in ('..',) for p in parts):
        return False
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | getattr(os, 'O_CLOEXEC', 0)
    dir_fd = os.dup(root_fd)
    try:
        for part in parts:
            try:
                nxt = os.open(part, flags, dir_fd=dir_fd)
            except OSError:
                return False
            os.close(dir_fd)
            dir_fd = nxt
        return True
    finally:
        os.close(dir_fd)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'PersonalCloud'
    sys_version = ''
    protocol_version = 'HTTP/1.1'
    timeout = 15
    disable_nagle_algorithm = True

    # Any method other than GET/HEAD (including unknown ones) is 405, never 501.
    def __getattr__(self, name):
        if name.startswith('do_'):
            return self.method_not_allowed
        raise AttributeError(name)

    def log_message(self, fmt, *args):
        if not self.server.quiet:
            sys.stderr.write('%s %s\n' % (time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), fmt % args))

    def log_request(self, code='-', size='-'):
        # Never log query strings or headers.
        raw = getattr(self, 'path', None)
        path = raw.split('?', 1)[0][:200] if isinstance(raw, str) else '-'
        self.log_message('%s %s %s', getattr(self, 'command', None) or '-', path, code)

    def version_string(self):
        return self.server_version

    def parse_request(self):
        if len(self.raw_requestline) > MAX_REQUEST_LINE:
            self.requestline = ''
            self.command = None
            self.path = '-'
            self.request_version = 'HTTP/1.1'
            self.close_connection = True
            self.send_error(414)
            return False
        if not super().parse_request():
            return False
        if len(self.headers) > MAX_HEADERS:
            self.close_connection = True
            self.send_error(431)
            return False
        return True

    def common_headers(self, kind='text/html; charset=utf-8', length=0, cache='no-cache'):
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(length))
        self.send_header('Cache-Control', cache)
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)

    def error_page(self, code, extra=()):
        body = b''
        if code == 404:
            fd, _ = resolve(self.server.root_fd, self.server.root_real, '/404.html')
            if fd is not None:
                with os.fdopen(fd, 'rb') as fh:
                    body = fh.read()
        if not body:
            title = {400: 'Bad request', 405: 'Method not allowed', 413: 'Request too large', 421: 'Misdirected request',
                     414: 'Address too long', 431: 'Headers too large'}.get(code, 'Error')
            body = ('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>%s</title></head>'
                    '<body><h1>%s</h1><p><a href="/">Personal Cloud home</a></p></body></html>' % (title, title)).encode()
        self.send_response(code)
        self.common_headers(length=len(body))
        for name, value in extra:
            self.send_header(name, value)
        if code in (400, 405, 413, 414, 421, 431):
            self.send_header('Connection', 'close')
            self.close_connection = True
        self.end_headers()
        if getattr(self, 'command', None) != 'HEAD':
            self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler's default error body echoes request data; use ours.
        try:
            self.error_page(code)
        except Exception:
            self.close_connection = True

    def method_not_allowed(self):
        self.error_page(405, (('Allow', 'GET, HEAD'),))

    def has_body(self):
        length = self.headers.get('Content-Length')
        if self.headers.get('Transfer-Encoding'):
            return True
        if length is None:
            return False
        try:
            return int(length) != 0
        except ValueError:
            return True

    def host_ok(self):
        host = (self.headers.get('Host') or '').strip().lower()
        if not host:
            return False
        if host.startswith('['):
            name = host[1:host.find(']')] if ']' in host else host
        else:
            name = host.rsplit(':', 1)[0] if host.count(':') == 1 else host
        return name == self.server.hostname

    def do_GET(self):
        self.serve(head=False)

    def do_HEAD(self):
        self.serve(head=True)

    def serve(self, head):
        if self.has_body():
            return self.error_page(413)
        if not self.host_ok():
            return self.error_page(421)
        target = self.path
        if '://' in target.split('?', 1)[0]:
            return self.error_page(400)
        raw = target.split('?', 1)[0].split('#', 1)[0]
        try:
            path = urllib.parse.unquote(raw, errors='strict')
        except UnicodeDecodeError:
            return self.error_page(400)
        if '//' in path:
            return self.error_page(404)
        fd, kind = resolve(self.server.root_fd, self.server.root_real, path)
        if fd is None:
            if kind == 'type' and not path.endswith('/') and is_directory(self.server.root_fd, path):
                location = urllib.parse.quote(path + '/')
                self.send_response(301)
                self.common_headers(length=0)
                self.send_header('Location', location)
                self.end_headers()
                return None
            return self.error_page(404)
        with os.fdopen(fd, 'rb') as fh:
            info = os.fstat(fh.fileno())
            modified = email.utils.formatdate(info.st_mtime, usegmt=True)
            etag = '"%x-%x"' % (int(info.st_mtime), info.st_size)
            if self.headers.get('If-None-Match') == etag:
                self.send_response(304)
                self.send_header('ETag', etag)
                for name, value in SECURITY_HEADERS:
                    self.send_header(name, value)
                self.end_headers()
                return None
            body = b'' if head else fh.read(MAX_FILE + 1)
        self.send_response(200)
        cache = 'no-cache' if kind == '.html' else 'public, max-age=3600'
        self.common_headers(TYPES[kind], info.st_size, cache)
        self.send_header('Last-Modified', modified)
        self.send_header('ETag', etag)
        if path.startswith(DOWNLOAD_PREFIX):
            name = os.path.basename(path)
            self.send_header('Content-Disposition', "attachment; filename*=UTF-8''" + urllib.parse.quote(name))
        self.end_headers()
        if not head:
            self.wfile.write(body)
        return None


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    allow_reuse_address = True

    def __init__(self, address, family, context, root, hostname, connections, quiet=False,
                 handshakes=DEFAULT_HANDSHAKES, handshake_timeout=DEFAULT_HANDSHAKE_TIMEOUT):
        self.address_family = family
        self.context_lock = threading.Lock()
        self.tls = context
        self.hostname = hostname
        self.quiet = quiet
        self.slots = threading.BoundedSemaphore(connections)
        self.handshake_slots = threading.BoundedSemaphore(max(handshakes, connections))
        self.handshake_timeout = handshake_timeout
        self.root_real = os.path.realpath(root)
        self.root_fd = os.open(self.root_real, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_CLOEXEC', 0))
        super().__init__(address, Handler)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()

    def set_context(self, context):
        with self.context_lock:
            self.tls = context

    def process_request(self, request, client_address):
        if not self.handshake_slots.acquire(blocking=False):
            # Handshake bound reached: shed load instead of queueing unboundedly.
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.handshake_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        serving = False
        try:
            request.settimeout(self.handshake_timeout)
            with self.context_lock:
                context = self.tls
            try:
                tls = context.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                self.shutdown_request(request)
                return
            serving = self.slots.acquire(blocking=False)
            try:
                if serving:
                    tls.settimeout(Handler.timeout)
                    self.finish_request(tls, client_address)
                else:
                    # TLS is complete (REALITY has what it needs); the serving
                    # bound is full, so answer a small 503 instead of a page.
                    tls.settimeout(1.0)
                    tls.sendall(BUSY_RESPONSE)
            except Exception:
                pass
            finally:
                # Send a TLS close_notify before the TCP close. A relaying
                # REALITY inbound forwards the alert, so clients see a clean end
                # of stream even where a bare FIN is held back by the relay.
                try:
                    tls.settimeout(0.5)
                    tls.unwrap()
                except (OSError, ValueError):
                    pass
                self.shutdown_request(tls)
        finally:
            if serving:
                self.slots.release()
            self.handshake_slots.release()

    def handle_error(self, request, client_address):
        pass


def tls_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION | getattr(ssl, 'OP_NO_RENEGOTIATION', 0)
    context.set_alpn_protocols(['http/1.1'])
    context.load_cert_chain(cert, key)
    return context


def certificate_covers(cert_path, hostname):
    """True if the PEM certificate's SAN DNS names cover hostname (RFC 6125)."""
    try:
        info = ssl._ssl._test_decode_cert(cert_path)  # stdlib PEM decoder; no network
    except Exception:
        return False
    names = [v.lower() for k, v in info.get('subjectAltName', ()) if k == 'DNS']
    host = hostname.lower()
    for name in names:
        if name == host:
            return True
        if name.startswith('*.') and host.count('.') >= 2 and host.split('.', 1)[1] == name[2:]:
            return True
    return False


def credential(path, name):
    """systemd LoadCredential= places secrets in $CREDENTIALS_DIRECTORY."""
    if path:
        return path
    directory = os.environ.get('CREDENTIALS_DIRECTORY')
    if not directory:
        raise Refused('certificate path not given and no systemd credentials directory is available')
    return os.path.join(directory, name)


def listeners_on_port(port):
    """Every LISTEN socket on TCP `port` from procfs: list of local IP strings."""
    found = []
    for table, family in (('/proc/net/tcp', socket.AF_INET), ('/proc/net/tcp6', socket.AF_INET6)):
        try:
            with open(table) as fh:
                rows = fh.read().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if len(fields) < 4 or fields[3] != '0A':
                continue
            address, port_hex = fields[1].split(':')
            if int(port_hex, 16) != port:
                continue
            raw = bytes.fromhex(address)
            if family == socket.AF_INET:
                ip = socket.inet_ntop(family, raw[::-1])
            else:
                ip = socket.inet_ntop(family, b''.join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
            found.append(ip)
    return found


def check(args):
    """Health check used by `sbox doctor` and the transaction: verified HTTPS."""
    result = {'listen': args.listen, 'port': args.port, 'hostname': args.hostname, 'checks': []}
    via = args.connect_port is not None
    target = (args.connect_host or args.listen, args.connect_port if via else args.port)
    if via:
        result['via'] = '%s:%d' % target

    def record(name, ok, detail='', severity='fail'):
        result['checks'].append({'check': name, 'ok': bool(ok), 'detail': detail, 'severity': severity})
        return ok

    addresses = listeners_on_port(args.port)
    record('listener present', bool(addresses), ','.join(addresses))
    record('listener loopback only', bool(addresses) and all(a in LOOPBACK or a == '::ffff:127.0.0.1' for a in addresses), ','.join(addresses))
    if via:
        record('relay port listening', bool(listeners_on_port(target[1])), ','.join(listeners_on_port(target[1])))
    context = ssl.create_default_context(cafile=args.cafile) if args.cafile else ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    pages = {}
    try:
        for page in ('/', '/files/', '/media/', '/about/'):
            with socket.create_connection(target, timeout=args.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=args.hostname) as tls:
                    if page == '/':
                        peer = tls.getpeercert()
                        subject = dict(x[0] for x in peer.get('subject', ()) if x)
                        record('certificate trusted and matches hostname', True, subject.get('commonName', ''))
                        record('certificate not expiring within 7 days', ssl.cert_time_to_seconds(peer['notAfter']) - time.time() > 7 * 86400, peer['notAfter'], 'warning')
                    tls.sendall(('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: sbox-doctor\r\n\r\n' % (page, args.hostname)).encode())
                    data = b''
                    while len(data) < 2 * 1024 * 1024:
                        chunk = tls.recv(65536)
                        if not chunk:
                            break
                        data += chunk
            head, _, body = data.partition(b'\r\n\r\n')
            status = head.split(b'\r\n', 1)[0].decode('latin-1', 'replace')
            pages[page] = status
            record('page %s served' % page, ' 200 ' in status + ' ' and SITE_MARKER.encode() in body, status)
    except (OSError, ssl.SSLError, KeyError, ValueError) as error:
        record('verified HTTPS request', False, type(error).__name__ + ': ' + str(error)[:200])
    result['ok'] = all(c['ok'] for c in result['checks'] if c['severity'] == 'fail')
    result['warnings'] = [c['check'] for c in result['checks'] if c['severity'] == 'warning' and not c['ok']]
    print(json.dumps(result, indent=None if args.compact else 2))
    return 0 if result['ok'] else 1


REQUIRED_PAGES = ('index.html', 'files/index.html', 'media/index.html', 'about/index.html')


def site_problems(root):
    """Required pages that this process cannot open and read, with the reason.

    Run as the sandboxed service user (ExecStartPre), so a permission or
    mount problem is reported with the exact path instead of a generic error."""
    problems = []
    for page in REQUIRED_PAGES:
        path = os.path.join(root, page)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
                    problems.append('%s: not a non-empty regular file' % path)
                elif SITE_MARKER.encode() not in os.read(fd, 65536):
                    problems.append('%s: not a Personal Cloud page' % path)
            finally:
                os.close(fd)
        except OSError as error:
            problems.append('%s: %s' % (path, error.strerror or type(error).__name__))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description='SBOX Personal Cloud loopback HTTPS site (REALITY self-hosted fallback).')
    parser.add_argument('--listen', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--root', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'site'))
    parser.add_argument('--cert', default='')
    parser.add_argument('--key', default='')
    parser.add_argument('--connections', type=int, default=DEFAULT_CONNECTIONS)
    parser.add_argument('--handshakes', type=int, default=DEFAULT_HANDSHAKES)
    parser.add_argument('--handshake-timeout', type=float, default=DEFAULT_HANDSHAKE_TIMEOUT)
    parser.add_argument('--quiet', action='store_true')
    parser.add_argument('--check', action='store_true', help='verify a running instance and exit')
    parser.add_argument('--preflight', action='store_true', help='verify that every required page is readable by this process and exit')
    parser.add_argument('--cafile', default='', help='health check only: lab CA instead of the system trust store')
    parser.add_argument('--timeout', type=float, default=5.0)
    parser.add_argument('--compact', action='store_true')
    parser.add_argument('--connect-port', type=int, default=None, help='health check only: connect here (e.g. the public REALITY port) instead of the website port')
    parser.add_argument('--connect-host', default='', help='health check only: loopback address used with --connect-port')
    if argv is None:
        argv = sys.argv[1:]
    if '--preflight' in argv and '--hostname' not in argv:
        argv = list(argv) + ['--hostname', 'preflight.invalid']
    args = parser.parse_args(argv)
    if args.preflight:
        problems = site_problems(os.path.realpath(args.root))
        for problem in problems:
            print('sbox-fallback-web: preflight: ' + problem, file=sys.stderr)
        if not problems:
            print('sbox-fallback-web: preflight: %d pages readable' % len(REQUIRED_PAGES), file=sys.stderr)
        return 2 if problems else 0
    try:
        args.listen = loopback_only(args.listen)
        if not valid_hostname(args.hostname):
            raise Refused('hostname is not a valid DNS name')
        if not 1024 <= args.port <= 65535:
            raise Refused('port must be 1024-65535')
        if args.check:
            if args.connect_host:
                args.connect_host = loopback_only(args.connect_host)
            if args.connect_port is not None and not 1 <= args.connect_port <= 65535:
                raise Refused('connect port must be 1-65535')
            return check(args)
        if not 1 <= args.connections <= 256:
            raise Refused('connections must be 1-256')
        if not args.connections <= args.handshakes <= 512:
            raise Refused('handshakes must be between connections and 512')
        if not 0.5 <= args.handshake_timeout <= 30:
            raise Refused('handshake timeout must be 0.5-30 seconds')
        cert, key = credential(args.cert, 'tls.crt'), credential(args.key, 'tls.key')
        if not certificate_covers(cert, args.hostname):
            raise Refused('certificate does not cover ' + args.hostname)
        root = os.path.realpath(args.root)
        problems = site_problems(root)
        if problems:
            raise Refused('site is not readable: ' + '; '.join(problems))
        family = socket.AF_INET6 if ':' in args.listen else socket.AF_INET
        threading.stack_size(512 * 1024)
        server = Server((args.listen, args.port), family, tls_context(cert, key), root, args.hostname.lower(), args.connections, args.quiet,
                        args.handshakes, args.handshake_timeout)
    except Refused as error:
        print('sbox-fallback-web: refused: ' + str(error), file=sys.stderr)
        return 2
    except (OSError, ssl.SSLError) as error:
        print('sbox-fallback-web: cannot start: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1 if getattr(error, 'errno', None) != errno.EADDRINUSE else 3

    def reload(*_):
        try:
            server.set_context(tls_context(cert, key))
            print('sbox-fallback-web: certificate reloaded', file=sys.stderr)
        except (OSError, ssl.SSLError) as error:
            print('sbox-fallback-web: reload failed, keeping previous certificate: ' + str(error), file=sys.stderr)

    signal.signal(signal.SIGHUP, reload)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    print('sbox-fallback-web: serving %s on https://%s:%d (loopback only)' % (args.hostname, args.listen, args.port), file=sys.stderr, flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
