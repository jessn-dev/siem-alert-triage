import http.server
import queue
import threading

from src.sources.base import BaseSource

MAX_BODY_BYTES = 1024 * 1024


class WebhookSource(BaseSource):
    """HTTP ingestion. Removes the shared-filesystem dependency between
    producer and engine, which is what makes multi-node scheduling possible.

    Accepts one JSON object per request, or newline-delimited JSON batches.
    """

    def __init__(self, host="0.0.0.0", port=8002, maxsize=10000, auth_token=None):
        self.host = host
        self.port = port
        self.auth_token = auth_token
        # Bounded: if detection falls behind, shed load loudly instead of
        # growing the queue until the process is OOM-killed.
        self.q = queue.Queue(maxsize=maxsize)
        self.dropped = 0
        self.running = True

        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                if outer.auth_token:
                    import hmac
                    auth_header = self.headers.get('Authorization')
                    if not hmac.compare_digest(auth_header or "", f"Bearer {outer.auth_token}"):
                        self.send_response(401)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return

                length = int(self.headers.get('content-length', 0))
                if length <= 0 or length > MAX_BODY_BYTES:
                    self.send_response(413 if length else 400)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return

                body = self.rfile.read(length).decode('utf-8', errors='replace')
                accepted = 0
                for line in body.splitlines():
                    if not line.strip():
                        continue
                    try:
                        outer.q.put_nowait(line)
                        accepted += 1
                    except queue.Full:
                        outer.dropped += 1

                self.send_response(202 if accepted else 503)
                self.send_header('Content-Length', '0')
                self.end_headers()

            def do_GET(self):
                # Container healthcheck target.
                self.send_response(200 if outer.running else 503)
                self.send_header('Content-Length', '0')
                self.end_headers()

            def log_message(self, fmt, *args):
                pass

        self.server = http.server.ThreadingHTTPServer((self.host, self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def read_events(self):
        while self.running:
            try:
                # Yielding None on idle keeps the engine's housekeeping timer
                # ticking even when no events are arriving.
                yield self.q.get(timeout=1.0)
            except queue.Empty:
                yield None
        self.server.shutdown()
