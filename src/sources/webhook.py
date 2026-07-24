import http.server
import threading
import queue
from src.sources.base import BaseSource

class WebhookSource(BaseSource):
    def __init__(self, host="0.0.0.0", port=8002):
        self.host = host
        self.port = port
        self.q = queue.Queue()
        self.running = True
        
        outer = self
        
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(req):
                content_len = int(req.headers.get('content-length', 0))
                post_body = req.rfile.read(content_len)
                outer.q.put(post_body.decode('utf-8'))
                req.send_response(200)
                req.end_headers()
                
            def log_message(self, format, *args):
                pass
                
        self.server = http.server.HTTPServer((self.host, self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        
    def read_events(self):
        while self.running:
            try:
                line = self.q.get(timeout=1.0)
                yield line
            except queue.Empty:
                yield None
