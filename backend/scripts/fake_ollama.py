import json
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        out={"category":"none","risk_level":"none","tool":None,"forbidden_action":None,"secrets":"none","reason":"заглушка"}
        raw=json.dumps({"message":{"content":json.dumps(out)}}).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    def log_message(self,*a):pass
HTTPServer(('127.0.0.1',11434),H).serve_forever()
