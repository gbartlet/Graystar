from http.server import BaseHTTPRequestHandler, HTTPServer


class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)

        self.send_header('Content type', 'text/html')
        self.end_headers()

        message = "Welcome to GrayStar server"
        self.wfile.write(bytes(message,"utf8"))
        return

try:
    server_address = ('127.0.0.1', 8081)
    httpd = HTTPServer(server_address,testHTTPServer_RequestHandler)
    print ('running server...')
    httpd.serve_forever()
except KeyboardInterrupt:
    print ('^C received, shutting down the web server')
    httpd.socket.close()
