#!/usr/bin/env python3
# The script runs server which used as local mock of destination service API
# This tool allows to check headers after modification by krakend (JWT claims propagation, modifiers)
# Run server: python dump_server.py

import http.server as SimpleHTTPServer
import socketserver as SocketServer
import logging

PORT = 8000

class GetHandler(
        SimpleHTTPServer.SimpleHTTPRequestHandler
        ):

    def do_GET(self):
        logging.error(self.headers)
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)


Handler = GetHandler
httpd = SocketServer.TCPServer(("", PORT), Handler)

logging.error("Starting server")
httpd.serve_forever()
