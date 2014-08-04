import SimpleHTTPServer
import SocketServer
import daemon
import os

""" Setup Server Params """
handler = SimpleHTTPServer.SimpleHTTPRequestHandler
SocketServer.TCPServer.allow_reuse_address = True
httpd = SocketServer.TCPServer(("0.0.0.0", 8000), handler)
daemon_context = daemon.DaemonContext()
daemon_context.files_preserve = [httpd.fileno()]

with daemon_context:
    os.chdir("/tmp/")
    httpd.handle_request()

