"""
Syslog receivers (agentless push). Stands in for a Vector / rsyslog relay.

  UDP  -- one datagram = one event (RFC 3164 / 5424 / bare vendor formats)
  TCP  -- newline-framed or RFC 6587 octet-counted ("<len> <msg>") streams

Whatever arrives is handed to the pipeline byte-for-byte; the envelope is
parsed later, generically, by src/parser/envelope.py.
"""
import re
import socket
import socketserver
import threading

from src import config
from src.pipeline import process_event


def _serve_udp(port: int, channel: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind(("0.0.0.0", port))
    print(f"[syslog] listening on UDP :{port} (channel={channel})")
    while True:
        data, addr = sock.recvfrom(65535)
        try:
            process_event(data.rstrip(b"\r\n\x00"), channel=channel)
        except Exception as e:  # noqa: BLE001 - ingestion must never crash on a bad packet
            print(f"[syslog] error handling packet from {addr}: {e}")


_OCTET = re.compile(rb"^(\d{1,6}) ")


class _TcpHandler(socketserver.StreamRequestHandler):
    channel = "tcp:5514"

    def handle(self):
        buf = b""
        while True:
            chunk = self.request.recv(65536)
            if not chunk:
                break
            buf += chunk
            while buf:
                m = _OCTET.match(buf)
                if m:  # RFC 6587 octet counting
                    n = int(m.group(1))
                    start = m.end()
                    if len(buf) < start + n:
                        break
                    msg, buf = buf[start:start + n], buf[start + n:]
                else:  # newline framing
                    idx = buf.find(b"\n")
                    if idx < 0:
                        break
                    msg, buf = buf[:idx], buf[idx + 1:]
                msg = msg.strip(b"\r\n\x00")
                if msg:
                    try:
                        process_event(msg, channel=self.channel)
                    except Exception as e:  # noqa: BLE001
                        print(f"[syslog-tcp] error: {e}")
        if buf.strip():
            process_event(buf.strip(), channel=self.channel)


def start_background(port: int = None, channel: str = None):
    port = port or config.SYSLOG_UDP_PORT
    t = threading.Thread(target=_serve_udp, args=(port, channel or f"udp:{port}"), daemon=True)
    t.start()
    return t


def start_tcp_background(port: int = None, channel: str = None):
    port = port or config.SYSLOG_UDP_PORT
    handler = type("Handler", (_TcpHandler,), {"channel": channel or f"tcp:{port}"})
    server = socketserver.ThreadingTCPServer(("0.0.0.0", port), handler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[syslog] listening on TCP :{port} (channel={handler.channel})")
    return t
