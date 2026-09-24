"""
Minimal UDP syslog receiver. Stands in for Vector's syslog source in this
prototype -- same role (agentless push listener), simplified to stdlib
sockets so the whole project runs with zero external services.
"""
import socket
import threading

from src import config
from src.pipeline import process_event


def _serve(port: int, channel: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"[syslog] listening on UDP :{port} (channel={channel})")
    while True:
        data, addr = sock.recvfrom(65535)
        try:
            process_event(data, channel=channel)
        except Exception as e:  # noqa: BLE001 - ingestion must never crash on a bad packet
            print(f"[syslog] error handling packet from {addr}: {e}")


def start_background(port: int = None):
    port = port or config.SYSLOG_UDP_PORT
    t = threading.Thread(target=_serve, args=(port, f"udp:{port}"), daemon=True)
    t.start()
    return t
