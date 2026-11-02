"""Opt-in integration test. Launches only the Python fixture, captures loopback."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from netlens.capture import capture
from netlens.report import save_report


def fixture(port, udp_port):
    with socket.create_connection(('127.0.0.1', int(port))) as connection:
        time.sleep(0.5)
        connection.sendall(b'GET / HTTP/1.1\r\nHost: fixture.example.com\r\nConnection: close\r\n\r\n')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(('127.0.0.1', 0))
            time.sleep(0.5)
            for _ in range(4):
                udp.sendto(b'netlens-fixture', ('127.0.0.1', int(udp_port)))
                time.sleep(0.3)
        connection.recv(1024)


def main():
    with socket.socket() as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        server.bind(('127.0.0.1', 0))
        server.listen()
        udp.bind(('127.0.0.1', 0))
        port, udp_port = server.getsockname()[1], udp.getsockname()[1]
        def serve():
            with server.accept()[0] as connection:
                connection.recv(4096)
                time.sleep(2)
                connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
        threading.Thread(target=serve, daemon=True).start()
        report = capture(sys.executable, ['\\Device\\NPF_Loopback'], 6,
                         [str(Path(__file__).resolve()), '--fixture', str(port), str(udp_port)],
                         networks=False, log=print)
        save_report(report, 'reports/live-capture')
        endpoints = report['endpoints']
        assert any(e['port'] == port and e['transport'] == 'tcp' for e in endpoints), endpoints
        assert any(e['port'] == udp_port and e['transport'] == 'udp' and e['packets'] > 0 for e in endpoints), endpoints
        assert any(n['name'] == 'fixture.example.com' and n['source'] == 'http_host'
                   for e in endpoints for n in e['hostnames']), endpoints
        print('LIVE PASS', json.dumps(report['statistics']))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--fixture':
        fixture(*sys.argv[2:])
    else:
        main()
