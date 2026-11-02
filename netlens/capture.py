import collections
import csv
import ipaddress
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import psutil

from .discovery import domain_name, enrich_networks, utcnow

FIELDS = ['frame.time_epoch', 'ip.src', 'ipv6.src', 'ip.dst', 'ipv6.dst',
          'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport',
          'dns.qry.name', 'dns.a', 'dns.aaaa', 'tls.handshake.extensions_server_name', 'http.host']
FLAGS = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0


def tshark_path(explicit=None):
    candidates = [explicit, os.environ.get('NETLENS_TSHARK'),
                  str(Path(__file__).resolve().parent.parent / 'third-party/wireshark/tshark.exe'),
                  r'C:\Program Files\Wireshark\tshark.exe', shutil.which('tshark')]
    for value in candidates:
        if value and Path(value).is_file():
            return str(Path(value).resolve())
    raise FileNotFoundError('Не найден tshark.exe. Установите Wireshark с TShark и Npcap.')


def interfaces(explicit=None):
    result = subprocess.run([tshark_path(explicit), '-D'], capture_output=True,
                            encoding='utf-8', errors='replace', timeout=15, creationflags=FLAGS)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return [line for line in result.stdout.splitlines() if line.strip()]


def ip_normal(value):
    return str(ipaddress.ip_address(value.split('%')[0]))


def socket_rows(connections):
    rows = []
    for conn in connections:
        if not conn.laddr:
            continue
        proto = 'tcp' if conn.type == socket.SOCK_STREAM else 'udp'
        local = (ip_normal(conn.laddr.ip), conn.laddr.port)
        remote = (ip_normal(conn.raddr.ip), conn.raddr.port) if conn.raddr else None
        rows.append((proto, local, remote, conn.pid))
    return rows


def packet_tuple(row):
    try:
        timestamp = float(row[0])
        src, dst = ip_normal(row[1] or row[2]), ip_normal(row[3] or row[4])
        if row[5] and row[6]:
            return timestamp, 'tcp', (src, int(row[5])), (dst, int(row[6]))
        if row[7] and row[8]:
            return timestamp, 'udp', (src, int(row[7])), (dst, int(row[8]))
    except (ValueError, IndexError):
        pass
    return None


def owners_for_packet(proto, src, dst, rows):
    """Return all possible owners; wildcard UDP binds can overlap other sockets."""
    matches = set()
    for transport, local, remote, pid in rows:
        if transport != proto:
            continue
        for ours, theirs in ((src, dst), (dst, src)):
            if local[1] != ours[1]:
                continue
            if local[0] != ours[0] and not (
                proto == 'udp' and local[0] in ('0.0.0.0', '::') and
                ipaddress.ip_address(local[0]).version == ipaddress.ip_address(ours[0]).version
            ):
                continue
            if remote and remote != theirs:
                continue
            if proto == 'tcp' and not remote:
                continue
            matches.add((pid, theirs))
    return matches


def valid_names(value):
    result = set()
    for part in value.split(','):
        try:
            result.add(domain_name(part))
        except (ValueError, UnicodeError):
            pass
    return result


def analyze_packets(path, snapshots, targets, socket_endpoints):
    """Use only adjacent socket snapshots, never session-wide UDP port ownership."""
    endpoints = dict(socket_endpoints)
    dns_answers = collections.defaultdict(list)
    packets, matched, ambiguous = 0, 0, 0
    cursor = 0
    # Snapshots are timestamped when enumeration starts and finishes. Wide/slow
    # samples are deliberately excluded from packet attribution.
    with open(path, encoding='utf-8', errors='replace', newline='') as stream:
        for row in csv.reader(stream, delimiter='\t', quoting=csv.QUOTE_NONE):
            if len(row) != len(FIELDS):
                continue
            packet = packet_tuple(row)
            if not packet:
                continue
            packets += 1
            timestamp, proto, src, dst = packet
            while cursor + 1 < len(snapshots) and snapshots[cursor + 1][0] <= timestamp:
                cursor += 1
            near = []
            for index in (cursor - 1, cursor, cursor + 1):
                if 0 <= index < len(snapshots):
                    start, end, rows, active = snapshots[index]
                    if end - start <= 0.5 and start - 0.15 <= timestamp <= end + 0.15:
                        near.append((rows, active))
            owners = set()
            active_targets = set()
            for rows, active in near:
                owners.update(owners_for_packet(proto, src, dst, rows))
                active_targets.update(active)
            names = valid_names(row[9])
            for ip in (row[10] + ',' + row[11]).split(','):
                try:
                    dns_answers[ip_normal(ip)].append((timestamp, names))
                except ValueError:
                    pass
            relevant = {(pid, remote) for pid, remote in owners if pid in active_targets}
            if not relevant:
                continue
            # Local app-to-app traffic and shared binds are kept out of confirmed output.
            if len(relevant) != 1:
                ambiguous += 1
                continue
            pid, remote = next(iter(relevant))
            if any(other_pid != pid and other_remote == remote for other_pid, other_remote in owners):
                ambiguous += 1
                continue
            matched += 1
            key = (proto, remote[0], remote[1])
            if key not in endpoints:
                endpoints[key] = new_endpoint(proto, remote, pid, '')
                endpoints[key]['first_seen'] = timestamp
                endpoints[key]['last_seen'] = timestamp
            item = endpoints[key]
            item['first_seen'] = min(item['first_seen'], timestamp)
            item['last_seen'] = max(item['last_seen'], timestamp)
            item['pids'].add(pid)
            item['evidence'].add('tcp_tuple_sampled' if proto == 'tcp' else 'udp_unique_bind_sampled')
            item['packets'] += 1
            for field, source in ((row[12], 'tls_sni'), (row[13].split(':', 1)[0], 'http_host')):
                for name in valid_names(field):
                    item['hostnames'].add((name, source))
            if remote[1] == 53:
                for name in names:
                    item['hostnames'].add((name, 'dns_query_on_process_socket'))
    for item in endpoints.values():
        # Shared resolver/CDN answers are merely candidates, with no ownership claim.
        for timestamp, names in dns_answers.get(item['ip'], []):
            if item['first_seen'] - 60 <= timestamp <= item['last_seen'] + 1:
                item['dns_candidates'].update(names)
        item['pids'] = sorted(item['pids'])
        item['evidence'] = sorted(s for s in item['evidence'] if s)
        item['hostnames'] = [{'name': n, 'source': s} for n, s in sorted(item['hostnames'])]
        item['dns_candidates'] = sorted(item['dns_candidates'])
    return sorted(endpoints.values(), key=lambda r: (r['ip'], r['transport'], r['port'])), {
        'ip_packets': packets, 'attributed_packets': matched, 'ambiguous_packets': ambiguous}


def new_endpoint(proto, remote, pid, evidence):
    now = time.time()
    return {'ip': remote[0], 'port': remote[1], 'transport': proto, 'pids': {pid},
            'evidence': {evidence} if evidence else set(), 'packets': 0,
            'hostnames': set(), 'dns_candidates': set(), 'first_seen': now, 'last_seen': now}


def capture(exe, interface_ids, seconds=60, args=(), include_children=True,
            attach=False, networks=True, tshark=None, log=lambda _: None, cancel=None):
    exe = Path(exe).resolve(strict=True)
    if exe.suffix.lower() != '.exe':
        raise ValueError('Выберите исполняемый файл .exe.')
    if not interface_ids or not 1 <= seconds <= 3600:
        raise ValueError('Выберите интерфейс и длительность от 1 до 3600 секунд.')
    cancel = cancel or threading.Event()
    report = {'kind': 'capture', 'created_at': utcnow(), 'exe': str(exe),
              'interfaces': list(interface_ids), 'duration_requested': seconds,
              'warnings': [], 'processes': [], 'sampling_interval': 0.1}
    binary = tshark_path(tshark)
    report['tshark'] = binary
    targets = {}  # PID -> creation time, protects against PID reuse.
    if attach:
        for proc in psutil.process_iter(['exe', 'create_time']):
            try:
                if proc.info['exe'] and os.path.normcase(proc.info['exe']) == os.path.normcase(str(exe)):
                    targets[proc.pid] = proc.info['create_time']
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        if not targets:
            raise ValueError('Запущенный процесс с указанным путём не найден.')
    command = [binary, '-n', '-l', '-a', f'duration:{seconds}', '-c', '200000',
               '-f', 'ip or ip6', '-T', 'fields', '-E', 'separator=/t',
               '-E', 'quote=n', '-E', 'occurrence=a']
    for interface in interface_ids:
        command.extend(['-i', str(interface)])
    for field in FIELDS:
        command.extend(['-e', field])
    ready = threading.Event()
    stderr_lines = collections.deque(maxlen=80)
    snapshots, endpoints, seen_processes = [], {}, set()
    capture_children = []
    with tempfile.TemporaryDirectory(prefix='netlens-') as temp:
        packet_file = Path(temp) / 'packets.tsv'
        with packet_file.open('w', encoding='utf-8', newline='') as output:
            sniffer = subprocess.Popen(command, stdout=output, stderr=subprocess.PIPE,
                                       encoding='utf-8', errors='replace', creationflags=FLAGS)
            def read_stderr():
                for line in sniffer.stderr:
                    stderr_lines.append(line.strip())
                    if 'Capturing on' in line:
                        ready.set()
            reader = threading.Thread(target=read_stderr, daemon=True)
            reader.start()
            try:
                until = time.monotonic() + 15
                while not ready.wait(0.1):
                    if sniffer.poll() is not None or time.monotonic() > until:
                        raise RuntimeError('Захват не запустился: ' + '\n'.join(stderr_lines))
                    if cancel.is_set():
                        raise RuntimeError('Запуск захвата отменён.')
                capture_children = psutil.Process(sniffer.pid).children(recursive=True)
                log('Захват готов. Запуск / подключение приложения…')
                if not attach:
                    launched = subprocess.Popen([str(exe), *args], cwd=str(exe.parent))
                    proc = psutil.Process(launched.pid)
                    targets[proc.pid] = proc.create_time()
                started = time.monotonic()
                while sniffer.poll() is None and not cancel.is_set():
                    tick = time.time()
                    active = set()
                    for pid, created in list(targets.items()):
                        try:
                            proc = psutil.Process(pid)
                            if proc.create_time() != created:
                                continue
                            active.add(pid)
                            if include_children:
                                for child in proc.children(recursive=True):
                                    targets.setdefault(child.pid, child.create_time())
                                    active.add(child.pid)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    for pid in active - seen_processes:
                        try:
                            proc = psutil.Process(pid)
                            report['processes'].append({'pid': pid, 'exe': proc.exe(),
                                                        'created': targets[pid]})
                            seen_processes.add(pid)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    rows = socket_rows(psutil.net_connections(kind='inet'))
                    target_ports = {(proto, local[1]) for proto, local, remote, pid in rows if pid in active}
                    # Retain competing owners for the same ports, not all system sockets.
                    rows = [r for r in rows if (r[0], r[1][1]) in target_ports]
                    end = time.time()
                    snapshots.append((tick, end, rows, active))
                    for proto, local, remote, pid in rows:
                        if pid in active and remote:
                            key = (proto, *remote)
                            item = endpoints.setdefault(key, new_endpoint(proto, remote, pid, 'socket_table'))
                            item['pids'].add(pid)
                            item['last_seen'] = end
                    if len(snapshots) % 20 == 1:
                        log(f'Захват: {time.monotonic() - started:.0f} с; процессов {len(active)}; адресов {len(endpoints)}')
                    cancel.wait(max(0, 0.1 - (time.time() - tick)))
                report['elapsed_seconds'] = round(time.monotonic() - started, 2)
                if sniffer.poll() is not None and sniffer.returncode:
                    raise RuntimeError('Ошибка TShark: ' + '\n'.join(stderr_lines))
            finally:
                if sniffer.poll() is None:
                    try:
                        capture_children.extend(psutil.Process(sniffer.pid).children(recursive=True))
                    except psutil.Error:
                        pass
                    sniffer.terminate()
                try:
                    sniffer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    sniffer.kill()
                    sniffer.wait()
                for child in capture_children:
                    try:
                        if child.is_running():
                            child.terminate()
                    except psutil.Error:
                        pass
                reader.join(timeout=3)
                sniffer.stderr.close()
        log('Сопоставление пакетов с процессами…')
        report['endpoints'], report['statistics'] = analyze_packets(packet_file, snapshots, targets, endpoints)
    report['cancelled'] = cancel.is_set()
    report['warnings'].extend([
        'Привязка пакетов выполняется по периодическим снимкам сокетов; короткие соединения могут быть пропущены.',
        'DNS candidates — предположения по общему DNS-трафику, а не доказательство обращения приложения.',
        'DoH/DoT, TLS ECH, VPN/прокси и передача работы другому процессу могут скрывать домены или конечные адреса.',
        'Захват ограничен 200000 пакетами. Выбранные интерфейсы могут содержать трафик других программ.'
    ])
    report['networks'] = enrich_networks([r['ip'] for r in report['endpoints']], log, cancel) if networks else []
    return report
