"""Detect the Windows capture driver without installing or changing services."""
from .i18n import tr
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess

NPCAP_DOWNLOAD_URL = 'https://npcap.com/#download'
WINDOWS = os.name == 'nt'


@dataclass(frozen=True)
class DriverStatus:
    available: bool
    message: str


def npcap_status():
    if not WINDOWS:
        return DriverStatus(False, tr('Захват Windows-приложений доступен в Windows'))
    system = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'
    if not all((system / 'Npcap' / name).is_file() for name in ('wpcap.dll', 'Packet.dll')):
        return DriverStatus(False, tr('Для захвата приложения установите драйвер Npcap'))
    try:
        result = subprocess.run([str(system / 'sc.exe'), 'query', 'npcap'], capture_output=True,
                                timeout=3, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, subprocess.TimeoutExpired):
        return DriverStatus(False, tr('Не удалось проверить службу Npcap'))
    if result.returncode:
        return DriverStatus(False, tr('Служба Npcap недоступна. Проверьте установку драйвера'))
    return DriverStatus(True, tr('Npcap установлен'))
