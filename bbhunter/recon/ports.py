"""
TCP connect port tarayici (saf socket). SYN-stealth degildir; tam baglanti kurar.
Yalnizca kapsam ici hostlar/IP'ler taranir.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from ..scope import Scope
from ..util import good, info, parallel_map

# Yaygin web/servis portlari
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2375, 2376, 3000, 3306,
    3389, 4443, 5000, 5432, 5601, 5900, 5984, 6379, 7001, 8000, 8008, 8009,
    8080, 8081, 8088, 8089, 8443, 8500, 8888, 9000, 9042, 9090, 9200, 9300,
    9443, 10000, 11211, 15672, 27017, 27018,
]


@dataclass
class HostPorts:
    host: str
    open_ports: list[int] = field(default_factory=list)


def scan_host(host: str, ports: list[int], timeout: float = 2.0) -> HostPorts:
    result = HostPorts(host=host)

    def _probe(port: int) -> int | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    return port
        except (OSError, socket.gaierror, UnicodeError):
            return None
        return None

    for p in parallel_map(_probe, ports, threads=min(100, len(ports))):
        if p is not None:
            result.open_ports.append(p)
    result.open_ports.sort()
    return result


def scan(
    hosts: list[str],
    scope: Scope,
    *,
    ports: list[int] | None = None,
    timeout: float = 2.0,
    threads: int = 20,
) -> list[HostPorts]:
    ports = ports or TOP_PORTS
    targets = scope.filter(hosts)
    info(f"Port tarama: {len(targets)} host x {len(ports)} port")

    results: list[HostPorts] = []

    def _one(host: str) -> HostPorts:
        return scan_host(host, ports, timeout=timeout)

    for hp in parallel_map(_one, targets, threads=threads):
        if hp.open_ports:
            good(f"{hp.host}: {hp.open_ports}")
            results.append(hp)
    return results
