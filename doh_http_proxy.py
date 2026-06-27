#!/usr/bin/env python3
from __future__ import annotations

import argparse
import atexit
import base64
import ctypes
import json
import ipaddress
import os
import selectors
import shutil
import subprocess
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote, urlsplit

import requests
import dns.message
import dns.rdatatype
import dns.rcode

DEFAULT_HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
DEFAULT_OPTIMIZE_DNS_REPORT_PATH = "optimized_dns_report.json"
DEFAULT_STARTUP_CONFIG_PATH = os.path.join(
    os.path.expanduser("~"),
    ".doh_http_proxy",
    "startup_config.json",
)

try:
    import msvcrt
except ImportError:  # pragma: no cover - non-Windows fallback
    msvcrt = None

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows fallback
    winreg = None


ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_WHITE = "\033[37m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"


def enable_ansi_colors() -> None:
    if os.name != "nt":
        return

    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        if handle == 0:
            return

        mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return

        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


ResolvedPair = Tuple[str, str]
ResolvedAddress = Tuple[str, socket.AddressFamily]


def normalize_host(host: str) -> str:
    host = host.strip().strip("[]").rstrip(".").lower()

    if not host:
        return host

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
        return True
    except ValueError:
        return False


def family_for_ip(ip: str) -> socket.AddressFamily:
    version = ipaddress.ip_address(ip).version
    return socket.AF_INET6 if version == 6 else socket.AF_INET


def is_benign_socket_disconnect(exc: BaseException) -> bool:
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return True

    winerror = getattr(exc, "winerror", None)
    return winerror in {10053, 10054}


def format_byte_count(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    amount = float(max(0, value))

    for unit in units:
        if amount < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(amount)} {unit}"

            return f"{amount:.1f} {unit}"

        amount /= 1024.0

    return f"{int(amount)} B"


class TrafficStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sent_bytes = 0
        self._received_bytes = 0

    def record_sent(self, amount: int) -> None:
        if amount <= 0:
            return

        with self._lock:
            self._sent_bytes += amount

    def record_received(self, amount: int) -> None:
        if amount <= 0:
            return

        with self._lock:
            self._received_bytes += amount

    def snapshot(self) -> Tuple[int, int]:
        with self._lock:
            return self._sent_bytes, self._received_bytes


def build_proxy_session_lines(
    config: StartupConfig,
    doh_urls: List[str],
    hosts_manager: Optional[HostsFileManager],
    optimize_dns_report_store: Optional["OptimizeDNSReportStore"],
    stats: TrafficStats,
) -> List[str]:
    lines = [
        f"Local HTTP proxy: http://{config.listen}:{config.port}",
        f"DoH file: {config.doh_file}",
        "DoH endpoints:",
    ]

    for index, url in enumerate(doh_urls, start=1):
        role = "primary" if index == 1 else f"fallback-{index - 1}"
        lines.append(f"  {index}. [{role}] {url}")

    lines.append(f"DoH method: {config.doh_method}")
    if config.use_doh_proxy and config.doh_proxy:
        lines.append(f"DoH proxy for all DoH endpoints: {config.doh_proxy}")
    else:
        lines.append("DoH proxy for all DoH endpoints: disabled")

    if config.use_upstream_proxy and config.upstream_proxy:
        lines.append(f"Upstream proxy: {config.upstream_proxy}")
    else:
        lines.append("Upstream proxy: disabled")

    lines.append(f"IP family: {config.family}")
    lines.append(f"Resolved log: {config.output or 'disabled'}")
    lines.append(f"System proxy: {'enabled' if config.set_system_proxy else 'disabled'}")
    lines.append(
        "Auto change hosts: "
        + ("enabled" if hosts_manager is not None else "disabled")
    )
    lines.append("Optimize DNS: " + ("enabled" if config.optimize_dns else "disabled"))
    lines.append("Emergency Mode: " + ("enabled" if config.emergency_mode else "disabled"))

    if optimize_dns_report_store:
        lines.append(f"Optimize DNS report: {config.optimize_dns_report}")
        lines.append(
            f"Optimize DNS refresh interval: {config.optimize_dns_refresh_interval}s"
        )

    lines.append("Press Ctrl+C to stop.")
    lines.append("")

    sent_bytes, received_bytes = stats.snapshot()
    lines.append(f"Sent: {format_byte_count(sent_bytes)}")
    lines.append(f"Received: {format_byte_count(received_bytes)}")

    return lines


def render_proxy_session_screen(
    config: StartupConfig,
    doh_urls: List[str],
    hosts_manager: Optional[HostsFileManager],
    optimize_dns_report_store: Optional["OptimizeDNSReportStore"],
    stats: TrafficStats,
    *,
    clear: bool,
) -> None:
    if clear and sys.stdout.isatty():
        enable_ansi_colors()
        sys.stdout.write("\033[2J\033[H")

    for line in build_proxy_session_lines(
        config,
        doh_urls,
        hosts_manager,
        optimize_dns_report_store,
        stats,
    ):
        sys.stdout.write(line + "\n")

    sys.stdout.flush()


class ResolutionLog:
    """
    فایل خروجی را thread-safe و atomic آپدیت می‌کند.

    فرمت:
        IP domain

    domain کلید یکتا است.
    اگر domain قبلا وجود داشته باشد، IP همان رکورد آپدیت می‌شود
    و رکورد تکراری جدید ساخته نمی‌شود.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._pairs: List[ResolvedPair] = []
        self._domain_to_index: Dict[str, int] = {}
        self._loaded_had_duplicates = False
        self._load_existing()

        if self._loaded_had_duplicates and self.path:
            with self._lock:
                self._write_atomic_locked()

    def _load_existing(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return

        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                parts = line.split()

                if len(parts) < 2:
                    continue

                ip = parts[0]
                domain = normalize_host(parts[1])

                if not domain:
                    continue

                existing_index = self._domain_to_index.get(domain)

                if existing_index is None:
                    self._domain_to_index[domain] = len(self._pairs)
                    self._pairs.append((ip, domain))
                else:
                    # اگر فایل قبلی domain تکراری داشته باشد، آخرین IP نگه داشته می‌شود.
                    self._pairs[existing_index] = (ip, domain)
                    self._loaded_had_duplicates = True

    def add_many(self, pairs: Iterable[ResolvedPair]) -> None:
        if not self.path:
            return

        changed = False

        with self._lock:
            for ip, domain in pairs:
                normalized_domain = normalize_host(domain)

                if not normalized_domain:
                    continue

                existing_index = self._domain_to_index.get(normalized_domain)

                if existing_index is None:
                    self._domain_to_index[normalized_domain] = len(self._pairs)
                    self._pairs.append((ip, normalized_domain))
                    changed = True
                else:
                    old_ip, _old_domain = self._pairs[existing_index]

                    if old_ip != ip:
                        self._pairs[existing_index] = (ip, normalized_domain)
                        changed = True

            if changed:
                self._write_atomic_locked()

    def _write_atomic_locked(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(
            prefix=".doh-proxy-resolved-",
            suffix=".tmp",
            dir=directory,
            text=True,
        )

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for ip, domain in self._pairs:
                    f.write(f"{ip} {domain}\n")

                f.flush()
                os.fsync(f.fileno())

            os.replace(tmp_path, self.path)

        finally:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass


@dataclass
class StartupConfig:
    listen: str = "0.0.0.0"
    port: int = 8080
    set_system_proxy: bool = True
    doh_file: str = "doh-list.txt"
    doh_proxy: Optional[str] = "http://127.0.0.1:10808"
    use_doh_proxy: bool = True
    use_upstream_proxy: bool = False
    upstream_proxy: Optional[str] = None
    output: str = "resolved.txt"
    auto_change_hosts: bool = True
    doh_method: str = "POST"
    insecure_doh_tls: bool = False
    family: str = "ipv4"
    min_ttl: int = 30
    max_ttl: int = 300
    client_timeout: float = 10.0
    connect_timeout: float = 10.0
    idle_timeout: float = 300.0
    max_header_bytes: int = 65536
    optimize_dns: bool = True
    optimize_dns_refresh_interval: float = 60.0
    optimize_dns_report: str = DEFAULT_OPTIMIZE_DNS_REPORT_PATH
    emergency_mode: bool = False
    verbose: bool = False


class OptimizedDNSCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: Dict[str, "_OptimizedDNSCacheEntry"] = {}
        self._seen_hosts: set[str] = set()

    def remember_host(self, host: str) -> None:
        host = normalize_host(host)

        if not host or is_ip_literal(host):
            return

        with self._lock:
            self._seen_hosts.add(host)

    def snapshot_hosts(self) -> List[str]:
        with self._lock:
            return sorted(self._seen_hosts)

    def get(self, host: str) -> Optional[str]:
        host = normalize_host(host)

        with self._lock:
            entry = self._cache.get(host)

            if not entry:
                return None

            return entry.ip

    def set(self, host: str, ip: str) -> None:
        host = normalize_host(host)

        if not host or not ip:
            return

        with self._lock:
            self._cache[host] = _OptimizedDNSCacheEntry(ip=ip, failures=0)

    def forget(self, host: str) -> None:
        host = normalize_host(host)

        with self._lock:
            self._cache.pop(host, None)

    def record_failure(self, host: str, ip: str) -> int:
        host = normalize_host(host)

        if not host or not ip:
            return 0

        with self._lock:
            entry = self._cache.get(host)

            if not entry or entry.ip != ip:
                return 0

            entry.failures += 1
            return entry.failures


@dataclass
class _OptimizedDNSCacheEntry:
    ip: str
    failures: int = 0


class OptimizeDNSReportStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._hosts: Dict[str, dict] = {}
        self._generated_at = ""

    def update_host(self, host: str, report: dict) -> None:
        host = normalize_host(host)

        if not host or not self.path:
            return

        with self._lock:
            self._hosts[host] = report

    def flush(self) -> None:
        with self._lock:
            self._generated_at = datetime.now(timezone.utc).isoformat()
            self._write_atomic_locked()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "generated_at": self._generated_at or datetime.now(timezone.utc).isoformat(),
                "hosts": dict(self._hosts),
            }

    def _write_atomic_locked(self) -> None:
        if not self.path:
            return

        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(
            prefix=".doh-proxy-optimize-dns-",
            suffix=".json",
            dir=directory,
            text=True,
        )

        payload = {
            "generated_at": self._generated_at,
            "hosts": self._hosts,
        }

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())

            os.replace(tmp_path, self.path)

        finally:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass


class OptimizeDNSRefreshService:
    def __init__(
        self,
        resolver: "DoHResolver",
        cache: OptimizedDNSCache,
        report_store: OptimizeDNSReportStore,
        resolution_log: Optional[ResolutionLog],
        hosts_manager: Optional[HostsFileManager],
        connect_timeout: float,
        refresh_interval: float = 60.0,
        probe_ports: Tuple[int, ...] = (443, 80),
        verbose: bool = False,
    ) -> None:
        self.resolver = resolver
        self.cache = cache
        self.report_store = report_store
        self.resolution_log = resolution_log
        self.hosts_manager = hosts_manager
        self.connect_timeout = connect_timeout
        self.refresh_interval = refresh_interval
        self.probe_ports = probe_ports
        self.verbose = verbose
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="optimize-dns-refresh",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 1.0) -> None:
        self._stop_event.set()
        # Do not let shutdown wait for a long refresh sweep; the thread is daemonized.
        self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop_event.wait(self.refresh_interval):
            try:
                self.refresh_once()
            except Exception as exc:
                if self.verbose:
                    print_verbose_error(f"[optimize-dns] refresh sweep failed: {exc}")

    def refresh_once(self) -> None:
        hosts = self.cache.snapshot_hosts()

        try:
            for host in hosts:
                if self._stop_event.is_set():
                    return

                report = self._refresh_host(host)
                if report is not None:
                    self.report_store.update_host(host, report)
        finally:
            self.report_store.flush()

    def _refresh_host(self, host: str) -> Optional[dict]:
        try:
            attempts = self.resolver.resolve_attempts(host, force_refresh=True)
        except Exception as exc:
            if self.verbose:
                print_verbose_error(f"[optimize-dns] refresh resolve failed for {host}: {exc}")
            return {
                "host": host,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "best_ip": None,
                "best_latency_ms": None,
                "resolver_results": [],
                "candidates": [],
                "error": str(exc),
            }

        resolver_results: List[dict] = []
        candidates: Dict[str, dict] = {}

        for attempt in attempts:
            resolver_results.append(
                {
                    "resolver": attempt.doh_url,
                    "addresses": [
                        {"ip": ip, "family": "ipv6" if family == socket.AF_INET6 else "ipv4"}
                        for ip, family in attempt.addresses
                    ],
                }
            )

            for ip, family in attempt.addresses:
                candidate = candidates.get(ip)

                if candidate is None:
                    candidate = {
                        "ip": ip,
                        "family": "ipv6" if family == socket.AF_INET6 else "ipv4",
                        "sources": [],
                        "tests": [],
                        "best_latency_ms": None,
                        "selected": False,
                    }
                    candidates[ip] = candidate

                if attempt.doh_url not in candidate["sources"]:
                    candidate["sources"].append(attempt.doh_url)

        if not candidates:
            return {
                "host": host,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "best_ip": None,
                "best_latency_ms": None,
                "resolver_results": resolver_results,
                "candidates": [],
                "error": "no usable IP addresses from resolvers",
            }

        for candidate in candidates.values():
            candidate["tests"] = self._probe_candidate(candidate["ip"])
            success_latencies = [
                test["latency_ms"]
                for test in candidate["tests"]
                if test["success"] and test["latency_ms"] is not None
            ]
            candidate["best_latency_ms"] = min(success_latencies) if success_latencies else None

        successful_candidates = [
            candidate
            for candidate in candidates.values()
            if candidate["best_latency_ms"] is not None
        ]

        best_candidate = None

        if successful_candidates:
            best_candidate = min(
                successful_candidates,
                key=lambda item: (item["best_latency_ms"], item["ip"]),
            )
            best_candidate["selected"] = True
            self.cache.set(host, best_candidate["ip"])
            self._persist_best_ip(host, best_candidate["ip"])

        return {
            "host": host,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "best_ip": best_candidate["ip"] if best_candidate else None,
            "best_latency_ms": best_candidate["best_latency_ms"] if best_candidate else None,
            "resolver_results": resolver_results,
            "candidates": list(candidates.values()),
        }

    def _persist_best_ip(self, host: str, ip: str) -> None:
        if not host or not ip or is_ip_literal(host):
            return

        if self.resolution_log:
            self.resolution_log.add_many([(ip, host)])

        if self.hosts_manager:
            try:
                self.hosts_manager.add_many([(ip, host)])
            except OSError as exc:
                if self.verbose:
                    print_verbose_error(f"[optimize-dns] failed to update hosts for {host}: {exc}")

    def _probe_candidate(self, ip: str) -> List[dict]:
        results: List[dict] = []

        for port in self.probe_ports:
            result = self._probe_single_port(ip, port)
            results.append(result)

        return results

    def _probe_single_port(self, ip: str, port: int) -> dict:
        family = family_for_ip(ip)
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.connect_timeout)
        started_at = time.perf_counter()

        try:
            if family == socket.AF_INET6:
                sock.connect((ip, port, 0, 0))
            else:
                sock.connect((ip, port))

            latency_ms = round((time.perf_counter() - started_at) * 1000.0, 3)
            return {
                "port": port,
                "success": True,
                "latency_ms": latency_ms,
                "error": None,
            }

        except OSError as exc:
            latency_ms = round((time.perf_counter() - started_at) * 1000.0, 3)
            return {
                "port": port,
                "success": False,
                "latency_ms": latency_ms,
                "error": str(exc),
            }

        finally:
            sock.close()


@dataclass
class HostsEntry:
    ip: str
    domains: List[str]


@dataclass
class EmergencyResolutionMatch:
    ip: str
    source: str


class EmergencyDNSLookup:
    def __init__(
        self,
        report_path: str = DEFAULT_OPTIMIZE_DNS_REPORT_PATH,
        hosts_path: str = DEFAULT_HOSTS_PATH,
    ) -> None:
        self.report_path = report_path
        self.hosts_path = hosts_path
        self._lock = threading.Lock()
        self._report_mtime: Optional[float] = None
        self._report_index: Dict[str, str] = {}
        self._hosts_mtime: Optional[float] = None
        self._hosts_index: Dict[str, str] = {}

    def lookup(self, host: str) -> Optional[EmergencyResolutionMatch]:
        candidates = self.lookup_candidates(host)
        return candidates[0] if candidates else None

    def lookup_candidates(self, host: str) -> List[EmergencyResolutionMatch]:
        host = normalize_host(host)

        if not host or is_ip_literal(host):
            return []

        matches: List[EmergencyResolutionMatch] = []

        report_ip = self._lookup_report(host)

        if report_ip:
            matches.append(EmergencyResolutionMatch(ip=report_ip, source=self.report_path))

        hosts_ip = self._lookup_hosts(host)

        if hosts_ip and hosts_ip != report_ip:
            matches.append(EmergencyResolutionMatch(ip=hosts_ip, source=self.hosts_path))

        return matches

    def _lookup_report(self, host: str) -> Optional[str]:
        if not self.report_path or not os.path.exists(self.report_path):
            return None

        try:
            mtime = os.path.getmtime(self.report_path)
        except OSError:
            return None

        with self._lock:
            if self._report_mtime != mtime:
                self._report_index = self._load_report_index()
                self._report_mtime = mtime

            return self._report_index.get(host)

    def _load_report_index(self) -> Dict[str, str]:
        try:
            with open(self.report_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return {}

        hosts = payload.get("hosts")

        if not isinstance(hosts, dict):
            return {}

        index: Dict[str, str] = {}

        for raw_host, report in hosts.items():
            host = normalize_host(str(raw_host))

            if not host:
                continue

            ip = self._extract_report_ip(report)

            if ip:
                index[host] = ip

        return index

    def _extract_report_ip(self, report: object) -> Optional[str]:
        if not isinstance(report, dict):
            return None

        best_ip = report.get("best_ip")

        if isinstance(best_ip, str) and best_ip.strip():
            return normalize_host(best_ip)

        candidates = report.get("candidates")

        if not isinstance(candidates, list):
            return None

        fallback_ips: List[str] = []

        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue

            ip = candidate.get("ip")

            if not isinstance(ip, str) or not ip.strip():
                continue

            normalized_ip = normalize_host(ip)

            if not normalized_ip:
                continue

            if candidate.get("selected"):
                return normalized_ip

            fallback_ips.append(normalized_ip)

        return fallback_ips[0] if fallback_ips else None

    def _lookup_hosts(self, host: str) -> Optional[str]:
        if not self.hosts_path or not os.path.exists(self.hosts_path):
            return None

        try:
            mtime = os.path.getmtime(self.hosts_path)
        except OSError:
            return None

        with self._lock:
            if self._hosts_mtime != mtime:
                self._hosts_index = self._load_hosts_index()
                self._hosts_mtime = mtime

            return self._hosts_index.get(host)

    def _load_hosts_index(self) -> Dict[str, str]:
        try:
            with open(self.hosts_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            return {}

        index: Dict[str, str] = {}

        for line in lines:
            entry = self._parse_hosts_entry(line)

            if not entry:
                continue

            for domain in entry.domains:
                if domain not in index:
                    index[domain] = entry.ip

        return index

    def _parse_hosts_entry(self, line: str) -> Optional[HostsEntry]:
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            return None

        tokens = stripped.split()

        if len(tokens) < 2:
            return None

        ip = tokens[0].strip()
        domains: List[str] = []

        for token in tokens[1:]:
            if token.startswith("#"):
                break

            domain = normalize_host(token)

            if domain:
                domains.append(domain)

        if not ip or not domains:
            return None

        return HostsEntry(ip=ip, domains=domains)


class HostsFileManager:
    """
    Keeps a managed section in the Windows hosts file.
    A snapshot of the original hosts file is created once when the manager starts.
    Existing non-managed entries are preserved.
    """

    def __init__(
        self,
        path: str = DEFAULT_HOSTS_PATH,
        backup_path: str = r"C:\Windows\System32\drivers\etc\hosts_backup",
        marker: str = "# doh_http_proxy",
    ) -> None:
        self.path = path
        self.backup_base_path = backup_path
        self.backup_path = backup_path
        self.marker = marker
        self._lock = threading.Lock()
        self._ensure_backup()

    def _next_backup_path(self) -> str:
        directory = os.path.dirname(os.path.abspath(self.backup_base_path)) or "."
        base_name = os.path.basename(self.backup_base_path)
        stem, suffix = os.path.splitext(base_name)

        candidate = os.path.join(directory, base_name)
        index = 1

        while os.path.exists(candidate):
            candidate = os.path.join(directory, f"{stem}_{index}{suffix}")
            index += 1

        return candidate

    def _ensure_backup(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return

        backup_path = self._next_backup_path()
        directory = os.path.dirname(os.path.abspath(backup_path)) or "."
        os.makedirs(directory, exist_ok=True)
        shutil.copy2(self.path, backup_path)
        self.backup_path = backup_path

    def add_many(self, pairs: Iterable[ResolvedPair]) -> None:
        if not self.path:
            return

        updates: Dict[str, str] = {}

        for ip, domain in pairs:
            normalized_domain = normalize_host(domain)

            if not normalized_domain:
                continue

            updates[normalized_domain] = ip

        if not updates:
            return

        with self._lock:
            existing_lines = self._read_lines()
            updated_lines = self._merge_lines(existing_lines, updates)
            self._write_lines(updated_lines)

    def _read_lines(self) -> List[str]:
        if not os.path.exists(self.path):
            return []

        with open(self.path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()

    def _merge_lines(self, lines: List[str], updates: Dict[str, str]) -> List[str]:
        merged: List[str] = []
        managed_domains: set[str] = set()

        for line in lines:
            entry = self._parse_entry(line)

            if not entry:
                merged.append(line)
                continue

            matching_domain = next(
                (domain for domain in entry.domains if domain in updates),
                None,
            )

            if matching_domain is None:
                merged.append(line)
                continue

            if matching_domain in managed_domains:
                continue

            managed_domains.add(matching_domain)
            merged.append(self._format_line(updates[matching_domain], matching_domain))

        for domain, ip in updates.items():
            if domain not in managed_domains:
                merged.append(self._format_line(ip, domain))

        return merged

    def _parse_entry(self, line: str) -> Optional[HostsEntry]:
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            return None

        tokens = stripped.split()

        if len(tokens) < 2:
            return None

        ip = tokens[0]
        domains: List[str] = []

        for token in tokens[1:]:
            if token.startswith("#"):
                break

            domains.append(normalize_host(token))

        domains = [domain for domain in domains if domain]

        if not domains:
            return None

        return HostsEntry(ip=ip, domains=domains)

    def _format_line(self, ip: str, domain: str) -> str:
        return f"{ip} {domain} {self.marker}"

    def _write_lines(self, lines: List[str]) -> None:
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(
            prefix=".doh-proxy-hosts-",
            suffix=".tmp",
            dir=directory,
            text=True,
        )

        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
                f.write("\r\n".join(lines))

                if lines:
                    f.write("\r\n")

                f.flush()
                os.fsync(f.fileno())

            self._replace_file(tmp_path)

        finally:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass

    def _replace_file(self, tmp_path: str) -> None:
        if os.name == "nt":
            try:
                replace_result = ctypes.windll.kernel32.ReplaceFileW(
                    ctypes.c_wchar_p(self.path),
                    ctypes.c_wchar_p(tmp_path),
                    None,
                    0,
                    None,
                    None,
                )

                if replace_result:
                    return
            except Exception:
                pass

        os.replace(tmp_path, self.path)


class WindowsSystemProxyManager:
    """
    Temporarily manages the current user's Internet Settings proxy values.
    """

    REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def __init__(self) -> None:
        self._previous: Dict[str, Tuple[bool, Optional[object]]] = {}
        self._applied = False

    def snapshot(self) -> None:
        if os.name != "nt" or winreg is None:
            return

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            self.REG_PATH,
            0,
            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE,
        ) as key:
            for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
                try:
                    value, reg_type = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    self._previous[name] = (False, None)
                else:
                    self._previous[name] = (True, value)

    def apply(self, listen_host: str, port: int) -> None:
        if os.name != "nt" or winreg is None:
            raise RuntimeError("system proxy settings are only supported on Windows")

        proxy_host = self._system_proxy_host(listen_host)
        proxy_value = self._format_proxy_server(proxy_host, port)

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            self.REG_PATH,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
        ) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_value)
            winreg.SetValueEx(
                key,
                "ProxyOverride",
                0,
                winreg.REG_SZ,
                "localhost;127.0.0.1;[::1]",
            )

        self._applied = True
        self._refresh()

    def restore(self) -> None:
        if not self._applied or os.name != "nt" or winreg is None:
            return

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            self.REG_PATH,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
        ) as key:
            self._restore_value(key, "ProxyEnable")
            self._restore_value(key, "ProxyServer")
            self._restore_value(key, "ProxyOverride")

        self._refresh()
        self._applied = False

    def _restore_value(self, key: object, name: str) -> None:
        existed, value = self._previous.get(name, (False, None))

        if not existed:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass
            return

        if isinstance(value, int):
            reg_type = winreg.REG_DWORD
        else:
            reg_type = winreg.REG_SZ

        winreg.SetValueEx(key, name, 0, reg_type, value)

    @staticmethod
    def _system_proxy_host(listen_host: str) -> str:
        normalized = listen_host.strip().strip("[]")

        if normalized in {"0.0.0.0", ""}:
            return "127.0.0.1"

        if normalized == "::":
            return "::1"

        return normalized

    @staticmethod
    def _format_proxy_server(host: str, port: int) -> str:
        if ":" in host and not host.startswith("["):
            return f"[{host}]:{port}"

        return f"{host}:{port}"

    @staticmethod
    def _refresh() -> None:
        if os.name != "nt":
            return

        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(None, 39, None, 0)
        wininet.InternetSetOptionW(None, 37, None, 0)


class PortInUseError(RuntimeError):
    def __init__(self, listen: str, port: int, pids: List[int], details: List[str]) -> None:
        self.listen = listen
        self.port = port
        self.pids = pids
        self.details = details
        pid_text = ", ".join(str(pid) for pid in pids) if pids else "unknown"
        detail_text = "; ".join(details) if details else "no details available"
        super().__init__(
            f"{listen}:{port} is already in use by PID(s) {pid_text} ({detail_text})"
        )


def is_admin() -> bool:
    if os.name != "nt":
        return False

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _read_key() -> int:
    if msvcrt is None:
        raise RuntimeError("interactive menu requires Windows console support")

    key = msvcrt.getch()

    if key in (b"\x00", b"\xe0"):
        return 256 + msvcrt.getch()[0]

    return key[0]


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _read_prefilled_line(prompt: str, initial: str) -> Optional[str]:
    if msvcrt is None or not sys.stdin.isatty() or not sys.stdout.isatty():
        return input(f"{prompt}: {initial}\n> ")

    text = str(initial)
    sys.stdout.write(f"{prompt}: {text}")
    sys.stdout.flush()
    rendered_length = len(f"{prompt}: {text}")

    while True:
        key = msvcrt.getwch()

        if key in ("\r", "\n"):
            sys.stdout.write("\n")
            sys.stdout.flush()
            return text

        if key == "\x1b":
            sys.stdout.write("\n")
            sys.stdout.flush()
            return None

        if key in ("\b", "\x7f"):
            if text:
                text = text[:-1]
        elif key == "\x03":
            raise KeyboardInterrupt
        elif key in ("\x00", "\xe0"):
            # Ignore extended keys in the inline editor.
            msvcrt.getwch()
            continue
        elif key.isprintable():
            text += key
        else:
            continue

        display = f"{prompt}: {text}"
        padding = max(0, rendered_length - len(display))
        sys.stdout.write("\r" + display + (" " * padding))
        sys.stdout.flush()
        rendered_length = len(display)


def prompt_edit_value(label: str, current: object, validator) -> object:
    while True:
        raw = _read_prefilled_line(label, str(current))

        if raw is None:
            return current

        if not raw:
            return current

        try:
            return validator(raw)
        except ValueError as exc:
            print(f"Invalid value: {exc}")


def prompt_optional_proxy_value(label: str, current: Optional[str]) -> Optional[str]:
    while True:
        raw = _read_prefilled_line(label, current or "")

        if raw is None:
            return current

        try:
            return validate_optional_proxy(raw)
        except ValueError as exc:
            print(f"Invalid value: {exc}")


def build_startup_config_from_namespace(args: argparse.Namespace) -> StartupConfig:
    config = load_saved_startup_config() or StartupConfig()

    for field_name in StartupConfig.__dataclass_fields__:
        value = getattr(args, field_name, None)

        if value is not None:
            setattr(config, field_name, value)

    return config


def namespace_from_startup_config(config: StartupConfig) -> argparse.Namespace:
    return argparse.Namespace(**config.__dict__)


def get_startup_config_path() -> str:
    return DEFAULT_STARTUP_CONFIG_PATH


def save_startup_config(config: StartupConfig, path: Optional[str] = None) -> str:
    if path is None:
        fd, temp_path = tempfile.mkstemp(
            prefix=".doh-proxy-config-",
            suffix=".json",
            text=True,
        )
        target_path = temp_path
    else:
        directory = os.path.dirname(os.path.abspath(path)) or "."
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(
            prefix=".doh-proxy-config-",
            suffix=".json",
            dir=directory,
            text=True,
        )
        target_path = path

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config.__dict__, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())

        if path is not None:
            os.replace(temp_path, path)
            return path
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise

    return target_path


def load_startup_config(path: str, delete: bool = True) -> StartupConfig:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if delete:
        try:
            os.unlink(path)
        except OSError:
            pass

    if not isinstance(data, dict):
        raise TypeError("config file must contain a JSON object")

    defaults = StartupConfig().__dict__.copy()

    for key in defaults:
        if key in data:
            defaults[key] = data[key]

    return StartupConfig(**defaults)


def load_saved_startup_config() -> Optional[StartupConfig]:
    path = get_startup_config_path()

    if not os.path.exists(path):
        return None

    try:
        return load_startup_config(path, delete=False)
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return None


def save_persistent_startup_config(config: StartupConfig) -> None:
    save_startup_config(config, get_startup_config_path())


def launch_elevated(script_path: str, config_path: str) -> bool:
    if os.name != "nt":
        return False

    script_path = os.path.abspath(script_path)
    params = f'"{script_path}" --config-file "{config_path}"'
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1,
    )

    return result > 32


def parse_listening_rows() -> List[Tuple[str, int]]:
    try:
        completed = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return []

    rows: List[Tuple[str, int]] = []

    for line in completed.stdout.splitlines():
        parts = line.split()

        if len(parts) < 5:
            continue

        protocol = parts[0].upper()

        if protocol != "TCP":
            continue

        state = parts[-2].upper()

        if state != "LISTENING":
            continue

        local_address = parts[1]

        try:
            pid = int(parts[-1])
        except ValueError:
            continue

        if pid <= 0:
            continue

        rows.append((local_address, pid))

    return rows


def listening_pids_for_target(listen_host: str, port: int) -> Tuple[List[int], List[str]]:
    matches: List[Tuple[str, int]] = []
    target = normalize_host(listen_host).strip("[]").lower()
    wildcard_hosts = {"0.0.0.0", "::", "[::]"}

    for local_address, pid in parse_listening_rows():
        if pid <= 0:
            continue

        if ":" not in local_address:
            continue

        address_part, port_text = local_address.rsplit(":", 1)

        try:
            address_port = int(port_text)
        except ValueError:
            continue

        if address_port != port:
            continue

        normalized_address = address_part.strip("[]").lower()

        if target in wildcard_hosts:
            matches.append((local_address, pid))
            continue

        if normalized_address in wildcard_hosts or normalized_address == target:
            matches.append((local_address, pid))

    ordered_pids: List[int] = []
    details: List[str] = []

    for local_address, pid in matches:
        if pid not in ordered_pids:
            ordered_pids.append(pid)
        details.append(f"{local_address} -> PID {pid}")

    return ordered_pids, details


def validate_listen_host(raw: str) -> str:
    value = raw.strip()

    if not value:
        raise ValueError("listen IP cannot be empty")

    return value


def validate_port(raw: str) -> int:
    port = int(raw)

    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    return port


def validate_non_empty_path(raw: str) -> str:
    value = raw.strip()

    if not value:
        raise ValueError("value cannot be empty")

    return value


def validate_optional_proxy(raw: str) -> Optional[str]:
    value = raw.strip()

    if not value:
        return None

    if "://" not in value:
        value = "http://" + value

    parsed = urlsplit(value)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("proxy scheme must be http or https")

    if not parsed.hostname:
        raise ValueError("proxy host is required")

    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("proxy port must be between 1 and 65535")

    return value


def _menu_rows(config: StartupConfig) -> List[Tuple[str, str]]:
    upstream_proxy_enabled = config.use_upstream_proxy and bool(config.upstream_proxy)
    doh_proxy_enabled = config.use_doh_proxy and bool(config.doh_proxy)

    return [
        ("listen IP", config.listen),
        ("listen port", str(config.port)),
        ("Set System Proxy", "ON" if config.set_system_proxy else "OFF"),
        ("DoH File", config.doh_file),
        ("DoH Proxy Address", config.doh_proxy or "disabled"),
        ("Use DoH Proxy", "ON" if doh_proxy_enabled else "OFF"),
        ("Use Upstream Proxy", "ON" if upstream_proxy_enabled else "OFF"),
        ("Upstream Proxy Address", config.upstream_proxy or "disabled"),
        ("Output Resolved Hosts", config.output),
        ("Auto Change Hosts (requires admin)", "ON" if config.auto_change_hosts else "OFF"),
        ("Optimize DNS", "ON" if config.optimize_dns else "OFF"),
        ("Emergency Mode", "ON" if config.emergency_mode else "OFF"),
        ("Verbose", "ON" if config.verbose else "OFF"),
        ("Start", "Press Enter"),
    ]


def _fit_text(text: str, width: int) -> str:
    if width <= 0:
        return ""

    if len(text) <= width:
        return text

    if width <= 3:
        return text[:width]

    return text[: width - 3] + "..."


def _wrap_color(text: str, color: str, enabled: bool = True) -> str:
    if not enabled:
        return text

    return f"{color}{text}{ANSI_RESET}"


def print_verbose_error(message: str) -> None:
    enable_ansi_colors()
    print(_wrap_color(message, ANSI_RED, enabled=sys.stderr.isatty()), file=sys.stderr)


def render_menu(config: StartupConfig, selected: int, message: str) -> None:
    clear_screen()
    enable_ansi_colors()
    rows = _menu_rows(config)
    label_width = max(len(label) for label, _value in rows)
    value_width = max(len(value) for _label, value in rows)
    content_width = label_width + 2 + value_width
    term_width = shutil.get_terminal_size((100, 20)).columns
    box_width = max(66, min(term_width - 2, content_width + 6))
    inner_width = box_width - 2
    label_width = min(label_width, max(18, inner_width - value_width - 4))
    value_width = min(value_width, max(0, inner_width - label_width - 3))

    print(_wrap_color("DoH HTTP Proxy", ANSI_GREEN))
    print(_wrap_color("Navigate with ↑/↓. Toggle with ←/→. Enter to select.", ANSI_WHITE))
    print()
    print("┌" + "─" * inner_width + "┐")

    for index, (label, value) in enumerate(rows):
        cursor = "▶" if index == selected else " "
        label_text = _fit_text(label, label_width)
        value_text = _fit_text(value, value_width)
        row = f"{cursor} {label_text:<{label_width}}"

        if index == selected:
            row = _wrap_color(cursor, ANSI_GREEN) + " " + _wrap_color(
                f"{label_text:<{label_width}}",
                ANSI_GREEN,
            )
        else:
            row = _wrap_color(cursor, ANSI_WHITE) + " " + _wrap_color(
                f"{label_text:<{label_width}}",
                ANSI_WHITE,
            )

        if value_text:
            if value_text in {"ON", "Press Enter"}:
                value_color = ANSI_GREEN
            elif value_text in {"OFF", "disabled"}:
                value_color = ANSI_RED
            else:
                value_color = ANSI_WHITE

            row += "  " + _wrap_color(value_text, value_color)

        print("│" + f" {row:<{inner_width - 2}} " + "│")

    print("└" + "─" * inner_width + "┘")

    if message:
        print()
        print(_wrap_color(message, ANSI_RED))


def render_menu(config: StartupConfig, selected: int, message: str) -> None:
    clear_screen()
    enable_ansi_colors()
    rows = _menu_rows(config)
    label_width = max(len(label) for label, _value in rows)
    value_width = max(len(value) for _label, value in rows)
    terminal_width = shutil.get_terminal_size((100, 20)).columns
    max_row_width = max(60, terminal_width - 4)
    label_width = min(label_width, max(18, max_row_width - value_width - 8))
    value_width = min(value_width, max(0, max_row_width - label_width - 8))

    print(_wrap_color("DoH HTTP Proxy", ANSI_GREEN))
    print(_wrap_color("Navigate with ↑/↓. Toggle with ←/→. Enter to select.", ANSI_WHITE))
    print()

    for index, (label, value) in enumerate(rows):
        cursor = "▶" if index == selected else " "
        label_text = _fit_text(label, label_width)
        value_text = _fit_text(value, value_width)

        if index == selected:
            row = _wrap_color(cursor, ANSI_GREEN) + " " + _wrap_color(
                f"{label_text:<{label_width}}",
                ANSI_GREEN,
            )
        else:
            row = _wrap_color(cursor, ANSI_WHITE) + " " + _wrap_color(
                f"{label_text:<{label_width}}",
                ANSI_WHITE,
            )

        if value_text:
            if value_text in {"ON", "Press Enter"}:
                value_color = ANSI_GREEN
            elif value_text in {"OFF", "disabled"}:
                value_color = ANSI_RED
            else:
                value_color = ANSI_WHITE

            row += "  " + _wrap_color(value_text, value_color)

        print(row)

    if message:
        print()
        print(_wrap_color(message, ANSI_RED))


def edit_selected_field(config: StartupConfig, selected: int) -> None:
    if selected == 0:
        config.listen = prompt_edit_value("listen IP", config.listen, validate_listen_host)
    elif selected == 1:
        config.port = prompt_edit_value("listen port", config.port, validate_port)
    elif selected == 3:
        config.doh_file = prompt_edit_value("DoH File", config.doh_file, validate_non_empty_path)
    elif selected == 4:
        config.doh_proxy = prompt_edit_value(
            "DoH Proxy Address",
            config.doh_proxy or "",
            validate_optional_proxy,
        )
    elif selected == 7:
        config.upstream_proxy = prompt_optional_proxy_value(
            "Upstream Proxy Address",
            config.upstream_proxy,
        )
        config.use_upstream_proxy = config.upstream_proxy is not None
    elif selected == 8:
        config.output = prompt_edit_value(
            "Output Resolved Hosts",
            config.output,
            validate_non_empty_path,
        )


def toggle_selected_field(config: StartupConfig, selected: int, direction: int) -> None:
    if selected == 2:
        config.set_system_proxy = not config.set_system_proxy
    elif selected == 5:
        config.use_doh_proxy = not config.use_doh_proxy

        if config.use_doh_proxy and not config.doh_proxy:
            config.doh_proxy = prompt_optional_proxy_value(
                "DoH Proxy Address",
                config.doh_proxy,
            )

            if config.doh_proxy is None:
                config.use_doh_proxy = False
    elif selected == 6:
        config.use_upstream_proxy = not config.use_upstream_proxy

        if config.use_upstream_proxy and not config.upstream_proxy:
            config.upstream_proxy = prompt_optional_proxy_value(
                "Upstream Proxy Address",
                config.upstream_proxy,
            )

            if config.upstream_proxy is None:
                config.use_upstream_proxy = False
    elif selected == 9:
        config.auto_change_hosts = not config.auto_change_hosts
    elif selected == 10:
        config.optimize_dns = not config.optimize_dns
    elif selected == 11:
        config.emergency_mode = not config.emergency_mode
    elif selected == 12:
        config.verbose = not config.verbose


def load_namespace_from_config_file(config_file: str) -> argparse.Namespace:
    config = load_startup_config(config_file)
    args = namespace_from_startup_config(config)
    args.config_file = config_file
    return args


def should_show_menu(args: argparse.Namespace) -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty() and not getattr(args, "config_file", None)


def maybe_apply_system_proxy(config: StartupConfig) -> Optional[WindowsSystemProxyManager]:
    if not config.set_system_proxy:
        return None

    manager = WindowsSystemProxyManager()
    manager.snapshot()

    try:
        manager.apply(config.listen, config.port)
    except Exception:
        try:
            manager.restore()
        except Exception:
            pass
        raise

    def cleanup() -> None:
        try:
            manager.restore()
        except Exception:
            pass

    atexit.register(cleanup)
    return manager


def start_proxy_session(args: argparse.Namespace) -> int:
    try:
        pids, details = listening_pids_for_target(args.listen, args.port)

        if pids:
            raise PortInUseError(args.listen, args.port, pids, details)
    except PortInUseError:
        raise
    except Exception:
        # If the port check fails, we still let the bind attempt below be the source of truth.
        pass

    try:
        doh_urls = unique_preserve_order(read_doh_file(args.doh_file))
    except OSError as exc:
        print(f"Could not read DoH file: {args.doh_file}: {exc}", file=sys.stderr)
        return 2

    if not doh_urls:
        print(
            f"No DoH endpoint found in file: {args.doh_file}",
            file=sys.stderr,
        )
        return 2

    resolution_log = ResolutionLog(args.output) if args.output else None
    hosts_manager: Optional[HostsFileManager] = None

    if args.auto_change_hosts:
        if os.name == "nt" and is_admin():
            try:
                hosts_manager = HostsFileManager()
            except OSError as exc:
                if args.verbose:
                    print_verbose_error(
                        f"[hosts] disabled: could not initialize hosts manager: {exc}"
                    )
        elif args.verbose:
            print_verbose_error(
                "[hosts] disabled: auto-change-hosts requires Windows administrator privileges."
            )

    optimized_dns_cache = OptimizedDNSCache() if args.optimize_dns else None
    optimize_dns_report_store = (
        OptimizeDNSReportStore(args.optimize_dns_report)
        if args.optimize_dns and args.optimize_dns_report
        else None
    )
    emergency_lookup = (
        EmergencyDNSLookup(args.optimize_dns_report, DEFAULT_HOSTS_PATH)
        if args.emergency_mode
        else None
    )

    resolver = DoHResolver(
        doh_urls=doh_urls,
        method=args.doh_method,
        timeout=args.connect_timeout,
        doh_proxy=args.doh_proxy if args.use_doh_proxy else None,
        verify_tls=not args.insecure_doh_tls,
        family_mode=args.family,
        min_ttl=args.min_ttl,
        max_ttl=args.max_ttl,
        verbose=args.verbose,
    )

    config = build_startup_config_from_namespace(args)
    system_proxy_manager: Optional[WindowsSystemProxyManager] = None
    optimize_dns_service: Optional[OptimizeDNSRefreshService] = None

    try:
        server = make_server(
            args,
            resolver,
            resolution_log,
            hosts_manager,
            optimized_dns_cache,
            emergency_lookup,
        )
    except OSError as exc:
        pids, details = listening_pids_for_target(args.listen, args.port)

        if pids:
            raise PortInUseError(args.listen, args.port, pids, details) from exc

        raise

    with server:
        try:
            if config.set_system_proxy:
                system_proxy_manager = maybe_apply_system_proxy(config)

            if optimized_dns_cache and optimize_dns_report_store:
                optimize_dns_service = OptimizeDNSRefreshService(
                    resolver=resolver,
                    cache=optimized_dns_cache,
                    report_store=optimize_dns_report_store,
                    resolution_log=resolution_log,
                    hosts_manager=hosts_manager,
                    connect_timeout=args.connect_timeout,
                    refresh_interval=args.optimize_dns_refresh_interval,
                    verbose=args.verbose,
                )
                optimize_dns_service.start()

            live_traffic_output = not args.verbose and sys.stdout.isatty()

            render_proxy_session_screen(
                config=config,
                doh_urls=doh_urls,
                hosts_manager=hosts_manager,
                optimize_dns_report_store=optimize_dns_report_store,
                stats=server.traffic_stats,
                clear=live_traffic_output,
            )

            serve_thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.5},
                name="doh-http-proxy-server",
                daemon=True,
            )
            serve_thread.start()

            try:
                last_render = time.monotonic()

                while serve_thread.is_alive():
                    serve_thread.join(timeout=0.2)

                    if live_traffic_output and serve_thread.is_alive():
                        now = time.monotonic()

                        if now - last_render >= 1.0:
                            render_proxy_session_screen(
                                config=config,
                                doh_urls=doh_urls,
                                hosts_manager=hosts_manager,
                                optimize_dns_report_store=optimize_dns_report_store,
                                stats=server.traffic_stats,
                                clear=True,
                            )
                            last_render = now
            except KeyboardInterrupt:
                print("\nStopping...")
                server.shutdown()
                server.server_close()
                serve_thread.join(timeout=2.0)

        finally:
            if system_proxy_manager is not None:
                try:
                    system_proxy_manager.restore()
                except Exception:
                    pass

            if optimize_dns_service is not None:
                try:
                    optimize_dns_service.stop()
                except Exception:
                    pass

    return 0


def run_interactive_menu(config: StartupConfig) -> int:
    selected = 0
    message = ""

    while True:
        render_menu(config, selected, message)
        message = ""

        try:
            key = _read_key()
        except KeyboardInterrupt:
            return 0

        if key in (3, 27):  # Ctrl+C / Escape
            return 0

        if key == 13:  # Enter
            if selected == 13:
                try:
                    pids, details = listening_pids_for_target(config.listen, config.port)

                    if pids:
                        message = (
                            f"{config.listen}:{config.port} is already in use by PID(s) "
                            f"{', '.join(str(pid) for pid in pids)}"
                        )
                        continue
                except Exception:
                    pass

                if config.auto_change_hosts and not is_admin():
                    if os.name != "nt":
                        message = "Auto Change Hosts requires Windows administrator privileges."
                        continue

                    save_persistent_startup_config(config)
                    config_file = save_startup_config(config)

                    if launch_elevated(__file__, config_file):
                        return 0

                    try:
                        os.unlink(config_file)
                    except OSError:
                        pass

                    message = "Elevation was cancelled or failed. The proxy was not started."
                    continue

                save_persistent_startup_config(config)

                try:
                    result = start_proxy_session(namespace_from_startup_config(config))
                    if result == 0:
                        message = "Proxy stopped. Back to main menu."
                    else:
                        message = f"Proxy exited with code {result}."
                    continue
                except KeyboardInterrupt:
                    message = "Proxy stopped. Back to main menu."
                    continue
                except PortInUseError as exc:
                    message = (
                        f"{exc.listen}:{exc.port} is already in use. "
                        f"PID(s): {', '.join(str(pid) for pid in exc.pids)}"
                    )
                    continue
                except OSError as exc:
                    message = f"Failed to start proxy: {exc}"
                    continue

            if selected in (2, 5, 6, 9, 10, 11, 12):
                try:
                    toggle_selected_field(config, selected, 1)
                    save_persistent_startup_config(config)
                except KeyboardInterrupt:
                    return 0
                continue

            try:
                edit_selected_field(config, selected)
                save_persistent_startup_config(config)
            except KeyboardInterrupt:
                return 0
            continue

        if key in (328, 336):  # Up/Down
            menu_size = len(_menu_rows(config))

            if key == 328:
                selected = (selected - 1) % menu_size
            else:
                selected = (selected + 1) % menu_size
            continue

        if key in (331, 333):  # Left/Right
            if selected in (2, 5, 6, 9, 10, 11, 12):
                try:
                    toggle_selected_field(config, selected, -1 if key == 331 else 1)
                    save_persistent_startup_config(config)
                except KeyboardInterrupt:
                    return 0
            continue

    return 0


@dataclass
class CacheEntry:
    expires_at: float
    addresses: List[ResolvedAddress]


@dataclass
class ResolveAttempt:
    doh_url: str
    addresses: List[ResolvedAddress]


class DoHResolver:
    def __init__(
        self,
        doh_urls: List[str],
        method: str = "POST",
        timeout: float = 5.0,
        doh_proxy: Optional[str] = None,
        verify_tls: bool = True,
        family_mode: str = "ipv4",
        min_ttl: int = 30,
        max_ttl: int = 300,
        verbose: bool = False,
    ) -> None:
        if not doh_urls:
            raise ValueError("at least one DoH URL is required")

        self.doh_urls = doh_urls
        self.method = method.upper()
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.family_mode = family_mode
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.verbose = verbose

        self.session = requests.Session()

        # فقط --doh-proxy ملاک باشد، نه proxyهای محیط سیستم.
        self.session.trust_env = False

        self.proxies = self._build_requests_proxies(doh_proxy)

        # cache key:
        #   (doh_url, host, qtype)
        self._cache: Dict[Tuple[str, str, str], CacheEntry] = {}
        self._cache_lock = threading.Lock()

    @staticmethod
    def _build_requests_proxies(proxy_url: Optional[str]) -> Optional[Dict[str, str]]:
        if not proxy_url:
            return None

        return {
            "http": proxy_url,
            "https": proxy_url,
        }

    def resolve_attempts(
        self,
        host: str,
        force_refresh: bool = False,
    ) -> List[ResolveAttempt]:
        """
        همه‌ی DoHها را به ترتیب امتحان می‌کند.

        اگر یک DoH:
          - timeout بدهد
          - HTTP error بدهد
          - DNS response نامعتبر بدهد
          - رکورد A/AAAA قابل استفاده ندهد

        به DoH بعدی می‌رود.

        خروجی، attemptهای موفق DNS است.
        تست اتصال TCP در ProxyHandler انجام می‌شود؛ چون فقط آنجا مشخص می‌شود
        IP واقعا قابل استفاده هست یا نه.
        """
        host = normalize_host(host)

        if not host:
            raise ValueError("empty host")

        if is_ip_literal(host):
            return [
                ResolveAttempt(
                    doh_url="literal-ip",
                    addresses=[(host, family_for_ip(host))],
                )
            ]

        attempts: List[ResolveAttempt] = []
        errors: List[str] = []

        for doh_url in self.doh_urls:
            try:
                addresses = self._resolve_with_one_doh(
                    doh_url,
                    host,
                    force_refresh=force_refresh,
                )

                if not addresses:
                    raise RuntimeError("no usable A/AAAA records")

                attempts.append(
                    ResolveAttempt(
                        doh_url=doh_url,
                        addresses=addresses,
                    )
                )

            except Exception as exc:
                errors.append(f"{doh_url}: {exc}")

                if self.verbose:
                    print_verbose_error(f"[DoH fallback] failed: {host} via {doh_url}: {exc}")

                continue

        if not attempts:
            raise RuntimeError(
                f"all DoH resolvers failed for {host}; "
                f"errors: {' | '.join(errors)}"
            )

        return attempts

    def invalidate(self, host: str, doh_url: str) -> None:
        """
        وقتی IPهای یک DoH قابل اتصال نبودند، cache همان host برای همان DoH حذف می‌شود
        تا درخواست بعدی مجبور شود دوباره resolve کند.
        """
        host = normalize_host(host)

        with self._cache_lock:
            keys_to_delete = [
                key
                for key in self._cache
                if key[0] == doh_url and key[1] == host
            ]

            for key in keys_to_delete:
                del self._cache[key]

    def _resolve_with_one_doh(
        self,
        doh_url: str,
        host: str,
        force_refresh: bool = False,
    ) -> List[ResolvedAddress]:
        qtypes = self._qtypes_for_mode()
        addresses: List[ResolvedAddress] = []

        for qtype in qtypes:
            qtype_addresses = self._resolve_one_qtype(
                doh_url,
                host,
                qtype,
                force_refresh=force_refresh,
            )
            addresses.extend(qtype_addresses)

        seen_ips: set[str] = set()
        unique_addresses: List[ResolvedAddress] = []

        for ip, family in addresses:
            if ip not in seen_ips:
                unique_addresses.append((ip, family))
                seen_ips.add(ip)

        return unique_addresses

    def _qtypes_for_mode(self) -> List[str]:
        if self.family_mode == "ipv6":
            return ["AAAA"]

        if self.family_mode == "both-ipv6-first":
            return ["AAAA", "A"]

        if self.family_mode == "both-ipv4-first":
            return ["A", "AAAA"]

        return ["A"]

    def _resolve_one_qtype(
        self,
        doh_url: str,
        host: str,
        qtype: str,
        force_refresh: bool = False,
    ) -> List[ResolvedAddress]:
        now = time.time()
        cache_key = (doh_url, host, qtype)

        if not force_refresh:
            with self._cache_lock:
                cached = self._cache.get(cache_key)

                if cached and cached.expires_at > now:
                    return list(cached.addresses)

        raw_response = self._send_doh_query(doh_url, host, qtype)
        message = dns.message.from_wire(raw_response)

        rcode = message.rcode()

        if rcode != dns.rcode.NOERROR:
            raise RuntimeError(
                f"DNS RCODE for {host}/{qtype}: {dns.rcode.to_text(rcode)}"
            )

        addresses: List[ResolvedAddress] = []
        ttls: List[int] = []

        expected_rdtype = dns.rdatatype.from_text(qtype)

        for rrset in message.answer:
            if rrset.rdtype != expected_rdtype:
                continue

            ttls.append(int(rrset.ttl))

            for item in rrset.items:
                ip = item.to_text()
                addresses.append((ip, family_for_ip(ip)))

        ttl = self._clamp_ttl(min(ttls) if ttls else self.min_ttl)
        expires_at = time.time() + ttl

        with self._cache_lock:
            self._cache[cache_key] = CacheEntry(
                expires_at=expires_at,
                addresses=list(addresses),
            )

        if self.verbose:
            ips = ", ".join(ip for ip, _ in addresses) or "-"
            print(
                f"[DoH] {host}/{qtype} via {doh_url} -> {ips} TTL={ttl}s",
                file=sys.stderr,
            )

        return addresses

    def _clamp_ttl(self, ttl: int) -> int:
        return max(self.min_ttl, min(self.max_ttl, ttl))

    def _send_doh_query(self, doh_url: str, host: str, qtype: str) -> bytes:
        rdtype = dns.rdatatype.from_text(qtype)
        query = dns.message.make_query(host, rdtype)
        wire_query = query.to_wire()

        headers = {
            "Accept": "application/dns-message",
            "User-Agent": "local-doh-http-proxy/1.0",
        }

        if self.method == "POST":
            headers["Content-Type"] = "application/dns-message"

            response = self.session.post(
                doh_url,
                data=wire_query,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_tls,
                proxies=self.proxies,
            )

        else:
            encoded = base64.urlsafe_b64encode(wire_query).rstrip(b"=").decode("ascii")

            response = self.session.get(
                doh_url,
                params={"dns": encoded},
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_tls,
                proxies=self.proxies,
            )

        if response.status_code != 200:
            preview = response.content[:200].decode("utf-8", errors="replace")
            raise RuntimeError(f"DoH HTTP {response.status_code}: {preview}")

        return response.content


def recv_until_header_end(
    sock: socket.socket,
    limit: int = 65536,
) -> Tuple[bytes, bytes]:
    data = bytearray()

    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)

        if not chunk:
            break

        data.extend(chunk)

        if len(data) > limit:
            raise ValueError("HTTP header too large")

    raw = bytes(data)
    header_end = raw.find(b"\r\n\r\n")

    if header_end == -1:
        return raw, b""

    return raw[: header_end + 4], raw[header_end + 4 :]


def parse_headers(header_lines: List[str]) -> List[Tuple[str, str]]:
    headers: List[Tuple[str, str]] = []

    for line in header_lines:
        if not line or ":" not in line:
            continue

        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))

    return headers


def get_header(headers: List[Tuple[str, str]], wanted: str) -> Optional[str]:
    wanted_lower = wanted.lower()

    for name, value in headers:
        if name.lower() == wanted_lower:
            return value

    return None


def split_host_port(value: str, default_port: int) -> Tuple[str, int]:
    value = value.strip()

    if value.startswith("["):
        end = value.find("]")

        if end == -1:
            raise ValueError(f"invalid IPv6 host-port: {value}")

        host = value[1:end]
        rest = value[end + 1 :]

        if rest.startswith(":"):
            return host, int(rest[1:])

        return host, default_port

    if value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        return host, int(port_text)

    return value, default_port


def origin_form_from_absolute_url(target: str) -> str:
    parsed = urlsplit(target)

    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    return path


def format_host_port(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"

    return f"{host}:{port}"


def build_absolute_url(host: str, port: int, target: str) -> str:
    authority = host if port == 80 and ":" not in host else format_host_port(host, port)
    origin_form = target or "/"

    if not origin_form.startswith("/"):
        origin_form = "/" + origin_form

    return f"http://{authority}{origin_form}"


@dataclass(frozen=True)
class UpstreamProxyConfig:
    scheme: str
    hostname: str
    port: int
    username: str = ""
    password: str = ""

    @property
    def authority(self) -> str:
        return format_host_port(self.hostname, self.port)

    @property
    def display(self) -> str:
        return f"{self.scheme}://{self.authority}"

    @property
    def authorization_header(self) -> Optional[str]:
        if not self.username:
            return None

        token = f"{self.username}:{self.password}".encode("utf-8")
        return "Basic " + base64.b64encode(token).decode("ascii")


def parse_upstream_proxy(raw: Optional[str]) -> Optional[UpstreamProxyConfig]:
    if raw is None:
        return None

    value = raw.strip()

    if not value:
        return None

    parsed = urlsplit(value)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("upstream proxy scheme must be http or https")

    if not parsed.hostname:
        raise ValueError("upstream proxy host is required")

    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)

    if not (1 <= port <= 65535):
        raise ValueError("upstream proxy port must be between 1 and 65535")

    return UpstreamProxyConfig(
        scheme=parsed.scheme,
        hostname=parsed.hostname,
        port=port,
        username=unquote(parsed.username or ""),
        password=unquote(parsed.password or ""),
    )


def should_skip_forward_header(name: str) -> bool:
    lower = name.lower()

    return lower in {
        "proxy-connection",
        "proxy-authorization",
        "connection",
        "keep-alive",
    }


@dataclass
class UpstreamConnectResult:
    sock: socket.socket
    connected_to: str
    resolved_by: str
    proxied: bool = False


class ProxyHandler(socketserver.BaseRequestHandler):
    server: "ThreadedHTTPProxy"

    def handle(self) -> None:
        client = self.request
        client.settimeout(self.server.client_timeout)

        try:
            header_bytes, body_remainder = recv_until_header_end(
                client,
                self.server.max_header_bytes,
            )

            if not header_bytes:
                return

            header_text = header_bytes.decode("iso-8859-1", errors="replace")
            lines = header_text.split("\r\n")
            request_line = lines[0]

            self.server.traffic_stats.record_received(len(header_bytes) + len(body_remainder))

            parts = request_line.split(" ", 2)

            if len(parts) != 3:
                self.send_error(client, 400, "Bad request line")
                return

            method, target, version = parts
            headers = parse_headers(lines[1:])

            if method.upper() == "CONNECT":
                self.handle_connect(client, target, body_remainder)
            else:
                self.handle_plain_http(
                    client=client,
                    method=method,
                    target=target,
                    version=version,
                    headers=headers,
                    body_remainder=body_remainder,
                )

        except Exception as exc:
            if is_benign_socket_disconnect(exc):
                return

            if self.server.verbose:
                print_verbose_error(f"[client error] {self.client_address}: {exc}")

            try:
                self.send_error(client, 502, str(exc))
            except Exception:
                pass

    def handle_connect(
        self,
        client: socket.socket,
        target: str,
        body_remainder: bytes,
    ) -> None:
        host, port = split_host_port(target, 443)
        host = normalize_host(host)

        connection = self.open_upstream(host, port, tunnel=True)

        if not connection.proxied:
            self.record_resolution(host, connection.connected_to)

        if self.server.verbose:
            if connection.proxied:
                print(
                    f"[CONNECT] {host}:{port} via upstream proxy "
                    f"{self.server.upstream_proxy.display}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[CONNECT] {host}:{port} via {connection.connected_to} "
                    f"resolved_by={connection.resolved_by}",
                    file=sys.stderr,
                )

        self.send_with_stats(client, b"HTTP/1.1 200 Connection Established\r\n\r\n")

        try:
            if body_remainder:
                self.send_with_stats(connection.sock, body_remainder)

            self.relay(client, connection.sock)

        except Exception as exc:
            if is_benign_socket_disconnect(exc):
                return

            if not connection.proxied:
                self.record_optimized_dns_failure(
                    host,
                    connection.connected_to,
                    connection.resolved_by,
                )
            raise

        finally:
            connection.sock.close()

    def handle_plain_http(
        self,
        client: socket.socket,
        method: str,
        target: str,
        version: str,
        headers: List[Tuple[str, str]],
        body_remainder: bytes,
    ) -> None:
        parsed = urlsplit(target)

        if parsed.scheme and parsed.scheme.lower() != "http":
                self.send_error(client, 400, f"Unsupported URL scheme: {parsed.scheme}")
                return

        if parsed.scheme:
            host = parsed.hostname or ""
            port = parsed.port or 80
            upstream_target = origin_form_from_absolute_url(target)
        else:
            host_header = get_header(headers, "Host")

            if not host_header:
                self.send_error(client, 400, "Missing Host header")
                return

            host, port = split_host_port(host_header, 80)
            upstream_target = target or "/"

        host = normalize_host(host)
        connection = self.open_upstream(host, port, tunnel=False)

        if not connection.proxied:
            self.record_resolution(host, connection.connected_to)

        if self.server.verbose:
            if connection.proxied:
                print(
                    f"[HTTP] {method} {host}:{port}{upstream_target} "
                    f"via upstream proxy {self.server.upstream_proxy.display}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[HTTP] {method} {host}:{port}{upstream_target} "
                    f"via {connection.connected_to} resolved_by={connection.resolved_by}",
                    file=sys.stderr,
                )

        try:
            upstream_request = self.rebuild_http_request(
                method=method,
                target=upstream_target,
                version=version,
                headers=headers,
                host=host,
                port=port,
                proxied=connection.proxied,
            )

            self.send_with_stats(connection.sock, upstream_request)

            if body_remainder:
                self.send_with_stats(connection.sock, body_remainder)

            self.relay(client, connection.sock)

        except Exception as exc:
            if is_benign_socket_disconnect(exc):
                return

            if not connection.proxied:
                self.record_optimized_dns_failure(
                    host,
                    connection.connected_to,
                    connection.resolved_by,
                )
            raise

        finally:
            connection.sock.close()

    def send_with_stats(self, sock: socket.socket, data: bytes) -> None:
        if not data:
            return

        sock.sendall(data)
        self.server.traffic_stats.record_sent(len(data))

    def rebuild_http_request(
        self,
        method: str,
        target: str,
        version: str,
        headers: List[Tuple[str, str]],
        host: str,
        port: int,
        proxied: bool = False,
    ) -> bytes:
        request_target = target

        if proxied:
            parsed = urlsplit(target)

            if not parsed.scheme:
                request_target = build_absolute_url(host, port, target)

        out: List[str] = [f"{method} {request_target} {version}"]

        has_host = False

        for name, value in headers:
            if should_skip_forward_header(name):
                continue

            if name.lower() == "host":
                has_host = True
                out.append(f"Host: {value}")
            else:
                out.append(f"{name}: {value}")

        if not has_host:
            host_header = host if port == 80 and ":" not in host else format_host_port(host, port)
            out.append(f"Host: {host_header}")

        if proxied and self.server.upstream_proxy and self.server.upstream_proxy.authorization_header:
            out.append(f"Proxy-Authorization: {self.server.upstream_proxy.authorization_header}")

        out.append("Connection: close")
        out.append("")
        out.append("")

        return "\r\n".join(out).encode("iso-8859-1")

    def record_resolution(self, host: str, connected_ip: str) -> None:
        if is_ip_literal(host):
            return

        if self.server.resolution_log:
            self.server.resolution_log.add_many([(connected_ip, host)])

        if not self.server.hosts_manager:
            return

        try:
            self.server.hosts_manager.add_many([(connected_ip, host)])
        except OSError as exc:
            if getattr(exc, "winerror", None) == 5 or isinstance(exc, PermissionError):
                self.server.hosts_manager = None
            if self.server.verbose:
                print_verbose_error(f"[hosts] failed to update hosts for {host}: {exc}")

    def record_optimized_dns_failure(
        self,
        host: str,
        connected_ip: str,
        source: str,
    ) -> int:
        if source != "dns-cache" or is_ip_literal(host):
            return 0

        cache = self.server.optimized_dns_cache

        if not cache:
            return 0

        failure_count = cache.record_failure(host, connected_ip)

        if failure_count >= 5:
            cache.forget(host)

            if self.server.verbose:
                print_verbose_error(
                    f"[optimize-dns] cached IP for {host} reached "
                    f"{failure_count} failures; re-resolving"
                )

        return failure_count

    def _connect_to_ip(
        self,
        ip: str,
        port: int,
        family: Optional[int] = None,
    ) -> socket.socket:
        if family is None:
            family = family_for_ip(ip)

        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.server.connect_timeout)

        try:
            if family == socket.AF_INET6:
                sock.connect((ip, port, 0, 0))
            else:
                sock.connect((ip, port))

            sock.settimeout(None)
            return sock

        except OSError:
            sock.close()
            raise

    def _connect_to_upstream_proxy(self, proxy: UpstreamProxyConfig) -> socket.socket:
        sock = socket.create_connection(
            (proxy.hostname, proxy.port),
            timeout=self.server.connect_timeout,
        )

        try:
            if proxy.scheme == "https":
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=proxy.hostname)

            sock.settimeout(None)
            return sock
        except OSError:
            sock.close()
            raise

    def _send_proxy_connect(
        self,
        sock: socket.socket,
        host: str,
        port: int,
        proxy: UpstreamProxyConfig,
    ) -> None:
        authority = format_host_port(host, port)
        request_lines = [
            f"CONNECT {authority} HTTP/1.1",
            f"Host: {authority}",
            "Proxy-Connection: keep-alive",
            "Connection: keep-alive",
        ]

        if proxy.authorization_header:
            request_lines.append(f"Proxy-Authorization: {proxy.authorization_header}")

        request_lines.extend(["", ""])
        request_bytes = "\r\n".join(request_lines).encode("iso-8859-1")
        self.send_with_stats(sock, request_bytes)

        header_bytes, body_remainder = recv_until_header_end(sock, self.server.max_header_bytes)

        if not header_bytes:
            raise OSError("upstream proxy closed the connection during CONNECT")

        self.server.traffic_stats.record_received(len(header_bytes) + len(body_remainder))
        response_text = header_bytes.decode("iso-8859-1", errors="replace")
        status_line = response_text.split("\r\n", 1)[0]
        parts = status_line.split(" ", 2)

        if len(parts) < 2:
            raise OSError(f"invalid upstream proxy response: {status_line}")

        try:
            status_code = int(parts[1])
        except ValueError as exc:
            raise OSError(f"invalid upstream proxy status: {status_line}") from exc

        if status_code != 200:
            raise OSError(f"upstream proxy CONNECT failed: {status_line}")

    def open_upstream(
        self,
        host: str,
        port: int,
        tunnel: bool = False,
    ) -> UpstreamConnectResult:
        """
        ترتیب کار:

        1. DoH اصلی resolve می‌شود.
        2. اتصال TCP به IPهای همان DoH امتحان می‌شود.
        3. اگر هیچ IPای وصل نشد، cache همان DoH/host حذف می‌شود.
        4. DoHهای fallback به ترتیب امتحان می‌شوند.
        5. اولین اتصال موفق برگردانده می‌شود.
        """
        proxy = self.server.upstream_proxy

        if proxy:
            sock = self._connect_to_upstream_proxy(proxy)

            try:
                if tunnel:
                    self._send_proxy_connect(sock, host, port, proxy)

                return UpstreamConnectResult(
                    sock=sock,
                    connected_to=proxy.display,
                    resolved_by="upstream-proxy",
                    proxied=True,
                )
            except Exception:
                sock.close()
                raise

        if self.server.optimized_dns_cache and not is_ip_literal(host):
            self.server.optimized_dns_cache.remember_host(host)

        if is_ip_literal(host):
            sock = self._connect_to_ip(host, port)
            return UpstreamConnectResult(
                sock=sock,
                connected_to=host,
                resolved_by="literal-ip",
            )

        emergency_errors: List[str] = []

        if getattr(self.server, "emergency_lookup", None):
            emergency_matches = self.server.emergency_lookup.lookup_candidates(host)

            for match in emergency_matches:
                try:
                    sock = self._connect_to_ip(match.ip, port)

                    if self.server.optimized_dns_cache and not is_ip_literal(host):
                        self.server.optimized_dns_cache.set(host, match.ip)

                    return UpstreamConnectResult(
                        sock=sock,
                        connected_to=match.ip,
                        resolved_by=match.source,
                    )

                except OSError as exc:
                    if self.server.verbose:
                        print_verbose_error(
                            f"[emergency] connect failed for {host} via {match.source}: "
                            f"{match.ip}:{port}: {exc}"
                        )

                    emergency_errors.append(
                        f"{match.source}: {match.ip}:{port}: {exc}"
                    )

        if self.server.optimized_dns_cache:
            cached_ip = self.server.optimized_dns_cache.get(host)

            if cached_ip:
                try:
                    sock = self._connect_to_ip(cached_ip, port)
                    return UpstreamConnectResult(
                        sock=sock,
                        connected_to=cached_ip,
                        resolved_by="dns-cache",
                    )

                except OSError as exc:
                    failure_count = self.record_optimized_dns_failure(
                        host,
                        cached_ip,
                        "dns-cache",
                    )

                    if self.server.verbose:
                        suffix = f" ({failure_count}/5)" if failure_count else ""
                        print_verbose_error(
                            f"[optimize-dns] cached IP failed for {host}: "
                            f"{cached_ip}:{port}: {exc}{suffix}"
                        )

                    if failure_count < 5:
                        raise

        all_errors: List[str] = list(emergency_errors)

        for doh_url in self.server.resolver.doh_urls:
            try:
                addresses = self.server.resolver._resolve_with_one_doh(doh_url, host)

                if not addresses:
                    raise RuntimeError("no usable A/AAAA records")

            except Exception as exc:
                all_errors.append(f"{doh_url}: {exc}")

                if self.server.verbose:
                    print_verbose_error(f"[fallback] resolve failed for {host} via {doh_url}: {exc}")

                continue

            endpoint_errors: List[str] = []

            for ip, family in addresses:
                try:
                    sock = self._connect_to_ip(ip, port, family=family)
                    if self.server.optimized_dns_cache and not is_ip_literal(host):
                        self.server.optimized_dns_cache.set(host, ip)
                    return UpstreamConnectResult(
                        sock=sock,
                        connected_to=ip,
                        resolved_by=doh_url,
                    )

                except OSError as exc:
                    endpoint_errors.append(f"{ip}:{port}: {exc}")

            self.server.resolver.invalidate(host, doh_url)

            all_errors.append(
                f"{doh_url}: {'; '.join(endpoint_errors) or 'no addresses tried'}"
            )

            if self.server.verbose:
                print_verbose_error(
                    f"[fallback] connect failed for {host}:{port} "
                    f"using {doh_url}; trying next DoH"
                )

        raise OSError(
            f"could not connect to {host}:{port}; "
            f"tried all DoH results: {' | '.join(all_errors)}"
        )

    def relay(self, client: socket.socket, upstream: socket.socket) -> None:
        client.settimeout(None)
        upstream.settimeout(None)

        sel = selectors.DefaultSelector()
        sel.register(client, selectors.EVENT_READ, upstream)
        sel.register(upstream, selectors.EVENT_READ, client)

        try:
            while True:
                events = sel.select(timeout=self.server.idle_timeout)

                if not events:
                    break

                for key, _ in events:
                    src: socket.socket = key.fileobj
                    dst: socket.socket = key.data

                    try:
                        data = src.recv(65536)
                    except Exception as exc:
                        if is_benign_socket_disconnect(exc):
                            return
                        raise

                    if not data:
                        return

                    self.server.traffic_stats.record_received(len(data))

                    try:
                        dst.sendall(data)
                    except Exception as exc:
                        if is_benign_socket_disconnect(exc):
                            return
                        raise

                    self.server.traffic_stats.record_sent(len(data))

        finally:
            sel.close()

    def send_error(self, sock: socket.socket, status: int, message: str) -> None:
        reason = {
            400: "Bad Request",
            502: "Bad Gateway",
            504: "Gateway Timeout",
        }.get(status, "Error")

        body = f"{status} {reason}\n{message}\n".encode("utf-8", errors="replace")

        response = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii") + body

        sock.sendall(response)
        self.server.traffic_stats.record_sent(len(response))


class ThreadedHTTPProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: Tuple[str, int],
        handler_class: type[ProxyHandler],
        resolver: DoHResolver,
        upstream_proxy: Optional[UpstreamProxyConfig],
        resolution_log: Optional[ResolutionLog],
        hosts_manager: Optional[HostsFileManager],
        optimized_dns_cache: Optional[OptimizedDNSCache],
        emergency_lookup: Optional[EmergencyDNSLookup],
        client_timeout: float,
        connect_timeout: float,
        idle_timeout: float,
        max_header_bytes: int,
        verbose: bool,
    ) -> None:
        self.resolver = resolver
        self.upstream_proxy = upstream_proxy
        self.resolution_log = resolution_log
        self.hosts_manager = hosts_manager
        self.optimized_dns_cache = optimized_dns_cache
        self.emergency_lookup = emergency_lookup
        self.client_timeout = client_timeout
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.max_header_bytes = max_header_bytes
        self.verbose = verbose
        self.traffic_stats = TrafficStats()

        super().__init__(server_address, handler_class)


def read_doh_file(path: str) -> List[str]:
    """
    فایل DoH را می‌خواند.

    اولین خط معتبر: DoH اصلی
    خطوط معتبر بعدی: fallback DoHها

    خطوط خالی و خطوطی که با # شروع شوند نادیده گرفته می‌شوند.
    """
    urls: List[str] = []

    with open(path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            urls.append(line)

    return urls


def unique_preserve_order(values: Iterable[str]) -> List[str]:
    unique_values: List[str] = []
    seen: set[str] = set()

    for value in values:
        if value not in seen:
            unique_values.append(value)
            seen.add(value)

    return unique_values


def make_server(
    args: argparse.Namespace,
    resolver: DoHResolver,
    resolution_log: Optional[ResolutionLog],
    hosts_manager: Optional[HostsFileManager],
    optimized_dns_cache: Optional[OptimizedDNSCache],
    emergency_lookup: Optional[EmergencyDNSLookup],
) -> ThreadedHTTPProxy:
    if ":" in args.listen and not args.listen.count("."):
        ThreadedHTTPProxy.address_family = socket.AF_INET6
    else:
        ThreadedHTTPProxy.address_family = socket.AF_INET

    upstream_proxy = None

    if args.use_upstream_proxy:
        upstream_proxy = parse_upstream_proxy(validate_optional_proxy(args.upstream_proxy or ""))

        if upstream_proxy is None:
            raise ValueError("--use-upstream-proxy requires --upstream-proxy")

    return ThreadedHTTPProxy(
        server_address=(args.listen, args.port),
        handler_class=ProxyHandler,
        resolver=resolver,
        upstream_proxy=upstream_proxy,
        resolution_log=resolution_log,
        hosts_manager=hosts_manager,
        optimized_dns_cache=optimized_dns_cache,
        emergency_lookup=emergency_lookup,
        client_timeout=args.client_timeout,
        connect_timeout=args.connect_timeout,
        idle_timeout=args.idle_timeout,
        max_header_bytes=args.max_header_bytes,
        verbose=args.verbose,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Local HTTP proxy that resolves destination domains through DoH. "
            "The first DoH in --doh-file is primary and the rest are fallbacks. "
            "Interactive runs load the last saved settings and command-line "
            "arguments override them."
        )
    )

    parser.add_argument(
        "--listen",
        help="Listen address. Default: 0.0.0.0",
    )

    parser.add_argument(
        "--port",
        type=int,
        help="Listen port. Default: 8080",
    )

    parser.add_argument(
        "--doh-file",
        help=(
            "TXT file containing DoH endpoint URLs. "
            "The first valid line is primary; the remaining valid lines are fallbacks."
        ),
    )

    parser.add_argument(
        "--doh-method",
        choices=["GET", "POST"],
        help="DoH method for all DoH endpoints. Default: POST",
    )

    parser.add_argument(
        "--doh-proxy",
        help=(
            "Optional HTTP/HTTPS proxy used for all DoH requests, e.g. "
            "http://127.0.0.1:7890 or https://proxy.example:8443"
        ),
    )

    parser.add_argument(
        "--use-doh-proxy",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable the DoH proxy. Default: enabled",
    )

    parser.add_argument(
        "--use-upstream-proxy",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable an upstream proxy for client connections. Default: disabled",
    )

    parser.add_argument(
        "--upstream-proxy",
        help=(
            "Optional HTTP/HTTPS proxy for client connections, e.g. "
            "http://127.0.0.1:7890 or https://proxy.example:8443"
        ),
    )

    parser.add_argument(
        "--insecure-doh-tls",
        action="store_true",
        default=None,
        help="Disable TLS certificate verification for DoH HTTPS endpoints.",
    )

    parser.add_argument(
        "--family",
        choices=["ipv4", "ipv6", "both-ipv4-first", "both-ipv6-first"],
        help="Which DNS record family to use. Default: ipv4",
    )

    parser.add_argument(
        "--min-ttl",
        type=int,
        help="Minimum cache TTL seconds. Default: 30",
    )

    parser.add_argument(
        "--max-ttl",
        type=int,
        help="Maximum cache TTL seconds. Default: 300",
    )

    parser.add_argument(
        "--output",
        help=(
            "TXT file for '[IP] [domain]' rows. "
            "Domain is unique and updated in place. Default: resolved.txt"
        ),
    )

    parser.add_argument(
        "--set-system-proxy",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable system proxy management. Default: enabled",
    )

    parser.add_argument(
        "--auto-change-hosts",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable hosts file updates. Default: enabled",
    )

    parser.add_argument(
        "--optimize-dns",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable domain-to-IP connection cache. Default: enabled",
    )

    parser.add_argument(
        "--optimize-dns-refresh-interval",
        type=float,
        help="Background OptimizeDNS sweep interval in seconds. Default: 60",
    )

    parser.add_argument(
        "--optimize-dns-report",
        help=(
            "JSON report file for OptimizeDNS sweeps. "
            "Default: optimized_dns_report.json"
        ),
    )

    parser.add_argument(
        "--emergency-mode",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Prioritize optimized_dns_report.json and the Windows hosts file "
            "before trying DoH. Default: disabled"
        ),
    )

    parser.add_argument(
        "--client-timeout",
        type=float,
        help="Initial client read timeout. Default: 10",
    )

    parser.add_argument(
        "--connect-timeout",
        type=float,
        help="Upstream connect timeout. Default: 10",
    )

    parser.add_argument(
        "--idle-timeout",
        type=float,
        help="Tunnel idle timeout. Default: 300",
    )

    parser.add_argument(
        "--max-header-bytes",
        type=int,
        help="Max HTTP header size. Default: 65536",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        default=None,
        help="Print connection, DoH, and fallback details to stderr.",
    )

    parser.add_argument(
        "--config-file",
        help=argparse.SUPPRESS,
    )

    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.config_file:
        try:
            args = load_namespace_from_config_file(args.config_file)
        except (OSError, ValueError, TypeError) as exc:
            print(f"Could not load config file: {exc}", file=sys.stderr)
            return 2

    startup_config = build_startup_config_from_namespace(args)
    save_persistent_startup_config(startup_config)

    if should_show_menu(args):
        return run_interactive_menu(startup_config)

    try:
        return start_proxy_session(namespace_from_startup_config(startup_config))
    except PortInUseError as exc:
        print(
            f"{exc.listen}:{exc.port} is already in use by PID(s): "
            f"{', '.join(str(pid) for pid in exc.pids)}",
            file=sys.stderr,
        )
        for detail in exc.details:
            print(f"  {detail}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Failed to start proxy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
