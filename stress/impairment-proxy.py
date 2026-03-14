#!/usr/bin/env python3
"""
ZTLP Network Impairment Proxy — Userspace UDP relay with configurable impairment.

Sits between client and server, forwarding UDP packets while applying:
  - Latency (fixed delay + jitter with normal distribution)
  - Packet loss (random, correlated/burst via Gilbert-Elliott)
  - Corruption (random bit-flip in payload)
  - Reordering (delayed delivery of some packets)
  - Duplication (send packet twice)
  - Bandwidth limiting (token bucket)

Configuration is loaded from /tmp/impairment.json (watched for changes).
Metrics are written to /tmp/impairment-metrics.json.

Usage:
    impairment-proxy --client-addr 172.30.1.50 --server-addr 172.30.2.40 --port 23095
"""

import argparse
import hashlib
import json
import os
import random
import select
import socket
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

CONFIG_PATH = "/tmp/impairment.json"
METRICS_PATH = "/tmp/impairment-metrics.json"

# ── Configuration ────────────────────────────────────────────

@dataclass
class ImpairmentConfig:
    # Latency
    delay_ms: float = 0.0           # Base delay in ms
    jitter_ms: float = 0.0          # Jitter (std dev) in ms
    # Packet loss
    loss_pct: float = 0.0           # Random loss percentage (0-100)
    loss_correlation: float = 0.0   # Loss correlation for burst (0-100)
    # Corruption
    corrupt_pct: float = 0.0        # Bit corruption percentage (0-100)
    # Reordering
    reorder_pct: float = 0.0        # Percentage of packets to delay
    reorder_delay_ms: float = 50.0  # Extra delay for reordered packets
    # Duplication
    duplicate_pct: float = 0.0      # Percentage of packets to duplicate
    # Bandwidth
    rate_kbps: int = 0              # Rate limit in kbps (0 = unlimited)
    # Direction: "both", "upstream" (client→server), "downstream" (server→client)
    direction: str = "both"
    # Active
    enabled: bool = True


def load_config() -> ImpairmentConfig:
    """Load impairment config from JSON file."""
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
        return ImpairmentConfig(**{k: v for k, v in data.items() if k in ImpairmentConfig.__dataclass_fields__})
    except (FileNotFoundError, json.JSONDecodeError, TypeError):
        return ImpairmentConfig()


# ── Impairment Engine ────────────────────────────────────────

class ImpairmentEngine:
    def __init__(self):
        self.config = ImpairmentConfig()
        self._last_loss = False  # For correlated loss (Gilbert-Elliott)
        self._token_bucket = 0.0
        self._last_token_time = time.monotonic()
        self._lock = threading.Lock()
        
        # Metrics
        self.metrics = {
            "packets_forwarded": 0,
            "packets_dropped_loss": 0,
            "packets_corrupted": 0,
            "packets_reordered": 0,
            "packets_duplicated": 0,
            "packets_dropped_rate": 0,
            "bytes_forwarded": 0,
            "start_time": time.time(),
        }
    
    def update_config(self, config: ImpairmentConfig):
        with self._lock:
            self.config = config
    
    def should_drop(self) -> bool:
        """Determine if packet should be dropped (loss simulation)."""
        cfg = self.config
        if cfg.loss_pct <= 0:
            return False
        
        if cfg.loss_correlation > 0:
            # Gilbert-Elliott correlated loss
            if self._last_loss:
                p = cfg.loss_pct / 100.0 + (cfg.loss_correlation / 100.0) * (1 - cfg.loss_pct / 100.0)
            else:
                p = cfg.loss_pct / 100.0 * (1 - cfg.loss_correlation / 100.0)
            drop = random.random() < p
        else:
            drop = random.random() < (cfg.loss_pct / 100.0)
        
        self._last_loss = drop
        return drop
    
    def should_corrupt(self) -> bool:
        cfg = self.config
        return cfg.corrupt_pct > 0 and random.random() < (cfg.corrupt_pct / 100.0)
    
    def corrupt_packet(self, data: bytes) -> bytes:
        """Flip a random bit in the packet."""
        if len(data) < 20:  # Don't corrupt tiny packets
            return data
        ba = bytearray(data)
        # Flip a random bit in the payload area (skip first 16 bytes = header)
        pos = random.randint(16, len(ba) - 1)
        bit = random.randint(0, 7)
        ba[pos] ^= (1 << bit)
        return bytes(ba)
    
    def should_reorder(self) -> bool:
        cfg = self.config
        return cfg.reorder_pct > 0 and random.random() < (cfg.reorder_pct / 100.0)
    
    def should_duplicate(self) -> bool:
        cfg = self.config
        return cfg.duplicate_pct > 0 and random.random() < (cfg.duplicate_pct / 100.0)
    
    def get_delay(self) -> float:
        """Get delay in seconds for this packet."""
        cfg = self.config
        if cfg.delay_ms <= 0 and cfg.jitter_ms <= 0:
            return 0.0
        delay = cfg.delay_ms
        if cfg.jitter_ms > 0:
            delay += random.gauss(0, cfg.jitter_ms)
        return max(0, delay / 1000.0)
    
    def check_rate_limit(self, pkt_size: int) -> bool:
        """Token bucket rate limiter. Returns True if packet should pass."""
        cfg = self.config
        if cfg.rate_kbps <= 0:
            return True
        
        now = time.monotonic()
        elapsed = now - self._last_token_time
        self._last_token_time = now
        
        # Add tokens (bytes) based on elapsed time
        rate_bps = cfg.rate_kbps * 1000 / 8  # Convert kbps to bytes/sec
        self._token_bucket += elapsed * rate_bps
        # Cap bucket at 2x burst (allow small bursts)
        max_bucket = rate_bps * 0.1  # 100ms worth of tokens
        self._token_bucket = min(self._token_bucket, max(max_bucket, pkt_size * 2))
        
        if self._token_bucket >= pkt_size:
            self._token_bucket -= pkt_size
            return True
        return False
    
    def applies_to_direction(self, is_upstream: bool) -> bool:
        """Check if impairment applies to this direction."""
        d = self.config.direction
        if d == "both":
            return True
        if d == "upstream" and is_upstream:
            return True
        if d == "downstream" and not is_upstream:
            return True
        return False
    
    def write_metrics(self):
        """Write metrics to file."""
        try:
            m = dict(self.metrics)
            m["uptime_s"] = round(time.time() - m["start_time"], 1)
            m["config"] = {
                "delay_ms": self.config.delay_ms,
                "jitter_ms": self.config.jitter_ms,
                "loss_pct": self.config.loss_pct,
                "corrupt_pct": self.config.corrupt_pct,
                "reorder_pct": self.config.reorder_pct,
                "duplicate_pct": self.config.duplicate_pct,
                "rate_kbps": self.config.rate_kbps,
                "direction": self.config.direction,
            }
            with open(METRICS_PATH, "w") as f:
                json.dump(m, f, indent=2)
        except Exception:
            pass


# ── Delayed Packet Queue ────────────────────────────────────

class DelayedQueue:
    """Priority queue of (send_time, data, addr, sock) tuples."""
    def __init__(self):
        self._queue: deque = deque()
        self._lock = threading.Lock()
    
    def push(self, send_time: float, data: bytes, addr: tuple, sock: socket.socket):
        with self._lock:
            # Insert in order (usually at end since delays are similar)
            self._queue.append((send_time, data, addr, sock))
    
    def flush_ready(self) -> list:
        """Return all packets whose send_time has passed."""
        now = time.monotonic()
        ready = []
        with self._lock:
            while self._queue and self._queue[0][0] <= now:
                ready.append(self._queue.popleft())
        return ready
    
    def next_deadline(self) -> Optional[float]:
        """Time until next packet should be sent (seconds)."""
        with self._lock:
            if not self._queue:
                return None
            return max(0, self._queue[0][0] - time.monotonic())


# ── Proxy ────────────────────────────────────────────────────

class ImpairmentProxy:
    def __init__(self, bind_port: int, server_addr: str, server_port: int):
        self.bind_port = bind_port
        self.server_addr = server_addr
        self.server_port = server_port
        self.engine = ImpairmentEngine()
        self.delayed = DelayedQueue()
        
        # Track client addresses (we learn them from incoming packets)
        self._client_addrs: dict = {}  # addr -> last_seen_time
        
        # Sockets
        self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client_sock.bind(("0.0.0.0", bind_port))
        self.client_sock.setblocking(False)
        
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_sock.setblocking(False)
    
    def run(self):
        """Main event loop."""
        print(f"[proxy] Listening on :{self.bind_port}, forwarding to {self.server_addr}:{self.server_port}")
        print(f"[proxy] Config: {CONFIG_PATH}")
        print(f"[proxy] Metrics: {METRICS_PATH}")
        
        # Config reload thread
        config_thread = threading.Thread(target=self._config_watcher, daemon=True)
        config_thread.start()
        
        # Metrics thread
        metrics_thread = threading.Thread(target=self._metrics_writer, daemon=True)
        metrics_thread.start()
        
        while True:
            # Calculate timeout for select based on delayed queue
            timeout = self.delayed.next_deadline()
            if timeout is None:
                timeout = 0.1
            else:
                timeout = min(timeout, 0.1)
            
            readable, _, _ = select.select(
                [self.client_sock, self.server_sock], [], [], timeout
            )
            
            for sock in readable:
                try:
                    data, addr = sock.recvfrom(65535)
                except (BlockingIOError, OSError):
                    continue
                
                if sock is self.client_sock:
                    # Client → Server (upstream)
                    self._client_addrs[addr] = time.monotonic()
                    self._process_packet(data, (self.server_addr, self.server_port),
                                        self.server_sock, is_upstream=True)
                else:
                    # Server → Client (downstream)
                    # Forward to the most recent client
                    if self._client_addrs:
                        client_addr = max(self._client_addrs, key=self._client_addrs.get)
                        self._process_packet(data, client_addr,
                                            self.client_sock, is_upstream=False)
            
            # Flush delayed packets
            for _, pkt_data, pkt_addr, pkt_sock in self.delayed.flush_ready():
                try:
                    pkt_sock.sendto(pkt_data, pkt_addr)
                except OSError:
                    pass
    
    def _process_packet(self, data: bytes, dest: tuple, sock: socket.socket, is_upstream: bool):
        """Apply impairment and forward packet."""
        eng = self.engine
        
        # Check if impairment applies to this direction
        if not eng.applies_to_direction(is_upstream):
            sock.sendto(data, dest)
            eng.metrics["packets_forwarded"] += 1
            eng.metrics["bytes_forwarded"] += len(data)
            return
        
        if not eng.config.enabled:
            sock.sendto(data, dest)
            eng.metrics["packets_forwarded"] += 1
            eng.metrics["bytes_forwarded"] += len(data)
            return
        
        # Rate limit check
        if not eng.check_rate_limit(len(data)):
            eng.metrics["packets_dropped_rate"] += 1
            return
        
        # Loss check
        if eng.should_drop():
            eng.metrics["packets_dropped_loss"] += 1
            return
        
        # Corruption
        if eng.should_corrupt():
            data = eng.corrupt_packet(data)
            eng.metrics["packets_corrupted"] += 1
        
        # Duplication (send extra copy)
        if eng.should_duplicate():
            delay = eng.get_delay()
            if delay > 0:
                send_time = time.monotonic() + delay
                self.delayed.push(send_time, data, dest, sock)
            else:
                try:
                    sock.sendto(data, dest)
                except OSError:
                    pass
            eng.metrics["packets_duplicated"] += 1
        
        # Calculate delay
        delay = eng.get_delay()
        
        # Reordering: add extra delay to some packets
        if eng.should_reorder():
            delay += eng.config.reorder_delay_ms / 1000.0
            eng.metrics["packets_reordered"] += 1
        
        if delay > 0.001:  # > 1ms
            send_time = time.monotonic() + delay
            self.delayed.push(send_time, data, dest, sock)
        else:
            try:
                sock.sendto(data, dest)
            except OSError:
                pass
        
        eng.metrics["packets_forwarded"] += 1
        eng.metrics["bytes_forwarded"] += len(data)
    
    def _config_watcher(self):
        """Watch config file for changes and reload."""
        last_mtime = 0
        while True:
            try:
                mtime = os.path.getmtime(CONFIG_PATH)
                if mtime != last_mtime:
                    config = load_config()
                    self.engine.update_config(config)
                    last_mtime = mtime
                    print(f"[proxy] Config reloaded: delay={config.delay_ms}ms loss={config.loss_pct}% "
                          f"corrupt={config.corrupt_pct}% reorder={config.reorder_pct}% "
                          f"dup={config.duplicate_pct}% rate={config.rate_kbps}kbps "
                          f"dir={config.direction}")
            except Exception:
                pass
            time.sleep(0.5)
    
    def _metrics_writer(self):
        """Periodically write metrics to file."""
        while True:
            self.engine.write_metrics()
            time.sleep(2)


# ── Main ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ZTLP Network Impairment Proxy")
    parser.add_argument("--port", type=int, default=23095, help="Listen port (default: 23095)")
    parser.add_argument("--server-addr", required=True, help="Real server address")
    parser.add_argument("--server-port", type=int, default=23095, help="Real server port")
    args = parser.parse_args()
    
    # Write default config
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            json.dump({"enabled": False}, f)
    
    proxy = ImpairmentProxy(args.port, args.server_addr, args.server_port)
    proxy.run()


if __name__ == "__main__":
    main()
