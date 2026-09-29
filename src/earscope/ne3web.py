#!/usr/bin/env python3
"""
ne3web.py - Tmu Ear Violator 4000 Streamer
A tiny, dependency-free web viewer for HNDEC / NE3 / NE7 WiFi ear cameras
(the ones that normally want the "SL ylz" app).

  1. Turn the scope on, join its WiFi "HNDEC-xxxxxx" (no password).
  2. python3 ne3web.py
  3. Open http://localhost:8080

Pure Python standard library (3.8+). Works on Windows, macOS, Linux, and
Android via Termux. Protocol based on the reverse engineering in
https://github.com/haxko/NE3-Scope (WTFPL).

Required Notice: Copyright (c) 2026 Matthew Armstrong (https://github.com/The-Dorkknight)
Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). No warranty.

Endpoints:
  /             viewer UI (auto-rotate, mirror, zoom, circle mask, snapshot, record)
  /stream.mjpg  plain MJPEG stream (VLC, OBS, ffmpeg, <img> tags)
  /snapshot.jpg latest frame
  /status       JSON status
"""
VERSION = "1.0.0"

import argparse
import shlex
import signal
import collections
import os
import select
import subprocess
import sys
import json
import socket
import struct
import threading
import time
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from math import atan2, degrees
from urllib.parse import urlparse, parse_qs

# --------------------------------------------------------------------------
# Camera protocol
# --------------------------------------------------------------------------
HDR = struct.Struct("<xxHxxxxQQxxxxxxxxIIIHHBxxxxxxx")  # 56 bytes
CHUNK = 1024

QTABLES = {
    5: ("ffdb004300a06e788c7864a08c828cb4aaa0bef0fffff0dcdcf0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffdb004301aab4b4f0d2f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    10: ("ffdb00430050373c463c32504641465a55505f78c882786e6e78f5afb991c8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
         "ffdb004301555a5a786978eb8282ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    25: ("ffdb0043002016181c1814201c1a1c24222026305034302c2c3062464a3a5074667a787266706e8090b89c8088ae8a6e70a0daa2aebec4ced0ce7c9ae2f2e0c8f0b8cacec6",
         "ffdb004301222424302a305e34345ec6847084c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6"),
    50: ("ffdb004300100b0c0e0c0a100e0d0e1211101318281a181616183123251d283a333d3c3933383740485c4e404457453738506d51575f626768673e4d71797064785c656763",
         "ffdb0043011112121815182f1a1a2f634238426363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363"),
    75: ("ffdb004300080606070605080707070909080a0c140d0c0b0b0c1912130f141d1a1f1e1d1a1c1c20242e2720222c231c1c2837292c30313434341f27393d38323c2e333432",
         "ffdb0043010909090c0b0c180d0d1832211c213232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232"),
    100: ("ffdb00430001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
          "ffdb00430101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"),
}
HUFFMAN = bytes.fromhex(
    "ffc4001f0000010501010101010100000000000000000102030405060708090a0b"
    "ffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9fa"
    "ffc4001f0100030101010101010101010000000000000102030405060708090a0b"
    "ffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9fa"
)
SOS = bytes.fromhex("ffda000c03010002110311003f00")
_hdr_cache = {}


def jpeg_header(q, h, w):
    """The camera strips the JPEG header off every frame; rebuild it."""
    key = (q, h, w)
    if key not in _hdr_cache:
        lum, chrom = QTABLES.get(q, QTABLES[100])
        _hdr_cache[key] = (b"\xff\xd8" + bytes.fromhex(lum) + bytes.fromhex(chrom)
                           + b"\xff\xc0\x00\x11\x08" + struct.pack(">HH", h, w)
                           + bytes.fromhex("03011100021101031101") + HUFFMAN + SOS)
    return _hdr_cache[key]


class Frame:
    def __init__(self, img_no, count, q, w, h):
        self.img_no, self.count, self.q, self.w, self.h = img_no, count, q, w, h
        self.chunks = {}
        self.angle = None

    def add(self, pkt_no, payload):
        if pkt_no == 0 and len(payload) > CHUNK:
            # Accelerometer reading rides along in packet 0 as text "xxxxx yyyy"
            try:
                a = payload[CHUNK:]
                x, y = int(a[:5].decode()), int(a[6:].decode())
                self.angle = 90.0 if (x == 0 and y == 1024) else degrees(atan2(x, y))
            except (ValueError, UnicodeDecodeError):
                pass
        self.chunks[pkt_no] = payload[:CHUNK]

    def complete(self):
        return len(self.chunks) == self.count

    def jpeg(self):
        return (jpeg_header(self.q, self.h, self.w)
                + b"".join(self.chunks[i] for i in range(self.count)) + b"\xff\xd9")


# --------------------------------------------------------------------------
# Log (shown in the viewer's Log panel, also printed to the terminal)
# --------------------------------------------------------------------------
_log_lock = threading.Lock()
_log_lines = collections.deque(maxlen=800)
_log_id = 0


def log(msg):
    global _log_id
    line = time.strftime("%H:%M:%S ") + str(msg)
    with _log_lock:
        _log_id += 1
        _log_lines.append((_log_id, line))
    print(line, flush=True)


def log_since(after):
    with _log_lock:
        return [l for l in _log_lines if l[0] > after], _log_id


def _hex(b, n=24):
    return b[:n].hex(" ") + (" ..." if len(b) > n else "")


def default_gateways():
    """[(interface, gateway_ip)] from /proc/net/route (Linux/Android)."""
    out = []
    try:
        with open("/proc/net/route") as f:
            for row in f.readlines()[1:]:
                p = row.split()
                if p[1] == "00000000" and int(p[3], 16) & 2:
                    out.append((p[0], socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))))
    except (OSError, ValueError, IndexError):
        pass
    return out


def my_ip_towards(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((ip, 9))
        a = s.getsockname()[0]
        s.close()
        return a
    except OSError as e:
        return f"none ({e.strerror or e})"


def jpeg_size(b):
    """(width, height) from a JPEG's SOF marker, or (0, 0)."""
    i = 2
    while i + 9 < len(b):
        if b[i] != 0xFF:
            i += 1
            continue
        m = b[i + 1]
        if m in (0xC0, 0xC1, 0xC2):
            h, w = struct.unpack(">HH", b[i + 5:i + 9])
            return w, h
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7 or m == 0xFF:
            i += 2 if m != 0xFF else 1
            continue
        i += 2 + struct.unpack(">H", b[i + 2:i + 4])[0]
    return 0, 0


class Camera(threading.Thread):
    NE3_DEFAULT_IP = "192.168.169.1"
    NE7_VIDEO, NE7_SENSOR = 44506, 52219
    NE7_DISCOVERY = (58090, 46526)

    def __init__(self, ip=None, port=8800, local_port=36000, verbose=False,
                 socket_hook=None, protocol="auto"):
        super().__init__(daemon=True)
        self.forced_ip = ip                  # None = find it automatically
        self.protocol_choice = protocol      # "auto", "ne3" or "ne7"
        self.protocol = None                 # what we actually found
        self.addr = (ip or self.NE3_DEFAULT_IP, port)
        self.bsock = None
        # Optional callable(sock) -> str|None: used on Android to pin the socket
        # to WiFi so traffic can't leak out over mobile data.
        self.socket_hook = socket_hook
        self.local_port = local_port
        self.verbose = verbose
        self.cond = threading.Condition()
        self.seq = 0            # increments per delivered frame
        self.jpeg = None
        self.angle = 0.0
        self.size = (0, 0)
        self.connected = False
        self.fps = 0.0
        self.state = "starting"
        self.diagnosing = False
        self._fps_t, self._fps_n = time.time(), 0
        self._reconnect = threading.Event()
        self._hard = threading.Event()     # close + reopen the socket
        self._paused = threading.Event()   # set while diagnostics own the socket
        self._idle = threading.Event()     # set when the loop has noticed the pause
        self._last_err = None

    # -- outgoing messages ------------------------------------------------
    def _send(self, data, addr=None):
        try:
            self.sock.sendto(data, addr or self.addr)
        except OSError as e:
            err = f"send to {(addr or self.addr)[0]} failed: {e.strerror or e}"
            if err != self._last_err:        # log each distinct error once
                log("[cam] " + err)
                self._last_err = err

    def _init(self):
        self._send(b"\xef\x00\x04\x00")

    def _msgs(self, msgs):
        body = (bytes.fromhex("02020001") + struct.pack("<Q", len(msgs))
                + bytes(8) + bytes.fromhex("0a4b142d00000000") + b"".join(msgs) + bytes(8))
        self._send(b"\xef\x02" + struct.pack("<H", len(body) + 4) + body)

    @staticmethod
    def _ack(n):
        return struct.pack("<Q", n) + bytes.fromhex("0100000014000000ffffffff")

    @staticmethod
    def _req(n):
        return struct.pack("<Q", n) + bytes.fromhex("0300000010000000")

    def _publish(self, frame):
        self._publish_jpeg(frame.jpeg(), frame.w, frame.h, f"JPEG quality {frame.q}",
                           frame.angle)

    def _publish_jpeg(self, jpeg, w, h, note="", angle=None):
        with self.cond:
            self.jpeg = jpeg
            if angle is not None:
                self.angle = angle
            self.size = (w, h)
            self.seq += 1
            self.cond.notify_all()
        if not self.connected:
            log(f"[cam] streaming ({(self.protocol or '?').upper()}): {w}x{h} {note}".rstrip())
        self.connected = True
        self.state = "streaming"
        self._fps_n += 1
        now = time.time()
        if now - self._fps_t >= 1:
            self.fps = self._fps_n / (now - self._fps_t)
            self._fps_t, self._fps_n = now, 0

    def _run_hook(self):
        if not self.socket_hook:
            return
        try:
            msg = None
            for sk in (self.sock, self.bsock):
                if sk is not None:
                    msg = self.socket_hook(sk) or msg
            if msg and msg != getattr(self, "_hook_msg", None):
                log("[net] " + msg)
                self._hook_msg = msg
        except Exception as e:  # never let the hook kill the stream
            log(f"[net] WiFi binding failed: {e}")

    # -- public controls --------------------------------------------------
    def reconnect(self):
        log("[cam] reconnect requested")
        self._reconnect.set()

    def hard_reset(self):
        log("[cam] full reset requested")
        self._hard.set()

    def _open_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind(("0.0.0.0", self.local_port))
        except OSError:
            # Port taken (another viewer still running?) - use any free port.
            self.sock.bind(("0.0.0.0", 0))
            log(f"[cam] UDP port {self.local_port} busy, using "
                f"{self.sock.getsockname()[1]} instead")
        self.sock.settimeout(0.025)
        # Second socket for the NE7 protocol (broadcast discovery + stream)
        self.bsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.bsock.bind(("0.0.0.0", 0))
        self.bsock.settimeout(0.05)

    def _close_sockets(self):
        for sk in (self.sock, self.bsock):
            try:
                if sk is not None:
                    sk.close()
            except OSError:
                pass

    def diagnose(self):
        """Run network/protocol tests in the background; results go to the log."""
        if self.diagnosing:
            return False
        threading.Thread(target=self._diagnose, daemon=True).start()
        return True

    # -- main loop --------------------------------------------------------
    def _pause_point(self):
        """Block while diagnostics own the sockets. True if we were paused."""
        if not self._paused.is_set():
            self._idle.clear()
            return False
        while self._paused.is_set():
            self._idle.set()
            time.sleep(0.1)
        self._idle.clear()
        return True

    def _interrupted(self):
        """True if the current protocol loop should hand back to run()."""
        return self._hard.is_set() or self._reconnect.is_set()

    def run(self):
        self._open_socket()
        self._run_hook()
        while True:
            self._pause_point()
            if self._hard.is_set():
                self._hard.clear()
                self._close_sockets()
                self._open_socket()
                self._hook_msg = None
                self._run_hook()
            self._reconnect.clear()
            self._last_err = None
            self.connected = False
            found = self._detect()
            if not found:
                continue
            self.protocol, ip = found
            try:
                if self.protocol == "ne3":
                    self.addr = (ip, self.addr[1])
                    self._run_ne3()
                else:
                    self._run_ne7(ip)
            except Exception as e:           # keep going whatever happens
                log(f"[cam] error in {self.protocol} loop: {e!r}")
                time.sleep(1)
            self.connected = False

    # -- finding the scope ------------------------------------------------
    def _candidates(self):
        gws = [gw for _, gw in default_gateways()]
        ips = [self.forced_ip] if self.forced_ip else []
        ips += [self.NE3_DEFAULT_IP, "192.168.1.1"] + gws
        return list(dict.fromkeys(ips))

    def _detect(self):
        """Say hello in both protocols until one answers -> (protocol, ip)."""
        want = self.protocol_choice
        self.state = "searching"
        log(f"[cam] looking for the scope ({'NE3 + NE7' if want == 'auto' else want.upper()})...")
        last_send = last_log = 0.0
        t0 = time.time()
        while True:
            if self._pause_point() or self._interrupted():
                return None
            now = time.time()
            if now - last_send > 1.0:
                cands = self._candidates()
                if want in ("auto", "ne3"):
                    for ip in cands:
                        self._send(b"", (ip, 1234))
                        self._send(b"\xef\x00\x04\x00", (ip, self.addr[1]))
                if want in ("auto", "ne7"):
                    targets = ["255.255.255.255", "192.168.1.255"]
                    targets += [ip.rsplit(".", 1)[0] + ".255" for ip in cands]
                    targets += cands                          # unicast too
                    for t in dict.fromkeys(targets):
                        for port in self.NE7_DISCOVERY:
                            self._bsend(b"\x66\x39\x01\x01", (t, port))
                if self.socket_hook:
                    self._run_hook()
                last_send = now
            if now - last_log > 15 and now - t0 > 5:
                log("[cam] still looking - is the scope on and are you on its WiFi? "
                    "(Log -> Run diagnostics)")
                last_log = now
            ready, _, _ = select.select([self.sock, self.bsock], [], [], 0.2)
            for sk in ready:
                try:
                    data, src = sk.recvfrom(4096)
                except OSError:
                    continue
                if sk is self.sock and data[:1] == b"\x93" and want in ("auto", "ne3"):
                    log(f"[cam] found NE3 scope at {src[0]}")
                    return "ne3", src[0]
                if sk is self.bsock and data[:1] == b"{" and want in ("auto", "ne7"):
                    info = data.decode("utf-8", "replace")
                    try:
                        j = json.loads(info)
                        info = ", ".join(f"{k}={v}" for k, v in list(j.items())[:8])
                    except ValueError:
                        info = info[:160]
                    log(f"[cam] found NE7 scope at {src[0]}: {info}")
                    return "ne7", src[0]

    def _bsend(self, data, addr):
        try:
            self.bsock.sendto(data, addr)
        except OSError as e:
            if self.verbose:
                log(f"[cam] send to {addr[0]}:{addr[1]} failed: {e.strerror or e}")

    # -- NE7 protocol -----------------------------------------------------
    def _run_ne7(self, ip):
        """Video arrives as JPEG chunks from port 44506: 4-byte header
        (frame no, flags, chunk no from 1, ?); flags bit 0 = last chunk, which
        also carries 5 trailing bytes. Tilt sensor packets come from 52219."""
        def start():
            self._bsend(b"\x86\x06\x01", (ip, self.NE7_SENSOR))
            self._bsend(b"\x20\x36", (ip, self.NE7_VIDEO))
        self.state = "waiting"
        start()
        t_start = last_video = last_start = time.time()
        cur_no, done_no, chunks, total = None, None, {}, None
        sensor_logged = odd_logged = bad_jpeg_logged = 0
        tail_logged = False
        while True:
            if self._pause_point():
                start()
                last_video = last_start = time.time()
                cur_no, chunks, total = None, {}, None
            if self._interrupted():
                return
            now = time.time()
            quiet = now - last_video
            if quiet > 1.5 and now - last_start > 1.0:
                if self.connected and quiet > 3:
                    log("[cam] NE7 stream stopped - no video for 3 s, retrying")
                    self.connected, self.state = False, "waiting"
                start()
                last_start = now
            if quiet > 10:
                log("[cam] no NE7 video for 10 s - searching again")
                return
            try:
                data, src = self.bsock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError as e:
                err = f"receive failed: {e.strerror or e}"
                if err != self._last_err:
                    log("[cam] " + err)
                    self._last_err = err
                time.sleep(0.5)
                continue
            if src[0] != ip:
                continue
            if src[1] == self.NE7_VIDEO and len(data) > 4:
                fno, flags, cno = data[0], data[1], data[2]
                if fno == done_no:
                    continue                      # late duplicate of a shown frame
                if fno != cur_no:
                    cur_no, chunks, total = fno, {}, None
                payload = data[4:]
                if flags & 1:
                    total = cno                   # last chunk; any trailer is trimmed below
                chunks[cno] = payload
                last_video = now
                if total and all(i in chunks for i in range(1, total + 1)):
                    jpeg = b"".join(chunks[i] for i in range(1, total + 1))
                    cur_no, done_no, chunks, total = None, fno, {}, None
                    if not jpeg.startswith(b"\xff\xd8"):
                        k = jpeg.find(b"\xff\xd8")
                        if bad_jpeg_logged < 3:
                            log(f"[cam] NE7 frame doesn't start with a JPEG marker "
                                f"(found at {k}): {_hex(jpeg)}")
                            bad_jpeg_logged += 1
                        if k < 0:
                            continue
                        jpeg = jpeg[k:]
                    # Some units append a few bytes after the image, some don't.
                    # Cut at the real end-of-image marker instead of guessing.
                    e = jpeg.rfind(b"\xff\xd9", max(0, len(jpeg) - 32))
                    trailer = len(jpeg) - (e + 2) if e >= 0 else None
                    if not tail_logged:
                        log(f"[cam] NE7 frame ends: ...{jpeg[-10:].hex(' ')} "
                            f"({'no end marker' if trailer is None else f'{trailer} trailing bytes'})")
                        tail_logged = True
                    jpeg = jpeg[:e + 2] if e >= 0 else jpeg + b"\xff\xd9"
                    w, h = jpeg_size(jpeg)
                    self.state = "streaming"
                    self._publish_jpeg(jpeg, w, h)
            elif src[1] == self.NE7_SENSOR and len(data) >= 24:
                x, y, z, a = struct.unpack_from(">BxBxBxxxxxxxxxxxxxHxxxx", data)
                # The UI adds 90 degrees (NE3 convention); NE7 gives degrees directly
                self.angle = a - 90.0
                if sensor_logged < 3:
                    log(f"[cam] NE7 tilt sensor: x={x} y={y} z={z} angle={a}")
                    sensor_logged += 1
            elif src[1] in self.NE7_DISCOVERY:
                continue                          # extra discovery replies
            elif odd_logged < 5:
                log(f"[cam] unexpected NE7 packet from {src[0]}:{src[1]} "
                    f"({len(data)} bytes): {_hex(data)}")
                odd_logged += 1

    # -- NE3 protocol -----------------------------------------------------
    def _run_ne3(self):
        log(f"[cam] NE3: talking to {self.addr[0]}:{self.addr[1]} from UDP port "
            f"{self.sock.getsockname()[1]}")
        cur, last_done = None, -1
        last_rx = time.time()
        last_more = last_null = last_hook = 0.0
        odd_logged = 0
        self._send(b"", (self.addr[0], 1234))
        self._init()
        self.state = "waiting"
        while True:
            if self._pause_point():
                self._init()
                cur, last_done, last_rx = None, -1, time.time()
            if self._interrupted():
                return
            now = time.time()
            if self.socket_hook and not self.connected and now - last_hook > 3:
                self._run_hook()
                last_hook = now
            if now - last_null > 5:
                self._send(b"", (self.addr[0], 1234))  # keepalive
                last_null = now
            try:
                data, src = self.sock.recvfrom(2048)
            except socket.timeout:
                if now - last_rx > 0.5:
                    if self.connected and now - last_rx > 3:
                        log("[cam] stream stopped - no data for 3 s, retrying")
                        self.connected, self.state = False, "waiting"
                    if now - last_rx > 10:
                        log("[cam] no NE3 data for 10 s - searching again")
                        return
                    self._init()
                    cur, last_done = None, -1
                    time.sleep(0.2)
                elif cur and last_done == cur.img_no:
                    self._msgs([self._ack(cur.img_no), self._req(cur.img_no + 1)])
                else:
                    self._msgs([])
                continue
            except OSError as e:
                err = f"receive failed: {e.strerror or e}"
                if err != self._last_err:
                    log("[cam] " + err)
                    self._last_err = err
                time.sleep(0.5)  # e.g. network down / WiFi switching
                continue

            last_rx = time.time()
            if len(data) < HDR.size or data[0] != 0x93 or data[1] != 0x01:
                if odd_logged < 5 and not (data[:1] == b"\x93" and data[1:2] == b"\x04"):
                    log(f"[cam] unexpected packet from {src[0]}:{src[1]} "
                        f"({len(data)} bytes): {_hex(data)}")
                    odd_logged += 1
                continue
            try:
                _, img_no, _, pkt_no, count, _, w, h, q = HDR.unpack_from(data)
            except struct.error:
                continue
            if count == 0 or count > 4096 or pkt_no >= count:
                continue
            if cur is None or img_no > cur.img_no:
                cur = Frame(img_no, count, q, w, h)
            elif img_no < cur.img_no:
                continue
            cur.add(pkt_no, data[HDR.size:])
            if cur.complete() and last_done != img_no:
                self._publish(cur)
                last_done = img_no
                self._msgs([self._ack(img_no), self._req(img_no + 1)])
            elif last_rx - last_more > 0.025:
                self._msgs([])
                last_more = last_rx

    def wait_frame(self, after, timeout=2.0):
        with self.cond:
            self.cond.wait_for(lambda: self.seq > after, timeout)
            return self.seq, self.jpeg, self.angle

    # -- diagnostics ------------------------------------------------------
    def _listen(self, sock, seconds):
        sock.settimeout(0.2)
        end, got, sources = time.time() + seconds, 0, {}
        while time.time() < end:
            try:
                d, a = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError as e:
                log(f"   receive error: {e.strerror or e}")
                break
            got += 1
            key = f"{a[0]}:{a[1]}"
            sources[key] = sources.get(key, 0) + 1
            if got <= 3:
                log(f"   <- {key} {len(d)} bytes: {_hex(d)}")
        return got, sources

    def _diagnose(self):
        self.diagnosing = True
        was = self.state
        self.state = "diagnosing"
        self._paused.set()
        self._idle.wait(2)
        try:
            log("===== diagnostics =====")
            log(f"Python {sys.version.split()[0]} on {sys.platform}")
            gws = default_gateways()
            for dev, gw in gws:
                log(f"route: default via {gw} on {dev}")
            if not gws:
                log("route: couldn't read default gateway")
            for ip in dict.fromkeys([self.addr[0], "192.168.1.1", "192.168.10.123"]):
                log(f"my address towards {ip}: {my_ip_towards(ip)}")
            targets = self._candidates()

            log("-- test 1: NE3 protocol")
            found = found7 = False
            for ip in targets:
                log(f"   -> hello to {ip}:{self.addr[1]}")
                try:
                    self.sock.sendto(b"", (ip, 1234))
                    self.sock.sendto(b"\xef\x00\x04\x00", (ip, self.addr[1]))
                except OSError as e:
                    log(f"   send failed: {e.strerror or e}")
                    continue
                got, src = self._listen(self.sock, 2.5)
                if got:
                    log(f"   RESULT: {got} packets from {src}")
                    found = True
                    break
                log("   RESULT: no reply")

            log("-- test 2: NE7 protocol (broadcast discovery)")
            b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            b.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            b.bind(("0.0.0.0", 0))
            for bc in ("192.168.1.255", "255.255.255.255", "192.168.169.255"):
                for port in (58090, 46526):
                    try:
                        b.sendto(b"\x66\x39\x01\x01", (bc, port))
                    except OSError as e:
                        log(f"   send to {bc}:{port} failed: {e.strerror or e}")
            got, src = self._listen(b, 2.5)
            found7 = got > 0
            b.close()
            log(f"   RESULT: {got} replies from {src}" if got else "   RESULT: no reply")

            log("-- test 3: ping")
            for ip in targets:
                cmd = ["ping", "-n" if os.name == "nt" else "-c", "2", ip]
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                    log(f"   {ip}: {'replies' if r.returncode == 0 else 'NO reply'}")
                except Exception as e:
                    log(f"   {ip}: ping not available ({type(e).__name__})")

            if sys.platform.startswith("linux") and not hasattr(sys, "getandroidapilevel"):
                try:
                    r = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=3)
                    first = (r.stdout.strip() or r.stderr.strip() or "?").splitlines()[0]
                    log(f"firewall (ufw): {first}")
                except Exception:
                    pass
            log("===== done: NE3 " + ("ANSWERED" if found else "no reply") +
                ", NE7 " + ("ANSWERED" if found7 else "no reply") + " =====")
        except Exception as e:
            log(f"diagnostics crashed: {e!r}")
        finally:
            self.sock.settimeout(0.025)
            self._paused.clear()
            self.diagnosing = False
            self.state = was
            self._reconnect.set()


# --------------------------------------------------------------------------
# Web UI
# --------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#8e9398">
<title>Tmu Ear Violator 4000 Streamer</title>
<link rel="icon" href="data:image/webp;base64,__FAV__">
<style>
:root{
  --mono:"DejaVu Sans Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --ink:#1d2126;--engrave:#23272c;--hi:rgba(255,255,255,.55);--lo:rgba(0,0,0,.38);
  --phos:#8dffb0;--phos-dim:#3f8f5b;--phos-bg:#08120c;
  --led-g:#46ff8a;--led-a:#ffb020;--led-r:#ff3b30;
  /* brushed aluminium: a seamless grain tile (short broken streaks, generated
     from filtered noise) blended over a soft, slightly warm sheen */
  --alu:url(data:image/webp;base64,__GRAIN__),
    radial-gradient(ellipse 65% 140% at 30% 45%,rgba(255,252,244,.5),transparent 70%),
    linear-gradient(115deg,#6e7379 0%,#979ca1 24%,#bdbdb8 46%,#a3a7ab 64%,#8a8f94 82%,#6c7177 100%);
  --alu-size:512px 256px,100% 100%,100% 100%;
  --alu-blend:overlay,normal,normal;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{display:flex;flex-direction:column;background-color:#9ea3a7;background-image:var(--alu);background-size:var(--alu-size);background-blend-mode:var(--alu-blend);
  color:var(--ink);font:14px/1.4 var(--mono);-webkit-tap-highlight-color:transparent;overflow:hidden}

/* ---------- plates, screws, engraving ---------- */
.plate{position:relative;background-image:var(--alu);background-size:var(--alu-size);background-blend-mode:var(--alu-blend);background-color:#9ea3a7}
header.plate{display:flex;align-items:center;gap:12px;padding:10px 30px;
  box-shadow:0 1px 0 var(--lo),0 2px 0 var(--hi),inset 0 -1px 0 rgba(0,0,0,.12)}
footer.plate{display:flex;flex-wrap:wrap;justify-content:center;align-items:stretch;gap:10px;
  padding:12px 30px calc(12px + env(safe-area-inset-bottom));
  box-shadow:0 -1px 0 var(--lo),0 -2px 0 var(--hi),inset 0 1px 0 rgba(255,255,255,.5)}
.screw{position:absolute;width:12px;height:12px;border-radius:50%;
  background:radial-gradient(circle at 35% 30%,#fdfdfd,#a3a9ae 55%,#5f656b);
  box-shadow:inset 0 0 0 1px rgba(0,0,0,.35),0 1px 0 var(--hi)}
.screw::after{content:"";position:absolute;left:2px;right:2px;top:5px;height:2px;border-radius:1px;
  background:#4b5157;box-shadow:0 1px 0 rgba(255,255,255,.5);transform:rotate(var(--r,30deg))}
.screw.tl{left:9px;top:9px}.screw.tr{right:9px;top:9px;--r:-50deg}
.screw.bl{left:9px;bottom:9px;--r:75deg}.screw.br{right:9px;bottom:9px;--r:10deg}
header .screw.tl,header .screw.tr{top:50%;margin-top:-6px}
footer .screw.bl,footer .screw.br{bottom:calc(9px + env(safe-area-inset-bottom))}
.eng{font:700 9px/1 var(--mono);letter-spacing:.24em;text-transform:uppercase;color:var(--engrave);
  text-shadow:0 1px 0 var(--hi),0 -1px 0 rgba(0,0,0,.18)}

/* ---------- header ---------- */
.logo{width:52px;height:52px;flex:none;border-radius:12px;display:block;
  filter:drop-shadow(0 2px 2px rgba(0,0,0,.45))}
.idplate{display:flex;flex-direction:column;gap:3px;min-width:0}
.idplate .eng{font-size:8.5px;letter-spacing:.3em}
.lcd{background-color:var(--phos-bg);
  background-image:repeating-linear-gradient(0deg,rgba(0,0,0,.35) 0 1px,transparent 1px 3px);
  color:var(--phos);text-shadow:0 0 6px rgba(90,255,150,.55);border:1px solid #16241a;border-radius:6px;
  box-shadow:inset 0 2px 7px #000,0 1px 0 var(--hi);font:600 12px/1 var(--mono);letter-spacing:.08em;
  text-transform:uppercase}
#st{margin-left:auto;display:flex;align-items:center;gap:9px;padding:9px 12px;min-width:0;flex:0 1 auto}
#stt{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.led{width:10px;height:10px;flex:none;border-radius:50%;background:#3a2c20;
  box-shadow:inset 0 1px 2px rgba(0,0,0,.8),0 1px 0 rgba(255,255,255,.25)}
.led.g{background:radial-gradient(circle at 40% 35%,#eaffef,var(--led-g) 45%,#12a44a);box-shadow:0 0 8px var(--led-g)}
.led.a{background:radial-gradient(circle at 40% 35%,#fff5dc,var(--led-a) 45%,#b86b00);box-shadow:0 0 8px var(--led-a)}
.led.r{background:radial-gradient(circle at 40% 35%,#ffe1de,var(--led-r) 45%,#a3150d);box-shadow:0 0 8px var(--led-r)}

/* ---------- machined keys ---------- */
button{font:700 11px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--ink);
  padding:10px 12px;border-radius:6px;border:1px solid #6f757c;cursor:pointer;white-space:nowrap;
  display:inline-flex;align-items:center;justify-content:center;gap:7px;
  background:linear-gradient(#f7f8f9,#d4d8dc 48%,#c3c8cd 52%,#b4bac0);
  box-shadow:inset 0 1px 0 #fff,inset 0 -2px 0 rgba(0,0,0,.14),0 2px 3px rgba(0,0,0,.35),0 1px 0 rgba(0,0,0,.25);
  text-shadow:0 1px 0 rgba(255,255,255,.75);transition:transform .05s}
button:hover{filter:brightness(1.04)}
button:active{transform:translateY(1px);box-shadow:inset 0 1px 3px rgba(0,0,0,.35),0 1px 0 var(--hi)}
button:disabled{opacity:.5;cursor:default}
button:focus-visible{outline:2px solid #1f7a4a;outline-offset:2px}
/* indicator LED on toggle keys */
.tg::before{content:"";width:7px;height:7px;border-radius:50%;background:#3d2f2a;
  box-shadow:inset 0 1px 1px rgba(0,0,0,.7),0 1px 0 rgba(255,255,255,.6)}
.tg.on::before{background:radial-gradient(circle at 40% 35%,#eaffef,var(--led-g) 50%,#139a45);box-shadow:0 0 6px var(--led-g)}
.tg.amb.on::before{background:radial-gradient(circle at 40% 35%,#fff5dc,var(--led-a) 50%,#b86b00);box-shadow:0 0 6px var(--led-a)}
#bRec::before,#fsRec::before{content:"";width:7px;height:7px;border-radius:50%;background:#4a2320;
  box-shadow:inset 0 1px 1px rgba(0,0,0,.7)}
#bRec.rec::before,#fsRec.rec::before{background:radial-gradient(circle at 40% 35%,#ffe1de,var(--led-r) 50%,#a3150d);
  box-shadow:0 0 7px var(--led-r);animation:blink 1s steps(2,start) infinite}
@keyframes blink{to{visibility:hidden}}

/* ---------- control modules ---------- */
.mod{position:relative;display:flex;flex-direction:column;gap:7px;padding:8px 10px 10px;border-radius:9px;
  background:rgba(0,0,0,.06);border:1px solid rgba(0,0,0,.28);
  box-shadow:inset 0 1px 4px rgba(0,0,0,.28),0 1px 0 var(--hi)}
.mod .row{display:flex;gap:7px;align-items:center;flex-wrap:wrap;justify-content:center}
#zv{padding:6px 8px;min-width:58px;text-align:center}
/* knurled zoom knob on a milled groove */
input[type=range]{-webkit-appearance:none;appearance:none;width:130px;height:24px;background:transparent;margin:0}
input[type=range]::-webkit-slider-runnable-track{height:6px;border-radius:3px;
  background:linear-gradient(#50565c,#8f959b);box-shadow:inset 0 1px 2px rgba(0,0,0,.7),0 1px 0 var(--hi)}
input[type=range]::-moz-range-track{height:6px;border-radius:3px;
  background:linear-gradient(#50565c,#8f959b);box-shadow:inset 0 1px 2px rgba(0,0,0,.7),0 1px 0 var(--hi)}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:20px;height:20px;margin-top:-7px;border-radius:50%;
  background:radial-gradient(circle,#e9ecef 0 30%,transparent 31%),repeating-conic-gradient(#e2e5e8 0 9deg,#8e949a 9deg 18deg);
  border:1px solid #50565c;box-shadow:0 2px 3px rgba(0,0,0,.5)}
input[type=range]::-moz-range-thumb{width:20px;height:20px;border-radius:50%;
  background:radial-gradient(circle,#e9ecef 0 30%,transparent 31%),repeating-conic-gradient(#e2e5e8 0 9deg,#8e949a 9deg 18deg);
  border:1px solid #50565c;box-shadow:0 2px 3px rgba(0,0,0,.5)}

/* ---------- viewing screen ---------- */
main{flex:1;min-height:0;display:flex;padding:14px 16px}
.bezel{position:relative;flex:1;min-width:0;display:flex;align-items:center;justify-content:center;
  background:#040506;border-radius:14px;padding:10px;overflow:hidden;
  box-shadow:0 0 0 3px #7c8288,0 0 0 4px #4f555b,0 0 0 5px rgba(255,255,255,.6),
    inset 0 0 0 1px #000,inset 0 4px 18px rgba(0,0,0,.95)}
canvas{display:block;width:100%;height:100%;min-width:0;min-height:0;object-fit:contain;background:transparent;touch-action:none}
.hud{position:absolute;inset:0;pointer-events:none;color:var(--phos);font:600 11px/1 var(--mono);
  letter-spacing:.12em;text-shadow:0 0 5px rgba(90,255,150,.6)}
.cb{position:absolute;width:24px;height:24px;border:0 solid rgba(120,255,165,.55)}
.cb.tl{top:14px;left:14px;border-top-width:2px;border-left-width:2px}
.cb.tr{top:14px;right:14px;border-top-width:2px;border-right-width:2px}
.cb.bl{bottom:14px;left:14px;border-bottom-width:2px;border-left-width:2px}
.cb.br{bottom:14px;right:14px;border-bottom-width:2px;border-right-width:2px}
#hudL{position:absolute;top:20px;left:46px;display:flex;gap:7px;align-items:center}
#hudR{position:absolute;top:20px;right:46px}
#hudB{position:absolute;bottom:20px;left:46px;color:var(--phos-dim)}
#hudL .led{width:8px;height:8px}
.hud .recon{color:#ff6b61;text-shadow:0 0 6px rgba(255,60,50,.7)}
/* boot / waiting screen */
#msg{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:10px;text-align:center;padding:24px;color:var(--phos);background:radial-gradient(ellipse at center,#0c1a11,#040506 70%)}
#msg img{width:112px;height:112px;border-radius:24px;opacity:.95;filter:drop-shadow(0 0 18px rgba(90,255,150,.25))}
#msg .big{font:700 15px/1 var(--mono);letter-spacing:.3em;text-shadow:0 0 8px rgba(90,255,150,.7);animation:pulse 1.6s ease-in-out infinite}
#msg small{color:var(--phos-dim);font-size:12px;letter-spacing:.06em;max-width:30em}
@keyframes pulse{50%{opacity:.35}}

/* ---------- fullscreen ---------- */
#fsbar{display:none}
body.fs header,body.fs footer{display:none}
body.fs main{padding:0}
body.fs .bezel{position:fixed;inset:0;z-index:20;border-radius:0;padding:0;box-shadow:none}
body.fs #fsbar{display:flex;gap:8px;position:absolute;left:50%;bottom:calc(18px + env(safe-area-inset-bottom));
  transform:translateX(-50%);padding:8px;border-radius:10px;background-image:var(--alu);background-size:var(--alu-size);background-blend-mode:var(--alu-blend);background-color:#9ea3a7;
  box-shadow:0 4px 18px rgba(0,0,0,.6),inset 0 1px 0 #fff;transition:opacity .35s;z-index:3}
body.fs.idle #fsbar,body.fs.idle .hud{opacity:0;pointer-events:none}
body.fs.idle{cursor:none}
.hud{transition:opacity .35s}

/* ---------- log console ---------- */
#logp{position:fixed;left:0;right:0;bottom:0;height:min(62vh,540px);display:none;flex-direction:column;z-index:30;
  background-image:var(--alu);background-size:var(--alu-size);background-blend-mode:var(--alu-blend);background-color:#9ea3a7;box-shadow:0 -2px 0 var(--lo),0 -12px 30px rgba(0,0,0,.35);
  padding-bottom:env(safe-area-inset-bottom)}
#logp.open{display:flex}
#logbar{display:flex;gap:7px;align-items:center;padding:10px 14px;flex-wrap:wrap}
#logbar .eng{margin-right:auto;font-size:10px}
#logbar button{padding:8px 10px}
#logt{flex:1;overflow:auto;margin:0 12px 12px;padding:10px 12px;font:12px/1.45 var(--mono);
  white-space:pre-wrap;word-break:break-all;user-select:text;border-radius:8px;
  text-transform:none;letter-spacing:0;font-weight:400}
#toast{position:fixed;left:50%;bottom:110px;transform:translateX(-50%);padding:11px 16px;z-index:40;display:none;
  max-width:90vw;text-align:center}

/* ---------- small screens ---------- */
@media (max-width:640px){
  header.plate{padding:8px 26px;gap:10px}
  .logo{width:44px;height:44px;border-radius:10px}
  .idplate .eng{display:none}
  #bRe{padding:9px 10px}
  #bRe .t{display:none}
  main{padding:10px}
  footer.plate{gap:8px;padding:10px 10px calc(10px + env(safe-area-inset-bottom))}
  .mod{padding:7px 7px 8px}
  button{padding:9px 9px;font-size:10.5px;letter-spacing:.08em}
  input[type=range]{width:110px}
  #hudB{display:none}
}
/* phone on its side: picture on the left, controls in a column on the right */
@media (max-height:520px) and (orientation:landscape){
  body{display:grid;grid-template-columns:1fr 232px;grid-template-rows:auto 1fr}
  main{grid-column:1;grid-row:1/3;padding:8px 6px 8px calc(8px + env(safe-area-inset-left))}
  header.plate{grid-column:2;grid-row:1;flex-wrap:wrap;gap:6px;padding:8px 10px 8px;justify-content:center;
    box-shadow:inset 1px 0 0 var(--lo),inset 2px 0 0 var(--hi)}
  header .screw,footer .screw{display:none}
  .logo{width:34px;height:34px;border-radius:8px}
  .idplate{display:none}
  #st{margin-left:0;flex:1 1 120px;padding:7px 8px;font-size:10.5px}
  #bRe{padding:8px 9px}#bRe .t{display:none}
  footer.plate{grid-column:2;grid-row:2;flex-direction:column;flex-wrap:nowrap;justify-content:flex-start;
    overflow-y:auto;gap:7px;padding:6px 10px calc(8px + env(safe-area-inset-bottom)) 10px;
    box-shadow:inset 1px 0 0 var(--lo),inset 2px 0 0 var(--hi)}
  .mod{padding:6px 7px 7px;gap:5px}
  .mod .row{justify-content:flex-start;gap:5px}
  button{padding:8px 8px;font-size:10px}
  input[type=range]{width:118px}
  #hudB{display:none}
  .cb{width:16px;height:16px}.cb.tl,.cb.tr{top:10px}.cb.bl,.cb.br{bottom:10px}
  .cb.tl,.cb.bl{left:10px}.cb.tr,.cb.br{right:10px}
  #hudL,#hudR{top:14px;font-size:10px}#hudL{left:32px}#hudR{right:32px}
  #msg img{width:72px;height:72px;border-radius:16px}
}
#disc{position:fixed;inset:0;z-index:99;display:none;place-items:center;background:#000c;padding:16px}
#disc.on{display:grid}
#disc .box{max-width:460px;max-height:92vh;overflow:auto;background:linear-gradient(#c9ced4,#9aa1a9);color:#1b1f24;border-radius:10px;padding:20px 22px;box-shadow:0 20px 60px #000a;border:1px solid #5b6167}
#disc h2{margin:0 0 8px;font-size:17px;letter-spacing:.06em;text-transform:uppercase}
#disc p{margin:0 0 10px;font-size:14px;line-height:1.45}
#disc .row{display:flex;gap:8px;justify-content:flex-end;margin-top:14px}
</style></head><body>

<header class="plate">
  <span class="screw tl"></span><span class="screw tr"></span>
  <img class="logo" src="data:image/webp;base64,__LOGO__" alt="Tmu Ear Violator 4000">
  <div class="idplate"><span class="eng">Otoscopic imaging unit</span><span class="eng">Model 4000 · Rev __VERSION__</span></div>
  <div class="lcd" id="st" role="status"><span id="dot" class="led"></span><span id="stt">Connecting…</span></div>
  <button id="bRe" title="Restart the connection to the scope">↻<span class="t"> Reconnect</span></button>
</header>

<main>
  <div class="bezel" id="stage">
    <canvas id="c" width="1280" height="720"></canvas>
    <div class="hud" aria-hidden="true">
      <span class="cb tl"></span><span class="cb tr"></span><span class="cb bl"></span><span class="cb br"></span>
      <div id="hudL"><span id="hudLed" class="led"></span><span id="hudTxt">STANDBY</span></div>
      <div id="hudR">--:--:--</div>
      <div id="hudB">ZOOM 1.0× · FULL</div>
    </div>
    <div id="msg">
      <img src="data:image/webp;base64,__LOGO__" alt="">
      <div class="big">AWAITING SIGNAL</div>
      <small>Switch the scope on and join its HNDEC-xxxx WiFi.</small>
      <button id="bDiag0">Run diagnostics</button>
    </div>
    <div id="fsbar">
      <button id="fsSnap">Snapshot</button>
      <button id="fsRec">Record</button>
      <button id="fsExit" title="Exit fullscreen (Esc)">✕ Exit</button>
    </div>
  </div>
</main>

<footer class="plate">
  <span class="screw bl"></span><span class="screw br"></span>
  <div class="mod"><span class="eng">Optics</span><div class="row">
    <button id="bAuto" class="tg on" title="Keep the picture level using the scope's tilt sensor">Auto-level</button>
    <button id="bRot" title="Rotate 90°">⟳ 90°</button>
    <button id="bMir" class="tg" title="Mirror">Mirror</button>
    <button id="bView" class="tg amb" title="Full keeps every pixel. Square and Circle crop the sides.">Full</button>
  </div></div>
  <div class="mod"><span class="eng">Magnify</span><div class="row">
    <input id="zoom" type="range" min="1" max="4" step="0.05" value="1" aria-label="Zoom">
    <span id="zv" class="lcd">1.0×</span>
  </div></div>
  <div class="mod"><span class="eng">Capture</span><div class="row">
    <button id="bSnap">Snapshot</button>
    <button id="bRec">Record</button>
    <button id="bFs" title="Fullscreen (F or double-click the picture)">⛶ Full screen</button>
  </div></div>
  <div class="mod"><span class="eng">System</span><div class="row">
    <button id="bLog">Log</button>
  </div></div>
</footer>

<div id="logp"><div id="logbar"><span class="eng">System log</span>
  <button id="bDiag">Run diagnostics</button><button id="bRestart" title="Fully restart the viewer and its connection">Restart service</button><button id="bCopy">Copy</button><button id="bClose">Close</button></div>
<pre id="logt" class="lcd"></pre></div>
<div id="disc" role="dialog" aria-modal="true" aria-labelledby="discT"><div class="box">
  <h2 id="discT">Before you start</h2>
  <p>This is a hobby project and <b>not a medical device</b>. Don't push the scope further than is comfortable, and see a doctor or nurse for pain, discharge, hearing changes or wax you can't shift safely.</p>
  <p>The software is free for <b>non-commercial use only</b> (PolyForm Noncommercial 1.0.0) and comes <b>with no warranty</b>. You use it entirely at your own risk, and the author accepts no liability for any injury, damage or loss.</p>
  <p>Not affiliated with any camera maker or app developer. Nothing is sent over the internet.</p>
  <div class="row"><button id="discOk">I understand, continue</button></div>
</div></div>
<div id="toast" class="lcd"></div>

<script>
const c=document.getElementById('c'),x=c.getContext('2d'),msg=document.getElementById('msg');
const VIEWS=['full','square','circle'],VNAME={full:'Full',square:'Square',circle:'Circle'};
let savedView='full';try{savedView=localStorage.getItem('view')||'full'}catch(e){}
const S={auto:true,rot:0,mir:false,view:VIEWS.includes(savedView)?savedView:'full',zoom:1,angle:0,smooth:null,seq:0,img:null,live:false,proto:''};
const $=id=>document.getElementById(id);
(function(){let ok=false;try{ok=localStorage.getItem('ack1')==='1'}catch(e){}
  if(!ok){$('disc').classList.add('on');
    $('discOk').onclick=()=>{$('disc').classList.remove('on');try{localStorage.setItem('ack1','1')}catch(e){}};}})();
function tog(id,k){$(id).onclick=()=>{S[k]=!S[k];$(id).classList.toggle('on',S[k]);}}
tog('bAuto','auto');tog('bMir','mir');
function hudB(){$('hudB').textContent=`ZOOM ${S.zoom.toFixed(1)}× · ${VNAME[S.view].toUpperCase()}`}
function showView(){$('bView').textContent=VNAME[S.view];$('bView').classList.toggle('on',S.view!=='full');hudB()}
$('bView').onclick=()=>{S.view=VIEWS[(VIEWS.indexOf(S.view)+1)%VIEWS.length];showView();
  try{localStorage.setItem('view',S.view)}catch(e){}};
showView();
$('bRot').onclick=()=>S.rot=(S.rot+90)%360;
function setZoom(z){S.zoom=Math.min(4,Math.max(1,z));$('zoom').value=S.zoom;$('zv').textContent=S.zoom.toFixed(1)+'×';hudB()}
$('zoom').oninput=e=>setZoom(+e.target.value);
c.addEventListener('wheel',e=>{e.preventDefault();setZoom(S.zoom*(e.deltaY<0?1.1:0.9))},{passive:false});

// Frame loop: long-poll the newest JPEG, decode, draw.
async function pull(){
  for(;;){
    try{
      const r=await fetch('/frame?after='+S.seq,{cache:'no-store'});
      if(r.status===204){continue}
      S.seq=+r.headers.get('X-Seq');S.angle=+r.headers.get('X-Angle');
      const b=await r.blob();
      const bmp=('createImageBitmap' in window)?await createImageBitmap(b):await loadImg(b);
      if(S.img&&S.img.close)S.img.close();S.img=bmp;msg.style.display='none';
    }catch(e){await new Promise(r=>setTimeout(r,500))}
  }
}
function loadImg(b){return new Promise((ok,no)=>{const i=new Image();i.onload=()=>{URL.revokeObjectURL(i.src);ok(i)};i.onerror=no;i.src=URL.createObjectURL(b)})}

// Unwrap angle and smooth it so the image doesn't jitter
function smoothAngle(target){
  if(S.smooth===null)return S.smooth=target;
  let d=((target-S.smooth+540)%360)-180;
  return S.smooth+=d*0.25;
}
// Canvas = camera's native resolution, so snapshots/recordings keep every pixel.
// Full: whole frame. Square/Circle: centre crop (short side x short side).
function sizeCanvas(iw,ih){
  if(rec)return;                      // never resize mid-recording
  let W=iw,H=ih;
  if(S.view!=='full'){W=H=Math.min(iw,ih)}
  else if(!S.auto&&S.rot%180)[W,H]=[ih,iw];   // turned 90 degrees: swap to keep all pixels
  if(c.width!==W||c.height!==H){c.width=W;c.height=H}
}
function draw(){
  requestAnimationFrame(draw);
  const im=S.img;
  if(im)sizeCanvas(im.width,im.height);
  const W=c.width,H=c.height;
  x.setTransform(1,0,0,1,0,0);x.fillStyle='#000';x.fillRect(0,0,W,H);
  if(!im)return;
  const lvl=S.auto?smoothAngle(S.angle+90):0;
  const a=(lvl+S.rot)*Math.PI/180,iw=im.width,ih=im.height;
  let s;
  if(S.view==='full'){
    // Fit the rotated frame's bounding box: nothing is ever cut off
    const cs=Math.abs(Math.cos(a)),sn=Math.abs(Math.sin(a));
    s=Math.min(W/(iw*cs+ih*sn),H/(iw*sn+ih*cs));
  }else{
    s=Math.min(W,H)/Math.min(iw,ih);  // fill the square
  }
  s*=S.zoom;
  x.save();
  if(S.view==='circle'){x.beginPath();x.arc(W/2,H/2,Math.min(W,H)/2,0,Math.PI*2);x.clip();}
  x.translate(W/2,H/2);
  x.rotate(a);
  if(S.mir)x.scale(-1,1);
  x.imageSmoothingQuality='high';
  x.drawImage(im,-iw*s/2,-ih*s/2,iw*s,ih*s);
  x.restore();
}
function stamp(){const d=new Date(),p=n=>String(n).padStart(2,'0');return `${d.getFullYear()}${p(d.getMonth()+1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`}
const APP=__APP_MODE__;
function toast(t){const d=$('toast');d.textContent=t;d.style.display='block';clearTimeout(d._t);d._t=setTimeout(()=>d.style.display='none',2500)}
async function save(blob,name){
  if(APP){
    try{const r=await fetch('/save?name='+encodeURIComponent(name),{method:'POST',headers:{'Content-Type':blob.type||'application/octet-stream','X-EarScope':'1'},body:blob});
      const j=await r.json();toast(r.ok?'Saved to '+j.where:'Save failed: '+j.error)}catch(e){toast('Save failed')}
    return}
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),5000)}
function snap(){c.toBlob(b=>save(b,'earviolator-'+stamp()+'.png'),'image/png');toast('Snapshot captured')}
$('bSnap').onclick=snap;$('fsSnap').onclick=snap;

let rec=null,parts=[],recT0=0;
function recUi(on){for(const id of ['bRec','fsRec']){$(id).textContent=on?'■ Stop':'Record';$(id).classList.toggle('rec',on)}}
function toggleRec(){
  if(rec){rec.stop();return}
  if(!c.captureStream||!window.MediaRecorder){toast('Recording not supported in this browser');return}
  const types=['video/webm;codecs=vp9','video/webm','video/mp4'];
  const mime=types.find(t=>MediaRecorder.isTypeSupported(t))||'';
  rec=new MediaRecorder(c.captureStream(30),mime?{mimeType:mime}:{});parts=[];recT0=Date.now();
  rec.ondataavailable=e=>e.data.size&&parts.push(e.data);
  rec.onstop=()=>{const t=rec.mimeType||'video/webm';save(new Blob(parts,{type:t}),'earviolator-'+stamp()+(t.includes('mp4')?'.mp4':'.webm'));rec=null;recUi(false);hud()};
  rec.start(1000);recUi(true);hud();
}
$('bRec').onclick=toggleRec;$('fsRec').onclick=toggleRec;

// ---- fullscreen: native where the browser allows it, CSS otherwise (e.g. in the Android app)
let nativeFs=false,idleT=null;
function isFs(){return document.body.classList.contains('fs')}
function wake(){document.body.classList.remove('idle');clearTimeout(idleT);
  if(isFs())idleT=setTimeout(()=>document.body.classList.add('idle'),2500)}
async function enterFs(){
  document.body.classList.add('fs');wake();
  if(APP){post('/immersive?on=1').catch(()=>{});return}
  const el=document.documentElement;
  try{if(el.requestFullscreen){await el.requestFullscreen({navigationUI:'hide'});nativeFs=true}
      else if(el.webkitRequestFullscreen){el.webkitRequestFullscreen();nativeFs=true}}catch(e){nativeFs=false}
}
function exitFs(){
  document.body.classList.remove('fs','idle');clearTimeout(idleT);
  if(APP){post('/immersive?on=0').catch(()=>{});return}
  if(document.fullscreenElement&&document.exitFullscreen)document.exitFullscreen().catch(()=>{});
  else if(document.webkitFullscreenElement&&document.webkitExitFullscreen)document.webkitExitFullscreen();
  nativeFs=false;
}
function toggleFs(){isFs()?exitFs():enterFs()}
$('bFs').onclick=toggleFs;$('fsExit').onclick=exitFs;
c.addEventListener('dblclick',toggleFs);
document.addEventListener('fullscreenchange',()=>{if(!document.fullscreenElement&&nativeFs&&isFs())exitFs()});
document.addEventListener('webkitfullscreenchange',()=>{if(!document.webkitFullscreenElement&&nativeFs&&isFs())exitFs()});
document.addEventListener('keydown',e=>{
  if(e.target.tagName==='INPUT'&&e.target.type!=='range')return;
  if(e.key==='f'||e.key==='F'){e.preventDefault();toggleFs()}
  else if(e.key==='Escape'&&isFs())exitFs();
});
for(const ev of ['pointermove','pointerdown','touchstart'])$('stage').addEventListener(ev,()=>{if(isFs())wake()},{passive:true});

// ---- heads-up display
function hud(){
  const L=$('hudL'),led=$('hudLed'),t=$('hudTxt');
  if(rec){const s=Math.floor((Date.now()-recT0)/1000),p=n=>String(n).padStart(2,'0');
    led.className='led r';t.textContent=`REC ${p(Math.floor(s/60))}:${p(s%60)}`;L.classList.add('recon')}
  else{L.classList.remove('recon');
    if(S.live){led.className='led g';t.textContent='LIVE '+S.proto}
    else{led.className='led a';t.textContent='STANDBY'}}
  const d=new Date(),p=n=>String(n).padStart(2,'0');
  $('hudR').textContent=`${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
setInterval(hud,500);hud();

// ---- log panel, reconnect, diagnostics
const post=p=>fetch(p,{method:'POST',headers:{'X-EarScope':'1'}});
let logAfter=0,logOpen=false,logTimer=null;
async function pullLog(){
  try{const j=await (await fetch('/log?after='+logAfter,{cache:'no-store'})).json();
    if(j.last<logAfter){logAfter=0;$('logt').textContent+='\n----- restarted -----\n'}
    if(j.lines.length){const t=$('logt'),atEnd=t.scrollTop+t.clientHeight>=t.scrollHeight-20;
      t.textContent+=j.lines.map(l=>l[1]).join('\n')+'\n';logAfter=j.last;if(atEnd)t.scrollTop=t.scrollHeight}
  }catch(e){}
  if(logOpen)logTimer=setTimeout(pullLog,700);
}
function openLog(){logOpen=true;$('logp').classList.add('open');$('bLog').classList.add('on');clearTimeout(logTimer);pullLog()}
$('bLog').onclick=()=>logOpen?closeLog():openLog();
function closeLog(){logOpen=false;$('logp').classList.remove('open');$('bLog').classList.remove('on');clearTimeout(logTimer)}
$('bClose').onclick=closeLog;
$('bRe').onclick=async()=>{await post('/reconnect');toast('Reconnecting…')};
$('bRestart').onclick=async()=>{try{await post('/restart')}catch(e){}toast('Restarting…');openLog()};
async function diag(){openLog();const r=await post('/diagnose');if(r.status===409)toast('Diagnostics already running')}
$('bDiag').onclick=diag;$('bDiag0').onclick=diag;
$('bCopy').onclick=async()=>{const txt=$('logt').textContent;
  try{await navigator.clipboard.writeText(txt);toast('Log copied')}
  catch(e){const a=document.createElement('textarea');a.value=txt;document.body.appendChild(a);a.select();
    try{document.execCommand('copy');toast('Log copied')}catch(_){toast('Copy failed - select the text instead')}a.remove()}};

async function status(){
  try{const s=await (await fetch('/status',{cache:'no-store'})).json();
    S.live=s.connected;S.proto=(s.protocol||'').toUpperCase();
    $('dot').className='led '+(s.connected?'g':'a');
    $('stt').textContent=s.diagnosing?'Running diagnostics…':s.connected?`${S.proto} · ${s.width}×${s.height} · ${s.fps.toFixed(0)} FPS`:s.state==='searching'?'Searching for scope…':`Found ${S.proto} · awaiting video…`;
    $('bDiag').disabled=$('bDiag0').disabled=s.diagnosing;
    if(!s.connected&&!S.img)msg.style.display='';
  }catch(e){S.live=false;$('dot').className='led r';$('stt').textContent='Server offline'}
  setTimeout(status,1000);
}
pull();draw();status();
</script></body></html>"""


def make_handler(cam, saver=None, app_mode=False, restart=None, immersive=None):
    page = (PAGE.replace("__APP_MODE__", "true" if app_mode else "false")
                .replace("__LOGO__", LOGO_WEBP_B64).replace("__FAV__", FAVICON_WEBP_B64)
                .replace("__GRAIN__", GRAIN_WEBP_B64)
                .replace("__VERSION__", VERSION)).encode()

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            u = urlparse(self.path)
            # Custom header = browsers block cross-site pages from POSTing here
            if self.headers.get("X-EarScope") != "1":
                return self._send(403, b"forbidden", "text/plain")
            if u.path == "/reconnect":
                cam.reconnect()
                return self._send(200, b"{}", "application/json")
            if u.path == "/immersive":
                on = parse_qs(u.query).get("on", ["0"])[0] == "1"
                if immersive:
                    try:
                        immersive(on)
                    except Exception as e:
                        log(f"[app] fullscreen toggle failed: {e}")
                return self._send(200, b"{}", "application/json")
            if u.path == "/restart":
                self._send(200, b"{}", "application/json")
                if restart:                   # desktop: restart the whole program
                    log("[app] restarting...")
                    threading.Timer(0.3, restart).start()
                else:                         # app: reset the camera connection
                    cam.hard_reset()
                return
            if u.path == "/shutdown" and not app_mode:
                self._send(200, b"{}", "application/json")
                log("[app] shutting down (another copy is taking over)")
                threading.Timer(0.2, os._exit, args=(0,)).start()
                return
            if u.path == "/diagnose":
                ok = cam.diagnose()
                return self._send(200 if ok else 409, b"{}", "application/json")
            if u.path != "/save" or saver is None:
                return self._send(404, b"not found", "text/plain")
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if not 0 < n <= 1024 * 1024 * 1024:
                    raise ValueError("bad size")
                name = parse_qs(u.query).get("name", ["capture"])[0]
                name = "".join(ch for ch in name if ch.isalnum() or ch in "-_.").lstrip(".")[:80] or "capture"
                mime = self.headers.get("Content-Type", "application/octet-stream").split(";")[0]
                data = self.rfile.read(n)
                where = saver(name, mime, data)
                self._send(200, json.dumps({"where": where}).encode(), "application/json")
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}).encode(), "application/json")

        def do_GET(self):
            u = urlparse(self.path)
            try:
                if u.path == "/":
                    self._send(200, page, "text/html; charset=utf-8")
                elif u.path == "/frame":
                    after = int(parse_qs(u.query).get("after", ["0"])[0])
                    if after > cam.seq:       # page is from before a restart
                        after = 0
                    seq, jpg, ang = cam.wait_frame(after)
                    if seq <= after or jpg is None:
                        self.send_response(204)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                    else:
                        self._send(200, jpg, "image/jpeg",
                                   {"X-Seq": str(seq), "X-Angle": f"{ang:.2f}"})
                elif u.path == "/snapshot.jpg":
                    _, jpg, _ = cam.wait_frame(-1, 0)
                    if jpg:
                        self._send(200, jpg, "image/jpeg")
                    else:
                        self._send(503, b"no frame yet", "text/plain")
                elif u.path == "/status":
                    body = json.dumps({"connected": cam.connected, "fps": cam.fps,
                                       "width": cam.size[0], "height": cam.size[1],
                                       "angle": cam.angle, "state": cam.state,
                                       "diagnosing": cam.diagnosing, "version": VERSION,
                                       "protocol": cam.protocol}).encode()
                    self._send(200, body, "application/json")
                elif u.path == "/log":
                    after = int(parse_qs(u.query).get("after", ["0"])[0])
                    lines, last = log_since(after)
                    self._send(200, json.dumps({"lines": lines, "last": last}).encode(),
                               "application/json")
                elif u.path in ("/stream.mjpg", "/stream.mjpeg"):
                    self.send_response(200)
                    self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=f")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    seq = 0
                    while True:
                        seq, jpg, _ = cam.wait_frame(seq)
                        if jpg is None:
                            continue
                        self.wfile.write(b"--f\r\nContent-Type: image/jpeg\r\nContent-Length: "
                                         + str(len(jpg)).encode() + b"\r\n\r\n" + jpg + b"\r\n")
                else:
                    self._send(404, b"not found", "text/plain")
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    return H


def make_server(cam, host="127.0.0.1", port=8080, saver=None, app_mode=False, restart=None,
                immersive=None):
    """Build the web server. port=0 picks a free port (see server_address)."""
    srv = ThreadingHTTPServer((host, port), make_handler(cam, saver, app_mode, restart, immersive))
    srv.daemon_threads = True
    return srv


def main():
    ap = argparse.ArgumentParser(description="Tmu Ear Violator 4000 Streamer - viewer for HNDEC/NE3/NE7 WiFi ear cameras")
    ap.add_argument("--port", type=int, default=8080, help="web port (default 8080)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="web bind address; 0.0.0.0 to allow other devices (default 127.0.0.1)")
    ap.add_argument("--camera-ip", default=None, help="scope address (default: find it)")
    ap.add_argument("--protocol", choices=["auto", "ne3", "ne7"], default="auto",
                    help="camera protocol (default: auto-detect)")
    ap.add_argument("--camera-port", type=int, default=8800)
    ap.add_argument("--local-port", type=int, default=36000, help="local UDP port")
    ap.add_argument("--no-browser", action="store_true", help="don't open a browser tab")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--restarted", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    shown = "localhost" if a.host in ("127.0.0.1", "0.0.0.0") else a.host

    # Same version already running? Just open it.
    if running_version(a.port) == VERSION and not a.restarted:
        url = f"http://localhost:{a.port}"
        print(f"The Tmu Ear Violator 4000 is already running: {url}")
        if not a.no_browser:
            webbrowser.open(url)
        return
    # Anything else (older copies, stuck copies) gets shut down so we can
    # have the camera and the port to ourselves.
    stop_other_copies(a.port)

    # Find a free web port, starting at --port.
    cam = Camera(a.camera_ip, a.camera_port, a.local_port, a.verbose, protocol=a.protocol)
    srv = None
    for port in range(a.port, a.port + 20):
        try:
            srv = make_server(cam, a.host, port, restart=restart_self)
            break
        except OSError:
            continue
    if srv is None:
        raise SystemExit(f"No free port between {a.port} and {a.port + 19}; try --port 9000")

    cam.start()
    url = f"http://{shown}:{port}"
    print(f"Tmu Ear Violator 4000 Streamer {VERSION}: {url}   (MJPEG: {url}/stream.mjpg)   Ctrl+C to quit")
    if not (a.no_browser or a.restarted):
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


def restart_self():
    """Replace this process with a fresh copy (same arguments, no new tab)."""
    args = [sys.executable, os.path.abspath(sys.argv[0])] + \
        [x for x in sys.argv[1:] if x != "--restarted"] + ["--restarted"]
    sys.stdout.flush()
    if os.name == "nt":          # Windows has no real exec: start new, then exit
        subprocess.Popen(args)
        os._exit(0)
    os.execv(sys.executable, args)


def _other_copy_pids():
    """PIDs of other Python processes running ne3web.py."""
    names = {"ne3web.py", os.path.basename(sys.argv[0])}
    skip = {os.getpid(), os.getppid()}
    pids = []
    try:
        if os.name == "nt":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-CimInstance Win32_Process | ForEach-Object "
                 "{ \"$($_.ProcessId) $($_.CommandLine)\" }"],
                capture_output=True, text=True, timeout=10).stdout
        else:
            out = subprocess.run(["ps", "-eo", "pid=,args="],
                                 capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return pids
    for row in out.splitlines():
        parts = row.strip().split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        pid, cmd = int(parts[0]), parts[1]
        # The program itself must be Python (not an editor or a shell that
        # merely mentions the file), and one of its arguments must be the script.
        try:
            argv = shlex.split(cmd, posix=os.name != "nt")
        except ValueError:
            argv = cmd.split()
        if pid in skip or not argv:
            continue
        exe = os.path.basename(argv[0].strip('"')).lower()
        if not exe.startswith(("python", "py.exe", "pythonw")):
            continue
        if any(os.path.basename(x.strip('"')) in names for x in argv[1:3]):
            pids.append(pid)
    return pids


def stop_other_copies(port):
    """Politely ask newer copies to quit, then terminate any that remain."""
    for p in range(port, port + 20):
        if running_version(p) not in (None, "old"):
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{p}/shutdown", data=b"",
                                             headers={"X-EarScope": "1"})
                urllib.request.urlopen(req, timeout=1).close()
            except Exception:
                pass
    time.sleep(0.3)
    pids = _other_copy_pids()
    for pid in pids:
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                               capture_output=True, timeout=5)
            else:
                os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
    if pids:
        print(f"Stopped {len(pids)} older copy/copies: {pids}")
        for _ in range(50):                      # wait until they've really exited
            if not (set(pids) & set(_other_copy_pids())):
                break
            time.sleep(0.1)
        time.sleep(0.2)


def running_version(port):
    """Version of a viewer already on this port, 'old' if pre-0.2, else None."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=0.5) as r:
            st = json.loads(r.read())
            return st.get("version", "old") if "connected" in st else None
    except Exception:
        return None


# --------------------------------------------------------------------------
# Embedded artwork (WebP, base64) so the viewer stays a single file
# --------------------------------------------------------------------------
LOGO_WEBP_B64 = (
    "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"
)
GRAIN_WEBP_B64 = (   # 1024x512 seamless brushed-metal grain, drawn at 512x256 CSS px
    "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"
)
FAVICON_WEBP_B64 = (
    "UklGRooKAABXRUJQVlA4WAoAAAAQAAAAPwAAPwAAQUxQSAEBAAABkFzbtmlb8+z9nIJRM5IwE7DysZGGbft92/7lfdaaX6Wz6r9F"
    "xAQAgIvga4cO3n5N7NvDkfoURA7/dkDHKRN/3g34f3jkLJIaiyZYYiVX8uEBOJS8ZBAmXgLfVMDBRdmvGWgy8F1e5LxbZ6DRwB3v"
    "0cFAs4F9SL9TsSP6KLOBSsPC1kmNLcU6f0qxJLx6T7Wk/PzV2s//v3lv7fMZxZLwekpjS7EuNFEtCdvTH6jYEX2ShR4GO4GDcG6b"
    "wUrgfop3Ud47BhuBHwvh4FDxhkGSJ4Hva+AAeBSskRqLJlhiJTeL4fG3B3qvmPjrwQge/3ZAWvPE2cefif14NtWaDjgAAABWUDgg"
    "YgkAANAkAJ0BKkAAQAA+MRSGQqIhDP5nABABglkALO5QVceZn5nkgOl34jtsb7bTeYz9ivWe9FO8k+gB4MHw3fuV6JOA+Z0+APgs"
    "8aeynGa5s8w/n5+N/LH1a/zvgb7of6j1Avxf+af4z5jOPxrp/lvUC9Vvm3+P/sv7d/lv69P8l6AfVv/c+pP+Yf7L1L/yHg7dw+wJ"
    "/H/6V/rv75+Wn0n/wH/R/vv5Z+0H8t/sf/J/xn+J+Qb+T/0r/Xf3z95v9F///qq9i37DeyJ+qX30HW2KM7QE3yEUGsROmDSfx9YN"
    "SWYbhcQuIgMbcGo2rPDmnOx3+4dv7tYxqrgKcnfIi97AkuE/xTO1t7hFDCZsJNEMD0q3afgCgJGgpwOGa/RSxXjwvoiPNi9jPA3n"
    "WxEV+NdleAD++TBPqqB5tXwzmug8r16BrS58vjeo46uHUrVLfwWWQkoQzlBI6sKKj2kbDUymbmWbLDlSSmiUz8FenADxkO9pzPG+"
    "Af6xKEaaUIK7AiYQWEnR9h0/2a/p1TssJ47tqSPNKYGj4kYTMbIePrG1VHT31vrdRdDTn2sxHTUPZJRe895GJYDZ95DUUKbZMPoL"
    "245Ntk6YR9fP4p1kGFMQ72lxNYcQKUllqNeXcEuOiXuaaG8skTDK2dZWSuNt6n5NpnuERRDiSyUb8q9U88Vrh9yhaPZ9DlqOyM2c"
    "3LPvWKEjCV3LmTYVaQbAMLIx+aub86QvDv+mDuQj1IYxWHpyVQ1WM4IzHQQyl1UEnbSUkT639iv8iv/GL3q0U/NZAbv3xRtVo+i/"
    "+Tan7Vuy14zSbdz2aH7Mbz0Y9yeaTtMlnAnyiCJ+9DD5NRLbWx3pIdx7dp393FY4vcX0Tq4Kw6/NHo2PvAAvjEFqRD2bywTxQ1WL"
    "SGEXa7q+3rjHN5RKZX8GbZcV29zNiwugyt6ReGx/Y6nBYz/17UPtrzxgPR9t5hwDthD/Jt8x1N/81x9fmAV7agPt04nhI7lpYst+"
    "ZreUORqSjsVFhJIDVgP32d70Nvj2hZiEwbOlM62gRsBhm7AEGthJ9RMtFa/bR/FeDjATmoMCmq344O2ilBFJQSrUCqfXsX/7de2z"
    "2fNanRTfV5IO+j1RyQ+81c9Z+IbXAdATr+8wnZmhLBYcNH9fxoUfLbwwaTeo7/OGHz/6XDKlX4Bw3szj2cZ0JVCr4FuoGbAZleEV"
    "v6khIzMBU0PCWhGjspVt5PLEviPOteA1r74ASju4/QYmSG3gphLh7FAviDRUtTfF72kvJvM3BTIa2NftmrF6Wl8/rFkpQoz61ncJ"
    "Q9HhLfrZmt9koNwccP+xiIsnLmAq9IW/0COSHfuhIGvqESTvUTSbvG2/5AKokbyhc3X3kINGHqBNiDjxnUglmTniM7+6Y5gfeg0O"
    "DWfAcSsemXbFieNs3uPi8OAnUIbH5jy/hyhxeYt/WsMXxY8zaTVjUtiKgIdvbuQwuhqvap8G6Co/9qQkHYtldpbblemYDnodJHph"
    "dQeizK7XxR4Y+//esFqJpxsQpW4dRKw5Na7XxgDDcW0f+6Y+9DDGLmgMW84kvnMoeOR4sQ4YsWnNeiTozQ5Sdr5S+0KZBDh709tQ"
    "b0UNf/ff3iqynuYL24eXjJN7u2sA+DkbBle9BoI+oMwamEsznoUI9aaSRC6WVH17XWxQGhXuGBTRcla89+Y1q762rDA2kofYx6nP"
    "uWSW6OSouuyJICAJROLi04laJDStQSsYR9Z1q+Wk+4RbasIsrVDoVVAKNHGxuiU1Vk1lcglpKlAoXs3vQPOsgnW9Bfd/o7TbIW8s"
    "5SkDHuTLC14sv7pOJYkkLAzdqjovecm/1CUkFh1XmSNyqOfNSRLvgOo/Mr2Wxea/COIM9a0wjJ+pmpm07/+nORRii6f29R5FcURg"
    "IM0fAPjeli4Tz8cIDNG02LyjGWlnVFW4jKRw/yEYArcaPg/PPWv/lZ8eyMqOmHY6T/BFf/x6fD8LQZjmJJJ/khS+Nt+r0mVrMDCw"
    "5E/Z4iar/9CICVln/y7fyoCaVWKZiF3Uv5lWLl5dd3P/5/Q6Zu4nJ3d4AElTknDpQcv8pkfnie/dtRIqiOLaha0XgqzeafwfUb08"
    "5yDR8vUA+METwRblzFKzKK3VEdLg2CQTnTR8QSEQIp3O0pnZu32hjW0IAH/o8Ro2jEi9yD4CY/oRmJi8kKb4TMhtbZKKpfEZ6r9G"
    "Dv4IsmjXlVCG0IeHpXeavEEBBvJeRz2xs4Pl7l1PXIxbkfc9+8pYbeKb6o/Zff0s7HhI32pLOb1SsXqw11Q+TeEsHTLW8SUC87kf"
    "rLjZ4vz/ylrSZpOlW6xHt3sP/W0yeQnbyAJOdrH1x5x1JCplwefLbd6ypJIPtg5jVr0xBqn7V+lp6cEklrZ+Ex6W/MaUwrtlyluf"
    "/nrkdqA9F7u+9t+3PeFc1N3t+5BcPv/MPSY5LaQBH0oH0TlpP45lVLqGQYLVFj/6zgx5wnCNeoOeJxV8CweSh6bILbn6H0yAW+Es"
    "fk4xpqaOp0bI/JJOFS8R39t7JfqQgh+EwSf8zquwKS3qc/8lR1346cP0hBD2gKw1Tsi6a/ljTmkg9Lew7Pl6nxp115wdmSlny7Xq"
    "9MnKa8JbdHbsAOWuy6s06OaWv6CK9iGt2pchUUKleIPnkEJyze5m8//9yJzQL1VCXMyDaTwxCsnGGTGtaZroPrQAhJSbVUrvNIC7"
    "A6m7p/U/27plwn7RPO88E9wDNlMw+W7r2ZSh7jHJR0rJmX4cJ5FO5Vlgw/p8c42y7j3E3U2zhOE3BfRMdCrzj6V6C+lQsKa0tJdT"
    "/D4yyMlOwRnJ6sy7qnMfR+80mOHCdDls9BFfYhQTFwXRcRoEnG4U1JTADSf75UlX+7L40Kp1uvcVaBDyfYACeXGcI5rDCvFVqt/D"
    "M3jGysNSLEqooPk+tWwGGjHnfCTwYrpnnx1F199S969T3yEfdSlKyadu8K3/21Jr8dvzlMzEc/dBDfmb/TCvUW9dTc+p+8lkR+YM"
    "qF/8SieDlC6M0CS/lC6MwkBuMi45/YZrfy5RmIDmT8L0MVRCWKXFSAjPN+lBfuiZdxRZfd0MuG2T2iZwLseKD8fcZBufr+bQZcnF"
    "tvtgbDnYP6Hlq5IrtJ/Kr9rCOceGEGkjM/05vEjBFEf4EL9XCxT/SImt7MziEGsmEFT3tQSTr8cwZ6B1CUM8UmyfOvyLlg1cgeYa"
    "B2tHGhgA"
)


if __name__ == "__main__":
    main()
