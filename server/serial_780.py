#!/usr/bin/env python3
"""Serial780：780 短信网关串口通信层（纯标准库）
与 main.lua v2 (uart.VUART_0) 对接，JSON 行协议 \n 分帧。

用法:
    from serial_780 import serial_780, start_serial_worker
    start_serial_worker()  # 启动读线程（自动推送短信/心跳处理）
    r = serial_780.command("get_status")     # 同步命令，返回 dict
    r = serial_780.command("send_sms", num="10086", text="hi", id="x1")
"""
import os
import sys
import json
import time
import termios
import select
import threading

# 串口自动探测顺序（PVE 直通下 VUART_0 实测 = ttyACM2，但顺序可能浮动）
CANDIDATE_PORTS = ["/dev/ttyACM2", "/dev/ttyACM1", "/dev/ttyACM0"]
BAUD = termios.B115200


class _Serial780:
    def __init__(self):
        self.fd = None
        self.port = None
        self.lock = threading.Lock()
        self.buf = b""
        self.running = False
        # 推送回调（新短信）
        self.on_sms = None          # def cb(num, text, timestr)
        # 命令响应等待表: req_name -> threading.Event + result
        self._waiters = {}
        self._waiters_lock = threading.Lock()
        self.last_heartbeat = 0
        self.last_boot = None

    # ---------------- 连接管理 ----------------
    def _open_port(self, port):
        try:
            fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            attrs = termios.tcgetattr(fd)
            attrs[4] = BAUD   # ispeed
            attrs[5] = BAUD   # ospeed
            attrs[3] &= ~(termios.ECHO | termios.ICANON | termios.ISIG)
            attrs[0] &= ~(termios.IXON | termios.ICRNL)
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            return fd
        except OSError:
            return None

    def _probe(self):
        """探测哪个 ttyACM 是 VUART_0：发 ping，2 秒内收到 JSON 响应即命中"""
        for port in CANDIDATE_PORTS:
            fd = self._open_port(port)
            if fd is None:
                continue
            try:
                os.write(fd, b'{"cmd":"ping"}\n')
                end = time.time() + 2
                buf = b""
                while time.time() < end:
                    r, _, _ = select.select([fd], [], [], 0.2)
                    if r:
                        try:
                            buf += os.read(fd, 4096)
                        except OSError:
                            break
                        for line in buf.split(b"\n"):
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                d = json.loads(line.decode("utf-8", errors="replace"))
                                if d.get("type") == "resp" and d.get("req") == "ping":
                                    return port, fd
                            except (ValueError, UnicodeDecodeError):
                                pass
            finally:
                pass
            os.close(fd)
        return None, None

    def connect(self):
        with self.lock:
            if self.fd is not None:
                return True
            port, fd = self._probe()
            if fd is not None:
                self.port, self.fd = port, fd
                print(f"[Serial780] 已连接 {port}")
                return True
            return False

    def disconnect(self):
        with self.lock:
            if self.fd is not None:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
                self.fd = None
                self.port = None

    @property
    def online(self):
        return self.fd is not None and (time.time() - self.last_heartbeat) < 150

    # ---------------- 发送 ----------------
    def _write(self, obj):
        with self.lock:
            if self.fd is None:
                raise ConnectionError("串口未连接")
            os.write(self.fd, (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))

    # ---------------- 命令（同步等待响应） ----------------
    def command(self, cmd, timeout=8, **kwargs):
        req = {"cmd": cmd, **kwargs}
        ev = threading.Event()
        slot = {"result": None}
        with self._waiters_lock:
            self._waiters[cmd] = (ev, slot)
        try:
            self._write(req)
        except ConnectionError:
            with self._waiters_lock:
                self._waiters.pop(cmd, None)
            return {"ok": False, "error": "serial not connected"}
        if not ev.wait(timeout):
            with self._waiters_lock:
                self._waiters.pop(cmd, None)
            return {"ok": False, "error": "timeout"}
        with self._waiters_lock:
            self._waiters.pop(cmd, None)
        return slot["result"] or {"ok": False, "error": "no response"}

    # ---------------- 读线程 ----------------
    def _reader(self):
        while self.running:
            if self.fd is None:
                if not self.connect():
                    time.sleep(3)
                    continue
            try:
                r, _, _ = select.select([self.fd], [], [], 0.5)
                if not r:
                    continue
                chunk = os.read(self.fd, 8192)
                if not chunk:
                    raise ConnectionError("EOF")
                self.buf += chunk
            except (OSError, ConnectionError):
                print("[Serial780] 连接断开，3 秒后重连...", file=sys.stderr)
                self.disconnect()
                time.sleep(3)
                continue

            # 按行切分处理
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                line = line.strip().decode("utf-8", errors="replace")
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                self._dispatch(d)

    def _dispatch(self, d):
        t = d.get("type")
        if t == "resp":
            req = d.get("req")
            with self._waiters_lock:
                waiter = self._waiters.get(req)
            if waiter:
                ev, slot = waiter
                slot["result"] = d
                ev.set()
        elif t == "sms":
            num = d.get("num", "未知")
            text = d.get("text", "")
            tstr = d.get("time", "")
            print(f"[Serial780] 新短信推送: {num} -> {text[:50]}")
            if self.on_sms:
                try:
                    self.on_sms(num, text, tstr)
                except Exception as e:
                    print(f"[Serial780] on_sms 回调异常: {e}", file=sys.stderr)
        elif t == "heartbeat":
            self.last_heartbeat = time.time()
            self._last_hb_data = d
        elif t == "boot":
            self.last_boot = d
            self.last_heartbeat = time.time()
            print(f"[Serial780] 设备启动: {d.get('version')}")

    # 便捷访问
    def heartbeat_data(self):
        return getattr(self, "_last_hb_data", None)

    def start(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._reader, daemon=True, name="serial780-reader").start()


serial_780 = _Serial780()


def start_serial_worker(on_sms=None):
    """启动串口工作线程。on_sms(num, text, timestr) 收到新短信时回调。"""
    serial_780.on_sms = on_sms
    serial_780.start()


if __name__ == "__main__":
    # 独立测试模式
    def on_sms(num, text, t):
        print(f"📱 [测试回调] {num}: {text}")

    start_serial_worker(on_sms)
    time.sleep(2)
    print("status:", json.dumps(serial_780.command("get_status"), ensure_ascii=False, indent=2))
    print("traffic:", serial_780.command("get_traffic"))
    print("\n监听推送 20 秒（Ctrl+C 退出）...")
    time.sleep(20)
