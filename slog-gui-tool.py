#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import datetime as dt
import time
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict, Any

import hid

VENDOR_ID = 0x246C

REPORT_ID = 0
REPORT_LEN = 64


# -------------------------
# Protocol helpers
# -------------------------
def checksum8(buf: List[int]) -> int:
    s = 0
    for b in buf[:-1]:
        s += b
    return s & 0xFF

def valid_frame(frame: bytes) -> bool:
    return len(frame) >= 2 and checksum8(list(frame)) == frame[-1]

def u32be(x: int) -> List[int]:
    return [(x >> 24) & 0xFF, (x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF]

def u16be(x: int) -> List[int]:
    return [(x >> 8) & 0xFF, x & 0xFF]

def read_u32be(b: bytes, off: int) -> int:
    return (b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]

def read_u16be(b: bytes, off: int) -> int:
    return (b[off] << 8) | b[off + 1]

def read_s16be(b: bytes, off: int) -> int:
    v = read_u16be(b, off)
    return v - 65536 if v > 32767 else v

def build_command(cmd_id: int, payload: List[int]) -> bytes:
    buf = [0x55, 0xAA, 0x00, cmd_id, 0x00, len(payload), *payload, 0x00]
    buf[-1] = checksum8(buf)
    return bytes(buf)

def enc_temp_c_x10_plus2000(temp_c: float) -> int:
    return int(round(temp_c * 10.0 + 2000.0))

def dec_temp_x10_plus2000(raw: int) -> float:
    return (raw - 2000) / 10.0

def enc_humi_x10(humi_rh: float) -> int:
    return int(round(humi_rh * 10.0))

def dec_humi_x10(raw: int) -> float:
    return raw / 10.0


# -------------------------
# Commands (from JS bundle)
# -------------------------
def cmd_write_time(device_epoch_seconds: int) -> bytes:
    return build_command(1, u32be(device_epoch_seconds))

def cmd_read_time() -> bytes:
    return build_command(2, [1])

def cmd_read_params() -> bytes:
    return build_command(2, [2])

def cmd_write_params(start_delay_s: int, interval_s: int,
                     temp_max_c: float, temp_min_c: float,
                     humi_max_rh: float, humi_min_rh: float) -> bytes:
    payload: List[int] = []
    payload += u32be(int(start_delay_s))
    payload += u16be(int(interval_s))
    payload += u16be(enc_temp_c_x10_plus2000(temp_max_c))
    payload += u16be(enc_temp_c_x10_plus2000(temp_min_c))
    payload += u16be(enc_humi_x10(humi_max_rh))
    payload += u16be(enc_humi_x10(humi_min_rh))
    return build_command(3, payload)

def cmd_read_alarm() -> bytes:
    return build_command(2, [3])

def cmd_read_stat() -> bytes:
    return build_command(2, [4])

def cmd_read_record(_n: int) -> bytes:
    base = [0x55, 0xAA, 0x00, 0x02, 0x00, 0x01, 0x05, 0x00]
    base[7] = checksum8(base)
    return bytes(base)

def cmd_read_device_info() -> bytes:
    return build_command(2, [6])

def cmd_reset() -> bytes:
    return build_command(8, [0xA5])

def cmd_write_sn(sn: str, ascii_mode: bool) -> bytes:
    payload: List[int] = []
    if ascii_mode:
        payload = [0] * 13
        for i, ch in enumerate(sn[:10]):
            payload[i] = ord(ch) & 0xFF
    else:
        for i in range(min(13, len(sn))):
            ch = sn[i]
            if ch.isdigit() or ("a" <= ch.lower() <= "f"):
                payload.append(int(ch, 16))
            else:
                payload.append(0)
        while len(payload) < 13:
            payload.append(0)
    return build_command(10, payload)

def cmd_self_check() -> bytes:
    return build_command(11, [1])

def cmd_key_test() -> bytes:
    return build_command(12, [1])

def cmd_led_test() -> bytes:
    return build_command(13, [1])


# -------------------------
# Parsers
# -------------------------
def parse_params(resp: bytes) -> Tuple[int, int, float, float, float, float]:
    start_delay = read_u32be(resp, 7)
    interval_s = read_u16be(resp, 11)
    tmax = dec_temp_x10_plus2000(read_u16be(resp, 13))
    tmin = dec_temp_x10_plus2000(read_u16be(resp, 15))
    hmax = dec_humi_x10(read_u16be(resp, 17))
    hmin = dec_humi_x10(read_u16be(resp, 19))
    return start_delay, interval_s, tmax, tmin, hmax, hmin

def parse_alarm(resp: bytes):
    def ts(off): return read_u32be(resp, off)
    def u16(off): return read_u16be(resp, off)
    return {
        "tempUpCount": u16(7),
        "tempUpTime": ts(9),
        "tempUpValueC": dec_temp_x10_plus2000(u16(13)),
        "tempDownCount": u16(15),
        "tempDownTime": ts(17),
        "tempDownValueC": dec_temp_x10_plus2000(u16(21)),
        "humiUpCount": u16(23),
        "humiUpTime": ts(25),
        "humiUpValueRH": dec_humi_x10(u16(29)),
        "humiDownCount": u16(31),
        "humiDownTime": ts(33),
        "humiDownValueRH": dec_humi_x10(u16(37)),
    }

def parse_stat(resp: bytes):
    def ts(off): return read_u32be(resp, off)
    def s16(off): return read_s16be(resp, off)
    def u16(off): return read_u16be(resp, off)
    return {
        "tempAvgC": s16(7) / 10.0,
        "tempMaxC": s16(9) / 10.0,
        "tempMaxTime": ts(11),
        "tempMinC": s16(15) / 10.0,
        "tempMinTime": ts(17),
        "tempUsefulCount": u16(21),
        "humiAvgRH": u16(23) / 10.0,
        "humiMaxRH": u16(25) / 10.0,
        "humiMaxTime": ts(27),
        "humiMinRH": u16(31) / 10.0,
        "humiMinTime": ts(33),
        "humiUsefulCount": u16(37),
        "normalCount": u16(39),
    }

def parse_record_chunk(frame16: bytes):
    if len(frame16) != 16 or not valid_frame(frame16):
        return None
    t = read_u32be(frame16, 7)
    temp_c = (read_u16be(frame16, 11) - 2000) / 10.0
    humi_rh = read_u16be(frame16, 13) / 10.0
    return t, temp_c, humi_rh

def parse_device_info(resp: bytes):
    serial_bytes = resp[7:20]
    version_bytes = resp[20:28]
    count = read_u16be(resp, 28)
    start_ts = read_u32be(resp, 30)
    end_ts = read_u32be(resp, 34)
    return {
        "serial_hex": serial_bytes.hex().upper(),
        "version_hex": version_bytes.hex().upper(),
        "record_count": count,
        "start_ts": start_ts,
        "end_ts": end_ts,
    }

def parse_self_check(resp: bytes):
    code = resp[6]
    messages = {
        0: "Self check succeeded",
        1: "EEPROM storage error",
        2: "Sensor error",
        3: "EEPROM storage error + sensor error",
        4: "Flash storage error",
    }
    return code, messages.get(code, "Unknown error")

def parse_key_test(resp: bytes):
    keymap = {1: "ShortStart", 2: "LongStart", 3: "ShortStop", 4: "LongStop"}
    ok = resp[5] == 1
    return ok, keymap.get(resp[6], "Unknown")

def status_text(code: int) -> str:
    return "success" if code == 1 else f"failed ({code})"


# -------------------------
# HID I/O
# -------------------------
@dataclass
class HidDevice:
    dev: object
    path: bytes
    vendor_id: int
    product_id: int
    interface_number: int

    @staticmethod
    def enumerate_mesavss() -> List[Dict[str, Any]]:
        return hid.enumerate(VENDOR_ID, 0)

    @staticmethod
    def open_by_path(path: bytes) -> "HidDevice":
        devs = hid.enumerate(VENDOR_ID, 0)
        match = None
        for d in devs:
            if d.get("path") == path:
                match = d
                break
        if not match:
            raise RuntimeError("Selected device is no longer present. Re-plug and click Refresh.")

        d = hid.device()
        d.open_path(path)
        try:
            d.set_nonblocking(False)
        except Exception:
            pass

        return HidDevice(
            dev=d,
            path=path,
            vendor_id=match.get("vendor_id", VENDOR_ID),
            product_id=match.get("product_id", 0),
            interface_number=match.get("interface_number", -1),
        )

    def close(self) -> None:
        try:
            self.dev.close()
        except Exception:
            pass

    def send_and_receive(self, cmd: bytes, expect_len: Optional[int], timeout_ms: int = 3000) -> bytes:
        out = bytearray(REPORT_LEN)
        out[:len(cmd)] = cmd
        self.dev.write(bytes([REPORT_ID]) + bytes(out))

        if expect_len is None:
            return b""

        deadline = time.time() + timeout_ms / 1000.0
        buf = bytearray()
        while len(buf) < expect_len and time.time() < deadline:
            chunk = self.dev.read(REPORT_LEN, timeout_ms)  # list[int]
            if not chunk:
                continue
            buf.extend(bytes(chunk))
            if len(chunk) < REPORT_LEN and len(buf) > 0:
                break
        if len(buf) < expect_len:
            raise TimeoutError(f"Receive timeout: got {len(buf)} bytes, expected {expect_len}")
        return bytes(buf[:expect_len])


# -------------------------
# Time handling
# -------------------------
def offset_minutes_from_arg(tz: str) -> int:
    tz = tz.strip()
    if tz.lower() == "local":
        return int(dt.datetime.now().astimezone().utcoffset().total_seconds() // 60)
    if tz.upper() == "UTC":
        return 0
    if ":" in tz:
        sign = 1
        if tz[0] == "-":
            sign = -1
        hh, mm = tz[1:].split(":")
        return sign * (int(hh) * 60 + int(mm))
    return int(tz)

def device_timestamp_from_now(offset_minutes: int) -> int:
    now = dt.datetime.now(dt.timezone.utc)
    return int(now.timestamp()) + offset_minutes * 60

def device_ts_to_local_iso(device_ts: int, tz_arg: str) -> str:
    off = offset_minutes_from_arg(tz_arg)
    real_epoch = device_ts - off * 60
    return dt.datetime.fromtimestamp(real_epoch, dt.timezone.utc).astimezone().isoformat()


# -------------------------
# GUI
# -------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mesavss HID Tool (VID 246C) — Multi-device")
        self.geometry("900x700")
        self.resizable(True, True)

        self.dev: Optional[HidDevice] = None
        self.devices: List[Dict[str, Any]] = []

        self._build()
        self.refresh_device_list()

    def set_status(self, msg: str, error: bool = False):
        self.status_var.set(("ERROR: " if error else "") + msg)

    def run_safe(self, fn):
        try:
            fn()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status(str(e), error=True)

    def require_dev(self) -> HidDevice:
        if not self.dev:
            raise RuntimeError("Not connected. Select a device and click Connect.")
        return self.dev

    def _build(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=8)

        self.status_var = tk.StringVar(value="Not connected.")
        ttk.Label(top, textvariable=self.status_var).pack(side="left")

        # Connection
        conn = ttk.LabelFrame(self, text="Connection (all Mesavss VID 0x246C HID devices)")
        conn.pack(fill="x", padx=10, pady=6)

        self.device_choice_var = tk.StringVar(value="")
        self.device_combo = ttk.Combobox(conn, textvariable=self.device_choice_var, state="readonly", width=110)
        self.device_combo.grid(row=0, column=0, columnspan=6, sticky="ew", padx=10, pady=(10, 6))

        # Buttons BELOW the combobox (requested)
        btn_row = ttk.Frame(conn)
        btn_row.grid(row=1, column=0, columnspan=6, sticky="w", padx=10, pady=(0, 10))
        ttk.Button(btn_row, text="Refresh", command=lambda: self.run_safe(self.refresh_device_list)).pack(side="left", padx=(0, 10))
        ttk.Button(btn_row, text="Connect", command=self.on_connect).pack(side="left", padx=(0, 10))
        ttk.Button(btn_row, text="Disconnect", command=self.on_disconnect).pack(side="left")

        ttk.Label(conn, text="TZ (for set/read):").grid(row=2, column=0, sticky="w", padx=10, pady=6)
        self.tz_var = tk.StringVar(value="local")
        ttk.Entry(conn, textvariable=self.tz_var, width=12).grid(row=2, column=1, sticky="w", padx=10, pady=6)
        ttk.Label(conn, text="(local | UTC | +01:00 | +120 etc.)").grid(row=2, column=2, sticky="w", padx=10, pady=6)

        self.connected_var = tk.StringVar(value="(none)")
        ttk.Label(conn, textvariable=self.connected_var, foreground="gray").grid(row=3, column=0, columnspan=6, sticky="w", padx=10, pady=6)

        # Make combobox stretch with frame
        conn.columnconfigure(0, weight=1)

        # Notebook
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=10)

        self._build_tab_config()
        self._build_tab_device()
        self._build_tab_stats()
        self._build_tab_alarms()
        self._build_tab_records()
        self._build_tab_tests_sn()

    def refresh_device_list(self):
        self.devices = HidDevice.enumerate_mesavss()
        items = []
        for d in self.devices:
            pid = d.get("product_id", 0)
            iface = d.get("interface_number", -1)
            up = d.get("usage_page", 0)
            u = d.get("usage", 0)
            prod = d.get("product_string") or ""
            mfg = d.get("manufacturer_string") or ""
            path = d.get("path")
            items.append(f"PID={pid:04x} iface={iface} usage_page={up} usage={u} mfg='{mfg}' product='{prod}' path={path!r}")
        self.device_combo["values"] = items
        if items:
            self.device_combo.current(0)
            self.device_choice_var.set(items[0])
            self.set_status(f"Found {len(items)} device(s).")
        else:
            self.device_choice_var.set("")
            self.set_status("No Mesavss (VID 246C) HID devices found.", error=True)

    def _selected_path(self) -> bytes:
        idx = self.device_combo.current()
        if idx < 0 or idx >= len(self.devices):
            raise RuntimeError("No device selected.")
        return self.devices[idx]["path"]

    # ----- Tabs -----
    def _build_tab_config(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="Config")

        self.start_delay_var = tk.StringVar(value="60")
        self.interval_s_var = tk.StringVar(value="60")
        self.interval_min_var = tk.StringVar(value="1")
        self.temp_max_var = tk.StringVar(value="70.0")
        self.temp_min_var = tk.StringVar(value="-30.0")
        self.humi_max_var = tk.StringVar(value="0.0")
        self.humi_min_var = tk.StringVar(value="0.0")

        ttk.Button(tab, text="Read config", command=lambda: self.run_safe(self.on_read_params)).grid(row=0, column=0, padx=10, pady=8, sticky="w")
        ttk.Button(tab, text="Write full config", command=lambda: self.run_safe(self.on_write_full)).grid(row=0, column=1, padx=10, pady=8, sticky="w")
        ttk.Button(tab, text="Read device time", command=lambda: self.run_safe(self.on_read_time)).grid(row=0, column=2, padx=10, pady=8, sticky="w")
        ttk.Button(tab, text="Set time to now", command=lambda: self.run_safe(self.on_set_time)).grid(row=0, column=3, padx=10, pady=8, sticky="w")

        def add_row(r, label, var):
            ttk.Label(tab, text=label).grid(row=r, column=0, sticky="w", padx=10, pady=6)
            ttk.Entry(tab, textvariable=var, width=14).grid(row=r, column=1, sticky="w", padx=10, pady=6)

        add_row(1, "Start delay (s):", self.start_delay_var)
        add_row(2, "Interval (s):", self.interval_s_var)
        ttk.Button(tab, text="Set interval ONLY (seconds)", command=lambda: self.run_safe(self.on_set_interval_s_only)).grid(row=2, column=2, padx=10, pady=6, sticky="w")
        add_row(3, "Interval (min):", self.interval_min_var)
        ttk.Button(tab, text="Set interval ONLY (minutes)", command=lambda: self.run_safe(self.on_set_interval_min_only)).grid(row=3, column=2, padx=10, pady=6, sticky="w")
        add_row(4, "High Temp. Alert (°C):", self.temp_max_var)
        add_row(5, "Low Temp. Alert (°C):", self.temp_min_var)
        add_row(6, "Humidity max (%RH):", self.humi_max_var)
        add_row(7, "Humidity min (%RH):", self.humi_min_var)

        self.cfg_out = tk.StringVar(value="")
        ttk.Label(tab, textvariable=self.cfg_out, foreground="gray").grid(row=8, column=0, columnspan=5, sticky="w", padx=10, pady=10)

        self.time_out = tk.StringVar(value="")
        ttk.Label(tab, textvariable=self.time_out, foreground="gray").grid(row=9, column=0, columnspan=5, sticky="w", padx=10, pady=6)

    def _build_tab_device(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="Device info")
        ttk.Button(tab, text="Read device info", command=lambda: self.run_safe(self.on_read_device_info)).pack(anchor="w", padx=10, pady=8)
        ttk.Button(tab, text="Reset / clear records", command=lambda: self.run_safe(self.on_reset)).pack(anchor="w", padx=10, pady=6)
        self.device_info_text = tk.Text(tab, height=22, wrap="word")
        self.device_info_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.device_info_text.insert("end", "No data.\n")
        self.device_info_text.configure(state="disabled")

    def _build_tab_stats(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="Stats")
        ttk.Button(tab, text="Read statistics", command=lambda: self.run_safe(self.on_read_stat)).pack(anchor="w", padx=10, pady=8)
        self.stats_text = tk.Text(tab, height=22, wrap="word")
        self.stats_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.stats_text.insert("end", "No data.\n")
        self.stats_text.configure(state="disabled")

    def _build_tab_alarms(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="Alarms")
        ttk.Button(tab, text="Read alarm summary", command=lambda: self.run_safe(self.on_read_alarm)).pack(anchor="w", padx=10, pady=8)
        self.alarms_text = tk.Text(tab, height=22, wrap="word")
        self.alarms_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.alarms_text.insert("end", "No data.\n")
        self.alarms_text.configure(state="disabled")

    def _build_tab_records(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="Records")
        top = ttk.Frame(tab)
        top.pack(fill="x", padx=10, pady=8)
        ttk.Label(top, text="Read N records (best effort):").pack(side="left")
        self.record_count_var = tk.StringVar(value="100")
        ttk.Entry(top, textvariable=self.record_count_var, width=10).pack(side="left", padx=8)
        ttk.Button(top, text="Read", command=lambda: self.run_safe(self.on_read_records)).pack(side="left")
        self.records_text = tk.Text(tab, height=24, wrap="none")
        self.records_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.records_text.insert("end", "No data.\n")
        self.records_text.configure(state="disabled")

    def _build_tab_tests_sn(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="Tests & SN")
        f1 = ttk.LabelFrame(tab, text="Diagnostics / tests")
        f1.pack(fill="x", padx=10, pady=8)
        ttk.Button(f1, text="Self check", command=lambda: self.run_safe(self.on_self_check)).grid(row=0, column=0, padx=10, pady=8, sticky="w")
        ttk.Button(f1, text="Key test", command=lambda: self.run_safe(self.on_key_test)).grid(row=0, column=1, padx=10, pady=8, sticky="w")
        ttk.Button(f1, text="LED test", command=lambda: self.run_safe(self.on_led_test)).grid(row=0, column=2, padx=10, pady=8, sticky="w")
        self.test_out = tk.StringVar(value="")
        ttk.Label(f1, textvariable=self.test_out, foreground="gray").grid(row=1, column=0, columnspan=5, sticky="w", padx=10, pady=6)

        f2 = ttk.LabelFrame(tab, text="Write SN (feature may vary by model)")
        f2.pack(fill="x", padx=10, pady=8)
        ttk.Label(f2, text="SN:").grid(row=0, column=0, sticky="w", padx=10, pady=6)
        self.sn_var = tk.StringVar(value="")
        ttk.Entry(f2, textvariable=self.sn_var, width=28).grid(row=0, column=1, sticky="w", padx=10, pady=6)
        self.sn_mode_var = tk.StringVar(value="ASCII")
        ttk.Radiobutton(f2, text="ASCII", variable=self.sn_mode_var, value="ASCII").grid(row=0, column=2, padx=10, pady=6, sticky="w")
        ttk.Radiobutton(f2, text="HEX nibbles", variable=self.sn_mode_var, value="HEX").grid(row=0, column=3, padx=10, pady=6, sticky="w")
        ttk.Button(f2, text="Write SN", command=lambda: self.run_safe(self.on_write_sn)).grid(row=1, column=1, padx=10, pady=8, sticky="w")
        self.sn_out = tk.StringVar(value="")
        ttk.Label(f2, textvariable=self.sn_out, foreground="gray").grid(row=2, column=0, columnspan=6, sticky="w", padx=10, pady=6)

    # ----- Connection actions -----
    def on_connect(self):
        def _():
            if self.dev:
                self.dev.close()
                self.dev = None

            path = self._selected_path()
            self.dev = HidDevice.open_by_path(path)
            self.connected_var.set(f"Connected: VID={self.dev.vendor_id:04x} PID={self.dev.product_id:04x} iface={self.dev.interface_number} path={self.dev.path!r}")
            self.set_status("Connected. Reading config...")

            # Auto-read params if supported
            try:
                resp = self.dev.send_and_receive(cmd_read_params(), expect_len=22, timeout_ms=1500)
                if not valid_frame(resp):
                    raise RuntimeError("Bad checksum in params response")
                start_delay, interval_s, tmax, tmin, hmax, hmin = parse_params(resp)
                self.start_delay_var.set(str(start_delay))
                self.interval_s_var.set(str(interval_s))
                self.interval_min_var.set(str(int(round(interval_s / 60))))
                self.temp_max_var.set(f"{tmax:.1f}")
                self.temp_min_var.set(f"{tmin:.1f}")
                self.humi_max_var.set(f"{hmax:.1f}")
                self.humi_min_var.set(f"{hmin:.1f}")
                self.cfg_out.set("Config loaded from device.")
                self.set_status("Connected. Config loaded.")
            except Exception as e:
                self.cfg_out.set("Connected, but this device did not respond to Read Params (feature may be unsupported).")
                self.set_status(f"Connected. Auto-load failed: {e}", error=True)

        self.run_safe(_)

    def on_disconnect(self):
        def _():
            if self.dev:
                self.dev.close()
                self.dev = None
            self.connected_var.set("(none)")
            self.set_status("Disconnected.")
        self.run_safe(_)

    # ----- Config/time actions -----
    def on_read_time(self):
        d = self.require_dev()
        tz = self.tz_var.get()
        resp = d.send_and_receive(cmd_read_time(), expect_len=12, timeout_ms=1500)
        if not valid_frame(resp):
            raise RuntimeError("Bad checksum in time response")
        dev_ts = read_u32be(resp, 7)
        self.time_out.set(f"Device time: {device_ts_to_local_iso(dev_ts, tz)} (raw={dev_ts})")
        self.set_status("Read time: success")

    def on_set_time(self):
        d = self.require_dev()
        tz = self.tz_var.get()
        off = offset_minutes_from_arg(tz)
        dev_ts = device_timestamp_from_now(off)
        resp = d.send_and_receive(cmd_write_time(dev_ts), expect_len=8, timeout_ms=1500)
        if not valid_frame(resp):
            raise RuntimeError("Bad checksum in write-time response")
        self.set_status(f"Set time: {status_text(resp[6])}")

    def on_read_params(self):
        d = self.require_dev()
        resp = d.send_and_receive(cmd_read_params(), expect_len=22, timeout_ms=1500)
        if not valid_frame(resp):
            raise RuntimeError("Bad checksum in params response")
        start_delay, interval_s, tmax, tmin, hmax, hmin = parse_params(resp)
        self.start_delay_var.set(str(start_delay))
        self.interval_s_var.set(str(interval_s))
        self.interval_min_var.set(str(int(round(interval_s / 60))))
        self.temp_max_var.set(f"{tmax:.1f}")
        self.temp_min_var.set(f"{tmin:.1f}")
        self.humi_max_var.set(f"{hmax:.1f}")
        self.humi_min_var.set(f"{hmin:.1f}")
        self.cfg_out.set("Config loaded from device.")
        self.set_status("Read config: success")

    def on_set_interval_s_only(self):
        d = self.require_dev()
        r = d.send_and_receive(cmd_read_params(), expect_len=22, timeout_ms=1500)
        if not valid_frame(r):
            raise RuntimeError("Bad checksum reading current params")
        start_delay, _old_interval, tmax, tmin, hmax, hmin = parse_params(r)

        new_interval_s = int(self.interval_s_var.get())
        if not (1 <= new_interval_s <= 65535):
            raise ValueError("Interval (seconds) must be 1..65535")

        w = d.send_and_receive(cmd_write_params(start_delay, new_interval_s, tmax, tmin, hmax, hmin),
                               expect_len=8, timeout_ms=1500)
        if not valid_frame(w):
            raise RuntimeError("Bad checksum writing params")
        st = status_text(w[6])

        r2 = d.send_and_receive(cmd_read_params(), expect_len=22, timeout_ms=1500)
        if valid_frame(r2):
            _, interval_s2, *_ = parse_params(r2)
            self.interval_s_var.set(str(interval_s2))
            self.interval_min_var.set(str(int(round(interval_s2 / 60))))
            if interval_s2 != new_interval_s:
                self.cfg_out.set(f"Interval requested {new_interval_s}s, device clamped to {interval_s2}s.")
            else:
                self.cfg_out.set(f"Interval set to {interval_s2}s.")
        else:
            self.cfg_out.set("Wrote interval, but could not verify (bad checksum).")

        self.set_status(f"Set interval (seconds only): {st}")

    def on_set_interval_min_only(self):
        d = self.require_dev()
        r = d.send_and_receive(cmd_read_params(), expect_len=22, timeout_ms=1500)
        if not valid_frame(r):
            raise RuntimeError("Bad checksum reading current params")
        start_delay, _old_interval, tmax, tmin, hmax, hmin = parse_params(r)

        new_interval_s = int(self.interval_min_var.get()) * 60
        if not (1 <= new_interval_s <= 65535):
            raise ValueError("Interval must be 1..65535 seconds")

        w = d.send_and_receive(cmd_write_params(start_delay, new_interval_s, tmax, tmin, hmax, hmin),
                               expect_len=8, timeout_ms=1500)
        if not valid_frame(w):
            raise RuntimeError("Bad checksum writing params")
        st = status_text(w[6])

        r2 = d.send_and_receive(cmd_read_params(), expect_len=22, timeout_ms=1500)
        if valid_frame(r2):
            _, interval_s2, *_ = parse_params(r2)
            self.interval_s_var.set(str(interval_s2))
            self.interval_min_var.set(str(int(round(interval_s2 / 60))))
            if interval_s2 != new_interval_s:
                self.cfg_out.set(f"Interval requested {new_interval_s}s, device clamped to {interval_s2}s.")
            else:
                self.cfg_out.set(f"Interval set to {interval_s2}s.")
        else:
            self.cfg_out.set("Wrote interval, but could not verify (bad checksum).")

        self.set_status(f"Set interval (minutes only): {st}")

    def on_write_full(self):
        d = self.require_dev()
        start_delay = int(self.start_delay_var.get())
        interval_s = int(self.interval_s_var.get())
        tmax = float(self.temp_max_var.get())
        tmin = float(self.temp_min_var.get())
        hmax = float(self.humi_max_var.get())
        hmin = float(self.humi_min_var.get())

        if not (0 <= start_delay <= 0xFFFFFFFF):
            raise ValueError("Start delay out of range")
        if not (1 <= interval_s <= 65535):
            raise ValueError("Interval (seconds) must be 1..65535")

        w = d.send_and_receive(cmd_write_params(start_delay, interval_s, tmax, tmin, hmax, hmin),
                               expect_len=8, timeout_ms=1500)
        if not valid_frame(w):
            raise RuntimeError("Bad checksum writing config")
        st = status_text(w[6])

        try:
            r2 = d.send_and_receive(cmd_read_params(), expect_len=22, timeout_ms=1500)
            if valid_frame(r2):
                start_delay2, interval_s2, tmax2, tmin2, hmax2, hmin2 = parse_params(r2)
                self.start_delay_var.set(str(start_delay2))
                self.interval_s_var.set(str(interval_s2))
                self.interval_min_var.set(str(int(round(interval_s2 / 60))))
                self.temp_max_var.set(f"{tmax2:.1f}")
                self.temp_min_var.set(f"{tmin2:.1f}")
                self.humi_max_var.set(f"{hmax2:.1f}")
                self.humi_min_var.set(f"{hmin2:.1f}")
                if interval_s2 != interval_s:
                    self.cfg_out.set(f"Wrote config, but interval was clamped to {interval_s2}s (requested {interval_s}s).")
                else:
                    self.cfg_out.set("Config written and verified.")
            else:
                self.cfg_out.set("Config written, but could not verify.")
        except Exception:
            self.cfg_out.set("Config written, but verify failed (device may not support readback).")

        self.set_status(f"Write full config: {st}")

    def on_read_device_info(self):
        d = self.require_dev()
        tz = self.tz_var.get()
        resp = d.send_and_receive(cmd_read_device_info(), expect_len=39, timeout_ms=1500)
        if not valid_frame(resp):
            raise RuntimeError("Bad checksum in device info response")
        info = parse_device_info(resp)
        text = []
        text.append(f"VID: {d.vendor_id:04x}  PID: {d.product_id:04x}  iface: {d.interface_number}")
        text.append(f"serial_hex:   {info['serial_hex']}")
        text.append(f"version_hex:  {info['version_hex']}")
        text.append(f"record_count: {info['record_count']}")
        text.append(f"start_time:   {device_ts_to_local_iso(info['start_ts'], tz)} (raw={info['start_ts']})")
        text.append(f"end_time:     {device_ts_to_local_iso(info['end_ts'], tz)} (raw={info['end_ts']})")
        self.device_info_text.configure(state="normal")
        self.device_info_text.delete("1.0", "end")
        self.device_info_text.insert("end", "\n".join(text) + "\n")
        self.device_info_text.configure(state="disabled")
        self.set_status("Read device info: success")

    def on_read_stat(self):
        d = self.require_dev()
        tz = self.tz_var.get()
        resp = d.send_and_receive(cmd_read_stat(), expect_len=42, timeout_ms=2000)
        if not valid_frame(resp):
            raise RuntimeError("Bad checksum in stats response")
        s = parse_stat(resp)
        text = []
        text.append(f"tempAvg: {s['tempAvgC']:.1f} °C")
        text.append(f"tempMax: {s['tempMaxC']:.1f} °C at {device_ts_to_local_iso(s['tempMaxTime'], tz)}")
        text.append(f"tempMin: {s['tempMinC']:.1f} °C at {device_ts_to_local_iso(s['tempMinTime'], tz)}")
        text.append(f"tempUsefulCount: {s['tempUsefulCount']}")
        text.append("")
        text.append(f"humiAvg: {s['humiAvgRH']:.1f} %RH")
        text.append(f"humiMax: {s['humiMaxRH']:.1f} %RH at {device_ts_to_local_iso(s['humiMaxTime'], tz)}")
        text.append(f"humiMin: {s['humiMinRH']:.1f} %RH at {device_ts_to_local_iso(s['humiMinTime'], tz)}")
        text.append(f"humiUsefulCount: {s['humiUsefulCount']}")
        text.append(f"normalCount: {s['normalCount']}")
        self.stats_text.configure(state="normal")
        self.stats_text.delete("1.0", "end")
        self.stats_text.insert("end", "\n".join(text) + "\n")
        self.stats_text.configure(state="disabled")
        self.set_status("Read statistics: success")

    def on_read_alarm(self):
        d = self.require_dev()
        tz = self.tz_var.get()
        resp = d.send_and_receive(cmd_read_alarm(), expect_len=40, timeout_ms=2000)
        if not valid_frame(resp):
            raise RuntimeError("Bad checksum in alarm response")
        a = parse_alarm(resp)
        text = []
        text.append(f"tempUpCount:   {a['tempUpCount']}")
        text.append(f"tempUpValue:   {a['tempUpValueC']:.1f} °C at {device_ts_to_local_iso(a['tempUpTime'], tz)}")
        text.append(f"tempDownCount: {a['tempDownCount']}")
        text.append(f"tempDownValue: {a['tempDownValueC']:.1f} °C at {device_ts_to_local_iso(a['tempDownTime'], tz)}")
        text.append("")
        text.append(f"humiUpCount:   {a['humiUpCount']}")
        text.append(f"humiUpValue:   {a['humiUpValueRH']:.1f} %RH at {device_ts_to_local_iso(a['humiUpTime'], tz)}")
        text.append(f"humiDownCount: {a['humiDownCount']}")
        text.append(f"humiDownValue: {a['humiDownValueRH']:.1f} %RH at {device_ts_to_local_iso(a['humiDownTime'], tz)}")
        self.alarms_text.configure(state="normal")
        self.alarms_text.delete("1.0", "end")
        self.alarms_text.insert("end", "\n".join(text) + "\n")
        self.alarms_text.configure(state="disabled")
        self.set_status("Read alarms: success")

    def on_read_records(self):
        d = self.require_dev()
        tz = self.tz_var.get()
        n = int(self.record_count_var.get())
        if n <= 0:
            raise ValueError("N must be > 0")
        expect_len = 16 * n
        resp = d.send_and_receive(cmd_read_record(n), expect_len=expect_len, timeout_ms=6000)
        lines = []
        good = 0
        for i in range(n):
            chunk = resp[i * 16:(i + 1) * 16]
            rec = parse_record_chunk(chunk)
            if not rec:
                continue
            t, tc, hr = rec
            lines.append(f"{i:04d}  {device_ts_to_local_iso(t, tz)}  temp={tc:.1f}°C  humi={hr:.1f}%RH  (raw_ts={t})")
            good += 1
        self.records_text.configure(state="normal")
        self.records_text.delete("1.0", "end")
        self.records_text.insert("end", "\n".join(lines) + ("\n" if lines else "No valid record frames.\n"))
        self.records_text.configure(state="disabled")
        self.set_status(f"Read records: success ({good}/{n} valid)")

    def on_reset(self):
        d = self.require_dev()
        if not messagebox.askyesno("Reset / clear records",
                                  "This will reset/clear records on the logger.\n\nContinue?"):
            return
        r = d.send_and_receive(cmd_reset(), expect_len=8, timeout_ms=2000)
        if not valid_frame(r):
            raise RuntimeError("Bad checksum in reset response")
        self.set_status(f"Reset: {status_text(r[6])}")

    def on_self_check(self):
        d = self.require_dev()
        r = d.send_and_receive(cmd_self_check(), expect_len=8, timeout_ms=2000)
        if not valid_frame(r):
            raise RuntimeError("Bad checksum in self-check response")
        code, msg = parse_self_check(r)
        self.test_out.set(f"Self check: {'success' if code == 0 else 'failed'} (code={code}) — {msg}")
        self.set_status("Self check: success" if code == 0 else f"Self check: failed ({code})", error=(code != 0))

    def on_key_test(self):
        d = self.require_dev()
        r = d.send_and_receive(cmd_key_test(), expect_len=8, timeout_ms=2000)
        if not valid_frame(r):
            raise RuntimeError("Bad checksum in key-test response")
        ok, key = parse_key_test(r)
        self.test_out.set(f"Key test: {'success' if ok else 'failed'} — {key}")
        self.set_status(f"Key test: {'success' if ok else 'failed'}")

    def on_led_test(self):
        d = self.require_dev()
        r = d.send_and_receive(cmd_led_test(), expect_len=8, timeout_ms=2000)
        if not valid_frame(r):
            raise RuntimeError("Bad checksum in LED-test response")
        self.test_out.set("LED test: command sent (response received).")
        self.set_status("LED test: success")

    def on_write_sn(self):
        d = self.require_dev()
        sn = self.sn_var.get().strip()
        if not sn:
            raise ValueError("SN must not be empty")
        ascii_mode = (self.sn_mode_var.get() == "ASCII")
        r = d.send_and_receive(cmd_write_sn(sn, ascii_mode), expect_len=8, timeout_ms=2000)
        if not valid_frame(r):
            raise RuntimeError("Bad checksum in write-SN response")
        st = status_text(r[6])
        self.sn_out.set(f"Write SN: {st}")
        self.set_status(f"Write SN: {st}", error=(st != "success"))


if __name__ == "__main__":
    App().mainloop()
