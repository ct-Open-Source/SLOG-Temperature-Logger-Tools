#!/usr/bin/env python3
"""
mesavss_cli.py — Mesavss HID CLI (VID 0x246C), best-effort multi-device tool

Works with the "SLOG"/"ATag" style protocol frames found in the vendor's WebHID JS.
It enumerates ALL HID devices with vendor id 0x246C, lets you pick one, and provides
commands for all known JS functions (even if a given device doesn't support them).

Linux note: you may need permissions for the HID interface (udev rules) or run with sudo.
Windows/macOS: should work if hidapi backend is available.

Examples:
  # list devices
  python3 mesavss_cli.py --list

  # read params from first matching device (index 0)
  python3 mesavss_cli.py --device 0 --read-params

  # set full config
  python3 mesavss_cli.py --device 0 --write-params --start-delay 60 --interval-s 60 --tmax 70 --tmin -30 --hmax 0 --hmin 0

  # set interval only
  python3 mesavss_cli.py --device 0 --set-interval-s 120

  # time read/set (tz affects interpretation and "now" offset)
  python3 mesavss_cli.py --device 0 --read-time --tz local
  python3 mesavss_cli.py --device 0 --set-time-now --tz +01:00

  # stats / alarm / device-info
  python3 mesavss_cli.py --device 0 --read-stat
  python3 mesavss_cli.py --device 0 --read-alarm
  python3 mesavss_cli.py --device 0 --read-device-info

  # records (best effort)
  python3 mesavss_cli.py --device 0 --read-records 100

  # tests
  python3 mesavss_cli.py --device 0 --self-check
  python3 mesavss_cli.py --device 0 --key-test
  python3 mesavss_cli.py --device 0 --led-test

  # write SN (feature varies)
  python3 mesavss_cli.py --device 0 --write-sn ASCII12345 --sn-mode ascii
  python3 mesavss_cli.py --device 0 --write-sn 0123456789ABCDE --sn-mode hex

  # reset (danger)
  python3 mesavss_cli.py --device 0 --reset
"""
import argparse
import datetime as dt
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

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
    # Frame: [0x55,0xAA,0x00, cmd, 0x00, len(payload), payload..., checksum]
    buf = [0x55, 0xAA, 0x00, cmd_id, 0x00, len(payload), *payload, 0x00]
    buf[-1] = checksum8(buf)
    return bytes(buf)


def hexdump(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


# temp/humi encoding used in params/alarm/records
def enc_temp_c_x10_plus2000(temp_c: float) -> int:
    return int(round(temp_c * 10.0 + 2000.0))


def dec_temp_x10_plus2000(raw: int) -> float:
    return (raw - 2000) / 10.0


def enc_humi_x10(humi_rh: float) -> int:
    return int(round(humi_rh * 10.0))


def dec_humi_x10(raw: int) -> float:
    return raw / 10.0


def status_text(code: int) -> str:
    return "success" if code == 1 else f"failed ({code})"


# -------------------------
# Commands (mirroring JS)
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
    # JS command doesn't include n, but responses are 16-byte chunks per record.
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


def parse_alarm(resp: bytes) -> Dict[str, Any]:
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


def parse_stat(resp: bytes) -> Dict[str, Any]:
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


def parse_record_chunk(frame16: bytes) -> Optional[Tuple[int, float, float]]:
    if len(frame16) != 16 or not valid_frame(frame16):
        return None
    t = read_u32be(frame16, 7)
    temp_c = (read_u16be(frame16, 11) - 2000) / 10.0
    humi_rh = read_u16be(frame16, 13) / 10.0
    return t, temp_c, humi_rh


def parse_device_info(resp: bytes) -> Dict[str, Any]:
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


def parse_self_check(resp: bytes) -> Tuple[int, str]:
    code = resp[6]
    messages = {
        0: "Self check succeeded",
        1: "EEPROM storage error",
        2: "Sensor error",
        3: "EEPROM storage error + sensor error",
        4: "Flash storage error",
    }
    return code, messages.get(code, "Unknown error")


def parse_key_test(resp: bytes) -> Tuple[bool, str]:
    keymap = {1: "ShortStart", 2: "LongStart", 3: "ShortStop", 4: "LongStop"}
    ok = resp[5] == 1
    return ok, keymap.get(resp[6], "Unknown")


# -------------------------
# Time helpers
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
# HID wrapper
# -------------------------
@dataclass
class HidDevice:
    dev: Any
    path: bytes
    vendor_id: int
    product_id: int
    interface_number: int

    @staticmethod
    def enumerate_vid() -> List[Dict[str, Any]]:
        return hid.enumerate(VENDOR_ID, 0)

    @staticmethod
    def open_by_index(index: int) -> "HidDevice":
        devs = hid.enumerate(VENDOR_ID, 0)
        if not devs:
            raise RuntimeError("No HID devices with VID 0x246C found.")
        if index < 0 or index >= len(devs):
            raise RuntimeError(f"--device index out of range (0..{len(devs)-1})")
        info = devs[index]
        path = info["path"]
        d = hid.device()
        d.open_path(path)
        try:
            d.set_nonblocking(False)
        except Exception:
            pass
        return HidDevice(
            dev=d,
            path=path,
            vendor_id=info.get("vendor_id", VENDOR_ID),
            product_id=info.get("product_id", 0),
            interface_number=info.get("interface_number", -1),
        )

    def close(self):
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
# CLI
# -------------------------
def list_devices() -> int:
    devs = HidDevice.enumerate_vid()
    if not devs:
        print("No HID devices with VID 0x246C found.")
        return 1

    for i, d in enumerate(devs):
        pid = d.get("product_id", 0)
        iface = d.get("interface_number", -1)
        up = d.get("usage_page", 0)
        u = d.get("usage", 0)
        mfg = d.get("manufacturer_string") or ""
        prod = d.get("product_string") or ""
        path = d.get("path")
        print(f"[{i}] VID={d.get('vendor_id', VENDOR_ID):04x} PID={pid:04x} iface={iface} "
              f"usage_page={up} usage={u} mfg='{mfg}' product='{prod}' path={path!r}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--list", action="store_true", help="List all HID devices with VID 0x246C and exit.")
    p.add_argument("--device", type=int, default=0, help="Device index from --list (default: 0).")
    p.add_argument("--tz", default="local", help="Timezone for time read/set (local|UTC|+01:00|+120 etc.).")
    p.add_argument("--timeout-ms", type=int, default=3000, help="HID read timeout in milliseconds.")

    # actions
    p.add_argument("--raw", action="store_true", help="Print raw frames as hex for each operation.")

    p.add_argument("--read-time", action="store_true")
    p.add_argument("--set-time-now", action="store_true")

    p.add_argument("--read-params", action="store_true")
    p.add_argument("--write-params", action="store_true")

    p.add_argument("--set-interval-s", type=int, default=None, help="Set ONLY interval seconds (reads current params first).")

    p.add_argument("--read-device-info", action="store_true")
    p.add_argument("--read-stat", action="store_true")
    p.add_argument("--read-alarm", action="store_true")

    p.add_argument("--read-records", type=int, default=None, help="Read N record chunks (best effort).")

    p.add_argument("--reset", action="store_true")

    p.add_argument("--write-sn", type=str, default=None)
    p.add_argument("--sn-mode", choices=["ascii", "hex"], default="ascii")

    p.add_argument("--self-check", action="store_true")
    p.add_argument("--key-test", action="store_true")
    p.add_argument("--led-test", action="store_true")

    # params for write-params
    p.add_argument("--start-delay", type=int, default=None)
    p.add_argument("--interval-s", type=int, default=None)
    p.add_argument("--tmax", type=float, default=None)
    p.add_argument("--tmin", type=float, default=None)
    p.add_argument("--hmax", type=float, default=None)
    p.add_argument("--hmin", type=float, default=None)

    args = p.parse_args()

    if args.list:
        return list_devices()

    dev = None
    try:
        dev = HidDevice.open_by_index(args.device)
        print(f"Using device: VID={dev.vendor_id:04x} PID={dev.product_id:04x} iface={dev.interface_number} path={dev.path!r}")

        # ---- time ----
        if args.read_time:
            cmd = cmd_read_time()
            if args.raw:
                print("read-time CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=12, timeout_ms=args.timeout_ms)
            if args.raw:
                print("read-time RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in time response")
            ts = read_u32be(resp, 7)
            print(f"time_raw: {ts}")
            print(f"time_iso({args.tz}): {device_ts_to_local_iso(ts, args.tz)}")

        if args.set_time_now:
            off = offset_minutes_from_arg(args.tz)
            ts = device_timestamp_from_now(off)
            cmd = cmd_write_time(ts)
            if args.raw:
                print("set-time CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=8, timeout_ms=args.timeout_ms)
            if args.raw:
                print("set-time RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in write-time response")
            print("status:", status_text(resp[6]))

        # ---- params ----
        if args.read_params:
            cmd = cmd_read_params()
            if args.raw:
                print("read-params CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=22, timeout_ms=args.timeout_ms)
            if args.raw:
                print("read-params RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in params response")
            start_delay, interval_s, tmax, tmin, hmax, hmin = parse_params(resp)
            print(f"start_delay_s: {start_delay}")
            print(f"interval_s:    {interval_s}")
            print(f"temp_max_c:    {tmax:.1f}")
            print(f"temp_min_c:    {tmin:.1f}")
            print(f"humi_max_rh:   {hmax:.1f}")
            print(f"humi_min_rh:   {hmin:.1f}")

        if args.set_interval_s is not None:
            # read current params first
            r = dev.send_and_receive(cmd_read_params(), expect_len=22, timeout_ms=args.timeout_ms)
            if not valid_frame(r):
                raise RuntimeError("Bad checksum reading current params")
            start_delay, _old_interval, tmax, tmin, hmax, hmin = parse_params(r)
            new_interval = int(args.set_interval_s)
            wcmd = cmd_write_params(start_delay, new_interval, tmax, tmin, hmax, hmin)
            if args.raw:
                print("write-interval CMD:", hexdump(wcmd))
            w = dev.send_and_receive(wcmd, expect_len=8, timeout_ms=args.timeout_ms)
            if args.raw:
                print("write-interval RAW:", hexdump(w))
            if not valid_frame(w):
                raise RuntimeError("Bad checksum writing params")
            print("status:", status_text(w[6]))

            # verify
            r2 = dev.send_and_receive(cmd_read_params(), expect_len=22, timeout_ms=args.timeout_ms)
            if valid_frame(r2):
                _, interval2, *_ = parse_params(r2)
                if interval2 != new_interval:
                    print(f"verify: interval clamped to {interval2} (requested {new_interval})")
                else:
                    print(f"verify: interval={interval2}")
            else:
                print("verify: failed (bad checksum)")

        if args.write_params:
            # If any are missing, try to read current and fill defaults.
            need_read = any(v is None for v in [args.start_delay, args.interval_s, args.tmax, args.tmin, args.hmax, args.hmin])
            cur = None
            if need_read:
                cur = dev.send_and_receive(cmd_read_params(), expect_len=22, timeout_ms=args.timeout_ms)
                if not valid_frame(cur):
                    raise RuntimeError("Bad checksum reading current params (needed to fill missing values)")
                c_start, c_interval, c_tmax, c_tmin, c_hmax, c_hmin = parse_params(cur)
            else:
                c_start = c_interval = 0
                c_tmax = c_tmin = 0.0
                c_hmax = c_hmin = 0.0

            start_delay = args.start_delay if args.start_delay is not None else c_start
            interval_s = args.interval_s if args.interval_s is not None else c_interval
            tmax = args.tmax if args.tmax is not None else c_tmax
            tmin = args.tmin if args.tmin is not None else c_tmin
            hmax = args.hmax if args.hmax is not None else c_hmax
            hmin = args.hmin if args.hmin is not None else c_hmin

            cmd = cmd_write_params(start_delay, interval_s, tmax, tmin, hmax, hmin)
            if args.raw:
                print("write-params CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=8, timeout_ms=args.timeout_ms)
            if args.raw:
                print("write-params RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in write-params response")
            print("status:", status_text(resp[6]))

        # ---- device info / stat / alarm ----
        if args.read_device_info:
            cmd = cmd_read_device_info()
            if args.raw:
                print("read-device-info CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=39, timeout_ms=args.timeout_ms)
            if args.raw:
                print("read-device-info RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in device-info response")
            info = parse_device_info(resp)
            print("serial_hex:", info["serial_hex"])
            print("version_hex:", info["version_hex"])
            print("record_count:", info["record_count"])
            print("start_time_raw:", info["start_ts"])
            print("start_time_iso:", device_ts_to_local_iso(info["start_ts"], args.tz))
            print("end_time_raw:", info["end_ts"])
            print("end_time_iso:", device_ts_to_local_iso(info["end_ts"], args.tz))

        if args.read_stat:
            cmd = cmd_read_stat()
            if args.raw:
                print("read-stat CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=42, timeout_ms=args.timeout_ms)
            if args.raw:
                print("read-stat RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in stat response")
            s = parse_stat(resp)
            print(f"tempAvgC: {s['tempAvgC']:.1f}")
            print(f"tempMaxC: {s['tempMaxC']:.1f} at {device_ts_to_local_iso(s['tempMaxTime'], args.tz)}")
            print(f"tempMinC: {s['tempMinC']:.1f} at {device_ts_to_local_iso(s['tempMinTime'], args.tz)}")
            print(f"tempUsefulCount: {s['tempUsefulCount']}")
            print(f"humiAvgRH: {s['humiAvgRH']:.1f}")
            print(f"humiMaxRH: {s['humiMaxRH']:.1f} at {device_ts_to_local_iso(s['humiMaxTime'], args.tz)}")
            print(f"humiMinRH: {s['humiMinRH']:.1f} at {device_ts_to_local_iso(s['humiMinTime'], args.tz)}")
            print(f"humiUsefulCount: {s['humiUsefulCount']}")
            print(f"normalCount: {s['normalCount']}")

        if args.read_alarm:
            cmd = cmd_read_alarm()
            if args.raw:
                print("read-alarm CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=40, timeout_ms=args.timeout_ms)
            if args.raw:
                print("read-alarm RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in alarm response")
            a = parse_alarm(resp)
            print(f"tempUpCount: {a['tempUpCount']} value={a['tempUpValueC']:.1f} at {device_ts_to_local_iso(a['tempUpTime'], args.tz)}")
            print(f"tempDownCount: {a['tempDownCount']} value={a['tempDownValueC']:.1f} at {device_ts_to_local_iso(a['tempDownTime'], args.tz)}")
            print(f"humiUpCount: {a['humiUpCount']} value={a['humiUpValueRH']:.1f} at {device_ts_to_local_iso(a['humiUpTime'], args.tz)}")
            print(f"humiDownCount: {a['humiDownCount']} value={a['humiDownValueRH']:.1f} at {device_ts_to_local_iso(a['humiDownTime'], args.tz)}")

        # ---- records ----
        if args.read_records is not None:
            n = int(args.read_records)
            if n <= 0:
                raise ValueError("--read-records N must be > 0")
            cmd = cmd_read_record(n)
            if args.raw:
                print("read-records CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=16 * n, timeout_ms=max(args.timeout_ms, 6000))
            if args.raw:
                print("read-records RAW(first 256b):", hexdump(resp[:256]) + (" ..." if len(resp) > 256 else ""))
            good = 0
            for i in range(n):
                chunk = resp[i * 16:(i + 1) * 16]
                rec = parse_record_chunk(chunk)
                if not rec:
                    continue
                ts, tc, hr = rec
                print(f"[{i:04d}] {device_ts_to_local_iso(ts, args.tz)}  temp={tc:.1f}C  humi={hr:.1f}%RH  raw_ts={ts}")
                good += 1
            print(f"records_valid: {good}/{n}")

        # ---- reset ----
        if args.reset:
            cmd = cmd_reset()
            if args.raw:
                print("reset CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=8, timeout_ms=args.timeout_ms)
            if args.raw:
                print("reset RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in reset response")
            print("status:", status_text(resp[6]))

        # ---- write SN ----
        if args.write_sn is not None:
            ascii_mode = (args.sn_mode == "ascii")
            cmd = cmd_write_sn(args.write_sn, ascii_mode)
            if args.raw:
                print("write-sn CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=8, timeout_ms=args.timeout_ms)
            if args.raw:
                print("write-sn RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in write-sn response")
            print("status:", status_text(resp[6]))

        # ---- tests ----
        if args.self_check:
            cmd = cmd_self_check()
            if args.raw:
                print("self-check CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=8, timeout_ms=args.timeout_ms)
            if args.raw:
                print("self-check RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in self-check response")
            code, msg = parse_self_check(resp)
            print(f"self_check: {'success' if code == 0 else 'failed'} (code={code}) — {msg}")

        if args.key_test:
            cmd = cmd_key_test()
            if args.raw:
                print("key-test CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=8, timeout_ms=args.timeout_ms)
            if args.raw:
                print("key-test RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in key-test response")
            ok, key = parse_key_test(resp)
            print(f"key_test: {'success' if ok else 'failed'} — {key}")

        if args.led_test:
            cmd = cmd_led_test()
            if args.raw:
                print("led-test CMD:", hexdump(cmd))
            resp = dev.send_and_receive(cmd, expect_len=8, timeout_ms=args.timeout_ms)
            if args.raw:
                print("led-test RAW:", hexdump(resp))
            if not valid_frame(resp):
                raise RuntimeError("Bad checksum in led-test response")
            print("led_test: success (response received)")

        # if no operations requested
        any_ops = any([
            args.read_time, args.set_time_now,
            args.read_params, args.write_params, args.set_interval_s is not None,
            args.read_device_info, args.read_stat, args.read_alarm,
            args.read_records is not None,
            args.reset,
            args.write_sn is not None,
            args.self_check, args.key_test, args.led_test,
        ])
        if not any_ops:
            print("No operation selected. Use --list and/or one of the --read/--write flags.")
            return 2

        return 0

    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        return 1
    finally:
        if dev:
            dev.close()


if __name__ == "__main__":
    raise SystemExit(main())
