# Mesavss/Seven-MS Temperature-Logger-Tools

A small cross-platform tool to configure Mesavss USB temperature/humidity data loggers (and related Mesavss devices) that expose a HID interface under **Vendor ID `0x246C`**.

This repository contains:

- **GUI (Tkinter)** for comfortable configuration (time, interval, thresholds, etc.)
- **CLI** for scripting and debugging (read/write config, device info, stats, alarms, tests, records)

The implementation is based on reverse-engineering the vendor’s WebHID application/protocol frames and is therefore **best-effort**: not every Mesavss device necessarily supports every command.

---

## Disclaimer (No Warranty / No Liability)

This software is provided **as-is**, **without any warranty**, and **without any guarantee of functionality**, merchantability, fitness for a particular purpose, or non-infringement.

It is shared **without any liability or obligation** from **heise Medien / c’t** (including editors, employees, contractors, or contributors). Use at your own risk.

**You are responsible** for verifying results and ensuring safe operation of your device(s). Some functions (e.g. reset/clear records) can irreversibly modify device state.

---

## AI Assistance Notice

Large parts of this software and/or documentation were created with the help of **AI**.  
Please review the code carefully before relying on it in production or safety-relevant contexts.

---

## Supported Devices

- Likely any MesaVSS/SevenMS Temperature logger that presents as USB HID device with **Vendor ID `0x246C`**
- Known working example: SLOG-30

Because different models may expose different HID interfaces (or different protocol variants), this tool:

- enumerates *all* HID interfaces under VID `0x246C`
- lets you select a device by index (CLI) or dropdown (GUI)
- tries commands best-effort and reports timeouts/checksum issues cleanly

---

## Features

### GUI

- Enumerate and select Mesavss HID devices (VID `0x246C`)
- Auto-read configuration on connect (if supported)
- Manual “Read config” button stays available
- Configure:
  - start delay
  - interval (seconds or minutes)
  - temperature min/max
  - humidity min/max
- Read/set device time (timezone-offset aware)
- Read:
  - device info
  - statistics
  - alarm summary
  - records (best effort)
- Diagnostic/test actions (may vary by device):
  - self-check
  - key test
  - LED test
  - write serial number (SN)

### CLI

- List all Mesavss HID devices (VID `0x246C`)
- Read/write config, set interval only
- Read/set device time
- Read device info, stats, alarms
- Read record chunks (best effort)
- Reset/clear records (dangerous)
- Diagnostic/test commands

---

## Installation

### Requirements

- Python 3.9+ (recommended)
- `hid` (hidapi wrapper)
- Tkinter (usually included with Python on Windows/macOS; on some Linux distros you must install it separately)

### Install dependencies

```bash
python3 -m pip install --upgrade pip
python3 -m pip install hid
```

If your platform has trouble with `hid`, try also installing `hidapi`:

```bash
python3 -m pip install hidapi
python3 -m pip install hid
```

---

## Linux: udev rules (no sudo needed)

On Linux, HID devices often appear as `/dev/hidraw*` and may require special permissions.

### 1) Create a udev rule

Create a file:

```bash
sudo nano /etc/udev/rules.d/99-mesavss-hid.rules
```

Put the following content inside:

```udev
# Mesavss HID devices (VID 0x246C): allow plugdev users to access hidraw nodes
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="246c", MODE="0660", GROUP="plugdev"
```

Notes:

- This grants access to users in the `plugdev` group.
- If your distro uses a different group convention, you can replace `plugdev` with e.g. `input` or `users`.

### 2) Add your user to the group

```bash
sudo usermod -aG plugdev "$USER"
```

Log out and log back in (or reboot) so the group membership becomes active.

### 3) Reload udev rules

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### 4) Verify permissions

Plug the device in and check which hidraw node belongs to it:

```bash
lsusb -d 246c:
ls -l /dev/hidraw*
```

If the rule matches, the device node should have group `plugdev` and mode `rw` for that group.

---

## Usage

### CLI

List devices:

```bash
python3 mesavss_cli.py --list
```

Example output:

```
[0] VID=246c PID=2022 iface=0 usage_page=0 usage=0 ... path=b'1-1.4:1.0'
[1] ...
```

Read configuration from device 0:

```bash
python3 mesavss_cli.py --device 0 --read-params
```

Set device time to “now” (using local timezone offset):

```bash
python3 mesavss_cli.py --device 0 --set-time-now --tz local
```

Set interval only (seconds), keeping other parameters unchanged:

```bash
python3 mesavss_cli.py --device 0 --set-interval-s 120
```

Read device info / stats / alarms:

```bash
python3 mesavss_cli.py --device 0 --read-device-info
python3 mesavss_cli.py --device 0 --read-stat
python3 mesavss_cli.py --device 0 --read-alarm
```

Read records (best effort):

```bash
python3 mesavss_cli.py --device 0 --read-records 100
```

Show raw frames (debugging):

```bash
python3 mesavss_cli.py --device 0 --read-params --raw
```

Warning: Reset clears records and may be irreversible:

```bash
python3 mesavss_cli.py --device 0 --reset
```

### GUI

Start the GUI:

```bash
python3 mesavss_gui.py
```

- Select the device from the dropdown
- Click **Connect**
- Configuration is auto-read on connect if supported
- Use **Read config** to re-read manually
- Use **Write full config** to apply settings

---

## Timezone Handling (Important)

Many Mesavss devices store timestamps as “device epoch seconds” plus an implicit offset.  
This tool uses the `--tz` / GUI “TZ” field to interpret and write time consistently.

Examples:

- `local` — uses your OS timezone offset
- `UTC` — offset 0
- `+01:00` / `-05:00` — explicit offsets
- `+120` — offset in minutes

If your CSV/PDF report shows a wrong timezone label but the timestamps are correct, the device (or report generator) may be hard-coded to display a fixed label. In that case, setting time correctly still matters, but the displayed label might not change.

---

## Known Limitations

- Not all Mesavss devices support all commands.
- Some devices expose multiple HID interfaces; only one may respond to the logger protocol.
- Record reading is “best effort” and assumes 16-byte record frames. Some models may differ.
- “Write SN”, tests, and reset behavior vary by device.

---

## Security / Safety Notes

- This tool communicates directly with HID interfaces.
- Use the **reset/clear** function only if you understand the consequences.
- Always verify settings by re-reading configuration after writing.

---

## License

Add your license here (e.g. MIT). If you don’t have one yet, GitHub’s license picker can help.

---

## Acknowledgements

- Reverse-engineered protocol structure inspired by the vendor’s WebHID implementation.
- Implementation and docs created with substantial assistance from AI.
