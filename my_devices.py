#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
外设电量 — 达尔优 AE6 V2 定版
1. 修复 64 位 ctypes 句柄截断导致的托盘图标创建失败问题
2. 修复字节偏移：rep[5] 为充电状态(02)，rep[6] 为电量(0x5F=95%)
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import dataclasses
import math
import os
import subprocess
import sys
import threading
import time
from typing import Optional

UI_SCALE = 1.0

# ===========================================================================
# Win32 API 基础签名与 64 位指针安全声明
# ===========================================================================
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
hid = ctypes.WinDLL("hid", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

INVALID_HANDLE_VALUE = wt.HANDLE(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_RW = 0x00000001 | 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
ERROR_IO_PENDING = 997
WAIT_TIMEOUT = 0x102

kernel32.CreateFileW.restype = wt.HANDLE
kernel32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.CreateEventW.restype = wt.HANDLE
kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
kernel32.GetOverlappedResult.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL]
kernel32.CancelIoEx.argtypes = [wt.HANDLE, ctypes.c_void_p]
kernel32.GetModuleHandleW.restype = wt.HMODULE
kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
user32.PostQuitMessage.argtypes = [ctypes.c_int]

class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD), ("Data4", ctypes.c_ubyte * 8)]
    def __init__(self, s: str = ""):
        super().__init__()
        s = (s or "{00000000-0000-0000-0000-000000000000}").strip().strip("{}")
        parts = s.split("-", 3)
        self.Data1 = int(parts[0], 16)
        self.Data2 = int(parts[1], 16)
        self.Data3 = int(parts[2], 16)
        rest = bytes.fromhex(parts[3].replace("-", ""))
        for i in range(8):
            self.Data4[i] = rest[i]

class HIDD_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Size", wt.ULONG), ("VendorID", wt.USHORT), ("ProductID", wt.USHORT), ("VersionNumber", wt.USHORT)]

class HIDP_CAPS(ctypes.Structure):
    _fields_ = [
        ("Usage", wt.USHORT), ("UsagePage", wt.USHORT),
        ("InputReportByteLength", wt.USHORT), ("OutputReportByteLength", wt.USHORT),
        ("FeatureReportByteLength", wt.USHORT), ("Reserved", wt.USHORT * 17),
        ("NumberLinkCollectionNodes", wt.USHORT), ("NumberInputButtonCaps", wt.USHORT),
        ("NumberInputValueCaps", wt.USHORT), ("NumberInputDataIndices", wt.USHORT),
        ("NumberOutputButtonCaps", wt.USHORT), ("NumberOutputValueCaps", wt.USHORT),
        ("NumberOutputDataIndices", wt.USHORT), ("NumberFeatureButtonCaps", wt.USHORT),
        ("NumberFeatureValueCaps", wt.USHORT), ("NumberFeatureDataIndices", wt.USHORT),
    ]

class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("InterfaceClassGuid", GUID), ("Flags", wt.DWORD), ("Reserved", ctypes.c_void_p)]

setupapi.SetupDiGetClassDevsW.restype = wt.HANDLE
setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), wt.LPCWSTR, wt.HWND, wt.DWORD]
setupapi.SetupDiEnumDeviceInterfaces.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(GUID), wt.DWORD, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]
setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [wt.HANDLE, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wt.HANDLE]

hid.HidD_GetAttributes.argtypes = [wt.HANDLE, ctypes.POINTER(HIDD_ATTRIBUTES)]
hid.HidD_GetPreparsedData.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(HIDP_CAPS)]

GUID_DEVINTERFACE_HID = GUID("{4D1E55B2-F16F-11CF-88CB-001111000030}")

@dataclasses.dataclass
class HidIface:
    path: str
    vid: int
    pid: int
    usage_page: int
    usage: int
    input_len: int
    output_len: int

def _open_path(path: str, access: int, overlapped: bool = False) -> int:
    flags = FILE_FLAG_OVERLAPPED if overlapped else 0
    return kernel32.CreateFileW(path, access, FILE_SHARE_RW, None, OPEN_EXISTING, flags, None)

def enumerate_hid() -> list[HidIface]:
    hdev = setupapi.SetupDiGetClassDevsW(ctypes.byref(GUID_DEVINTERFACE_HID), None, None, 0x12)
    if hdev == INVALID_HANDLE_VALUE or not hdev:
        return []
    out: list[HidIface] = []
    try:
        idx = 0
        while True:
            did = SP_DEVICE_INTERFACE_DATA()
            did.cbSize = ctypes.sizeof(did)
            if not setupapi.SetupDiEnumDeviceInterfaces(hdev, None, ctypes.byref(GUID_DEVINTERFACE_HID), idx, ctypes.byref(did)):
                break
            idx += 1
            need = wt.DWORD(0)
            setupapi.SetupDiGetDeviceInterfaceDetailW(hdev, ctypes.byref(did), None, 0, ctypes.byref(need), None)
            if not need.value:
                continue
            buf = ctypes.create_string_buffer(need.value)
            ctypes.cast(buf, ctypes.POINTER(wt.DWORD))[0] = 8
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(hdev, ctypes.byref(did), buf, need.value, ctypes.byref(need), None):
                continue
            path = ctypes.wstring_at(ctypes.addressof(buf) + 4)
            h = _open_path(path, 0)
            if not h or h == INVALID_HANDLE_VALUE:
                continue
            try:
                attrs = HIDD_ATTRIBUTES()
                attrs.Size = ctypes.sizeof(attrs)
                hid.HidD_GetAttributes(h, ctypes.byref(attrs))
                caps = HIDP_CAPS()
                pp = ctypes.c_void_p()
                if hid.HidD_GetPreparsedData(h, ctypes.byref(pp)):
                    hid.HidP_GetCaps(pp, ctypes.byref(caps))
                    hid.HidD_FreePreparsedData(pp)
                out.append(HidIface(
                    path=path, vid=attrs.VendorID, pid=attrs.ProductID,
                    usage_page=caps.UsagePage, usage=caps.Usage,
                    input_len=caps.InputReportByteLength,
                    output_len=caps.OutputReportByteLength))
            finally:
                kernel32.CloseHandle(h)
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(hdev)
    return out

class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p), ("Offset", wt.DWORD), ("OffsetHigh", wt.DWORD), ("hEvent", wt.HANDLE)]

class HidDevice:
    def __init__(self, path: str, write: bool = False):
        self.path = path
        access = GENERIC_READ | (GENERIC_WRITE if write else 0)
        self.h = _open_path(path, access)
        self.rh = _open_path(path, GENERIC_READ, overlapped=True)

    def close(self):
        for handle in (self.rh, self.h):
            if handle and handle != INVALID_HANDLE_VALUE:
                kernel32.CloseHandle(handle)
        self.rh = 0
        self.h = 0

    def write_output(self, data: bytes) -> int:
        if not self.h or self.h == INVALID_HANDLE_VALUE:
            return 0
        buf = ctypes.create_string_buffer(data, len(data))
        written = wt.DWORD(0)
        ok = kernel32.WriteFile(self.h, buf, len(data), ctypes.byref(written), None)
        return written.value if ok else 0

    def read_input(self, length: int, timeout_ms: int = 150) -> Optional[bytes]:
        if not self.rh or self.rh == INVALID_HANDLE_VALUE:
            return None
        ev = kernel32.CreateEventW(None, True, False, None)
        if not ev:
            return None
        try:
            ov = OVERLAPPED()
            ov.hEvent = ev
            buf = ctypes.create_string_buffer(length)
            got = wt.DWORD(0)
            ok = kernel32.ReadFile(self.rh, buf, length, ctypes.byref(got), ctypes.byref(ov))
            if not ok and ctypes.get_last_error() != ERROR_IO_PENDING:
                return None
            if kernel32.WaitForSingleObject(ev, timeout_ms) == WAIT_TIMEOUT:
                kernel32.CancelIoEx(self.rh, ctypes.byref(ov))
                return None
            kernel32.GetOverlappedResult(self.rh, ctypes.byref(ov), ctypes.byref(got), False)
            return bytes(buf.raw[:got.value])
        finally:
            kernel32.CloseHandle(ev)

@dataclasses.dataclass
class Reading:
    ok: bool = False
    level: Optional[int] = None
    status: str = "unknown"
    source: str = ""
    detail: str = ""
    name: str = ""
    ts: float = dataclasses.field(default_factory=time.time)
    present: bool = True
    vid: int = 0
    pid: int = 0

STATUS_TEXT = {"charging": "充电中 ⚡", "discharging": "放电中", "full": "已充满 ⚡", "wired": "有线直连 ⚡", "unknown": "使用中"}

# ===========================================================================
# 达尔优通信逻辑（精确对齐：rep[5] 为充电状态，rep[6] 为电量）
# ===========================================================================
def dareu_read(ifaces: list[HidIface]) -> Optional[Reading]:
    cands = [d for d in ifaces if d.vid == 0x260D and d.pid in (0x1261, 0x1260, 0x04ED)]
    if not cands:
        return None

    target_ifaces = [d for d in cands if d.usage_page == 0xFF02]
    if not target_ifaces:
        target_ifaces = [d for d in cands if d.usage_page != 0x01] or cands

    for d in target_ifaces:
        dev = None
        try:
            dev = HidDevice(d.path, write=True)

            out_len = d.output_len if d.output_len > 0 else 17
            req = bytearray(out_len)
            req[0] = 0x08
            req[1] = 0x04
            if out_len == 17:
                s = sum(req[:16])
                req[16] = (0x55 - (s & 0xFF)) & 0xFF

            dev.write_output(bytes(req))

            deadline = time.monotonic() + 0.35
            while time.monotonic() < deadline:
                in_len = max(d.input_len, 17)
                rep = dev.read_input(in_len, 80)
                if not rep or len(rep) < 7:
                    continue

                if rep[0] == 0x08 and rep[1] == 0x04:
                    # rep[5] 为状态：0x02 代表插线充电中
                    is_charging = (rep[5] in (1, 2)) or (len(rep) > 7 and rep[7] != 0) or (d.pid == 0x1260)
                    # rep[6] 为电量百分比：0x5F = 95%
                    bat = rep[6]

                    if 0 <= bat <= 100:
                        if is_charging:
                            status = "full" if bat >= 100 else "charging"
                            detail_str = "已充满 ⚡" if bat >= 100 else f"电量 {bat}% · 充电中 ⚡"
                        else:
                            status = "discharging"
                            detail_str = f"电量 {bat}% · 放电中"

                        return Reading(ok=True, level=bat, status=status,
                                       name="达尔优 AE6 V2", source="达尔优原厂协议",
                                       detail=detail_str, vid=d.vid, pid=d.pid, present=True)
        except Exception:
            pass
        finally:
            if dev:
                dev.close()

    return Reading(ok=False, name="达尔优 AE6 V2", source="达尔优协议",
                   detail="接收器已连接，等待鼠标唤醒", vid=0x260D, pid=0x1261, present=True)

def read_mouse(ifaces: list[HidIface]) -> Reading:
    r_dareu = dareu_read(ifaces)
    if r_dareu:
        return r_dareu
    return Reading(ok=False, name="达尔优 AE6 V2", source="", present=False, detail="未检测到达尔优无线鼠标")

# ===========================================================================
# 图标绘制（修正 64 位 GDI 句柄类型）
# ===========================================================================
class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
                ("biPlanes", wt.WORD), ("biBitCount", wt.WORD),
                ("biCompression", wt.DWORD), ("biSizeImage", wt.DWORD),
                ("biXPelsPerMeter", wt.LONG), ("biYPelsPerMeter", wt.LONG),
                ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD)]

class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]

class ICONINFO(ctypes.Structure):
    _fields_ = [("fIcon", wt.BOOL), ("xHotspot", wt.DWORD),
                ("yHotspot", wt.DWORD), ("hbmMask", wt.HBITMAP), ("hbmColor", wt.HBITMAP)]

user32.GetDC.argtypes = [wt.HWND]
user32.GetDC.restype = wt.HDC
user32.ReleaseDC.argtypes = [wt.HWND, wt.HDC]
user32.ReleaseDC.restype = ctypes.c_int
gdi32.CreateCompatibleDC.argtypes = [wt.HDC]
gdi32.CreateCompatibleDC.restype = wt.HDC
gdi32.CreateDIBSection.argtypes = [wt.HDC, ctypes.POINTER(BITMAPINFO), wt.UINT,
                                   ctypes.POINTER(ctypes.c_void_p), wt.HANDLE, wt.DWORD]
gdi32.CreateDIBSection.
