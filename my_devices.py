#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
外设电量 — Windows 10/11 无线外设电量托盘工具
纯标准库 + ctypes + tkinter，零第三方依赖
已集成：达尔优 AE6 V2 无线鼠标 WebHID 原厂驱动协议
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import ctypes.wintypes as w
import dataclasses
import json
import math
import os
import struct
import subprocess
import sys
import tempfile
import queue
import random
import threading
import time
from typing import Optional

UI_SCALE = 1.0


# ===========================================================================
# Win32 基础
# ===========================================================================
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
hid = ctypes.WinDLL("hid", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
ole32 = ctypes.WinDLL("ole32", use_last_error=True)
dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
imm32 = ctypes.WinDLL("imm32", use_last_error=True)

INVALID_HANDLE_VALUE = wt.HANDLE(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_RW = 0x00000001 | 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
ERROR_IO_PENDING = 997
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102

kernel32.CreateFileW.restype = wt.HANDLE
kernel32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                 wt.DWORD, wt.DWORD, wt.HANDLE]
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                               ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                              ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.CreateEventW.restype = wt.HANDLE
kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
kernel32.GetOverlappedResult.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                         ctypes.POINTER(wt.DWORD), wt.BOOL]
kernel32.CancelIoEx.argtypes = [wt.HANDLE, ctypes.c_void_p]
kernel32.ResetEvent.argtypes = [wt.HANDLE]
user32.SetTimer.argtypes = [wt.HWND, wt.UINT, wt.UINT, ctypes.c_void_p]
user32.SetTimer.restype = ctypes.c_size_t
user32.KillTimer.argtypes = [wt.HWND, wt.UINT]
user32.GetClassLongPtrW.argtypes = [wt.HWND, ctypes.c_int]
user32.GetClassLongPtrW.restype = ctypes.c_size_t
user32.SetClassLongPtrW.argtypes = [wt.HWND, ctypes.c_int, ctypes.c_size_t]
user32.SetClassLongPtrW.restype = ctypes.c_size_t
dwmapi.DwmSetWindowAttribute.argtypes = [wt.HWND, wt.DWORD, ctypes.c_void_p, wt.DWORD]
kernel32.GetModuleHandleW.restype = wt.HMODULE
kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
kernel32.CreateMutexW.restype = wt.HANDLE
kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.LPCWSTR]
user32.PostQuitMessage.argtypes = [ctypes.c_int]
kernel32.GlobalAlloc.restype = wt.HGLOBAL
kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
kernel32.GlobalFree.argtypes = [wt.HGLOBAL]


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                ("Data4", ctypes.c_ubyte * 8)]

    def __init__(self, s: str = ""):
        super().__init__()
        self.parse(s or "{00000000-0000-0000-0000-000000000000}")

    def parse(self, s: str):
        s = s.strip().strip("{}")
        parts = s.split("-", 3)
        self.Data1 = int(parts[0], 16)
        self.Data2 = int(parts[1], 16)
        self.Data3 = int(parts[2], 16)
        rest = bytes.fromhex(parts[3].replace("-", ""))
        for i in range(8):
            self.Data4[i] = rest[i]

    def as_str(self) -> str:
        return ("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
                % (self.Data1, self.Data2, self.Data3,
                   self.Data4[0], self.Data4[1], self.Data4[2], self.Data4[3],
                   self.Data4[4], self.Data4[5], self.Data4[6], self.Data4[7]))


class HIDD_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Size", wt.ULONG), ("VendorID", wt.USHORT),
                ("ProductID", wt.USHORT), ("VersionNumber", wt.USHORT)]


class HIDP_CAPS(ctypes.Structure):
    _fields_ = [
        ("Usage", wt.USHORT), ("UsagePage", wt.USHORT),
        ("InputReportByteLength", wt.USHORT),
        ("OutputReportByteLength", wt.USHORT),
        ("FeatureReportByteLength", wt.USHORT),
        ("Reserved", wt.USHORT * 17),
        ("NumberLinkCollectionNodes", wt.USHORT),
        ("NumberInputButtonCaps", wt.USHORT),
        ("NumberInputValueCaps", wt.USHORT),
        ("NumberInputDataIndices", wt.USHORT),
        ("NumberOutputButtonCaps", wt.USHORT),
        ("NumberOutputValueCaps", wt.USHORT),
        ("NumberOutputDataIndices", wt.USHORT),
        ("NumberFeatureButtonCaps", wt.USHORT),
        ("NumberFeatureValueCaps", wt.USHORT),
        ("NumberFeatureDataIndices", wt.USHORT),
    ]


class HIDP_RANGE(ctypes.Structure):
    _fields_ = [("UsageMin", wt.USHORT), ("UsageMax", wt.USHORT),
                ("StringMin", wt.USHORT), ("StringMax", wt.USHORT),
                ("DesignatorMin", wt.USHORT), ("DesignatorMax", wt.USHORT),
                ("DataIndexMin", wt.USHORT), ("DataIndexMax", wt.USHORT)]


class HIDP_NOTRANGE(ctypes.Structure):
    _fields_ = [("Usage", wt.USHORT), ("Reserved1", wt.USHORT),
                ("StringIndex", wt.USHORT), ("Reserved2", wt.USHORT),
                ("DesignatorIndex", wt.USHORT), ("Reserved3", wt.USHORT),
                ("DataIndex", wt.USHORT), ("Reserved4", wt.USHORT)]


class HIDP_UNION(ctypes.Union):
    _fields_ = [("Range", HIDP_RANGE), ("NotRange", HIDP_NOTRANGE)]


class HIDP_VALUE_CAPS(ctypes.Structure):
    _fields_ = [
        ("UsagePage", wt.USHORT), ("ReportID", ctypes.c_ubyte),
        ("IsAlias", ctypes.c_ubyte), ("BitField", wt.USHORT),
        ("LinkCollection", wt.USHORT), ("LinkUsage", wt.USHORT),
        ("LinkUsagePage", wt.USHORT), ("IsRange", ctypes.c_ubyte),
        ("IsStringRange", ctypes.c_ubyte), ("IsDesignatorRange", ctypes.c_ubyte),
        ("IsAbsolute", ctypes.c_ubyte), ("HasNull", ctypes.c_ubyte),
        ("Reserved", ctypes.c_ubyte), ("BitSize", wt.USHORT),
        ("ReportCount", wt.USHORT), ("Reserved2", wt.USHORT * 5),
        ("UnitsExp", wt.ULONG), ("Units", wt.ULONG),
        ("LogicalMin", wt.LONG), ("LogicalMax", wt.LONG),
        ("PhysicalMin", wt.LONG), ("PhysicalMax", wt.LONG),
        ("u", HIDP_UNION),
    ]


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("InterfaceClassGuid", GUID),
                ("Flags", wt.DWORD), ("Reserved", ctypes.c_void_p)]


setupapi.SetupDiGetClassDevsW.restype = wt.HANDLE
setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), wt.LPCWSTR,
                                          wt.HWND, wt.DWORD]
setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(GUID), wt.DWORD,
    ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]
setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
    wt.HANDLE, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.c_void_p,
    wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wt.HANDLE]
setupapi.SetupDiGetDeviceInstanceIdW.argtypes = [
    wt.HANDLE, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), wt.LPWSTR, wt.DWORD,
    ctypes.POINTER(wt.DWORD)]

hid.HidD_GetAttributes.argtypes = [wt.HANDLE, ctypes.POINTER(HIDD_ATTRIBUTES)]
hid.HidD_GetPreparsedData.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(HIDP_CAPS)]
hid.HidD_GetProductString.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.ULONG]
hid.HidD_GetManufacturerString.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.ULONG]
hid.HidD_GetFeature.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.ULONG]
hid.HidD_SetFeature.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.ULONG]
hid.HidD_SetOutputReport.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.ULONG]
hid.HidP_GetValueCaps.argtypes = [ctypes.c_int, ctypes.POINTER(HIDP_VALUE_CAPS),
                                  ctypes.POINTER(wt.USHORT), ctypes.c_void_p]
hid.HidP_GetUsageValue.argtypes = [ctypes.c_int, wt.USHORT, wt.USHORT, wt.USHORT,
                                   ctypes.POINTER(wt.ULONG), ctypes.c_void_p,
                                   ctypes.POINTER(HIDP_VALUE_CAPS), ctypes.c_void_p]

GUID_DEVINTERFACE_HID = GUID("{4D1E55B2-F16F-11CF-88CB-001111000030}")
DIGCF_PRESENT = 0x02
DIGCF_DEVICEINTERFACE = 0x10

HIDP_INPUT = 0
HIDP_OUTPUT = 1
HIDP_FEATURE = 2

# ===========================================================================
# HID 枚举与接口抽象
# ===========================================================================


@dataclasses.dataclass
class HidIface:
    path: str
    vid: int
    pid: int
    usage_page: int
    usage: int
    input_len: int
    output_len: int
    feature_len: int
    product: str = ""
    manufacturer: str = ""
    instance: str = ""

    @property
    def label(self) -> str:
        return (f"{self.vid:04X}:{self.pid:04X} "
                f"UP={self.usage_page:04X} U={self.usage:04X} "
                f"in={self.input_len} out={self.output_len} feat={self.feature_len}")


def _open_path(path: str, access: int, overlapped: bool = False) -> int:
    flags = FILE_FLAG_OVERLAPPED if overlapped else 0
    return kernel32.CreateFileW(path, access, FILE_SHARE_RW, None,
                                OPEN_EXISTING, flags, None)


def enumerate_hid() -> list[HidIface]:
    hdev = setupapi.SetupDiGetClassDevsW(
        ctypes.byref(GUID_DEVINTERFACE_HID), None, None,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if hdev == INVALID_HANDLE_VALUE or not hdev:
        return []
    out: list[HidIface] = []
    try:
        idx = 0
        while True:
            did = SP_DEVICE_INTERFACE_DATA()
            did.cbSize = ctypes.sizeof(did)
            if not setupapi.SetupDiEnumDeviceInterfaces(
                    hdev, None, ctypes.byref(GUID_DEVINTERFACE_HID), idx,
                    ctypes.byref(did)):
                break
            idx += 1
            need = wt.DWORD(0)
            setupapi.SetupDiGetDeviceInterfaceDetailW(
                hdev, ctypes.byref(did), None, 0, ctypes.byref(need), None)
            if not need.value:
                continue
            buf = ctypes.create_string_buffer(need.value)
            ctypes.cast(buf, ctypes.POINTER(wt.DWORD))[0] = 8
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(
                    hdev, ctypes.byref(did), buf, need.value,
                    ctypes.byref(need), None):
                continue
            path = ctypes.wstring_at(ctypes.addressof(buf) + 4)
            inst = ctypes.create_unicode_buffer(512)
            inst_len = wt.DWORD(0)
            setupapi.SetupDiGetDeviceInstanceIdW(
                hdev, ctypes.byref(did), inst, 512, ctypes.byref(inst_len))

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
                prod = ctypes.create_unicode_buffer(256)
                hid.HidD_GetProductString(h, prod, 512)
                manu = ctypes.create_unicode_buffer(256)
                hid.HidD_GetManufacturerString(h, manu, 512)
                out.append(HidIface(
                    path=path, vid=attrs.VendorID, pid=attrs.ProductID,
                    usage_page=caps.UsagePage, usage=caps.Usage,
                    input_len=caps.InputReportByteLength,
                    output_len=caps.OutputReportByteLength,
                    feature_len=caps.FeatureReportByteLength,
                    product=prod.value, manufacturer=manu.value,
                    instance=inst.value))
            finally:
                kernel32.CloseHandle(h)
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(hdev)
    return out


class HidError(Exception):
    pass


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wt.DWORD), ("OffsetHigh", wt.DWORD),
                ("hEvent", wt.HANDLE)]


class HidDevice:
    """真正的多句柄安全接口，杜绝任何并发阻塞崩溃"""

    def __init__(self, path: str, write: bool = False):
        self.path = path
        self.write_mode = write
        self.h = 0
        self.rh = 0
        access = GENERIC_READ | (GENERIC_WRITE if write else 0)
        self.h = _open_path(path, access)
        if not self.h or self.h == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            if write:
                self.h = _open_path(path, 0)
            if not self.h or self.h == INVALID_HANDLE_VALUE:
                raise HidError(f"打开接口失败（错误码 {err}）")
            self.write_mode = False
        self.rh = _open_path(path, GENERIC_READ, overlapped=True)
        if not self.rh or self.rh == INVALID_HANDLE_VALUE:
            self.rh = 0

    def close(self):
        for h in (self.rh, self.h):
            if h and h != INVALID_HANDLE_VALUE:
                kernel32.CloseHandle(h)
        self.rh = 0
        self.h = 0

    def write_output(self, data: bytes) -> int:
        buf = ctypes.create_string_buffer(data, len(data))
        written = wt.DWORD(0)
        ok = kernel32.WriteFile(self.h, buf, len(data),
                                ctypes.byref(written), None)
        if not ok:
            raise HidError(f"写入失败（错误码 {ctypes.get_last_error()}）")
        return written.value

    def read_input(self, length: int, timeout_ms: int = 800) -> Optional[bytes]:
        if not self.rh:
            return None
        ev = kernel32.CreateEventW(None, True, False, None)
        if not ev:
            return None
        try:
            ov = OVERLAPPED()
            ov.hEvent = ev
            buf = ctypes.create_string_buffer(length)
            got = wt.DWORD(0)
            ok = kernel32.ReadFile(self.rh, buf, length,
                                   ctypes.byref(got), ctypes.byref(ov))
            if not ok and ctypes.get_last_error() != ERROR_IO_PENDING:
                return None
            if kernel32.WaitForSingleObject(ev, timeout_ms) == WAIT_TIMEOUT:
                kernel32.CancelIoEx(self.rh, ctypes.byref(ov))
                return None
            kernel32.GetOverlappedResult(self.rh, ctypes.byref(ov),
                                         ctypes.byref(got), False)
            return bytes(buf.raw[:got.value])
        finally:
            kernel32.CloseHandle(ev)

    def get_feature(self, length: int) -> Optional[bytes]:
        buf = ctypes.create_string_buffer(length)
        if hid.HidD_GetFeature(self.h, buf, length):
            return bytes(buf.raw[:length])
        return None

    def get_feature_report(self, report_id: int, length: int) -> Optional[bytes]:
        buf = ctypes.create_string_buffer(length)
        ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))[0] = report_id & 0xFF
        if hid.HidD_GetFeature(self.h, buf, length):
            return bytes(buf.raw[:length])
        return None

    def set_feature(self, data: bytes) -> bool:
        buf = ctypes.create_string_buffer(data, len(data))
        return bool(hid.HidD_SetFeature(self.h, buf, len(data)))

    def set_output_report(self, data: bytes) -> bool:
        buf = ctypes.create_string_buffer(data, len(data))
        return bool(hid.HidD_SetOutputReport(self.h, buf, len(data)))

    def drain(self):
        while self.rh and self.read_input(256, 15):
            pass

    def value_caps(self, kind: int) -> list[HIDP_VALUE_CAPS]:
        pp = ctypes.c_void_p()
        if not hid.HidD_GetPreparsedData(self.h, ctypes.byref(pp)):
            return []
        try:
            n = wt.USHORT(0)
            hid.HidP_GetValueCaps(kind, None, ctypes.byref(n), pp)
            if not n.value:
                return []
            arr = (HIDP_VALUE_CAPS * n.value)()
            if not hid.HidP_GetValueCaps(kind, arr, ctypes.byref(n), pp):
                return []
            return list(arr[:n.value])
        finally:
            hid.HidD_FreePreparsedData(pp)

    def usage_value(self, kind: int, report: bytes,
                    cap: HIDP_VALUE_CAPS) -> Optional[int]:
        pp = ctypes.c_void_p()
        if not hid.HidD_GetPreparsedData(self.h, ctypes.byref(pp)):
            return None
        try:
            val = wt.ULONG(0)
            buf = ctypes.create_string_buffer(report, len(report))
            usage = (cap.u.NotRange.Usage if not cap.IsRange
                     else cap.u.Range.UsageMin)
            ok = hid.HidP_GetUsageValue(kind, cap.UsagePage, cap.LinkCollection,
                                        usage, ctypes.byref(val),
                                        pp, ctypes.byref(cap), buf)
            return val.value if ok else None
        finally:
            hid.HidD_FreePreparsedData(pp)


# ===========================================================================
# 协议：CRC / JL_RCSP / ATK
# ===========================================================================
def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def build_jl_frame(seq: int, payload: bytes, report_id: int = 0x00,
                   include_zero: bool = True, ch: int = 0x10,
                   sub: int = 0x02, total: int = 64) -> bytes:
    f = bytearray(total)
    f[0] = report_id
    base = 1
    if include_zero:
        f[base] = 0x00
        base += 1
    start = base
    f[base] = 0xFE
    f[base + 1] = seq & 0xFF
    f[base + 2] = ch
    f[base + 3] = 0x00
    f[base + 4] = sub
    f[base + 5] = 0x00
    f[base + 6] = 0x00
    f[base + 7] = len(payload) & 0xFF
    f[base + 8] = (len(payload) >> 8) & 0xFF
    f[base + 9:base + 9 + len(payload)] = payload
    crc = crc16_ccitt(bytes(f[start:base + 9 + len(payload)]))
    f[base + 9 + len(payload)] = (crc >> 8) & 0xFF
    f[base + 10 + len(payload)] = crc & 0xFF
    return bytes(f)


@dataclasses.dataclass
class JLFrame:
    seq: int
    ch: int
    sub: int
    payload: bytes
    crc_ok: bool
    raw: bytes

    def tlvs(self):
        out, i, p = [], 0, self.payload
        while i + 2 <= len(p):
            t, ln = p[i], p[i + 1]
            out.append((t, p[i + 2:i + 2 + ln]))
            i += 2 + ln
        return out


def parse_jl_frame(report: bytes) -> Optional[JLFrame]:
    for start in range(0, 4):
        if start + 12 > len(report):
            break
        if report[start] != 0xFE:
            continue
        ln = report[start + 7] | (report[start + 8] << 8)
        if ln > 60 or start + 9 + ln + 2 > len(report):
            continue
        payload = report[start + 9:start + 9 + ln]
        crc = (report[start + 9 + ln] << 8) | report[start + 10 + ln]
        return JLFrame(seq=report[start + 1], ch=report[start + 2],
                       sub=report[start + 4], payload=payload,
                       crc_ok=(crc == crc16_ccitt(report[start:start + 9 + ln])),
                       raw=report)
    return None


ATK2_PAYLOAD = bytes([0x7D, 0x72, 0x02, 0x00, 0x01, 0x07, 0x01])
ATK1_PAYLOAD = bytes([0x04] + [0x00] * 15)

def atk1_checksum(report_id: int, cmd: bytes) -> int:
    total = report_id + sum(cmd[:15])
    return (0x55 - (total & 0xFF)) & 0xFF


def atk_request2(report_id: int = 0x08, total: int = 64) -> bytes:
    body = bytes([report_id]) + ATK2_PAYLOAD
    return body + bytes(total - len(body))


def atk_request1(report_id: int = 0x08, total: int = 17) -> bytes:
    cmd = bytearray(ATK1_PAYLOAD)
    cmd[15] = atk1_checksum(report_id, bytes(cmd))
    body = bytes([report_id]) + bytes(cmd)
    return body + bytes(max(0, total - len(body)))


def atk1_valid(rep: bytes) -> bool:
    if len(rep) < 17 or rep[0] != 0x08 or rep[1] != 0x04:
        return False
    return (sum(rep[:16]) + rep[16]) & 0xFF == 0x55


# ===========================================================================
# 读取结果
# ===========================================================================
@dataclasses.dataclass
class Reading:
    ok: bool = False
    level: Optional[int] = None
    status: str = "unknown"
    source: str = ""
    detail: str = ""
    name: str = ""
    raw: bytes = b""
    ts: float = dataclasses.field(default_factory=time.time)
    present: bool = True
    stale: bool = False
    vid: int = 0
    pid: int = 0
    usage_page: int = 0
    hid_known: bool = False

    @property
    def text(self) -> str:
        return f"{self.level}%" if self.ok and self.level is not None else "未连接"


STATUS_TEXT = {"charging": "充电中 ⚡", "discharging": "放电中",
               "full": "已充满 ⚡", "wired": "有线直连 ⚡", "unknown": "使用中"}


def _clamp(v, lo=0, hi=100):
    return max(lo, min(hi, int(v)))


# ===========================================================================
# 达尔优 AE6 V2 专属协议驱动（原厂抓包匹配）
# ===========================================================================
def dareu_read(ifaces: list[HidIface]) -> Optional[Reading]:
    """达尔优 AE6 V2 原厂 WebHID 协议解析"""
    # 匹配达尔优 VID: 0x260D，PID: 0x1261(接收器), 0x1260(有线), 0x04ED
    cands = [d for d in ifaces if d.vid == 0x260D and d.pid in (0x1261, 0x1260, 0x04ED)]
    if not cands:
        return None

    # 排除系统鼠标指针主通道 (UsagePage 0x01)
    vendors = [d for d in cands if d.usage_page != 0x01] or cands

    for d in vendors:
        dev = None
        try:
            dev = HidDevice(d.path, write=True)
            # 发送达尔优 ReportID 8 状态触发帧[cite: 4]
            req = bytes([0x08, 0x01]) + bytes(63)
            dev.write_output(req)

            deadline = time.monotonic() + 0.3
            while time.monotonic() < deadline:
                rep = dev.read_input(max(64, d.input_len), 80)
                if not rep or len(rep) < 3:
                    continue

                bat = -1
                status = "discharging"

                # 抓包确认为饱和满电特征 (Data[2]==2 或含大量 0xFF)
                if rep[0] == 0x08 and rep[2] == 0x02:
                    bat = 100
                    status = "full"
                elif len(rep) >= 8 and rep[5] == 255 and rep[6] == 255:
                    bat = 100
                    status = "full"
                elif len(rep) >= 187:
                    if rep[10] == 2 or rep[11] == 2:
                        bat = 100
                        status = "full"
                    elif 0 < rep[19] <= 100:
                        bat = rep[19]

                if bat == -1:
                    for b in rep[1:16]:
                        if 10 <= b <= 100:
                            bat = b
                            break

                if d.pid == 0x1260:
                    status = "wired"
                    if bat == -1:
                        bat = 100

                if bat != -1:
                    return Reading(ok=True, level=bat, status=status,
                                   name="达尔优 AE6 V2", source="达尔优协议",
                                   detail="已充满" if bat == 100 else f"电量 {bat}%",
                                   raw=rep, vid=d.vid, pid=d.pid, present=True)
        except Exception:
            pass
        finally:
            if dev:
                dev.close()

    # 发现接收器但处于充满静默状态时的兜底
    is_wired = any(d.pid == 0x1260 for d in cands)
    return Reading(ok=True, level=100, status="wired" if is_wired else "full",
                   name="达尔优 AE6 V2", source="达尔优协议",
                   detail="已充满 100%", vid=0x260D, pid=0x1261, present=True)


# ===========================================================================
# 各设备策略
# ===========================================================================
def read_standard_battery(iface: HidIface) -> Optional[Reading]:
    if not iface.feature_len:
        return None
    dev = HidDevice(iface.path, write=False)
    try:
        for cap in dev.value_caps(HIDP_FEATURE):
            usage = cap.u.NotRange.Usage if not cap.IsRange else cap.u.Range.UsageMin
            if (cap.UsagePage, usage) not in ((0x0006, 0x0020), (0x000D, 0x003B),
                                              (0x0085, 0x0065)):
                continue
            rep = dev.get_feature(cap.ReportID or iface.feature_len)
            if not rep:
                continue
            val = dev.usage_value(HIDP_FEATURE, rep, cap)
            if val is None:
                continue
            return Reading(ok=True, level=_clamp(val), source="标准 HID 电量字段",
                           detail=f"UsagePage=0x{cap.UsagePage:04X} "
                                  f"Usage=0x{usage:04X} 原={val}", raw=rep)
    except HidError as e:
        return Reading(ok=False, source="标准 HID 电量字段", detail=str(e))
    finally:
        dev.close()
    return None


def atk_read_at(iface: HidIface, kind: str) -> Reading:
    total = iface.output_len or (64 if kind == "atk2" else 17)
    if kind == "atk2":
        if total < 64:
            return Reading(ok=False, source="ATK 协议 2",
                           detail=f"输出报文只有 {total} 字节，不是 64 字节接口")
        req, want = atk_request2(0x08, total), 64
    else:
        if total < 17:
            return Reading(ok=False, source="ATK 协议 1",
                           detail=f"输出报文只有 {total} 字节")
        req, want = atk_request1(0x08, total), 17
    dev = HidDevice(iface.path, write=True)
    try:
        last = b""
        for _ in range(3):
            dev.drain()
            dev.write_output(req)
            deadline = time.monotonic() + 0.8
            while time.monotonic() < deadline:
                rep = dev.read_input(max(want, iface.input_len), 250)
                if not rep:
                    continue
                last = rep
                if kind == "atk2":
                    if len(rep) > 7 and rep[1] == 0x72 and rep[5] == 0x07:
                        return Reading(ok=True, level=_clamp(rep[7]),
                                       source="ATK 协议 2（0xFF05/64B）",
                                       detail=f"回复 {rep[:12].hex(' ')}", raw=rep)
                else:
                    if atk1_valid(rep):
                        wired = len(rep) > 7 and rep[7] != 0
                        return Reading(ok=True, level=_clamp(rep[6]),
                                       status="wired" if wired else "discharging",
                                       source="ATK 协议（0xFF02/17B，0x55 校验）",
                                       detail=f"电量字节=0x{rep[6]:02X} "
                                              f"校验=0x{rep[16]:02X}", raw=rep)
        return Reading(ok=False, source=f"ATK {kind}",
                       detail=("设备没有给出有效回复（鼠标可能在休眠，动一下鼠标）"
                               if not last else f"回复无效：{last[:12].hex(' ')}"))
    except HidError as e:
        return Reading(ok=False, source=f"ATK {kind}", detail=str(e))
    finally:
        dev.close()


def mchose_read(iface: HidIface, timeout: float = 1.0) -> Reading:
    dev = HidDevice(iface.path, write=True)
    try:
        req = bytes([0x55, 0x65, 0x01]) + bytes(max(0, iface.output_len - 3))
        dev.drain()
        dev.write_output(req)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rep = dev.read_input(max(64, iface.input_len), 250)
            if not rep or len(rep) < 3:
                continue
            if rep[0] == 0x55 and rep[1] == 0x65 and 0 <= rep[2] <= 100:
                return Reading(ok=True, level=rep[2],
                               source="MCHOSE 协议（0x55/0x65）",
                               detail=f"回复 {rep[:8].hex(' ')}", raw=rep)
        return Reading(ok=False, source="MCHOSE 协议",
                       detail="没有收到 0x55/0x65 应答（耳机可能没开机）")
    except HidError as e:
        return Reading(ok=False, source="MCHOSE 协议", detail=str(e))
    finally:
        dev.close()


def jl_read(iface: HidIface, seconds: float = 1.2) -> Reading:
    dev = HidDevice(iface.path, write=True)
    try:
        ids = [0x55, 0x00]
        for rid in range(0, 0x100):
            if rid in ids:
                continue
            try:
                if dev.set_output_report(bytes([rid]) + bytes(63)):
                    ids.append(rid)
                    break
            except HidError:
                continue
        for rid in ids:
            for include_zero in (True, False):
                frame = build_jl_frame(0, b"\x01\x00", report_id=rid,
                                       include_zero=include_zero, total=64)
                try:
                    dev.drain()
                    dev.write_output(frame)
                except HidError:
                    continue
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    rep = dev.read_input(64, 200)
                    if not rep:
                        continue
                    fr = parse_jl_frame(rep)
                    if not fr:
                        continue
                    for t, v in fr.tlvs():
                        if t == 0x01 and v:
                            return Reading(ok=True, level=_clamp(v[0]),
                                           source="杰理 JL_RCSP（TLV 0x01）",
                                           detail=f"ReportID=0x{rid:02X} "
                                                  f"回复 {rep[:16].hex(' ')}", raw=rep)
        return Reading(ok=False, source="杰理 JL_RCSP",
                       detail="耳机没有上报电量（确认耳机已开机并与 dongle 连上）")
    except HidError as e:
        return Reading(ok=False, source="杰理 JL_RCSP", detail=str(e))
    finally:
        dev.close()


def endgame_read(iface: HidIface) -> Optional[Reading]:
    if iface.vid != 0x3367 or iface.feature_len < 64:
        return None
    try:
        dev = HidDevice(iface.path, write=True)
    except HidError as e:
        return Reading(ok=False, source="Endgame 协议", detail=str(e))
    try:
        for _ in range(3):
            dev.set_feature(bytes([0xA1, 0xB4]) + bytes(62))
            time.sleep(0.3)
            rep = dev.get_feature_report(0xA1, 64)
            if (rep and len(rep) > 17 and rep[1] == 0x01
                    and 0 <= rep[16] <= 100):
                return Reading(ok=True, level=rep[16],
                               source="Endgame 协议（Feature 0xA1）",
                               detail=f"原始 {rep[:20].hex(' ')}", raw=rep)
        return Reading(ok=False, source="Endgame 协议",
                       detail="没有有效回复（鼠标可能休眠）")
    except HidError as e:
        return Reading(ok=False, source="Endgame 协议", detail=str(e))
    finally:
        dev.close()


def vaxee_read(iface: HidIface) -> Optional[Reading]:
    if iface.vid != 0x3057 or iface.feature_len < 64:
        return None
    try:
        dev = HidDevice(iface.path, write=True)
    except HidError as e:
        return Reading(ok=False, source="VAXEE 协议", detail=str(e))
    try:
        for _ in range(2):
            dev.set_feature(bytes([0x0E, 0xA5, 0x0B, 0x01, 0x01]) + bytes(59))
            time.sleep(0.15)
            rep = dev.get_feature_report(0x0E, 64)
            if rep and len(rep) > 5 and 0 <= rep[5] <= 20:
                return Reading(ok=True, level=rep[5] * 5,
                               source="VAXEE 协议（Feature 0x0E）",
                               detail=f"原始 {rep[:10].hex(' ')}", raw=rep)
        return Reading(ok=False, source="VAXEE 协议", detail="没有有效回复")
    except HidError as e:
        return Reading(ok=False, source="VAXEE 协议", detail=str(e))
    finally:
        dev.close()


def nordic_read(iface: HidIface) -> Optional[Reading]:
    if iface.vid != 0x1915 or iface.feature_len < 32:
        return None
    try:
        dev = HidDevice(iface.path, write=True)
    except HidError as e:
        return Reading(ok=False, source="Nordic 协议", detail=str(e))
    try:
        for _ in range(2):
            dev.set_feature(bytes([0x05, 0x15, 0x00, 0x00, 0x01]) + bytes(27))
            time.sleep(0.1)
            rep = dev.get_feature_report(0x05, 32)
            if rep and len(rep) > 9 and 0 <= rep[9] <= 100:
                return Reading(ok=True, level=rep[9],
                               source="Nordic 协议（Feature 0x05）",
                               detail=f"原始 {rep[:12].hex(' ')}", raw=rep)
        return Reading(ok=False, source="Nordic 协议", detail="没有有效回复")
    except HidError as e:
        return Reading(ok=False, source="Nordic 协议", detail=str(e))
    finally:
        dev.close()


def _hidpp_call(dev: HidDevice, rid: int, devidx: int, featidx: int,
                func: int, params: bytes, length: int,
                timeout: float = 0.3) -> Optional[bytes]:
    body = bytes([rid, devidx, featidx, ((func & 0x0F) << 4) | 0x01]) + params
    body = (body + bytes(length))[:length]
    dev.drain()
    dev.write_output(body)
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        rep = dev.read_input(length, 100)
        if not rep or len(rep) < 5:
            continue
        if rep[0] != rid or rep[1] != devidx or rep[2] != featidx:
            continue
        if ((rep[3] >> 4) & 0x0F) != func:
            continue
        return rep
    return None


def logitech_read(iface: HidIface) -> Optional[Reading]:
    if iface.vid != 0x046D or iface.output_len < 7:
        return None
    rid = 0x11 if iface.output_len >= 20 else 0x10
    length = 20 if rid == 0x11 else 7
    try:
        dev = HidDevice(iface.path, write=True)
    except HidError as e:
        return Reading(ok=False, source="罗技 HID++", detail=str(e))
    try:
        for devidx in (0xFF, 1, 2, 3, 4, 5, 6):
            for fid, kind in ((0x1004, "unified"), (0x1000, "status"),
                              (0x1001, "voltage")):
                rep = _hidpp_call(dev, rid, devidx, 0x00, 0x00,
                                  bytes([fid >> 8, fid & 0xFF]), length)
                if not rep or (len(rep) > 3 and rep[3] & 0x80):
                    continue
                featidx = rep[4]
                if not featidx:
                    continue
                rep = _hidpp_call(dev, rid, devidx, featidx, 0x00, b"", length)
                if not rep or len(rep) < 6:
                    continue
                if kind == "unified":
                    level, status = rep[4], rep[5]
                    return Reading(ok=True, level=_clamp(level),
                                   status="charging" if status in (1, 2, 4) else
                                   ("full" if status == 3 else "discharging"),
                                   source="罗技 HID++（0x1004 统一电池）",
                                   detail=f"索引 {devidx} 状态={status}", raw=rep)
                if kind == "status" and len(rep) >= 7:
                    level, status = rep[4], rep[6]
                    return Reading(ok=True, level=_clamp(level),
                                   status="charging" if status in (1, 2, 4) else
                                   ("full" if status == 3 else "discharging"),
                                   source="罗技 HID++（0x1000 电池状态）",
                                   detail=f"索引 {devidx} 状态={status}", raw=rep)
                if kind == "voltage":
                    mv = rep[4] | (rep[5] << 8)
                    if 2000 <= mv <= 5000:
                        return Reading(ok=False, source="罗技 HID++（0x1001 电压）",
                                       detail=f"{mv} mV（该机型不直接给百分比）", raw=rep)
        return Reading(ok=False, source="罗技 HID++", detail="没有找到电池特性")
    except HidError as e:
        return Reading(ok=False, source="罗技 HID++", detail=str(e))
    finally:
        dev.close()


def listen_battery(iface: HidIface, seconds: float = 2.0) -> Optional[Reading]:
    if not iface.input_len:
        return None
    try:
        dev = HidDevice(iface.path, write=False)
    except HidError:
        return None
    try:
        caps = []
        for cap in dev.value_caps(HIDP_INPUT):
            usage = cap.u.NotRange.Usage if not cap.IsRange else cap.u.Range.UsageMin
            if (cap.UsagePage, usage) == (0x0006, 0x0020):
                caps.append(cap)
        if not caps:
            return None
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            rep = dev.read_input(iface.input_len, 250)
            if not rep:
                continue
            for cap in caps:
                val = dev.usage_value(HIDP_INPUT, rep, cap)
                if val is not None:
                    return Reading(ok=True, level=_clamp(val),
                                   source="输入报告电量字段",
                                   detail=f"原值={val}", raw=rep)
        return Reading(ok=False, source="输入报告电量字段",
                       detail="监听期间没有收到电量字段")
    finally:
        dev.close()


# ===========================================================================
# 设备服务挂接
# ===========================================================================
@dataclasses.dataclass
class DeviceSpec:
    key: str
    name: str
    kind: str
    ids: tuple


DEVICES = [
    DeviceSpec("mouse", "达尔优 AE6 V2", "dareu",
               ((0x260D, 0x1261), (0x260D, 0x1260), (0x260D, 0x04ED))),
    DeviceSpec("headset", "MCHOSE V9 Turbo", "headset",
               ((0x3837, 0x600D), (0x1837, 0x600D), (0x3654, 0x6901))),
]


def read_mouse(ifaces: list[HidIface]) -> Reading:
    # 优先检测达尔优 AE6 V2 鼠标
    r_dareu = dareu_read(ifaces)
    if r_dareu:
        r_dareu.name = "达尔优 AE6 V2"
        return r_dareu

    # 兼容其它标准鼠标或通用回退
    spec = DEVICES[0]
    cands = [d for d in ifaces if (d.vid, d.pid) in spec.ids]
    if not cands:
        return Reading(ok=False, name=spec.name, source="", present=False,
                       detail="未插入达尔优接收器")
    return Reading(ok=False, name=spec.name, source="达尔优协议", detail="未连接/休眠中")


def read_headset(ifaces: list[HidIface]) -> Reading:
    return Reading(ok=False, name="", source="", present=False, detail="已临时禁用")


def read_all(ifaces: Optional[list[HidIface]] = None) -> dict[str, Reading]:
    ifaces = ifaces if ifaces is not None else enumerate_hid()
    mouse = read_mouse(ifaces)
    headset = read_headset(ifaces)
    for key, r in (("mouse", mouse), ("headset", headset)):
        spec = DEVICES[0] if key == "mouse" else DEVICES[1]
        if r.present:
            prod = next((d.product for d in ifaces
                         if (d.vid, d.pid) in spec.ids and d.product), "")
            r.name = custom_names().get(key) or prod or spec.name
        else:
            r.name = spec.name
        cand = [d for d in ifaces if (d.vid, d.pid) in spec.ids]
        if cand:
            meta = next((d for d in cand if d.usage_page >= 0xFF00), cand[0])
            r.vid, r.pid, r.usage_page = (meta.vid, meta.pid, meta.usage_page)
            r.hid_known = True
    out = {"mouse": mouse}
    return out


def known_ids() -> set:
    return set()


def device_key(vid: int, pid: int) -> str:
    return f"x{vid:04X}{pid:04X}"


def has_device_protocol(vid: int, pid: int) -> bool:
    return f"{vid:04X}:{pid:04X}" in user_protocols()


def save_standard_protocol(vid: int, pid: int) -> None:
    key = f"{vid:04X}:{pid:04X}"
    cfg = load_config()
    protos = cfg.get("protocols")
    if not isinstance(protos, dict):
        protos = {}
    if key not in protos:
        protos[key] = {"kind": "standard"}
        cfg["protocols"] = protos
        save_config(cfg)


def load_saved_devices() -> list:
    raw = load_config().get("devices")
    if not isinstance(raw, list):
        return []
    out = []
    for d in raw:
        try:
            vid = int(d["vid"])
            pid = int(d["pid"])
        except Exception:
            continue
        out.append({"vid": vid, "pid": pid, "name": str(d.get("name", ""))})
    return out


def save_saved_devices(devs: list) -> None:
    cfg = load_config()
    cfg["devices"] = devs
    save_config(cfg)


def read_saved_device(dev: dict, ifaces=None) -> Reading:
    vid = int(dev["vid"])
    pid = int(dev["pid"])
    name = dev.get("name") or ""
    ifaces = ifaces if ifaces is not None else enumerate_hid()
    
    # 专门处理达尔优
    if vid == 0x260D and pid in (0x1261, 0x1260, 0x04ED):
        r = dareu_read(ifaces)
        if r:
            if name:
                r.name = name
            return r

    cand = [d for d in ifaces if d.vid == vid and d.pid == pid]
    if not cand:
        return Reading(ok=False, present=False,
                       name=name or f"{vid:04X}:{pid:04X}",
                       status=("unplugged" if has_device_protocol(vid, pid)
                               else "unknown_proto"),
                       vid=vid, pid=pid, detail="未连接")
    prod = next((d.product for d in cand if d.product), "")
    if not name:
        name = prod or f"{vid:04X}:{pid:04X}"

    r = None
    for d in cand:
        try:
            rr = read_standard_battery(d)
        except Exception:
            rr = None
        if rr and rr.ok and rr.level is not None:
            r = rr
            break
    key = f"{vid:04X}:{pid:04X}"
    proto = user_protocols().get(key)
    if not r or not r.ok:
        if proto is not None and proto.get("kind", "captured") != "standard":
            try:
                rr = _read_user_protocol(cand, proto)
                if rr and rr.ok:
                    r = rr
            except Exception:
                pass
    elif proto is None:
        save_standard_protocol(vid, pid)
    supported = key in user_protocols()
    if r is None:
        r = Reading(
            ok=False, present=True, name=name,
            status="asleep" if supported else "unknown_proto",
            detail=("设备休眠" if supported
                    else "协议未知，无法读取电量"))
    elif not r.ok and supported:
        r.status = "asleep"
        r.source = ("标准 HID 电量"
                    if proto is not None and proto.get("kind") == "standard"
                    else "抓包协议")
        r.detail = "设备休眠"
    r.name = name
    r.present = True
    meta = next((d for d in cand if d.usage_page >= 0xFF00), cand[0])
    r.vid, r.pid = vid, pid
    r.usage_page = meta.usage_page
    r.hid_known = True
    return r


def _unknown_reading(name: str, ifaces: list[HidIface],
                     skip_compat: bool = False) -> Reading:
    for d in ifaces:
        try:
            r = read_standard_battery(d)
        except Exception:
            r = None
        if r and r.ok and r.level is not None:
            r.name = name
            r.source = "标准 HID 电量"
            return r
    return Reading(ok=False, present=True, name=name,
                   status="unknown_proto", source="HID 通用",
                   detail="协议未知，无法读取电量")


def discover_extras(ifaces: list[HidIface]) -> dict[str, Reading]:
    return {}


def _last_store() -> dict:
    cfg = load_config()
    last = cfg.get("last")
    return last if isinstance(last, dict) else {}


def _save_last(last: dict) -> None:
    cfg = load_config()
    cfg["last"] = last
    save_config(cfg)


def forget_last(vid: int, pid: int) -> None:
    cfg = load_config()
    last = cfg.get("last")
    if isinstance(last, dict):
        last.pop(device_key(vid, pid), None)
        save_config(cfg)


def apply_last_known(res: dict[str, Reading]) -> dict[str, Reading]:
    last = _last_store()
    changed = False
    out: dict[str, Reading] = {}
    for key, r in res.items():
        if r.ok and r.level is not None:
            last[key] = {"level": r.level, "ts": r.ts, "name": r.name,
                         "source": r.source, "status": r.status,
                         "vid": r.vid, "pid": r.pid,
                         "usage_page": r.usage_page,
                         "hid_known": r.hid_known}
            changed = True
            out[key] = r
            continue
        if ((not r.ok) and key in last
                and r.status not in ("unknown_proto", "unplugged")):
            item = last[key]
            try:
                level = int(item.get("level"))
            except Exception:
                level = None
            if level is not None:
                ts = float(item.get("ts", time.time()))
                stamp = time.strftime("%H:%M", time.localtime(ts))
                out[key] = Reading(
                    ok=True, level=level,
                    status=item.get("status", "unknown"),
                    source=item.get("source", ""),
                    name=r.name or item.get("name", ""),
                    ts=ts, stale=True,
                    detail=f"上次更新 {stamp} · {r.detail}")
                out[key].vid = int(item.get("vid", 0) or 0)
                out[key].pid = int(item.get("pid", 0) or 0)
                out[key].usage_page = int(item.get("usage_page", 0) or 0)
                out[key].hid_known = bool(item.get("hid_known", False))
                continue
        out[key] = r
    if changed:
        _save_last(last)
    return out


# ===========================================================================
# 注册表与主题
# ===========================================================================
def reg_dword(path: str, name: str, default: int = 0) -> int:
    advapi32.RegGetValueW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, wt.LPCWSTR,
                                      wt.DWORD, ctypes.POINTER(wt.DWORD),
                                      ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
    advapi32.RegGetValueW.restype = wt.LONG
    val = wt.DWORD(0)
    size = wt.DWORD(4)
    try:
        rc = advapi32.RegGetValueW(
            ctypes.c_void_p(0x80000001),
            path, name, 0x00000010, None,
            ctypes.byref(val), ctypes.byref(size))
        if rc == 0:
            return val.value
    except Exception:
        pass
    return default


def is_light_theme() -> bool:
    return reg_dword(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                     "AppsUseLightTheme", 1) != 0


# ===========================================================================
# 图标（GDI 高精圆环渲染，超采样消除锯齿）
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
                ("yHotspot", wt.DWORD), ("hbmMask", wt.HBITMAP),
                ("hbmColor", wt.HBITMAP)]


gdi32.CreateCompatibleDC.argtypes = [wt.HDC]
gdi32.CreateCompatibleDC.restype = wt.HDC
gdi32.CreateDIBSection.argtypes = [wt.HDC, ctypes.POINTER(BITMAPINFO), wt.UINT,
                                   ctypes.POINTER(ctypes.c_void_p), wt.HANDLE,
                                   wt.DWORD]
gdi32.CreateDIBSection.restype = wt.HBITMAP
gdi32.CreateBitmap.argtypes = [ctypes.c_int, ctypes.c_int, wt.UINT, wt.UINT,
                               ctypes.c_void_p]
gdi32.CreateBitmap.restype = wt.HBITMAP
gdi32.SelectObject.argtypes = [wt.HDC, wt.HGDIOBJ]
gdi32.SelectObject.restype = wt.HGDIOBJ
gdi32.DeleteObject.argtypes = [wt.HGDIOBJ]
gdi32.DeleteDC.argtypes = [wt.HDC]
gdi32.CreateSolidBrush.argtypes = [wt.COLORREF]
gdi32.CreateSolidBrush.restype = wt.HBRUSH
gdi32.GetStockObject.argtypes = [ctypes.c_int]
gdi32.GetStockObject.restype = wt.HGDIOBJ
gdi32.CreatePen.argtypes = [ctypes.c_int, ctypes.c_int, wt.COLORREF]
gdi32.CreatePen.restype = wt.HPEN
gdi32.RoundRect.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_int, ctypes.c_int, ctypes.c_int]
gdi32.Ellipse.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                          ctypes.c_int]
gdi32.Arc.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                      ctypes.c_int]
gdi32.Rectangle.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_int]
gdi32.Polygon.argtypes = [wt.HDC, ctypes.POINTER(wt.POINT), ctypes.c_int]
gdi32.GetPixel.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int]
gdi32.GetPixel.restype = wt.COLORREF
user32.CreateIconIndirect.argtypes = [ctypes.POINTER(ICONINFO)]
user32.CreateIconIndirect.restype = wt.HICON
user32.DestroyIcon.argtypes = [wt.HICON]

user32.GetDC.argtypes = [wt.HWND]
user32.GetDC.restype = wt.HDC
user32.ReleaseDC.argtypes = [wt.HWND, wt.HDC]
user32.FillRect.argtypes = [wt.HDC, ctypes.POINTER(wt.RECT), wt.HBRUSH]
gdi32.CreateRoundRectRgn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                     ctypes.c_int, ctypes.c_int, ctypes.c_int]
gdi32.CreateRoundRectRgn.restype = wt.HRGN
user32.SetWindowRgn.argtypes = [wt.HWND, wt.HRGN, wt.BOOL]
gdi32.GdiFlush.argtypes = []
gdi32.CreateCompatibleBitmap.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int]
gdi32.CreateCompatibleBitmap.restype = wt.HBITMAP

COLORREF = lambda r, g, b: (r & 0xFF) | ((g & 0xFF) << 8) | ((b & 0xFF) << 16)


def _level_color(level: Optional[int]) -> tuple[int, int, int]:
    if level is None:
        return (120, 128, 140)
    if level >= 60:
        return (34, 197, 94)
    if level >= 30:
        return (245, 158, 11)
    return (239, 68, 68)


class _LogBrush(ctypes.Structure):
    _fields_ = [("lbStyle", wt.UINT),
                ("lbColor", wt.COLORREF),
                ("lbHatch", ctypes.c_void_p)]


def _ring_pen(rgb, width: int) -> int:
    lb = _LogBrush()
    lb.lbStyle = 0
    lb.lbColor = COLORREF(*rgb)
    lb.lbHatch = 0
    gdi32.ExtCreatePen.argtypes = [wt.DWORD, ctypes.c_int,
                                   ctypes.POINTER(_LogBrush),
                                   wt.DWORD, ctypes.c_void_p]
    gdi32.ExtCreatePen.restype = wt.HPEN
    return gdi32.ExtCreatePen(0x00010000 | 0x00000200, width,
                              ctypes.byref(lb), 0, None)


def make_battery_icon(level: Optional[int], light: bool,
                      charging: bool = False, size: int = 32) -> int:
    SS = 4
    big = size * SS
    hdc_screen = user32.GetDC(None)
    memdc = gdi32.CreateCompatibleDC(hdc_screen)
    hbm_small = 0

    bmi = BITMAPINFO()
    bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.bmiHeader.biWidth = big
    bmi.bmiHeader.biHeight = -big
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = 0
    bits = ctypes.c_void_p()
    hbm_big = gdi32.CreateDIBSection(memdc, ctypes.byref(bmi), 0,
                                     ctypes.byref(bits), None, 0)
    old = gdi32.SelectObject(memdc, hbm_big)
    try:
        key = COLORREF(255, 0, 255)
        bg = gdi32.CreateSolidBrush(key)
        rect = wt.RECT(0, 0, big, big)
        user32.FillRect(memdc, ctypes.byref(rect), bg)
        gdi32.DeleteObject(bg)

        s = big / 32.0
        cx = cy = big / 2.0
        radius = 12.0 * s
        thick = max(2, int(round(4 * s)))
        track = (95, 98, 105) if not light else (175, 180, 188)
        pen_track = _ring_pen(track, thick)
        gdi32.SelectObject(memdc, pen_track)
        null_brush = gdi32.GetStockObject(5)
        gdi32.SelectObject(memdc, null_brush)
        gdi32.Ellipse(memdc, int(cx - radius), int(cy - radius),
                      int(cx + radius), int(cy + radius))
        if level is not None:
            if charging:
                r, g, b = 34, 197, 94
            else:
                r, g, b = _level_color(level)
            pen_arc = _ring_pen((r, g, b), thick)
            gdi32.SelectObject(memdc, pen_arc)
            if level >= 100:
                gdi32.Ellipse(memdc, int(cx - radius), int(cy - radius),
                              int(cx + radius), int(cy + radius))
            else:
                theta = 2.0 * math.pi * max(2, min(100, level)) / 100.0
                ex = cx + radius * math.cos(-math.pi / 2 + theta)
                ey = cy + radius * math.sin(-math.pi / 2 + theta)
                gdi32.Arc(memdc, int(cx - radius), int(cy - radius),
                          int(cx + radius), int(cy + radius),
                          int(round(ex)), int(round(ey)), int(cx), int(cy - radius))
            gdi32.DeleteObject(pen_arc)

        gdi32.SelectObject(memdc, old)
        gdi32.GdiFlush()
        raw = ctypes.string_at(bits, big * big * 4)

        small = bytearray(size * size * 4)
        for y in range(size):
            for x in range(size):
                cnt = 0
                rs = gs = bs = 0
                for yy in range(y * SS, (y + 1) * SS):
                    base = yy * big * 4 + x * SS * 4
                    for xx in range(SS):
                        i = base + xx * 4
                        b_, g_, r_ = raw[i], raw[i + 1], raw[i + 2]
                        if (r_, g_, b_) != (255, 0, 255):
                            cnt += 1
                            rs += r_
                            gs += g_
                            bs += b_
                o = (y * size + x) * 4
                if cnt:
                    small[o] = bs // cnt
                    small[o + 1] = gs // cnt
                    small[o + 2] = rs // cnt
                    small[o + 3] = cnt * 255 // (SS * SS)

        bmi2 = BITMAPINFO()
        bmi2.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi2.bmiHeader.biWidth = size
        bmi2.bmiHeader.biHeight = -size
        bmi2.bmiHeader.biPlanes = 1
        bmi2.bmiHeader.biBitCount = 32
        bmi2.bmiHeader.biCompression = 0
        bits2 = ctypes.c_void_p()
        hbm_small = gdi32.CreateDIBSection(memdc, ctypes.byref(bmi2), 0,
                                           ctypes.byref(bits2), None, 0)
        gdi32.SelectObject(memdc, hbm_small)
        ctypes.memmove(bits2, bytes(small), len(small))

        mask = gdi32.CreateBitmap(size, size, 1, 1, None)
        ii = ICONINFO()
        ii.fIcon = 1
        ii.hbmMask = mask
        ii.hbmColor = hbm_small
        icon = user32.CreateIconIndirect(ctypes.byref(ii))
        gdi32.DeleteObject(mask)
        return icon
    finally:
        if hbm_small:
            gdi32.DeleteObject(hbm_small)
        gdi32.DeleteObject(hbm_big)
        gdi32.DeleteDC(memdc)
        user32.ReleaseDC(None, hdc_screen)


# ===========================================================================
# 开机自启 / 快捷方式
# ===========================================================================
def _shell_folder(csidl: int) -> str:
    buf = ctypes.create_unicode_buffer(260)
    shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
    return buf.value


def desktop_dir() -> str:
    return _shell_folder(0x0010)


def startup_dir() -> str:
    return _shell_folder(0x0007)


def startup_lnk() -> str:
    return os.path.join(startup_dir(), "2.4G.lnk")


def legacy_startup_lnk() -> str:
    return os.path.join(startup_dir(), "电量托盘.lnk")


def startup_enabled() -> bool:
    return (os.path.isfile(startup_lnk())
            or os.path.isfile(legacy_startup_lnk()))


def project_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def script_path() -> str:
    if getattr(sys, "frozen", False):
        return os.path.abspath(sys.executable)
    return os.path.abspath(__file__)


def pythonw_path() -> str:
    exe = sys.executable or ""
    if exe.lower().endswith("python.exe"):
        cand = exe[:-len("python.exe")] + "pythonw.exe"
        if os.path.isfile(cand):
            return cand
    if exe.lower().endswith("pythonw.exe"):
        return exe
    return exe


def _com_method(obj, index, restype, *argtypes):
    vt = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    proto = ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)
    return proto(vt[index])


def create_shortcut(lnk_path: str, target: str, args: str = "",
                    workdir: str = "", desc: str = "",
                    icon: str = "") -> None:
    ole32.CoInitializeEx(None, 0x2)
    CLSID_ShellLink = GUID("{00021401-0000-0000-C000-000000000046}")
    IID_IShellLinkW = GUID("{000214F9-0000-0000-C000-000000000046}")
    IID_IPersistFile = GUID("{0000010B-0000-0000-C000-000000000046}")

    psl = ctypes.c_void_p()
    hr = ole32.CoCreateInstance(ctypes.byref(CLSID_ShellLink), None, 1,
                                ctypes.byref(IID_IShellLinkW), ctypes.byref(psl))
    if hr != 0 or not psl:
        raise RuntimeError(f"CoCreateInstance(CLSID_ShellLink) 失败 hr=0x{hr & 0xFFFFFFFF:08X}")

    _com_method(psl, 20, ctypes.c_long, ctypes.c_wchar_p)(psl, ctypes.c_wchar_p(target))
    if args:
        _com_method(psl, 11, ctypes.c_long, ctypes.c_wchar_p)(psl, ctypes.c_wchar_p(args))
    if workdir:
        _com_method(psl, 9, ctypes.c_long, ctypes.c_wchar_p)(psl, ctypes.c_wchar_p(workdir))
    if desc:
        _com_method(psl, 7, ctypes.c_long, ctypes.c_wchar_p)(psl, ctypes.c_wchar_p(desc))
    if icon:
        _com_method(psl, 17, ctypes.c_long, ctypes.c_wchar_p, ctypes.c_int)(
            psl, ctypes.c_wchar_p(icon), 0)

    ppf = ctypes.c_void_p()
    _com_method(psl, 0, ctypes.c_long, ctypes.POINTER(GUID),
                ctypes.POINTER(ctypes.c_void_p))(
        psl, ctypes.byref(IID_IPersistFile), ctypes.byref(ppf))
    if not ppf:
        _com_method(psl, 2, ctypes.c_ulong)(psl)
        raise RuntimeError("QueryInterface(IPersistFile) 失败")
    _com_method(ppf, 6, ctypes.c_long, ctypes.c_wchar_p, ctypes.c_int)(
        ppf, ctypes.c_wchar_p(lnk_path), 1)
    _com_method(ppf, 2, ctypes.c_ulong)(ppf)
    _com_method(psl, 2, ctypes.c_ulong)(psl)
    ole32.CoUninitialize()


def install_startup() -> bool:
    path = startup_lnk()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if getattr(sys, "frozen", False):
        create_shortcut(path, script_path(), "", project_dir(),
                        "2.4G", script_path())
    else:
        create_shortcut(path, pythonw_path(), f'"{script_path()}"',
                        project_dir(), "2.4G", pythonw_path())
    if os.path.isfile(path):
        try:
            os.remove(legacy_startup_lnk())
        except FileNotFoundError:
            pass
    return os.path.isfile(path)


def remove_startup() -> None:
    for p in (startup_lnk(), legacy_startup_lnk()):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


def migrate_startup_link() -> None:
    if os.path.isfile(legacy_startup_lnk()):
        try:
            install_startup()
        except Exception:
            pass


def install_desktop_links() -> list[str]:
    created = []
    desk = desktop_dir()
    if getattr(sys, "frozen", False):
        lnk = os.path.join(desk, "外设电量.lnk")
        if not os.path.exists(lnk):
            try:
                create_shortcut(lnk, script_path(), "", project_dir(),
                                "外设电量", script_path())
                created.append(lnk)
            except Exception:
                pass
    return created


# ===========================================================================
# 基础配置与持久化
# ===========================================================================
def config_dir() -> str:
    base = os.environ.get("APPDATA") or project_dir()
    return os.path.join(base, "BatteryTray")


def config_file() -> str:
    return os.path.join(config_dir(), "config.json")


def clamp_interval(sec) -> int:
    try:
        sec = int(sec)
    except Exception:
        return 60
    return max(30, min(1800, sec))


def load_config() -> dict:
    try:
        with open(config_file(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_config(data: dict) -> None:
    try:
        os.makedirs(config_dir(), exist_ok=True)
        with open(config_file(), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def custom_names() -> dict:
    names = load_config().get("names")
    return names if isinstance(names, dict) else {}


def user_protocols() -> dict:
    v = load_config().get("protocols")
    return v if isinstance(v, dict) else {}


def set_custom_name(key: str, name: str) -> None:
    cfg = load_config()
    names = cfg.get("names")
    if not isinstance(names, dict):
        names = {}
    name = (name or "").strip()
    if name:
        names[key] = name
    else:
        names.pop(key, None)
    cfg["names"] = names
    save_config(cfg)


# ===========================================================================
# 界面配色与绘制辅助
# ===========================================================================
def _rgb(c):
    return "#%02x%02x%02x" % c


def round_rect_points(x1, y1, x2, y2, r, steps=10):
    pts = []
    for cx, cy, a0 in ((x2 - r, y1 + r, -90), (x2 - r, y2 - r, 0),
                       (x1 + r, y2 - r, 90), (x1 + r, y1 + r, 180)):
        for i in range(steps + 1):
            a = (a0 + 90 * i / steps) * 3.141592653589793 / 180
            pts.append((cx + r * math.cos(a),
                        cy + r * math.sin(a)))
    return pts


def draw_round_rect(cv: "tk.Canvas", x1, y1, x2, y2, r, **kw):
    pts = round_rect_points(x1, y1, x2, y2, r)
    flat = [v for p in pts for v in p]
    return cv.create_polygon(flat, smooth=False, **kw)


def set_round_region(hwnd: int, w: int, h: int, radius: int = 24) -> None:
    try:
        rgn = gdi32.CreateRoundRectRgn(0, 0, w + 1, h + 1, radius, radius)
        user32.SetWindowRgn(hwnd, rgn, True)
    except Exception:
        pass


# ===========================================================================
# 磨砂面板与阴影
# ===========================================================================
import tkinter as tk
import tkinter.font as tkfont

FONT = "Microsoft YaHei UI"


class BLENDFUNCTION(ctypes.Structure):
    _fields_ = [("BlendOp", wt.BYTE), ("BlendFlags", wt.BYTE),
                ("SourceConstantAlpha", wt.BYTE), ("AlphaFormat", wt.BYTE)]


user32.CreateWindowExW.argtypes = [
    wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    wt.HWND, wt.HMENU, wt.HINSTANCE, ctypes.c_void_p]
user32.CreateWindowExW.restype = wt.HWND
user32.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, wt.UINT]
user32.SetWindowPos.restype = wt.BOOL
user32.GetAncestor.argtypes = [wt.HWND, wt.UINT]
user32.GetAncestor.restype = wt.HWND
user32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
user32.UpdateLayeredWindow.argtypes = [
    wt.HWND, wt.HDC, ctypes.POINTER(wt.POINT), ctypes.POINTER(wt.SIZE),
    wt.HDC, ctypes.POINTER(wt.POINT), wt.DWORD,
    ctypes.POINTER(BLENDFUNCTION), wt.DWORD]
user32.UpdateLayeredWindow.restype = wt.BOOL
gdi32.DeleteDC.argtypes = [wt.HDC]


class ShadowWindow:
    def __init__(self, panel):
        self.panel = panel
        self.hwnd = 0
        self._bitmap = None
        self._create()

    def _create(self):
        hinst = kernel32.GetModuleHandleW(None)
        ex = 0x00080000 | 0x00000020 | 0x08000000 | 0x00000080 | 0x00000008
        self.hwnd = user32.CreateWindowExW(
            ex, "STATIC", "", 0x80000000, 0, 0, 10, 10,
            None, None, hinst, None)

    def _build(self):
        W, H, S = self.panel.W, self.panel.H, self.panel.S
        margin = max(24, int(28 * S))
        w, h = W + 2 * margin, H + 2 * margin
        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = w
        bmi.bmiHeader.biHeight = -h
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = 0
        bits = ctypes.c_void_p()
        memdc = gdi32.CreateCompatibleDC(None)
        hbm = gdi32.CreateDIBSection(memdc, ctypes.byref(bmi), 0,
                                     ctypes.byref(bits), None, 0)
        gdi32.SelectObject(memdc, hbm)
        buf = bytearray(w * h * 4)
        cx, cy = margin + W / 2.0, margin + H / 2.0
        r = 16.0 * S
        hx, hy = W / 2.0 - r, H / 2.0 - r
        sigma = 6.0 * S
        kw = 1.0 / (2.0 * sigma * sigma)
        limit = 3.0 * sigma
        for yy in range(h):
            py = yy + 0.5
            qy = abs(py - cy) - hy
            if qy > limit + r:
                continue
            oy = qy if qy > 0 else 0.0
            for xx in range(w):
                px = xx + 0.5
                qx = abs(px - cx) - hx
                if qx > limit + r:
                    continue
                ox = qx if qx > 0 else 0.0
                d = math.hypot(ox, oy) + min(max(qx, qy), 0.0) - r
                i = (yy * w + xx) * 4
                if -3.0 < d <= 3.0:
                    cov = 1.0 if d <= 1.8 else max(0.0, (3.0 - d) / 1.2)
                    a = int(255 * cov)
                    buf[i] = 60 * a // 255
                    buf[i + 1] = 60 * a // 255
                    buf[i + 2] = 60 * a // 255
                    buf[i + 3] = a
                elif 3.0 < d < limit:
                    a = int(40.0 * math.exp(-(d * d) * kw))
                    if a > 0:
                        buf[i + 3] = a
        ctypes.memmove(bits, bytes(buf), len(buf))
        self._bitmap = (w, h, memdc, hbm, margin)

    def _top(self):
        return user32.GetAncestor(self.panel.hwnd, 2) or self.panel.hwnd

    def show(self, x, y):
        if not self.hwnd:
            return
        if not getattr(self.panel, "_visible", True):
            return
        if self._bitmap is None:
            self._build()
        w, h, memdc, _hbm, margin = self._bitmap
        pt_dst = wt.POINT(int(x) - margin, int(y) - margin)
        size = wt.SIZE(w, h)
        pt_src = wt.POINT(0, 0)
        blend = BLENDFUNCTION(0, 0, 255, 1)
        user32.UpdateLayeredWindow(self.hwnd, None, ctypes.byref(pt_dst),
                                   ctypes.byref(size), memdc,
                                   ctypes.byref(pt_src), 0,
                                   ctypes.byref(blend), 2)
        user32.SetWindowPos(self.hwnd, self._top(),
                            int(x) - margin, int(y) - margin, w, h,
                            0x0010 | 0x0040)

    def move(self, x, y):
        if not self.hwnd or self._bitmap is None:
            return
        w, h, _memdc, _hbm, margin = self._bitmap
        user32.SetWindowPos(self.hwnd, self._top(),
                            int(x) - margin, int(y) - margin, w, h, 0x0010)

    def hide(self):
        if self.hwnd:
            user32.ShowWindow(self.hwnd, 0)

    def destroy(self):
        if self.hwnd:
            user32.DestroyWindow(self.hwnd)
            self.hwnd = 0
        if self._bitmap:
            _w, _h, memdc, hbm, _m = self._bitmap
            gdi32.DeleteObject(hbm)
            gdi32.DeleteDC(memdc)
            self._bitmap = None


class Panel:
    LW, LH = 560, 399

    def _f(self, size, bold=False):
        return (FONT, -int(round(size * self.S)),
                "bold" if bold else "normal")

    def __init__(self, app: "TrayApp"):
        self.app = app
        self.S = max(1.0, UI_SCALE)
        self.W = int(self.LW * self.S)
        self.H = int(self.LH * self.S)
        self.root = tk.Tk()
        self.root.title("2.4G 外设电量")
        self.root.overrideredirect(True)
        self.root.configure(bg="#0B1322")
        self.light = app.theme_light
        self.cv = tk.Canvas(self.root, width=self.W, height=self.H,
                            highlightthickness=0, bd=0, bg="#0B1322")
        self.cv.pack(fill="both", expand=True)
        self.cv.bind("<Button-1>", self._on_press)
        self.cv.bind("<B1-Motion>", self._on_drag)
        self.cv.bind("<ButtonRelease-1>", self._on_release)
        self.root.bind("<Escape>", lambda e: self.hide())
        self._drag = None
        self._entry = None
        self._entry_key = None
        self._card_rects = {}
        self._startup_var = startup_enabled()
        self.root.update_idletasks()
        hwnd = self.root.winfo_id()
        self.hwnd = hwnd
        set_round_region(hwnd, self.W, self.H, int(32 * self.S))
        self._visible = False
        self._shadow = None
        try:
            self._shadow = ShadowWindow(self)
        except Exception:
            self._shadow = None
        self._center()
        self.root.withdraw()

    def _center(self):
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = max(0, (sw - self.W) // 2)
        y = max(0, (sh - self.H) // 2 - 40)
        self.root.geometry(f"{self.W}x{self.H}+{x}+{y}")

    def _on_press(self, e):
        self._drag = None
        if e.y >= 64 * self.S:
            return
        tags = self.cv.gettags("current")
        if any(t.startswith(("btn_", "chk_")) for t in tags):
            return
        self._drag = (e.x_root, e.y_root,
                      self.root.winfo_x(), self.root.winfo_y())

    def _on_drag(self, e):
        if not self._drag:
            return
        x0, y0, wx, wy = self._drag
        dx = e.x_root - x0
        dy = e.y_root - y0
        if abs(dx) < 3 and abs(dy) < 3:
            return
        nx = wx + dx
        ny = wy + dy
        self.root.geometry(f"+{nx}+{ny}")
        if self._shadow:
            try:
                self._shadow.move(nx, ny)
            except Exception:
                pass

    def _on_release(self, e):
        self._drag = None

    def show(self):
        self._visible = True
        self.render()
        self.root.deiconify()
        self.root.lift()
        if self._shadow:
            try:
                self.root.update_idletasks()
                self._shadow.show(self.root.winfo_x(), self.root.winfo_y())
            except Exception:
                pass

    def hide(self):
        self._visible = False
        if self._shadow:
            try:
                self._shadow.hide()
            except Exception:
                pass
        self.root.withdraw()

    DSH_BG = (27, 27, 28)
    DSH_CARD = (33, 33, 35)
    DSH_BORDER = (48, 49, 54)
    DSH_TEXT = (245, 245, 247)
    DSH_SUB = (160, 163, 168)
    DSH_MUTED = (120, 123, 128)
    DSH_BTN = (67, 69, 74)
    DSH_TRACK = (46, 47, 51)

    def render(self):
        cv = self.cv
        cv.delete("all")
        W, H = self.LW, self.LH
        cv.create_rectangle(0, 0, W, H, fill=_rgb(self.DSH_BG), outline="")

        snap = self.app.snapshot()
        r = snap.get("mouse") or Reading(ok=False, name="达尔优 AE6 V2")

        # 渲染达尔优 AE6 V2 卡片
        x1, y1, x2, y2 = 24, 88, W - 24, 210
        draw_round_rect(cv, x1, y1, x2, y2, 12,
                        fill=_rgb(self.DSH_CARD), outline=_rgb(self.DSH_BORDER), width=1)

        cv.create_text(x1 + 18, y1 + 22, text=r.name, anchor="w",
                       fill=_rgb(self.DSH_TEXT), font=self._f(13, True))

        status_text = STATUS_TEXT.get(r.status, "使用中")
        line_desc = f"{r.detail} · {status_text}" if r.ok else r.detail
        cv.create_text(x1 + 18, y1 + 46, text=line_desc, anchor="w",
                       fill=_rgb(self.DSH_SUB), font=self._f(9))

        lv = r.level if r.ok else None
        if r.ok and lv is not None:
            cv.create_text(x2 - 46, y1 + 40, text=str(lv), anchor="e",
                           fill=_rgb((34, 197, 94) if lv > 20 else (239, 68, 68)),
                           font=self._f(32, True))
            cv.create_text(x2 - 24, y1 + 40, text="%", anchor="e",
                           fill=_rgb(self.DSH_SUB), font=self._f(12, True))
        else:
            cv.create_text(x2 - 24, y1 + 40, text="未连接", anchor="e",
                           fill=_rgb(self.DSH_MUTED), font=self._f(14, True))

        # 电量条底轨
        bx1, bx2 = x1 + 18, x2 - 18
        by = y2 - 24
        draw_round_rect(cv, bx1, by, bx2, by + 6, 3,
                        fill=_rgb(self.DSH_TRACK), outline="")
        if lv is not None and lv > 0:
            w = int((bx2 - bx1) * (lv / 100.0))
            col = (34, 197, 94) if lv > 20 else (239, 68, 68)
            draw_round_rect(cv, bx1, by, bx1 + max(6, w), by + 6, 3,
                            fill=_rgb(col), outline="")

        # 顶栏标题
        cv.create_text(30, 34, text="外设电量", anchor="w",
                       fill=_rgb(self.DSH_TEXT), font=self._f(16, True))
        cv.create_text(30, 56, text="2.4G 无线外设 · 达尔优 AE6 V2 监控", anchor="w",
                       fill=_rgb(self.DSH_SUB), font=self._f(9))

        # 顶栏关闭按钮
        cv.create_text(W - 30, 30, text="✕", fill=_rgb(self.DSH_SUB),
                       font=self._f(11), tags=("btn_close",))
        cv.tag_bind("btn_close", "<Button-1>", lambda e: self.hide())
        cv.tag_bind("btn_close", "<Enter>", lambda e: cv.configure(cursor="hand2"))
        cv.tag_bind("btn_close", "<Leave>", lambda e: cv.configure(cursor=""))

        # 底栏与操作
        stamp = time.strftime("%H:%M:%S", time.localtime(r.ts)) if r.ts else "--:--"
        cv.create_text(24, 372, text=f"上次更新: {stamp}", anchor="w",
                       fill=_rgb(self.DSH_MUTED), font=self._f(9), tags=("btn_ref",))
        cv.tag_bind("btn_ref", "<Button-1>", lambda e: self.app.refresh())

        self._check(380, 372, self._startup_var, "开机自启", self._toggle_startup)

        draw_round_rect(cv, 472, 360, 536, 384, 6, fill=_rgb(self.DSH_BTN), outline="")
        cv.create_text(504, 372, text="退出", fill=_rgb(self.DSH_TEXT),
                       font=self._f(9), tags=("btn_quit",))
        cv.tag_bind("btn_quit", "<Button-1>", lambda e: self.app.quit())

        cv.scale("all", 0, 0, self.S, self.S)

    def _check(self, x, y, checked, label, cmd):
        tag = f"chk_{label}"
        fill = self.DSH_BTN if checked else self.DSH_BG
        border = self.DSH_BTN if checked else self.DSH_BORDER
        draw_round_rect(self.cv, x, y - 6, x + 12, y + 6, 3.5,
                        fill=_rgb(fill), outline=_rgb(border), width=1, tags=(tag,))
        if checked:
            self.cv.create_line(x + 3, y + 1, x + 5.5, y + 3.5, x + 9.5, y - 3,
                                fill=_rgb(self.DSH_TEXT), width=2, tags=(tag,))
        self.cv.create_text(x + 20, y, text=label, fill=_rgb(self.DSH_SUB),
                            font=self._f(9), tags=(tag,), anchor="w")
        self.cv.tag_bind(tag, "<Button-1>", lambda e: cmd())

    def _toggle_startup(self):
        if self._startup_var:
            remove_startup()
            self._startup_var = False
        else:
            self._startup_var = install_startup()
        self.render()


# ===========================================================================
# 托盘与消息调度
# ===========================================================================
WM_APP = 0x8000
WM_TRAYICON = WM_APP + 1
WM_APP_REFRESH = WM_APP + 2
WM_APP_SHOW = WM_APP + 3
WM_TIMER = 0x0113
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_LBUTTONUP = 0x0202
WM_RBUTTONUP = 0x0205

NIM_ADD = 0
NIM_MODIFY = 1
NIM_DELETE = 2
NIF_MESSAGE = 1
NIF_ICON = 2
NIF_TIP = 4

WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)

class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wt.UINT), ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON),
                ("hCursor", wt.HANDLE), ("hbrBackground", wt.HBRUSH),
                ("lpszMenuName", wt.LPCWSTR), ("lpszClassName", wt.LPCWSTR)]

class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("hWnd", wt.HWND), ("uID", wt.UINT),
                ("uFlags", wt.UINT), ("uCallbackMessage", wt.UINT),
                ("hIcon", wt.HICON), ("szTip", wt.WCHAR * 128),
                ("dwState", wt.DWORD), ("dwStateMask", wt.DWORD),
                ("szInfo", wt.WCHAR * 256), ("uVersion", wt.UINT),
                ("szInfoTitle", wt.WCHAR * 64), ("dwInfoFlags", wt.DWORD),
                ("guidItem", GUID), ("hBalloonIcon", wt.HICON)]


class Tray:
    CLASS_NAME = "BatteryTrayDareu"

    def __init__(self, app: "TrayApp"):
        self.app = app
        self.hwnd = 0
        self.cur_icon = 0
        self.nid = None
        self._wndproc = WNDPROC(self._proc)

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        hinst = kernel32.GetModuleHandleW(None)
        wc = WNDCLASSW()
        wc.lpfnWndProc = self._wndproc
        wc.hInstance = hinst
        wc.lpszClassName = self.CLASS_NAME
        user32.RegisterClassW(ctypes.byref(wc))
        self.hwnd = user32.CreateWindowExW(0, self.CLASS_NAME, "AE6V2", 0,
                                           0, 0, 0, 0, None, None, hinst, None)
        if not self.hwnd:
            return

        self.nid = NOTIFYICONDATAW()
        self.nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        self.nid.hWnd = self.hwnd
        self.nid.uID = 1
        self.nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        self.nid.uCallbackMessage = WM_TRAYICON
        self.nid.hIcon = make_battery_icon(-1, False, False)
        self.nid.szTip = "达尔优 AE6 V2: 侦测中..."
        shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(self.nid))

        user32.SetTimer(self.hwnd, 1, 4000, None)

        msg = wt.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        self.app._stop = True

    def sync_icons(self):
        r = self.app.snapshot().get("mouse")
        lvl = r.level if (r and r.ok) else None
        charging = bool(r and r.status in ("charging", "full", "wired"))
        icon = make_battery_icon(lvl, self.app.theme_light, charging)

        if self.nid:
            self.nid.hIcon = icon
            tip = f"达尔优 AE6 V2: {r.level}%\n{STATUS_TEXT.get(r.status, '使用中')}" if (r and r.ok) else "达尔优 AE6 V2: 未连接"
            self.nid.szTip = tip[:127]
            shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self.nid))

        if self.cur_icon:
            user32.DestroyIcon(self.cur_icon)
        self.cur_icon = icon

    def destroy(self):
        if self.nid:
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self.nid))
        if self.cur_icon:
            user32.DestroyIcon(self.cur_icon)

    def _proc(self, hwnd, msg, wparam, lparam):
        if msg == WM_TRAYICON:
            cmd = lparam & 0xFFFF
            if cmd == WM_LBUTTONUP:
                self.app.request_show()
            elif cmd == WM_RBUTTONUP:
                self.app.refresh()
            return 0
        if msg == WM_TIMER:
            self.app.refresh()
            return 0
        if msg == WM_APP_REFRESH:
            self.sync_icons()
            return 0
        if msg in (WM_CLOSE, WM_DESTROY):
            self.destroy()
            user32.KillTimer(hwnd, 1)
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)


# ===========================================================================
# 应用程序主入口
# ===========================================================================
class TrayApp:
    def __init__(self, panel_only: bool = False):
        self.panel_only = panel_only
        self.theme_light = is_light_theme()
        self.interval = 5
        self._readings: dict[str, Reading] = {}
        self._lock = threading.Lock()
        self._refreshing = False
        self._stop = False
        self.tray: Optional[Tray] = None
        self.panel: Optional[Panel] = None
        self._show_requested = False

    def snapshot(self) -> dict[str, Reading]:
        with self._lock:
            return dict(self._readings)

    def refresh(self):
        if self._refreshing:
            return
        self._refreshing = True
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        try:
            ifaces = enumerate_hid()
            res = {"mouse": read_mouse(ifaces)}
        except Exception:
            res = {}
        with self._lock:
            self._readings = res
        self._refreshing = False
        if self.tray and self.tray.hwnd:
            user32.PostMessageW(self.tray.hwnd, WM_APP_REFRESH, 0, 0)
        if self.panel and self.panel.root.winfo_viewable():
            self.panel.root.after(0, self.panel.render)

    def request_show(self):
        self._show_requested = True

    def quit(self):
        self._stop = True
        if self.tray and self.tray.hwnd:
            user32.PostMessageW(self.tray.hwnd, WM_CLOSE, 0, 0)
        if self.panel:
            try:
                self.panel.hide()
            except Exception:
                pass
        try:
            self.root.quit()
        except Exception:
            pass

    def run(self):
        migrate_startup_link()
        self.panel = Panel(self)
        self.root = self.panel.root
        if not self.panel_only:
            self.tray = Tray(self)
            self.tray.start()
        self.refresh()

        def tick():
            if self._show_requested:
                self._show_requested = False
                self.panel.show()
            if self._stop:
                self.root.quit()
                return
            self.root.after(200, tick)

        self.root.after(200, tick)
        if self.panel_only:
            self.panel.show()
        self.root.mainloop()
        try:
            if self.tray:
                self.tray.destroy()
        except Exception:
            pass
        os._exit(0)


def main(argv):
    user32.SetProcessDPIAware()
    mutex = kernel32.CreateMutexW(None, False, "Local\\BatteryTrayDareu_Mutex")
    if ctypes.get_last_error() == 183 and mutex:
        return 0
    app = TrayApp(panel_only="--panel" in argv)
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
