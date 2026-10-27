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
# Win32 基础 API
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

hid.HidD_GetAttributes.argtypes = [wt.HANDLE, ctypes.POINTER(HIDD_ATTRIBUTES)]
hid.HidD_GetPreparsedData.argtypes = [wt.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(HIDP_CAPS)]
hid.HidD_GetProductString.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.ULONG]

GUID_DEVINTERFACE_HID = GUID("{4D1E55B2-F16F-11CF-88CB-001111000030}")
DIGCF_PRESENT = 0x02
DIGCF_DEVICEINTERFACE = 0x10


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
                out.append(HidIface(
                    path=path, vid=attrs.VendorID, pid=attrs.ProductID,
                    usage_page=caps.UsagePage, usage=caps.Usage,
                    input_len=caps.InputReportByteLength,
                    output_len=caps.OutputReportByteLength,
                    feature_len=caps.FeatureReportByteLength,
                    product=prod.value))
            finally:
                kernel32.CloseHandle(h)
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(hdev)
    return out


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wt.DWORD), ("OffsetHigh", wt.DWORD),
                ("hEvent", wt.HANDLE)]


class HidDevice:
    def __init__(self, path: str, write: bool = False):
        self.path = path
        access = GENERIC_READ | (GENERIC_WRITE if write else 0)
        self.h = _open_path(path, access)
        self.rh = _open_path(path, GENERIC_READ, overlapped=True)

    def close(self):
        for h in (self.rh, self.h):
            if h and h != INVALID_HANDLE_VALUE:
                kernel32.CloseHandle(h)
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
    raw: bytes = b""
    ts: float = dataclasses.field(default_factory=time.time)
    present: bool = True
    stale: bool = False
    vid: int = 0
    pid: int = 0

    @property
    def text(self) -> str:
        return f"{self.level}%" if self.ok and self.level is not None else "未连接"


STATUS_TEXT = {"charging": "充电中 ⚡", "discharging": "放电中",
               "full": "已充满 ⚡", "wired": "有线直连 ⚡", "unknown": "使用中"}


# ===========================================================================
# 达尔优 AE6 V2 专属协议驱动（原厂抓包匹配）
# ===========================================================================
def dareu_read(ifaces: list[HidIface]) -> Optional[Reading]:
    """达尔优 AE6 V2 原厂 WebHID 协议精准解析"""
    cands = [d for d in ifaces if d.vid == 0x260D and d.pid in (0x1261, 0x1260, 0x04ED)]
    if not cands:
        return None

    # 排除鼠标指针接口 (UsagePage 0x01)
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
                if not rep or len(rep) < 4:
                    continue

                if rep[0] != 0x08:
                    continue

                bat = -1
                status = "discharging"

                # 1. 状态判断 (Data[2])：2 为插线充电或充满；有线 PID 0x1260 也判定为充电
                if rep[2] == 2 or d.pid == 0x1260:
                    status = "charging"

                # 2. 检查充满饱和特征：5~12 字节全为 255 (0xFF)[cite: 8]
                if len(rep) >= 13 and all(b == 255 for b in rep[5:13]):
                    bat = 100
                    status = "full" if status == "charging" else "discharging"

                # 3. 正常工作或充电过程中的电量获取
                if bat == -1:
                    # 187 字节长配置帧
                    if len(rep) >= 187 and 0 < rep[19] <= 100:
                        bat = rep[19]
                    # 16 字节短报文：Data[3] 对应实际百分比或档位
                    elif 0 < rep[3] <= 100:
                        bat = rep[3]

                if bat != -1:
                    detail_str = "已充满" if bat == 100 else f"电量 {bat}%"
                    if status in ("charging", "wired"):
                        detail_str += " · 充电中"
                    return Reading(ok=True, level=bat, status=status,
                                   name="达尔优 AE6 V2", source="达尔优协议",
                                   detail=detail_str, raw=rep, vid=d.vid, pid=d.pid, present=True)
        except Exception:
            pass
        finally:
            if dev:
                dev.close()

    # 无法直接读取电量数值时的真实状态提示
    return Reading(ok=False, name="达尔优 AE6 V2", source="达尔优协议",
                   detail="接收器已连接，等待鼠标唤醒", vid=0x260D, pid=0x1261, present=True)


def read_mouse(ifaces: list[HidIface]) -> Reading:
    r_dareu = dareu_read(ifaces)
    if r_dareu:
        r_dareu.name = "达尔优 AE6 V2"
        return r_dareu

    return Reading(ok=False, name="达尔优 AE6 V2", source="", present=False,
                   detail="未检测到达尔优无线鼠标")


def read_all(ifaces: Optional[list[HidIface]] = None) -> dict[str, Reading]:
    ifaces = ifaces if ifaces is not None else enumerate_hid()
    mouse = read_mouse(ifaces)
    return {"mouse": mouse}


# ===========================================================================
# 基础配置与自启
# ===========================================================================
def config_dir() -> str:
    base = os.environ.get("APPDATA") or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "BatteryTray")


def startup_lnk() -> str:
    buf = ctypes.create_unicode_buffer(260)
    shell32.SHGetFolderPathW(None, 0x0007, None, 0, buf)
    return os.path.join(buf.value, "2.4G.lnk")


def startup_enabled() -> bool:
    return os.path.isfile(startup_lnk())


def install_startup() -> bool:
    path = startup_lnk()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    exe = sys.executable or ""
    script = os.path.abspath(__file__)
    if getattr(sys, "frozen", False):
        target, args = os.path.abspath(sys.executable), ""
    else:
        pythonw = exe[:-len("python.exe")] + "pythonw.exe" if exe.lower().endswith("python.exe") else exe
        target, args = (pythonw, f'"{script}"') if os.path.isfile(pythonw) else (exe, f'"{script}"')
    
    # 建立快捷方式
    try:
        import win32com.client
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(path)
        shortcut.TargetPath = target
        shortcut.Arguments = args
        shortcut.WorkingDirectory = os.path.dirname(script)
        shortcut.save()
        return True
    except Exception:
        # PowerShell 兜底
        ps = f'$s=(New-Object -COM WScript.Shell).CreateShortcut("{path}");$s.TargetPath="{target}";$s.Arguments=\'{args}\';$s.WorkingDirectory="{os.path.dirname(script)}";$s.Save()'
        subprocess.run(["powershell", "-Command", ps], capture_output=True)
        return os.path.isfile(path)


def remove_startup() -> None:
    if os.path.isfile(startup_lnk()):
        try:
            os.remove(startup_lnk())
        except Exception:
            pass


# ===========================================================================
# 图标渲染（GDI 高精圆环超采样）
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


gdi32.CreateCompatibleDC.restype = wt.HDC
gdi32.CreateDIBSection.restype = wt.HBITMAP
gdi32.CreateBitmap.restype = wt.HBITMAP
gdi32.SelectObject.restype = wt.HGDIOBJ
user32.CreateIconIndirect.restype = wt.HICON

COLORREF = lambda r, g, b: (r & 0xFF) | ((g & 0xFF) << 8) | ((b & 0xFF) << 16)


class _LogBrush(ctypes.Structure):
    _fields_ = [("lbStyle", wt.UINT), ("lbColor", wt.COLORREF), ("lbHatch", ctypes.c_void_p)]


def _ring_pen(rgb, width: int) -> int:
    lb = _LogBrush(lbStyle=0, lbColor=COLORREF(*rgb), lbHatch=0)
    gdi32.ExtCreatePen.restype = wt.HPEN
    return gdi32.ExtCreatePen(0x00010000 | 0x00000200, width, ctypes.byref(lb), 0, None)


def make_battery_icon(level: Optional[int], light: bool, charging: bool = False, size: int = 32) -> int:
    SS = 4
    big = size * SS
    hdc_screen = user32.GetDC(None)
    memdc = gdi32.CreateCompatibleDC(hdc_screen)

    bmi = BITMAPINFO()
    bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.bmiHeader.biWidth = big
    bmi.bmiHeader.biHeight = -big
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bits = ctypes.c_void_p()
    hbm_big = gdi32.CreateDIBSection(memdc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0)
    old = gdi32.SelectObject(memdc, hbm_big)
    try:
        bg = gdi32.CreateSolidBrush(COLORREF(255, 0, 255))
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
        gdi32.SelectObject(memdc, gdi32.GetStockObject(5))
        gdi32.Ellipse(memdc, int(cx - radius), int(cy - radius), int(cx + radius), int(cy + radius))

        if level is not None:
            if charging:
                r, g, b = 34, 197, 94
            elif level >= 60:
                r, g, b = 34, 197, 94
            elif level >= 30:
                r, g, b = 245, 158, 11
            else:
                r, g, b = 239, 68, 68
            pen_arc = _ring_pen((r, g, b), thick)
            gdi32.SelectObject(memdc, pen_arc)
            if level >= 100:
                gdi32.Ellipse(memdc, int(cx - radius), int(cy - radius), int(cx + radius), int(cy + radius))
            else:
                theta = 2.0 * math.pi * max(2, min(100, level)) / 100.0
                ex = cx + radius * math.cos(-math.pi / 2 + theta)
                ey = cy + radius * math.sin(-math.pi / 2 + theta)
                gdi32.Arc(memdc, int(cx - radius), int(cy - radius), int(cx + radius), int(cy + radius),
                          int(round(ex)), int(round(ey)), int(cx), int(cy - radius))
            gdi32.DeleteObject(pen_arc)

        gdi32.SelectObject(memdc, old)
        gdi32.GdiFlush()
        raw = ctypes.string_at(bits, big * big * 4)

        small = bytearray(size * size * 4)
        for y in range(size):
            for x in range(size):
                cnt, rs, gs, bs = 0, 0, 0, 0
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
        bits2 = ctypes.c_void_p()
        hbm_small = gdi32.CreateDIBSection(memdc, ctypes.byref(bmi2), 0, ctypes.byref(bits2), None, 0)
        ctypes.memmove(bits2, bytes(small), len(small))

        mask = gdi32.CreateBitmap(size, size, 1, 1, None)
        ii = ICONINFO(fIcon=1, xHotspot=0, yHotspot=0, hbmMask=mask, hbmColor=hbm_small)
        icon = user32.CreateIconIndirect(ctypes.byref(ii))
        gdi32.DeleteObject(mask)
        gdi32.DeleteObject(hbm_small)
        return icon
    finally:
        gdi32.DeleteObject(hbm_big)
        gdi32.DeleteDC(memdc)
        user32.ReleaseDC(None, hdc_screen)


# ===========================================================================
# 交互式管理面板
# ===========================================================================
import tkinter as tk

FONT = "Microsoft YaHei UI"


def _rgb(c):
    return "#%02x%02x%02x" % c


def round_rect_points(x1, y1, x2, y2, r, steps=10):
    pts = []
    for cx, cy, a0 in ((x2 - r, y1 + r, -90), (x2 - r, y2 - r, 0),
                       (x1 + r, y2 - r, 90), (x1 + r, y1 + r, 180)):
        for i in range(steps + 1):
            a = (a0 + 90 * i / steps) * 3.141592653589793 / 180
            pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
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


class Panel:
    LW, LH = 560, 399

    def _f(self, size, bold=False):
        return (FONT, -int(round(size * self.S)), "bold" if bold else "normal")

    def __init__(self, app: "TrayApp"):
        self.app = app
        self.S = max(1.0, UI_SCALE)
        self.W = int(self.LW * self.S)
        self.H = int(self.LH * self.S)
        self.root = tk.Tk()
        self.root.title("2.4G 外设电量")
        self.root.overrideredirect(True)
        self.root.configure(bg="#1B1B1C")
        self.cv = tk.Canvas(self.root, width=self.W, height=self.H,
                            highlightthickness=0, bd=0, bg="#1B1B1C")
        self.cv.pack(fill="both", expand=True)
        self.cv.bind("<Button-1>", self._on_press)
        self.cv.bind("<B1-Motion>", self._on_drag)
        self.cv.bind("<ButtonRelease-1>", lambda e: setattr(self, "_drag", None))
        self.root.bind("<Escape>", lambda e: self.hide())
        self._drag = None
        self._startup_var = startup_enabled()
        self.root.update_idletasks()
        set_round_region(self.root.winfo_id(), self.W, self.H, int(28 * self.S))
        self._center()
        self.root.withdraw()

    def _center(self):
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = max(0, (sw - self.W) // 2)
        y = max(0, (sh - self.H) // 2 - 40)
        self.root.geometry(f"{self.W}x{self.H}+{x}+{y}")

    def _on_press(self, e):
        if e.y >= 64 * self.S:
            return
        tags = self.cv.gettags("current")
        if any(t.startswith(("btn_", "chk_")) for t in tags):
            return
        self._drag = (e.x_root, e.y_root, self.root.winfo_x(), self.root.winfo_y())

    def _on_drag(self, e):
        if not self._drag:
            return
        x0, y0, wx, wy = self._drag
        self.root.geometry(f"+{wx + e.x_root - x0}+{wy + e.y_root - y0}")

    def show(self):
        self.render()
        self.root.deiconify()
        self.root.lift()

    def hide(self):
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

        # 鼠标卡片
        x1, y1, x2, y2 = 24, 88, W - 24, 210
        draw_round_rect(cv, x1, y1, x2, y2, 12, fill=_rgb(self.DSH_CARD), outline=_rgb(self.DSH_BORDER), width=1)

        cv.create_text(x1 + 18, y1 + 22, text=r.name, anchor="w",
                       fill=_rgb(self.DSH_TEXT), font=self._f(13, True))

        status_text = STATUS_TEXT.get(r.status, "使用中")
        line_desc = f"{r.detail} · {status_text}" if r.ok else r.detail
        cv.create_text(x1 + 18, y1 + 46, text=line_desc, anchor="w",
                       fill=_rgb(self.DSH_SUB), font=self._f(9))

        lv = r.level if r.ok else None
        if r.ok and lv is not None:
            col = (34, 197, 94) if lv > 20 else (239, 68, 68)
            cv.create_text(x2 - 46, y1 + 40, text=str(lv), anchor="e",
                           fill=_rgb(col), font=self._f(32, True))
            cv.create_text(x2 - 24, y1 + 40, text="%", anchor="e",
                           fill=_rgb(self.DSH_SUB), font=self._f(12, True))
        else:
            cv.create_text(x2 - 24, y1 + 40, text="未连接", anchor="e",
                           fill=_rgb(self.DSH_MUTED), font=self._f(14, True))

        # 电量条底轨与填充
        bx1, bx2 = x1 + 18, x2 - 18
        by = y2 - 24
        draw_round_rect(cv, bx1, by, bx2, by + 6, 3, fill=_rgb(self.DSH_TRACK), outline="")
        if lv is not None and lv > 0:
            w = int((bx2 - bx1) * (lv / 100.0))
            col = (34, 197, 94) if lv > 20 else (239, 68, 68)
            draw_round_rect(cv, bx1, by, bx1 + max(6, w), by + 6, 3, fill=_rgb(col), outline="")

        # 顶栏
        cv.create_text(30, 34, text="外设电量", anchor="w", fill=_rgb(self.DSH_TEXT), font=self._f(16, True))
        cv.create_text(30, 56, text="2.4G 无线外设 · 达尔优 AE6 V2 监控", anchor="w", fill=_rgb(self.DSH_SUB), font=self._f(9))

        cv.create_text(W - 30, 30, text="✕", fill=_rgb(self.DSH_SUB), font=self._f(11), tags=("btn_close",))
        cv.tag_bind("btn_close", "<Button-1>", lambda e: self.hide())
        cv.tag_bind("btn_close", "<Enter>", lambda e: cv.configure(cursor="hand2"))
        cv.tag_bind("btn_close", "<Leave>", lambda e: cv.configure(cursor=""))

        # 底栏
        stamp = time.strftime("%H:%M:%S", time.localtime(r.ts)) if r.ts else "--:--"
        cv.create_text(24, 372, text=f"上次更新: {stamp}", anchor="w", fill=_rgb(self.DSH_MUTED), font=self._f(9), tags=("btn_ref",))
        cv.tag_bind("btn_ref", "<Button-1>", lambda e: self.app.refresh())

        self._check(380, 372, self._startup_var, "开机自启", self._toggle_startup)

        draw_round_rect(cv, 472, 360, 536, 384, 6, fill=_rgb(self.DSH_BTN), outline="")
        cv.create_text(504, 372, text="退出", fill=_rgb(self.DSH_TEXT), font=self._f(9), tags=("btn_quit",))
        cv.tag_bind("btn_quit", "<Button-1>", lambda e: self.app.quit())

        cv.scale("all", 0, 0, self.S, self.S)

    def _check(self, x, y, checked, label, cmd):
        tag = f"chk_{label}"
        fill = self.DSH_BTN if checked else self.DSH_BG
        border = self.DSH_BTN if checked else self.DSH_BORDER
        draw_round_rect(self.cv, x, y - 6, x + 12, y + 6, 3.5, fill=_rgb(fill), outline=_rgb(border), width=1, tags=(tag,))
        if checked:
            self.cv.create_line(x + 3, y + 1, x + 5.5, y + 3.5, x + 9.5, y - 3, fill=_rgb(self.DSH_TEXT), width=2, tags=(tag,))
        self.cv.create_text(x + 20, y, text=label, fill=_rgb(self.DSH_SUB), font=self._f(9), tags=(tag,), anchor="w")
        self.cv.tag_bind(tag, "<Button-1>", lambda e: cmd())

    def _toggle_startup(self):
        if self._startup_var:
            remove_startup()
            self._startup_var = False
        else:
            self._startup_var = install_startup()
        self.render()


# ===========================================================================
# 托盘调度
# ===========================================================================
WM_APP = 0x8000
WM_TRAYICON = WM_APP + 1
WM_APP_REFRESH = WM_APP + 2
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
        self.hwnd = user32.CreateWindowExW(0, self.CLASS_NAME, "AE6V2", 0, 0, 0, 0, 0, None, None, hinst, None)
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
        icon = make_battery_icon(lvl, False, charging)

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
# 应用程序核心编排
# ===========================================================================
class TrayApp:
    def __init__(self, panel_only: bool = False):
        self.panel_only = panel_only
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
