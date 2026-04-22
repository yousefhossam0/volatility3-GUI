#!/usr/bin/env python3
"""
Volatility 3 — Professional Forensic Workstation GUI
A modern, feature-rich graphical interface for the Volatility 3 memory forensics framework.

Copyright (C) 2024 — Built on top of the Volatility Foundation framework.
"""

import sys
import os
import io
import csv
import json
import hashlib
import logging
import datetime
import tempfile
import traceback
import pathlib
import re
import psutil
from typing import Any, Dict, List, Optional, Type, Tuple
from urllib import parse, request
from collections import Counter

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem,
    QTabWidget, QTextEdit, QLineEdit, QLabel, QPushButton, QFileDialog,
    QProgressBar, QStatusBar, QToolBar, QMenuBar, QMenu, QGroupBox,
    QFormLayout, QSpinBox, QCheckBox, QComboBox, QHeaderView,
    QMessageBox, QFrame, QScrollArea, QSizePolicy, QAbstractItemView,
    QDialog, QDialogButtonBox, QPlainTextEdit, QStyle, QGridLayout,
    QGraphicsOpacityEffect, QStackedWidget, QTreeWidgetItemIterator
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QSize, QTimer, QSortFilterProxyModel,
    QAbstractTableModel, QModelIndex, QVariant, QPropertyAnimation,
    QEasingCurve, QPoint, QRect, QMimeData, QSequentialAnimationGroup,
    QParallelAnimationGroup
)
from PyQt6.QtGui import (
    QFont, QColor, QIcon, QAction, QPalette, QPixmap, QPainter,
    QLinearGradient, QBrush, QPen, QFontDatabase, QKeySequence,
    QDragEnterEvent, QDropEvent, QShortcut, QClipboard
)

# ─── Volatility 3 Imports ───────────────────────────────────────────────────
import volatility3.plugins
import volatility3.symbols
from volatility3 import framework
from volatility3.framework import (
    automagic, configuration, constants, contexts,
    exceptions, interfaces, plugins,
)
from volatility3.framework.automagic import stacker
from volatility3.framework.configuration import requirements

# ─── Constants ───────────────────────────────────────────────────────────────
APP_NAME = "Volatility 3 — Forensic Workstation"
APP_VERSION = constants.PACKAGE_VERSION
CONFIG_DIR = pathlib.Path.home() / ".vol3gui"
BOOKMARKS_FILE = CONFIG_DIR / "bookmarks.json"
RECENT_FILES_FILE = CONFIG_DIR / "recent.json"
RECENT_PLUGINS_FILE = CONFIG_DIR / "recent_plugins.json"
MAX_RECENT_FILES = 10
MAX_RECENT_PLUGINS = 8

CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# ─── Color Palette ───────────────────────────────────────────────────────────
COLORS = {
    "bg_darkest":     "#05080f",
    "bg_dark":        "#0b1120",
    "bg_surface":     "#111a2e",
    "bg_surface_alt": "#162035",
    "bg_hover":       "#1c2d4a",
    "bg_selected":    "#1a3a5c",
    "primary":        "#38bdf8",
    "primary_dim":    "#0ea5e9",
    "primary_glow":   "rgba(56,189,248,0.15)",
    "secondary":      "#a78bfa",
    "accent":         "#67e8f9",
    "success":        "#34d399",
    "warning":        "#fbbf24",
    "error":          "#f87171",
    "danger":         "#ef4444",
    "text_primary":   "#f0f4f8",
    "text_secondary": "#94a3b8",
    "text_muted":     "#64748b",
    "border":         "#1e293b",
    "border_light":   "#334155",
    "border_focus":   "#38bdf8",
    "row_suspicious": "#2d1a0a",
}

# ─── Plugin Metadata: Friendly Names, Descriptions, Categories ──────────────
# Maps vol3 plugin names → (Friendly Name, Short Description, Functional Category)
PLUGIN_FRIENDLY = {
    # ── Process Analysis ──
    "windows.pslist.PsList":         ("Process List",         "List all running processes",                    "🔍 Process Analysis"),
    "windows.pstree.PsTree":        ("Process Tree",         "Show processes in parent → child hierarchy",    "🔍 Process Analysis"),
    "windows.psscan.PsScan":        ("Process Scanner",      "Find hidden or unlinked processes in memory",   "🔍 Process Analysis"),
    "windows.cmdline.CmdLine":      ("Command Lines",        "Show command-line arguments for each process",  "🔍 Process Analysis"),
    "windows.dlllist.DllList":       ("Loaded DLLs",          "List DLL modules loaded by each process",       "🔍 Process Analysis"),
    "windows.handles.Handles":      ("Open Handles",         "Show file, registry & object handles",          "🔍 Process Analysis"),
    "windows.ldrmodules.LdrModules": ("Hidden Modules",      "Detect DLLs hidden from the loader",            "🔍 Process Analysis"),
    "windows.envars.Envars":        ("Environment Vars",     "Show process environment variables",            "🔍 Process Analysis"),
    "windows.getsids.GetSIDs":      ("Process SIDs",         "Show security identifiers for each process",    "🔍 Process Analysis"),
    "windows.privileges.Privs":     ("Process Privileges",   "List process token privileges",                 "🔍 Process Analysis"),
    "windows.threads.Threads":      ("Thread List",          "List threads and their start addresses",        "🔍 Process Analysis"),
    "windows.sessions.Sessions":    ("Login Sessions",       "Show active login sessions",                    "🔍 Process Analysis"),

    # ── Network Analysis ──
    "windows.netscan.NetScan":      ("Network Connections",  "Find TCP/UDP connections and listeners",        "🌐 Network Analysis"),
    "windows.netstat.NetStat":      ("Network Status",       "Show active network connections (netstat)",      "🌐 Network Analysis"),

    # ── Malware Detection ──
    "windows.malfind.Malfind":      ("Malware Finder",       "Detect injected or suspicious code in memory",  "🦠 Malware Detection"),
    "windows.ssdt.SSDT":            ("SSDT Hooks",           "Check System Service Descriptor Table for hooks","🦠 Malware Detection"),
    "windows.callbacks.Callbacks":  ("Kernel Callbacks",     "List registered notification callbacks",        "🦠 Malware Detection"),
    "windows.driverirp.DriverIrp":  ("Driver IRP Hooks",     "Check driver IRP function table for hooks",     "🦠 Malware Detection"),
    "windows.svcscan.SvcScan":      ("Windows Services",     "Scan for Windows service records",              "🦠 Malware Detection"),
    "windows.hollowprocesses.HollowProcesses": ("Hollow Processes", "Detect process hollowing technique",     "🦠 Malware Detection"),

    # ── Memory Analysis ──
    "windows.memmap.Memmap":        ("Memory Map",           "Show virtual-to-physical address mappings",     "💾 Memory Analysis"),
    "windows.vadinfo.VadInfo":      ("VAD Info",             "Show Virtual Address Descriptor details",       "💾 Memory Analysis"),
    "windows.vadwalk.VadWalk":      ("VAD Walker",           "Walk the VAD tree for a process",               "💾 Memory Analysis"),
    "windows.virtmap.VirtMap":      ("Virtual Map",          "List virtual memory layer mappings",            "💾 Memory Analysis"),

    # ── File System ──
    "windows.filescan.FileScan":    ("File Scanner",         "Scan memory for FILE_OBJECT structures",        "📁 File System"),
    "windows.dumpfiles.DumpFiles":  ("Dump Files",           "Extract files from memory",                     "📁 File System"),
    "windows.mftscan.MFTScan":      ("MFT Scanner",          "Scan for Master File Table entries (NTFS)",     "📁 File System"),

    # ── Registry ──
    "windows.registry.hivelist.HiveList":    ("Registry Hives",    "List loaded registry hive files",         "🗝️ Registry"),
    "windows.registry.printkey.PrintKey":    ("Registry Keys",     "Print specific registry key values",      "🗝️ Registry"),
    "windows.registry.userassist.UserAssist":("User Assist",       "Show recently run programs (UserAssist)", "🗝️ Registry"),
    "windows.registry.hivescan.HiveScan":    ("Hive Scanner",      "Scan for registry hive structures",       "🗝️ Registry"),
    "windows.registry.certificates.Certificates": ("Certificates", "Extract certificates from registry",     "🗝️ Registry"),

    # ── Credentials ──
    "windows.hashdump.Hashdump":    ("Password Hashes",      "Dump Windows password hashes (SAM)",            "🔐 Credentials"),
    "windows.lsadump.Lsadump":     ("LSA Secrets",          "Dump LSA secrets from memory",                  "🔐 Credentials"),
    "windows.cachedump.Cachedump":  ("Cached Credentials",   "Dump cached domain logon credentials",          "🔐 Credentials"),

    # ── System Information ──
    "windows.info.Info":            ("System Info",          "Show OS version, hardware & build info",        "ℹ️ System Info"),
    "windows.modules.Modules":     ("Kernel Modules",       "List loaded kernel drivers/modules",            "ℹ️ System Info"),
    "windows.driverscan.DriverScan":("Driver Scanner",      "Scan for kernel driver objects",                "ℹ️ System Info"),
    "windows.verinfo.VerInfo":      ("Version Info",         "Show file version information for PE files",    "ℹ️ System Info"),
    "windows.devicetree.DeviceTree":("Device Tree",         "Show the plugin/device object tree",            "ℹ️ System Info"),
    "timeliner.Timeliner":          ("Timeline",             "Create a forensic timeline of events",          "ℹ️ System Info"),
    "windows.crashinfo.Crashinfo":  ("Crash Info",           "Show crash dump header information",            "ℹ️ System Info"),
    "windows.poolscanner.PoolScanner": ("Pool Scanner",      "Scan kernel pool allocations",                  "ℹ️ System Info"),
    "windows.bigpools.BigPools":    ("Big Pool Tags",        "List large kernel pool allocations",            "ℹ️ System Info"),
    "windows.symlinkscan.SymlinkScan": ("Symlink Scanner",   "Scan for symbolic link objects",                "ℹ️ System Info"),
    "windows.mutantscan.MutantScan":   ("Mutex Scanner",     "Scan for mutex (mutant) objects",               "ℹ️ System Info"),

    # ── Linux ──
    "linux.pslist.PsList":          ("Process List",         "List running processes",                        "🔍 Process Analysis"),
    "linux.pstree.PsTree":         ("Process Tree",         "Show processes in hierarchy",                   "🔍 Process Analysis"),
    "linux.bash.Bash":             ("Bash History",         "Recover bash command history",                  "🔍 Process Analysis"),
    "linux.elfs.Elfs":             ("ELF Files",            "List ELF files loaded in memory",               "📁 File System"),
    "linux.lsmod.Lsmod":           ("Kernel Modules",       "List loaded kernel modules",                    "ℹ️ System Info"),
    "linux.lsof.Lsof":             ("Open Files",           "List open file descriptors",                    "📁 File System"),
    "linux.malfind.Malfind":       ("Malware Finder",       "Detect injected code in process memory",        "🦠 Malware Detection"),
    "linux.check_afinfo.Check_afinfo": ("Socket Hooks",     "Check network protocol handlers",               "🦠 Malware Detection"),

    # ── macOS ──
    "mac.pslist.PsList":            ("Process List",         "List running processes",                        "🔍 Process Analysis"),
    "mac.pstree.PsTree":           ("Process Tree",         "Show processes in hierarchy",                   "🔍 Process Analysis"),
    "mac.lsmod.Lsmod":             ("Kernel Extensions",    "List loaded kernel extensions",                 "ℹ️ System Info"),
    "mac.netstat.Netstat":          ("Network Status",       "Show network connections",                      "🌐 Network Analysis"),
    "mac.malfind.Malfind":         ("Malware Finder",       "Detect injected code",                          "🦠 Malware Detection"),
    "mac.lsof.Lsof":               ("Open Files",           "List open file descriptors",                    "📁 File System"),
}

# Suspicious process names that warrant visual flagging
SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "pwdump.exe", "wce.exe", "gsecdump.exe",
    "fgdump.exe", "bloodhound.exe", "rubeus.exe", "lazagne.exe",
    "nc.exe", "ncat.exe", "netcat.exe", "powershell_ise.exe",
    "psexec.exe", "psexesvc.exe", "remote.exe", "rclone.exe",
    "certutil.exe",  # can be legit but often used for download
    "mshta.exe", "regsvr32.exe", "rundll32.exe",  # LOLBins
    "bitsadmin.exe", "wmic.exe", "cmstp.exe",
}

# Known legitimate parent processes for svchost.exe
SVCHOST_LEGIT_PARENTS = {"services.exe"}

# Friendly column name mapping
COLUMN_FRIENDLY = {
    "PID": "PID",
    "PPID": "Parent PID",
    "ImageFileName": "Process Name",
    "Process": "Process Name",
    "Name": "Name",
    "Offset": "Memory Offset",
    "Offset(V)": "Virtual Offset",
    "Offset(P)": "Physical Offset",
    "Threads": "Threads",
    "Handles": "Handles",
    "SessionId": "Session",
    "Wow64": "32-bit (WoW64)",
    "CreateTime": "Created",
    "ExitTime": "Exited",
    "InheritedFrom": "Parent PID",
    "Comm": "Command",
    "Args": "Arguments",
    "Base": "Base Address",
    "Size": "Size",
    "Path": "File Path",
    "LocalAddr": "Local Address",
    "LocalPort": "Local Port",
    "ForeignAddr": "Remote Address",
    "ForeignPort": "Remote Port",
    "State": "State",
    "Proto": "Protocol",
    "Owner": "Owner Process",
    "Created": "Created",
}


def get_plugin_friendly_name(plugin_name: str) -> str:
    """Get human-readable name for a plugin."""
    if plugin_name in PLUGIN_FRIENDLY:
        return PLUGIN_FRIENDLY[plugin_name][0]
    # Auto-generate: split CamelCase → words
    short = plugin_name.split(".")[-1]
    return re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', short)


def get_plugin_description(plugin_name: str, plugin_class=None) -> str:
    """Get user-facing description for a plugin."""
    if plugin_name in PLUGIN_FRIENDLY:
        return PLUGIN_FRIENDLY[plugin_name][1]
    if plugin_class and plugin_class.__doc__:
        return plugin_class.__doc__.strip().split("\n")[0][:100]
    return ""


def get_plugin_category(plugin_name: str) -> str:
    """Get functional category for a plugin."""
    if plugin_name in PLUGIN_FRIENDLY:
        return PLUGIN_FRIENDLY[plugin_name][2]
    # Auto-detect from module path
    low = plugin_name.lower()
    if any(k in low for k in ['pslist', 'pstree', 'psscan', 'cmdline', 'dlllist', 'dll', 'handles',
                                'threads', 'envars', 'privs', 'sids', 'sessions', 'ldrmod', 'bash']):
        return "🔍 Process Analysis"
    if any(k in low for k in ['netscan', 'netstat', 'socket', 'netfilter']):
        return "🌐 Network Analysis"
    if any(k in low for k in ['malfind', 'ssdt', 'callback', 'hollow', 'hook', 'irp', 'svc', 'rootkit']):
        return "🦠 Malware Detection"
    if any(k in low for k in ['registry', 'hive', 'printkey', 'userassist', 'shimcache', 'amcache']):
        return "🗝️ Registry"
    if any(k in low for k in ['hash', 'lsadump', 'cache', 'credential', 'secret']):
        return "🔐 Credentials"
    if any(k in low for k in ['filescan', 'dumpfile', 'mft', 'elf', 'lsof']):
        return "📁 File System"
    if any(k in low for k in ['memmap', 'vad', 'virt', 'pool', 'bigpool']):
        return "💾 Memory Analysis"
    return "ℹ️ System Info"


def get_friendly_column(col_name: str) -> str:
    """Get user-friendly column header name."""
    return COLUMN_FRIENDLY.get(col_name, col_name)


def is_process_suspicious(process_name: str) -> bool:
    """Check if a process name is in the suspicious list."""
    return process_name.lower().strip() in {s.lower() for s in SUSPICIOUS_PROCESSES}


# ─── Dark Forensics QSS Theme ───────────────────────────────────────────────
DARK_THEME_QSS = f"""
/* ── Global ── */
QMainWindow, QWidget {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
    font-family: 'Segoe UI', 'Inter', 'Roboto', sans-serif;
    font-size: 13px;
}}
QMenuBar {{
    background-color: {COLORS['bg_darkest']};
    color: {COLORS['text_primary']};
    border-bottom: 1px solid {COLORS['border']};
    padding: 2px 0px; font-size: 13px;
}}
QMenuBar::item {{ padding: 6px 14px; border-radius: 4px; margin: 2px 1px; }}
QMenuBar::item:selected {{ background-color: {COLORS['bg_hover']}; color: {COLORS['primary']}; }}
QMenu {{
    background-color: {COLORS['bg_surface']}; color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']}; border-radius: 8px; padding: 6px 0px;
}}
QMenu::item {{ padding: 8px 32px 8px 20px; }}
QMenu::item:selected {{ background-color: {COLORS['bg_hover']}; color: {COLORS['primary']}; }}
QMenu::separator {{ height: 1px; background-color: {COLORS['border']}; margin: 4px 10px; }}
QToolBar {{
    background-color: {COLORS['bg_darkest']}; border-bottom: 1px solid {COLORS['border']};
    padding: 4px 8px; spacing: 4px;
}}
QToolBar::separator {{ width: 1px; background-color: {COLORS['border']}; margin: 4px 6px; }}
QToolButton {{
    background-color: transparent; color: {COLORS['text_secondary']};
    border: 1px solid transparent; border-radius: 6px; padding: 7px 14px;
    font-size: 12px; font-weight: 600;
}}
QToolButton:hover {{ background-color: {COLORS['bg_hover']}; color: {COLORS['primary']}; border-color: {COLORS['border_light']}; }}
QToolButton:pressed {{ background-color: {COLORS['bg_selected']}; color: {COLORS['accent']}; }}
QStatusBar {{
    background-color: {COLORS['bg_darkest']}; color: {COLORS['text_muted']};
    border-top: 1px solid {COLORS['border']}; font-size: 12px; padding: 2px 10px;
}}
QSplitter::handle {{ background-color: {COLORS['border']}; margin: 1px; }}
QSplitter::handle:horizontal {{ width: 2px; }}
QSplitter::handle:vertical {{ height: 2px; }}
QSplitter::handle:hover {{ background-color: {COLORS['primary']}; }}
QTreeWidget {{
    background-color: {COLORS['bg_surface']}; color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']}; border-radius: 8px; padding: 4px;
    outline: none; font-size: 12px;
}}
QTreeWidget::item {{ padding: 5px 8px; border-radius: 4px; margin: 1px 0px; }}
QTreeWidget::item:hover {{ background-color: {COLORS['bg_hover']}; }}
QTreeWidget::item:selected {{ background-color: {COLORS['bg_selected']}; color: {COLORS['accent']}; }}
QTreeWidget::branch {{ background-color: transparent; }}
QTreeWidget QHeaderView::section {{
    background-color: {COLORS['bg_darkest']}; color: {COLORS['text_muted']};
    border: none; border-bottom: 1px solid {COLORS['border']}; padding: 6px 10px;
    font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
}}
QTableWidget {{
    background-color: {COLORS['bg_surface']}; color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']}; border-radius: 8px;
    gridline-color: {COLORS['border']}; selection-background-color: {COLORS['bg_selected']};
    selection-color: {COLORS['accent']}; outline: none;
    font-family: 'Consolas', 'JetBrains Mono', 'Cascadia Code', monospace; font-size: 12px;
}}
QTableWidget::item {{ padding: 4px 8px; border-bottom: 1px solid {COLORS['border']}; }}
QTableWidget::item:hover {{ background-color: {COLORS['bg_hover']}; }}
QTableWidget::item:selected {{ background-color: {COLORS['bg_selected']}; color: {COLORS['accent']}; }}
QHeaderView::section {{
    background-color: {COLORS['bg_darkest']}; color: {COLORS['primary']};
    border: none; border-bottom: 2px solid {COLORS['primary_dim']};
    border-right: 1px solid {COLORS['border']}; padding: 8px 10px;
    font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
}}
QTabWidget::pane {{
    border: 1px solid {COLORS['border']}; border-top: 2px solid {COLORS['primary_dim']};
    border-radius: 0px 0px 8px 8px; background-color: {COLORS['bg_surface']};
}}
QTabBar::tab {{
    background-color: {COLORS['bg_surface_alt']}; color: {COLORS['text_secondary']};
    border: 1px solid {COLORS['border']}; border-bottom: none;
    border-radius: 6px 6px 0px 0px; padding: 8px 20px; margin-right: 2px;
    font-weight: 600; font-size: 12px;
}}
QTabBar::tab:hover {{ background-color: {COLORS['bg_hover']}; color: {COLORS['text_primary']}; }}
QTabBar::tab:selected {{ background-color: {COLORS['bg_surface']}; color: {COLORS['primary']}; border-bottom: 2px solid {COLORS['primary']}; }}
QTextEdit, QPlainTextEdit {{
    background-color: {COLORS['bg_surface']}; color: {COLORS['text_secondary']};
    border: 1px solid {COLORS['border']}; border-radius: 8px; padding: 8px;
    font-family: 'Consolas', 'JetBrains Mono', 'Cascadia Code', monospace; font-size: 12px;
    selection-background-color: {COLORS['bg_selected']};
}}
QLineEdit {{
    background-color: {COLORS['bg_surface']}; color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 8px 12px;
    font-size: 13px; selection-background-color: {COLORS['primary_dim']};
}}
QLineEdit:focus {{ border-color: {COLORS['border_focus']}; background-color: {COLORS['bg_surface_alt']}; }}
QLineEdit::placeholder {{ color: {COLORS['text_muted']}; }}
QPushButton {{
    background-color: {COLORS['bg_surface_alt']}; color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_light']}; border-radius: 6px; padding: 8px 20px;
    font-weight: 600; font-size: 13px;
}}
QPushButton:hover {{ background-color: {COLORS['bg_hover']}; border-color: {COLORS['primary']}; color: {COLORS['primary']}; }}
QPushButton:pressed {{ background-color: {COLORS['bg_selected']}; }}
QPushButton:disabled {{ background-color: {COLORS['bg_surface']}; color: {COLORS['text_muted']}; border-color: {COLORS['border']}; }}
QPushButton#runButton {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {COLORS['primary_dim']}, stop:1 {COLORS['primary']});
    color: {COLORS['bg_darkest']}; border: none; font-weight: 700; font-size: 14px;
    padding: 10px 24px; border-radius: 8px;
}}
QPushButton#runButton:hover {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {COLORS['primary']}, stop:1 {COLORS['accent']}); }}
QPushButton#runButton:disabled {{ background: {COLORS['bg_surface_alt']}; color: {COLORS['text_muted']}; }}
QPushButton#stopButton {{
    background-color: {COLORS['error']}; color: white; border: none;
    font-weight: 700; border-radius: 8px; padding: 10px 24px;
}}
QPushButton#stopButton:hover {{ background-color: {COLORS['danger']}; }}
QProgressBar {{
    background-color: {COLORS['bg_surface']}; border: 1px solid {COLORS['border']};
    border-radius: 6px; text-align: center; color: {COLORS['text_secondary']};
    font-size: 11px; font-weight: 600; height: 22px;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {COLORS['primary_dim']}, stop:1 {COLORS['primary']});
    border-radius: 5px;
}}
QGroupBox {{
    background-color: {COLORS['bg_surface']}; border: 1px solid {COLORS['border']};
    border-radius: 8px; margin-top: 16px; padding: 16px; padding-top: 28px;
    font-weight: 700; font-size: 12px; color: {COLORS['primary']};
}}
QGroupBox::title {{
    subcontrol-origin: margin; subcontrol-position: top left;
    padding: 4px 12px; color: {COLORS['primary']}; font-size: 12px; letter-spacing: 0.5px;
}}
QScrollBar:vertical {{
    background-color: {COLORS['bg_surface']}; width: 10px; border-radius: 5px; margin: 0px;
}}
QScrollBar::handle:vertical {{ background-color: {COLORS['border_light']}; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background-color: {COLORS['text_muted']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
QScrollBar:horizontal {{
    background-color: {COLORS['bg_surface']}; height: 10px; border-radius: 5px; margin: 0px;
}}
QScrollBar::handle:horizontal {{ background-color: {COLORS['border_light']}; border-radius: 5px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background-color: {COLORS['text_muted']}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0px; }}
QComboBox {{
    background-color: {COLORS['bg_surface']}; color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 6px 12px; font-size: 13px;
}}
QComboBox:hover {{ border-color: {COLORS['primary']}; }}
QComboBox::drop-down {{ border: none; padding-right: 8px; }}
QComboBox QAbstractItemView {{
    background-color: {COLORS['bg_surface']}; color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']}; selection-background-color: {COLORS['bg_selected']};
    selection-color: {COLORS['accent']}; outline: none;
}}
QSpinBox {{
    background-color: {COLORS['bg_surface']}; color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 6px 12px; font-size: 13px;
}}
QSpinBox:focus {{ border-color: {COLORS['primary']}; }}
QCheckBox {{ color: {COLORS['text_primary']}; spacing: 8px; font-size: 13px; }}
QCheckBox::indicator {{
    width: 18px; height: 18px; border-radius: 4px;
    border: 2px solid {COLORS['border_light']}; background-color: {COLORS['bg_surface']};
}}
QCheckBox::indicator:checked {{ background-color: {COLORS['primary']}; border-color: {COLORS['primary']}; }}
QCheckBox::indicator:hover {{ border-color: {COLORS['primary']}; }}
QLabel {{ color: {COLORS['text_primary']}; }}
QLabel#sectionTitle {{ color: {COLORS['primary']}; font-size: 13px; font-weight: 700; letter-spacing: 0.5px; padding: 8px 0px; }}
QLabel#headerLabel {{ color: {COLORS['text_primary']}; font-size: 20px; font-weight: 700; }}
QLabel#subtitleLabel {{ color: {COLORS['text_muted']}; font-size: 12px; }}
QLabel#imagePathLabel {{ color: {COLORS['accent']}; font-family: 'Consolas', 'JetBrains Mono', monospace; font-size: 12px; padding: 4px; }}
QFrame#separator {{ background-color: {COLORS['border']}; max-height: 1px; margin: 8px 0px; }}
QDialog {{ background-color: {COLORS['bg_dark']}; border: 1px solid {COLORS['border']}; border-radius: 12px; }}
QToolTip {{
    background-color: {COLORS['bg_surface']}; color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_light']}; border-radius: 6px; padding: 8px 12px; font-size: 12px;
}}
"""


# ═════════════════════════════════════════════════════════════════════════════
# SECTION: UTILITY CLASSES
# ═════════════════════════════════════════════════════════════════════════════

class _LogSignalBridge(QWidget):
    """Thread-safe bridge: emits a Qt signal so log text is written on the main thread."""
    log_ready = pyqtSignal(str)

    def __init__(self, text_edit: QTextEdit, parent=None):
        super().__init__(parent)
        self.setVisible(False)  # Invisible helper widget
        self.log_ready.connect(text_edit.append, Qt.ConnectionType.QueuedConnection)


class QTextEditLogHandler(logging.Handler):
    def __init__(self, text_edit: QTextEdit):
        super().__init__()
        self._bridge = _LogSignalBridge(text_edit)
        self.setFormatter(logging.Formatter("%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s", datefmt="%H:%M:%S"))

    def emit(self, record):
        try:
            msg = self.format(record)
            color = COLORS['text_secondary']
            if record.levelno >= logging.ERROR: color = COLORS['error']
            elif record.levelno >= logging.WARNING: color = COLORS['warning']
            elif record.levelno >= logging.INFO: color = COLORS['success']
            # Thread-safe: signal is queued to the main thread's event loop
            self._bridge.log_ready.emit(f'<span style="color:{color};">{msg}</span>')
        except Exception:
            pass


class ToastNotification(QLabel):
    _active_toasts: list = []
    _MAX_TOASTS = 5  # Prevent unbounded toast accumulation

    def __init__(self, parent, message, toast_type="info", duration=3000):
        super().__init__(parent)
        # Evict oldest toasts if we exceed the limit
        while len(ToastNotification._active_toasts) >= ToastNotification._MAX_TOASTS:
            oldest = ToastNotification._active_toasts.pop(0)
            try: oldest.deleteLater()
            except RuntimeError: pass
        icons = {"success": "✅", "error": "❌", "warning": "⚠️", "info": "ℹ️"}
        colors_map = {"success": COLORS['success'], "error": COLORS['error'], "warning": COLORS['warning'], "info": COLORS['primary']}
        bgs = {"success": "#052e16", "error": "#2d0a0a", "warning": "#2d1f05", "info": "#0a1929"}
        color = colors_map.get(toast_type, COLORS['primary'])
        bg = bgs.get(toast_type, "#0a1929")
        self.setText(f"  {icons.get(toast_type, 'ℹ️')}  {message}")
        self.setStyleSheet(f"QLabel {{ background-color: {bg}; color: {color}; border: 1px solid {color}; border-radius: 8px; padding: 12px 20px; font-size: 13px; font-weight: 600; }}")
        self.setFixedHeight(48); self.adjustSize()
        self.setFixedWidth(min(max(self.width(), 300) + 40, 600))
        ToastNotification._active_toasts.append(self)
        y = 12
        for t in ToastNotification._active_toasts:
            try: t.move((parent.width() - t.width()) // 2, y); y += t.height() + 6
            except RuntimeError: pass
        self.show(); self.raise_()
        self._opacity = QGraphicsOpacityEffect(self); self.setGraphicsEffect(self._opacity); self._opacity.setOpacity(0.0)
        start_pos = QPoint(self.x(), self.y() - 20)
        self._slide = QPropertyAnimation(self, b"pos"); self._slide.setDuration(250); self._slide.setStartValue(start_pos); self._slide.setEndValue(QPoint(self.x(), self.y())); self._slide.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade_in = QPropertyAnimation(self._opacity, b"opacity"); self._fade_in.setDuration(250); self._fade_in.setStartValue(0.0); self._fade_in.setEndValue(1.0)
        self._intro = QParallelAnimationGroup(self); self._intro.addAnimation(self._slide); self._intro.addAnimation(self._fade_in); self._intro.start()
        QTimer.singleShot(duration, self._fade_out)

    def _fade_out(self):
        try:
            self._fa = QPropertyAnimation(self._opacity, b"opacity"); self._fa.setDuration(350); self._fa.setStartValue(1.0); self._fa.setEndValue(0.0)
            self._fa.finished.connect(self._cleanup); self._fa.start()
        except RuntimeError:
            self._cleanup()

    def _cleanup(self):
        if self in ToastNotification._active_toasts: ToastNotification._active_toasts.remove(self)
        try: self.deleteLater()
        except RuntimeError: pass


class ShortcutsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Keyboard Shortcuts"); self.setMinimumSize(520, 560)
        layout = QVBoxLayout(self); layout.setContentsMargins(24,24,24,24); layout.setSpacing(16)
        title = QLabel("⌨️  Keyboard Shortcuts"); title.setStyleSheet(f"color: {COLORS['primary']}; font-size: 18px; font-weight: 700;"); layout.addWidget(title)
        sub = QLabel("Master these shortcuts to speed up your forensic workflow"); sub.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px;"); layout.addWidget(sub)
        shortcuts = [("Ctrl+O","Open memory image"),("F5","Run selected plugin"),("Shift+F5","Stop analysis"),("Ctrl+D","Dump & Hash executable"),("Ctrl+S","Save session"),("Ctrl+E","Export results"),("Ctrl+F","Focus search/filter"),("Ctrl+B","Bookmark plugin"),("Ctrl+N","Add forensic note"),("Ctrl+H","Hex viewer"),("Ctrl+W","Close tab"),("Ctrl+Shift+W","Close all tabs"),("Ctrl+Shift+C","Copy selected rows"),("F1","Show shortcuts"),("Ctrl+Q","Exit")]
        table = QTableWidget(len(shortcuts), 2); table.setHorizontalHeaderLabels(["Shortcut","Action"]); table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents); table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection); table.setShowGrid(False)
        for i,(k,d) in enumerate(shortcuts):
            ki = QTableWidgetItem(f"  {k}"); ki.setForeground(QColor(COLORS['accent'])); ki.setFont(QFont("Consolas",12,QFont.Weight.Bold)); table.setItem(i,0,ki)
            di = QTableWidgetItem(f"  {d}"); di.setForeground(QColor(COLORS['text_secondary'])); table.setItem(i,1,di)
        table.verticalHeader().setDefaultSectionSize(36); layout.addWidget(table)
        cb = QPushButton("Close"); cb.clicked.connect(self.close); layout.addWidget(cb, alignment=Qt.AlignmentFlag.AlignRight)


# ═════════════════════════════════════════════════════════════════════════════
# SECTION: MANAGERS
# ═════════════════════════════════════════════════════════════════════════════

class BookmarksManager:
    def __init__(self):
        self.bookmarks: List[str] = []
        try:
            if BOOKMARKS_FILE.exists(): self.bookmarks = json.loads(BOOKMARKS_FILE.read_text())
        except: self.bookmarks = []

    def _save(self):
        try: BOOKMARKS_FILE.write_text(json.dumps(self.bookmarks, indent=2))
        except: pass

    def toggle(self, plugin_name):
        if plugin_name in self.bookmarks: self.bookmarks.remove(plugin_name); self._save(); return False
        else: self.bookmarks.append(plugin_name); self._save(); return True

    def is_bookmarked(self, name): return name in self.bookmarks


class RecentFilesManager:
    def __init__(self):
        self.files: List[str] = []
        try:
            if RECENT_FILES_FILE.exists(): self.files = json.loads(RECENT_FILES_FILE.read_text())
        except: self.files = []

    def _save(self):
        try: RECENT_FILES_FILE.write_text(json.dumps(self.files, indent=2))
        except: pass

    def add(self, fp):
        if fp in self.files: self.files.remove(fp)
        self.files.insert(0, fp); self.files = self.files[:MAX_RECENT_FILES]; self._save()

    def get(self): return self.files
    def clear(self): self.files = []; self._save()


class RecentPluginsManager:
    def __init__(self):
        self.plugins: List[str] = []
        try:
            if RECENT_PLUGINS_FILE.exists(): self.plugins = json.loads(RECENT_PLUGINS_FILE.read_text())
        except: self.plugins = []

    def _save(self):
        try: RECENT_PLUGINS_FILE.write_text(json.dumps(self.plugins, indent=2))
        except: pass

    def add(self, name):
        if name in self.plugins: self.plugins.remove(name)
        self.plugins.insert(0, name); self.plugins = self.plugins[:MAX_RECENT_PLUGINS]; self._save()

    def get(self): return self.plugins


# ═════════════════════════════════════════════════════════════════════════════
# SECTION: ANALYSIS WORKER
# ═════════════════════════════════════════════════════════════════════════════

class AnalysisWorker(QThread):
    progress_update = pyqtSignal(float, str)
    analysis_finished = pyqtSignal(str, list, list)
    analysis_error = pyqtSignal(str, str)
    log_message = pyqtSignal(str)

    def __init__(self, plugin_class, image_path, plugin_name, extra_config=None):
        super().__init__()
        self.plugin_class = plugin_class; self.image_path = image_path
        self.plugin_name = plugin_name; self.extra_config = extra_config or {}
        self._is_cancelled = False

    def cancel(self): self._is_cancelled = True

    def _progress_callback(self, progress, description=None):
        if self._is_cancelled: raise InterruptedError("Analysis cancelled by user")
        self.progress_update.emit(progress, description or "")

    def run(self):
        try:
            self.log_message.emit(f"Starting analysis: {get_plugin_friendly_name(self.plugin_name)}")
            ctx = contexts.Context()
            # NOTE: framework.import_files is NOT thread-safe and is already called
            # once during app init (_init_volatility). Do NOT call it here.
            automagics_list = automagic.available(ctx)
            file_location = requirements.URIRequirement.location_from_file(self.image_path)
            ctx.config["automagic.LayerStacker.single_location"] = file_location
            selected_automagics = automagic.choose_automagic(automagics_list, self.plugin_class)
            ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(self.plugin_class)
            base_config_path = "plugins"
            plugin_config_path = interfaces.configuration.path_join(base_config_path, self.plugin_class.__name__)
            for key, value in self.extra_config.items():
                if value is not None and value != "":
                    ctx.config[interfaces.configuration.path_join(plugin_config_path, key)] = value
            output_dir = tempfile.gettempdir()
            class GUIFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
                def __init__(self, filename):
                    io.BytesIO.__init__(self); interfaces.plugins.FileHandlerInterface.__init__(self, filename)
                def close(self):
                    if self.closed: return None
                    self.seek(0)
                    with open(os.path.join(output_dir, self.preferred_filename), "wb") as f: f.write(self.read())
                    super().close()
            self.log_message.emit("Constructing plugin and running automagic...")
            constructed = plugins.construct_plugin(ctx, selected_automagics, self.plugin_class, base_config_path, self._progress_callback, GUIFileHandler)
            self.log_message.emit("Executing plugin...")
            grid = constructed.run()
            columns = [col.name for col in grid.columns]
            column_types = [col.type for col in grid.columns]
            rows = []
            def visitor(node, acc):
                if self._is_cancelled: raise InterruptedError("Analysis cancelled")
                row = []
                for ci, c in enumerate(grid.columns):
                    row.append(self._render_value(node.values[ci], column_types[ci]))
                acc.append(row); return acc
            if not grid.populated: grid.populate(visitor, rows)
            else: grid.visit(node=None, function=visitor, initial_accumulator=rows)
            self.log_message.emit(f"Analysis complete: {get_plugin_friendly_name(self.plugin_name)} — {len(rows)} results")
            self.analysis_finished.emit(self.plugin_name, columns, rows)
        except InterruptedError:
            self.log_message.emit(f"Analysis cancelled: {self.plugin_name}")
            self.analysis_error.emit(self.plugin_name, "Analysis was cancelled by user.")
        except Exception as e:
            tb = traceback.format_exc()
            self.log_message.emit(f"Error in {self.plugin_name}: {str(e)}")
            self.analysis_error.emit(self.plugin_name, f"{str(e)}\n\n{tb}")

    def _render_value(self, value, col_type):
        if isinstance(value, interfaces.renderers.BaseAbsentValue):
            from volatility3.framework import renderers as vol_renderers
            if isinstance(value, vol_renderers.NotApplicableValue): return "N/A"
            return "-"
        if isinstance(value, datetime.datetime): return value.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(value, bytes): return " ".join(f"{b:02x}" for b in value)
        if isinstance(value, int):
            from volatility3.framework.renderers import format_hints
            if col_type == format_hints.Hex: return f"0x{value:x}"
            return str(value)
        return str(value)


# ═════════════════════════════════════════════════════════════════════════════
# SECTION: DUMP & HASH WORKER
# ═════════════════════════════════════════════════════════════════════════════

class DumpHashWorker(QThread):
    """Worker thread that dumps process executable(s) from memory and computes hashes."""
    progress_update = pyqtSignal(str)
    dump_finished = pyqtSignal(list)   # list of dicts: {filename, path, pid, md5, sha1, sha256, size}
    dump_error = pyqtSignal(str)

    def __init__(self, image_path, plugin_list, mode="pid", target=None):
        super().__init__()
        self.image_path = image_path
        self.plugin_list = plugin_list
        self.mode = mode      # "pid", "virtaddr", "physaddr", or "filter"
        self.target = target  # Int for pid/addrs, string for filter
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def _progress_callback(self, progress, description=None):
        if self._is_cancelled:
            raise InterruptedError("Dump cancelled by user")

    def run(self):
        try:
            self.progress_update.emit("Initializing dump...")
            # Create a dedicated output directory
            dump_dir = os.path.join(tempfile.gettempdir(), f"vol3_dump_{datetime.datetime.now():%Y%m%d_%H%M%S}")
            os.makedirs(dump_dir, exist_ok=True)

            # Decide plugin based on mode
            if self.mode == "pid":
                dump_plugin_name = "windows.pslist.PsList"
            else:
                dump_plugin_name = "windows.dumpfiles.DumpFiles"

            if dump_plugin_name not in self.plugin_list:
                self.dump_error.emit(f"{dump_plugin_name} plugin not found.")
                return

            plugin_class = self.plugin_list[dump_plugin_name]
            ctx = contexts.Context()
            automagics_list = automagic.available(ctx)
            file_location = requirements.URIRequirement.location_from_file(self.image_path)
            ctx.config["automagic.LayerStacker.single_location"] = file_location
            selected_automagics = automagic.choose_automagic(automagics_list, plugin_class)
            ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin_class)
            base_config_path = "plugins"
            plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin_class.__name__)

            # Set configurations based on mode
            if self.mode == "pid":
                ctx.config[interfaces.configuration.path_join(plugin_config_path, "dump")] = True
                if self.target is not None:
                    ctx.config[interfaces.configuration.path_join(plugin_config_path, "pid")] = [int(self.target)]
            elif self.mode == "virtaddr":
                if self.target is not None:
                    ctx.config[interfaces.configuration.path_join(plugin_config_path, "virtaddr")] = [int(self.target, 16) if isinstance(self.target, str) and self.target.startswith("0x") else int(self.target)]
            elif self.mode == "physaddr":
                if self.target is not None:
                    ctx.config[interfaces.configuration.path_join(plugin_config_path, "physaddr")] = [int(self.target, 16) if isinstance(self.target, str) and self.target.startswith("0x") else int(self.target)]
            elif self.mode == "filter":
                if self.target:
                    ctx.config[interfaces.configuration.path_join(plugin_config_path, "filter")] = str(self.target)
                    ctx.config[interfaces.configuration.path_join(plugin_config_path, "ignore-case")] = True

            self.progress_update.emit(f"Dumping to: {dump_dir}")

            # Track dumped files
            dumped_files = []
            _dump_dir = dump_dir

            class HashFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
                def __init__(self, filename):
                    io.BytesIO.__init__(self)
                    interfaces.plugins.FileHandlerInterface.__init__(self, filename)

                def close(self):
                    if self.closed:
                        return None
                    self.seek(0)
                    out_path = os.path.join(_dump_dir, self.preferred_filename)
                    data = self.read()
                    with open(out_path, "wb") as f:
                        f.write(data)
                    dumped_files.append(out_path)
                    super().close()

            self.progress_update.emit("Running DumpFiles plugin...")
            constructed = plugins.construct_plugin(
                ctx, selected_automagics, plugin_class,
                base_config_path, self._progress_callback, HashFileHandler
            )
            grid = constructed.run()

            # Visit results to trigger file dumps
            def visitor(node, acc):
                if self._is_cancelled:
                    raise InterruptedError("Cancelled")
                return acc
            if not grid.populated:
                grid.populate(visitor, [])
            else:
                grid.visit(node=None, function=visitor, initial_accumulator=[])

            if self._is_cancelled:
                self.dump_error.emit("Dump cancelled by user.")
                return

            if not dumped_files:
                self.dump_error.emit(f"No files were dumped. The process (PID {self.pid}) may not have dumpable file objects.")
                return

            # Compute hashes for all dumped files
            self.progress_update.emit(f"Computing hashes for {len(dumped_files)} file(s)...")
            results = []
            for fpath in dumped_files:
                if self._is_cancelled:
                    break
                fname = os.path.basename(fpath)
                fsize = os.path.getsize(fpath)
                self.progress_update.emit(f"Hashing: {fname}")

                md5 = hashlib.md5()
                sha1 = hashlib.sha1()
                sha256 = hashlib.sha256()

                with open(fpath, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        md5.update(chunk)
                        sha1.update(chunk)
                        sha256.update(chunk)

                # Try to extract PID from filename
                file_pid = "?"
                if self.mode == "pid":
                    file_pid = str(self.target) if self.target is not None else "?"
                parts = fname.split(".")
                for p in parts:
                    if p.isdigit():
                        file_pid = p
                        break

                results.append({
                    "filename": fname,
                    "path": fpath,
                    "pid": str(file_pid),
                    "size": fsize,
                    "md5": md5.hexdigest(),
                    "sha1": sha1.hexdigest(),
                    "sha256": sha256.hexdigest(),
                })

            self.progress_update.emit(f"Done — {len(results)} file(s) hashed.")
            self.dump_finished.emit(results)

        except InterruptedError:
            self.dump_error.emit("Dump cancelled by user.")
        except Exception as e:
            tb = traceback.format_exc()
            self.dump_error.emit(f"{str(e)}\n\n{tb}")


class DumpHashDialog(QDialog):
    """Dialog to input PID and show dump and hash results."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Dump and Hash — Extract Executable and Compute Hashes")
        self.setMinimumSize(700, 500)
        self.resize(800, 560)
        self._worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # Title
        title = QLabel("🔬  Dump & Hash")
        title.setStyleSheet(f"color: {COLORS['primary']}; font-size: 18px; font-weight: 700;")
        layout.addWidget(title)

        desc = QLabel("Extract process executable from memory and compute MD5 / SHA1 / SHA256 hashes.")
        desc.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Mode selection
        mode_row = QHBoxLayout()
        mode_lbl = QLabel("Extraction Target:")
        mode_lbl.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: 600; font-size: 13px;")
        mode_row.addWidget(mode_lbl)

        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "Process Executable (by PID)",
            "Specific File (by Virtual Address)",
            "Specific File (by Physical Address)",
            "Search Files (by Name/Regex)"
        ])
        self.mode_combo.setStyleSheet(f"QComboBox {{ background-color: {COLORS['bg_surface']}; color: {COLORS['text_primary']}; padding: 4px; border: 1px solid {COLORS['border']}; border-radius: 4px; }}")
        mode_row.addWidget(self.mode_combo)
        mode_row.addStretch()
        layout.addLayout(mode_row)

        # Target input row
        self.target_row = QHBoxLayout()
        self.target_row.setSpacing(8)
        self.target_lbl = QLabel("Process PID:")
        self.target_lbl.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: 600; font-size: 13px;")
        self.target_row.addWidget(self.target_lbl)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter PID (e.g. 1234) or leave blank for all")
        self.target_input.setStyleSheet(f"QLineEdit {{ background-color: {COLORS['bg_darkest']}; color: {COLORS['text_primary']}; padding: 6px; border: 1px solid {COLORS['border']}; border-radius: 4px; }}")
        self.target_row.addWidget(self.target_input)

        self.target_hint = QLabel("💡 Tip: Use PsList or Malfind to find the PID")
        self.target_hint.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")
        self.target_row.addWidget(self.target_hint)
        self.target_row.addStretch()
        layout.addLayout(self.target_row)

        # Update labels based on mode
        def _on_mode_change(idx):
            if idx == 0:
                self.target_lbl.setText("Process PID:")
                self.target_input.setPlaceholderText("Enter PID (e.g. 1234) or leave blank for all")
                self.target_hint.setText("💡 Tip: Use PsList or Malfind to find the PID")
            elif idx == 1:
                self.target_lbl.setText("Virtual Address:")
                self.target_input.setPlaceholderText("e.g. 0xffff... (from FileScan)")
                self.target_hint.setText("💡 Tip: Run FileScan to find the file's Virtual Offset")
            elif idx == 2:
                self.target_lbl.setText("Physical Address:")
                self.target_input.setPlaceholderText("e.g. 0x100... (from FileScan)")
                self.target_hint.setText("💡 Tip: Run FileScan to find the file's Physical Offset")
            elif idx == 3:
                self.target_lbl.setText("File Name/Regex:")
                self.target_input.setPlaceholderText("e.g. password\.txt or \.pdf$")
                self.target_hint.setText("💡 Tip: Extracts all matching cached files")
        self.mode_combo.currentIndexChanged.connect(_on_mode_change)

        # Buttons row
        btn_row = QHBoxLayout()

        self.dump_btn = QPushButton("🔬 Dump & Hash")
        self.dump_btn.setStyleSheet(
            f"QPushButton {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {COLORS['primary_dim']},stop:1 {COLORS['primary']}); "
            f"color: {COLORS['bg_darkest']}; border: none; font-weight: 700; font-size: 13px; padding: 8px 20px; border-radius: 6px; }}"
            f"QPushButton:hover {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {COLORS['primary']},stop:1 {COLORS['accent']}); }}"
            f"QPushButton:disabled {{ background: {COLORS['bg_surface_alt']}; color: {COLORS['text_muted']}; }}"
        )
        btn_row.addWidget(self.dump_btn)

        self.hash_local_btn = QPushButton("📂 Hash Local File...")
        self.hash_local_btn.setStyleSheet(
            f"QPushButton {{ background: {COLORS['bg_surface']}; color: {COLORS['text_primary']}; border: 1px solid {COLORS['border']}; "
            f"font-weight: 600; font-size: 13px; padding: 8px 16px; border-radius: 6px; }}"
            f"QPushButton:hover {{ background: {COLORS['bg_surface_alt']}; }}"
        )
        self.hash_local_btn.clicked.connect(self._hash_local_file)
        btn_row.addWidget(self.hash_local_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)


        # Progress
        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")
        layout.addWidget(self.progress_label)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(["File", "PID", "Size", "MD5", "SHA1", "SHA256"])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self._context_menu)
        self.results_table.setFont(QFont("Consolas", 11))
        layout.addWidget(self.results_table)

        # Bottom buttons
        bottom = QHBoxLayout()
        self.copy_btn = QPushButton("📋 Copy All Hashes")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self._copy_all)
        bottom.addWidget(self.copy_btn)

        self.export_btn = QPushButton("💾 Export CSV")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export_csv)
        bottom.addWidget(self.export_btn)

        self.open_dir_btn = QPushButton("📂 Open Dump Folder")
        self.open_dir_btn.setEnabled(False)
        self.open_dir_btn.clicked.connect(self._open_dump_dir)
        bottom.addWidget(self.open_dir_btn)

        bottom.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        bottom.addWidget(close_btn)
        layout.addLayout(bottom)

        self._results_data = []
        self._dump_dir = None

    def _hash_local_file(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Select Dumped File", "", "All Files (*.*)")
        if not fp:
            return
        
        self.progress_label.setText(f"⏳ Hashing: {os.path.basename(fp)}...")
        self.progress_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")
        QApplication.processEvents()
        
        try:
            fsize = os.path.getsize(fp)
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()

            with open(fp, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    
            fname = os.path.basename(fp)
            # Attempt to get PID from filename
            file_pid = "?"
            parts = fname.split(".")
            for p in parts:
                if p.isdigit():
                    file_pid = p
                    break

            result = {
                "filename": fname,
                "path": fp,
                "pid": file_pid,
                "size": fsize,
                "md5": md5.hexdigest(),
                "sha1": sha1.hexdigest(),
                "sha256": sha256.hexdigest(),
            }
            
            # Append to existing results
            self._results_data.append(result)
            self.populate_results(self._results_data)
            
        except Exception as e:
            self.progress_label.setText(f"❌ Error hashing file: {e}")
            self.progress_label.setStyleSheet(f"color: {COLORS['error']}; font-size: 11px;")

    def populate_results(self, results):
        """Fill the table with hash results."""
        self._results_data = results
        self.results_table.setRowCount(len(results))
        for i, r in enumerate(results):
            self.results_table.setItem(i, 0, QTableWidgetItem(r["filename"]))
            self.results_table.setItem(i, 1, QTableWidgetItem(str(r["pid"])))

            size_str = self._fmt_size(r["size"])
            self.results_table.setItem(i, 2, QTableWidgetItem(size_str))

            md5_item = QTableWidgetItem(r["md5"])
            md5_item.setForeground(QColor(COLORS['text_secondary']))
            self.results_table.setItem(i, 3, md5_item)

            sha1_item = QTableWidgetItem(r["sha1"])
            sha1_item.setForeground(QColor(COLORS['accent']))
            sha1_item.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            self.results_table.setItem(i, 4, sha1_item)

            sha256_item = QTableWidgetItem(r["sha256"])
            sha256_item.setForeground(QColor(COLORS['text_secondary']))
            self.results_table.setItem(i, 5, sha256_item)

            if r.get("path"):
                self._dump_dir = os.path.dirname(r["path"])

        self.results_table.resizeColumnsToContents()
        header = self.results_table.horizontalHeader()
        for col in range(self.results_table.columnCount()):
            if header.sectionSize(col) > 300:
                header.resizeSection(col, 300)

        self.copy_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.open_dir_btn.setEnabled(self._dump_dir is not None)
        self.progress_label.setText(f"✅ {len(results)} file(s) dumped and hashed successfully.")
        self.progress_label.setStyleSheet(f"color: {COLORS['success']}; font-size: 11px; font-weight: 600;")

    def _context_menu(self, position):
        item = self.results_table.itemAt(position)
        if not item:
            return
        row = item.row()
        menu = QMenu(self)

        copy_sha1 = menu.addAction("📋 Copy SHA1")
        copy_sha1.triggered.connect(lambda: QApplication.clipboard().setText(
            self.results_table.item(row, 4).text() if self.results_table.item(row, 4) else ""))

        copy_sha256 = menu.addAction("📋 Copy SHA256")
        copy_sha256.triggered.connect(lambda: QApplication.clipboard().setText(
            self.results_table.item(row, 5).text() if self.results_table.item(row, 5) else ""))

        copy_md5 = menu.addAction("📋 Copy MD5")
        copy_md5.triggered.connect(lambda: QApplication.clipboard().setText(
            self.results_table.item(row, 3).text() if self.results_table.item(row, 3) else ""))

        menu.addSeparator()
        copy_row = menu.addAction("📋 Copy All Hashes for This File")
        copy_row.triggered.connect(lambda: self._copy_row(row))

        if self._results_data and row < len(self._results_data):
            vt_url = f"https://www.virustotal.com/gui/file/{self._results_data[row]['sha256']}"
            menu.addSeparator()
            vt_action = menu.addAction("🌐 Search on VirusTotal")
            vt_action.triggered.connect(lambda: __import__('webbrowser').open(vt_url))

        menu.exec(self.results_table.viewport().mapToGlobal(position))

    def _copy_row(self, row):
        if row < len(self._results_data):
            r = self._results_data[row]
            text = (f"File: {r['filename']}\n"
                    f"PID:  {r['pid']}\n"
                    f"MD5:    {r['md5']}\n"
                    f"SHA1:   {r['sha1']}\n"
                    f"SHA256: {r['sha256']}")
            QApplication.clipboard().setText(text)

    def _copy_all(self):
        lines = ["File | PID | MD5 | SHA1 | SHA256"]
        for r in self._results_data:
            lines.append(f"{r['filename']} | {r['pid']} | {r['md5']} | {r['sha1']} | {r['sha256']}")
        QApplication.clipboard().setText("\n".join(lines))

    def _export_csv(self):
        fp, _ = QFileDialog.getSaveFileName(self, "Export Hashes", f"dump_hashes_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv", "CSV Files (*.csv)")
        if not fp:
            return
        with open(fp, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Filename", "PID", "Size", "MD5", "SHA1", "SHA256", "Path"])
            for r in self._results_data:
                w.writerow([r["filename"], r["pid"], r["size"], r["md5"], r["sha1"], r["sha256"], r["path"]])

    def _open_dump_dir(self):
        if self._dump_dir and os.path.isdir(self._dump_dir):
            os.startfile(self._dump_dir)

    def _fmt_size(self, s):
        for u in ["B", "KB", "MB", "GB"]:
            if abs(s) < 1024.0:
                return f"{s:.1f} {u}"
            s /= 1024.0
        return f"{s:.1f} TB"


# ═════════════════════════════════════════════════════════════════════════════
# SECTION: RESULTS TAB (ENHANCED WITH TREE VIEW & HIGHLIGHTING)
# ═════════════════════════════════════════════════════════════════════════════

class ResultsTab(QWidget):
    filter_used = pyqtSignal()
    sort_used = pyqtSignal()
    export_done = pyqtSignal(str)

    def __init__(self, plugin_name, columns, rows, parent=None):
        super().__init__(parent)
        self.plugin_name = plugin_name
        self.columns = columns
        self.friendly_columns = [get_friendly_column(c) for c in columns]
        self.rows = rows
        self._is_process_view = self._detect_process_view()
        self._tree_mode = False
        self._pid_col = self._find_col(["PID"])
        self._ppid_col = self._find_col(["PPID", "InheritedFrom"])
        self._name_col = self._find_col(["ImageFileName", "Process", "Name", "Comm"])
        self._setup_ui()

    def _detect_process_view(self):
        col_set = {c.lower() for c in self.columns}
        return "pid" in col_set and ("ppid" in col_set or "inheritedfrom" in col_set)

    def _find_col(self, candidates):
        for c in candidates:
            for i, col in enumerate(self.columns):
                if col.lower() == c.lower(): return i
        return -1

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0,0,0,0); layout.setSpacing(6)

        # Top bar
        top = QHBoxLayout(); top.setSpacing(8)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍  Filter results... (type to search any column)")
        self.search_input.textChanged.connect(self._filter_table)
        self.search_input.setClearButtonEnabled(True)
        top.addWidget(self.search_input, 1)

        self.row_count_label = QLabel()
        self.row_count_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; padding: 0 6px;")
        top.addWidget(self.row_count_label)

        self.selection_label = QLabel("")
        self.selection_label.setStyleSheet(f"color: {COLORS['accent']}; font-size: 11px; font-weight: 600;")
        top.addWidget(self.selection_label)

        # Process tree toggle
        if self._is_process_view:
            self.tree_toggle = QPushButton("🌳 Tree View")
            self.tree_toggle.setFixedWidth(100)
            self.tree_toggle.setCheckable(True)
            self.tree_toggle.setToolTip("Toggle between flat table and process tree hierarchy")
            self.tree_toggle.clicked.connect(self._toggle_tree_view)
            top.addWidget(self.tree_toggle)

        copy_btn = QPushButton("📋 Copy"); copy_btn.setFixedWidth(80)
        copy_btn.setToolTip("Copy selected rows to clipboard"); copy_btn.clicked.connect(self._copy_selected)
        top.addWidget(copy_btn)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.VLine); sep.setStyleSheet(f"color: {COLORS['border']};")
        top.addWidget(sep)

        stats_btn = QPushButton("📊 Stats"); stats_btn.setFixedWidth(76); stats_btn.clicked.connect(self._show_stats)
        top.addWidget(stats_btn)

        for label, fmt, w in [("CSV","csv",50),("JSON","json",55),("HTML","html",55)]:
            b = QPushButton(label); b.setFixedWidth(w); b.clicked.connect(lambda _,f=fmt: self._export(f))
            top.addWidget(b)

        layout.addLayout(top)

        # Stack: flat table vs tree widget
        self.view_stack = QStackedWidget()

        # Flat table view
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.columns))
        self.table.setHorizontalHeaderLabels(self.friendly_columns)
        self.table.setRowCount(len(self.rows))
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().sectionClicked.connect(lambda: self.sort_used.emit())
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_context_menu)
        self.table.doubleClicked.connect(self._on_double_click)

        # Populate and highlight
        for row_idx, row_data in enumerate(self.rows):
            is_suspicious = False
            for col_idx, cell_value in enumerate(row_data):
                item = QTableWidgetItem(str(cell_value))
                if cell_value and isinstance(cell_value, str):
                    try:
                        if cell_value.startswith("0x") or cell_value.lstrip("-").isdigit():
                            item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                    except: pass
                    # Check for suspicious process
                    if col_idx == self._name_col and is_process_suspicious(cell_value):
                        is_suspicious = True
                self.table.setItem(row_idx, col_idx, item)

            # Highlight suspicious rows
            if is_suspicious:
                for col_idx in range(len(self.columns)):
                    item = self.table.item(row_idx, col_idx)
                    if item:
                        item.setBackground(QColor(COLORS['row_suspicious']))
                        if col_idx == self._name_col:
                            item.setForeground(QColor(COLORS['error']))
                            item.setText(f"⚠ {item.text()}")

        self.table.resizeColumnsToContents()
        header = self.table.horizontalHeader()
        for i in range(self.table.columnCount()):
            if header.sectionSize(i) > 350: header.resizeSection(i, 350)

        if self.table.selectionModel():
            self.table.selectionModel().selectionChanged.connect(self._on_selection_changed)

        self.view_stack.addWidget(self.table)

        # Tree view (for process results)
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(self.friendly_columns)
        self.tree_widget.setAlternatingRowColors(True)
        self.tree_widget.setRootIsDecorated(True)
        self.tree_widget.setAnimated(True)
        self.tree_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self._tree_context_menu)
        self.view_stack.addWidget(self.tree_widget)

        layout.addWidget(self.view_stack)

        # Suspicious warning banner
        if self._is_process_view:
            suspicious_count = sum(1 for r in self.rows if self._name_col >= 0 and self._name_col < len(r) and is_process_suspicious(str(r[self._name_col])))
            if suspicious_count > 0:
                banner = QLabel(f"  ⚠️  {suspicious_count} suspicious process{'es' if suspicious_count > 1 else ''} detected — highlighted in red")
                banner.setStyleSheet(f"background: {COLORS['row_suspicious']}; color: {COLORS['error']}; border: 1px solid {COLORS['error']}; border-radius: 6px; padding: 8px; font-weight: 600; font-size: 12px;")
                layout.addWidget(banner)

        self._update_row_count()

    def _toggle_tree_view(self):
        self._tree_mode = not self._tree_mode
        if self._tree_mode:
            self._build_process_tree()
            self.view_stack.setCurrentIndex(1)
            self.tree_toggle.setText("📋 Flat View")
        else:
            self.view_stack.setCurrentIndex(0)
            self.tree_toggle.setText("🌳 Tree View")

    def _build_process_tree(self):
        """Build a parent→child process tree from flat PID/PPID data."""
        self.tree_widget.clear()
        if self._pid_col < 0 or self._ppid_col < 0: return

        # Build lookup: pid → row data
        pid_to_rows = {}
        all_pids = set()
        for row in self.rows:
            try:
                pid = str(row[self._pid_col]).strip()
                all_pids.add(pid)
                if pid not in pid_to_rows: pid_to_rows[pid] = []
                pid_to_rows[pid].append(row)
            except: pass

        # Build lookup: pid → tree item
        pid_to_item = {}
        orphans = []

        # First pass: create items for all processes
        for row in self.rows:
            try:
                pid = str(row[self._pid_col]).strip()
                ppid = str(row[self._ppid_col]).strip()
                item = QTreeWidgetItem([str(v) for v in row])
                # Apply friendly column headers
                item.setData(0, Qt.ItemDataRole.UserRole, pid)
                item.setData(0, Qt.ItemDataRole.UserRole + 1, ppid)

                # Highlight suspicious
                if self._name_col >= 0 and self._name_col < len(row):
                    name = str(row[self._name_col])
                    if is_process_suspicious(name):
                        for c in range(len(row)):
                            item.setForeground(c, QColor(COLORS['error']))
                        item.setText(self._name_col, f"⚠ {name}")
                    # Flag svchost with wrong parent
                    if name.lower().strip() == "svchost.exe":
                        parent_name = ""
                        for r2 in self.rows:
                            if str(r2[self._pid_col]).strip() == ppid and self._name_col < len(r2):
                                parent_name = str(r2[self._name_col]).strip().lower()
                                break
                        if parent_name and parent_name not in SVCHOST_LEGIT_PARENTS:
                            for c in range(len(row)):
                                item.setForeground(c, QColor(COLORS['warning']))
                            item.setText(self._name_col, f"⚠ {name} (unexpected parent: {parent_name})")

                pid_to_item[pid] = (item, ppid)
            except: pass

        # Second pass: build hierarchy
        for pid, (item, ppid) in pid_to_item.items():
            if ppid in pid_to_item and ppid != pid:
                parent_item = pid_to_item[ppid][0]
                parent_item.addChild(item)
            else:
                self.tree_widget.addTopLevelItem(item)

        # Style: show child count
        def annotate(item):
            if item.childCount() > 0:
                name_col = self._name_col if self._name_col >= 0 else 0
                current = item.text(name_col)
                if not current.endswith(")") or "child" not in current:
                    item.setText(name_col, f"{current}  ({item.childCount()} children)")
                item.setForeground(name_col, QColor(COLORS['primary']))
            for i in range(item.childCount()):
                annotate(item.child(i))

        for i in range(self.tree_widget.topLevelItemCount()):
            annotate(self.tree_widget.topLevelItem(i))

        self.tree_widget.expandAll()
        for i in range(len(self.friendly_columns)):
            self.tree_widget.resizeColumnToContents(i)

    def _table_context_menu(self, position):
        """Right-click context menu for flat table."""
        item = self.table.itemAt(position)
        if not item: return
        menu = QMenu(self)
        copy_cell = menu.addAction("📋 Copy Cell Value")
        copy_cell.triggered.connect(lambda: QApplication.clipboard().setText(item.text()))
        copy_row = menu.addAction("📋 Copy Entire Row")
        copy_row.triggered.connect(lambda: self._copy_row(item.row()))
        menu.addSeparator()
        filter_action = menu.addAction(f"🔍 Filter by: \"{item.text()[:30]}\"")
        filter_action.triggered.connect(lambda: self.search_input.setText(item.text()))
        if self._is_process_view and self._pid_col >= 0:
            menu.addSeparator()
            pid_item = self.table.item(item.row(), self._pid_col)
            if pid_item:
                pid_val = pid_item.text()
                find_children = menu.addAction(f"👶 Find children of PID {pid_val}")
                find_children.triggered.connect(lambda: self.search_input.setText(pid_val))
        menu.exec(self.table.viewport().mapToGlobal(position))

    def _tree_context_menu(self, position):
        """Right-click context menu for tree view."""
        item = self.tree_widget.itemAt(position)
        if not item: return
        col = self.tree_widget.columnAt(position.x())
        menu = QMenu(self)
        copy_cell = menu.addAction(f"📋 Copy: \"{item.text(col)[:40]}\"")
        copy_cell.triggered.connect(lambda: QApplication.clipboard().setText(item.text(col)))
        copy_row = menu.addAction("📋 Copy Full Row")
        copy_row.triggered.connect(lambda: QApplication.clipboard().setText("\t".join(item.text(i) for i in range(self.tree_widget.columnCount()))))
        if item.childCount() > 0:
            menu.addSeparator()
            collapse = menu.addAction(f"📁 Collapse ({item.childCount()} children)")
            collapse.triggered.connect(lambda: item.setExpanded(False))
        menu.exec(self.tree_widget.viewport().mapToGlobal(position))

    def _copy_row(self, row):
        cells = []
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            cells.append(item.text() if item else "")
        QApplication.clipboard().setText("\t".join(cells))

    def _on_double_click(self, index):
        """Double-click a cell to copy its value."""
        item = self.table.item(index.row(), index.column())
        if item:
            QApplication.clipboard().setText(item.text())
            main_win = self.window()
            if hasattr(main_win, '_toast'):
                main_win._toast(f"Copied: {item.text()[:50]}", "info", 1500)

    def _on_selection_changed(self):
        count = len(self.table.selectionModel().selectedRows())
        self.selection_label.setText(f"{count} selected" if count > 0 else "")

    def _copy_selected(self):
        selection = self.table.selectionModel().selectedRows()
        rows_to_copy = sorted(idx.row() for idx in selection) if selection else range(self.table.rowCount())
        lines = ["\t".join(self.friendly_columns)]
        for row in rows_to_copy:
            cells = [self.table.item(row, col).text() if self.table.item(row, col) else "" for col in range(self.table.columnCount())]
            lines.append("\t".join(cells))
        QApplication.clipboard().setText("\n".join(lines))
        main_win = self.window()
        if hasattr(main_win, '_toast'): main_win._toast(f"Copied {len(list(rows_to_copy))} rows", "success", 2000)

    def _filter_table(self, text):
        text = text.lower()
        visible = 0
        for row in range(self.table.rowCount()):
            match = not text or any(self.table.item(row, col) and text in self.table.item(row, col).text().lower() for col in range(self.table.columnCount()))
            self.table.setRowHidden(row, not match)
            if match: visible += 1
        self.row_count_label.setText(f"{visible} / {self.table.rowCount()} rows")
        if text: self.filter_used.emit()

    def _update_row_count(self):
        self.row_count_label.setText(f"{self.table.rowCount()} rows")

    def _show_stats(self):
        dialog = QDialog(self); dialog.setWindowTitle(f"Statistics — {get_plugin_friendly_name(self.plugin_name)}")
        dialog.setMinimumSize(500, 400); layout = QVBoxLayout(dialog)
        title = QLabel(f"📊  Statistics for {get_plugin_friendly_name(self.plugin_name)}")
        title.setStyleSheet(f"color: {COLORS['primary']}; font-size: 16px; font-weight: 700;"); layout.addWidget(title)
        info = QLabel(f"Total rows: {len(self.rows)} • Columns: {len(self.columns)}")
        info.setStyleSheet(f"color: {COLORS['text_muted']};"); layout.addWidget(info)
        st = QTableWidget(len(self.columns), 4); st.setHorizontalHeaderLabels(["Column","Unique","Most Common","Empty"])
        st.horizontalHeader().setStretchLastSection(True); st.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        for i, col in enumerate(self.columns):
            vals = [self.rows[r][i] for r in range(len(self.rows)) if i < len(self.rows[r])]
            unique = len(set(vals)); empty = sum(1 for v in vals if v in ("-","N/A","",None))
            counter = Counter(v for v in vals if v not in ("-","N/A","",None))
            mc = counter.most_common(1)[0][0] if counter else "-"
            st.setItem(i,0,QTableWidgetItem(self.friendly_columns[i])); st.setItem(i,1,QTableWidgetItem(str(unique)))
            st.setItem(i,2,QTableWidgetItem(str(mc)[:50])); st.setItem(i,3,QTableWidgetItem(str(empty)))
        st.resizeColumnsToContents(); layout.addWidget(st)
        cb = QPushButton("Close"); cb.clicked.connect(dialog.close); layout.addWidget(cb, alignment=Qt.AlignmentFlag.AlignRight)
        dialog.exec()

    def _export(self, fmt):
        default_name = f"vol3_{self.plugin_name.replace('.','_')}_{datetime.datetime.now():%Y%m%d_%H%M%S}"
        ext_map = {"csv":"CSV Files (*.csv)","json":"JSON Files (*.json)","html":"HTML Files (*.html)"}
        filepath, _ = QFileDialog.getSaveFileName(self, f"Export as {fmt.upper()}", default_name, ext_map.get(fmt, "All Files (*)"))
        if not filepath: return
        try:
            if fmt == "csv":
                with open(filepath, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f); w.writerow(self.friendly_columns); w.writerows(self.rows)
            elif fmt == "json":
                data = [dict(zip(self.friendly_columns, r)) for r in self.rows]
                with open(filepath, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, default=str)
            elif fmt == "html":
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>{get_plugin_friendly_name(self.plugin_name)}</title>')
                    f.write(f'<style>body{{font-family:Segoe UI,sans-serif;background:{COLORS["bg_dark"]};color:{COLORS["text_primary"]};padding:24px}}h1{{color:{COLORS["primary"]};font-size:22px}}table{{border-collapse:collapse;width:100%;font-size:13px}}th{{background:{COLORS["bg_darkest"]};color:{COLORS["primary"]};padding:10px 12px;text-align:left;border-bottom:2px solid {COLORS["primary_dim"]}}}td{{padding:8px 12px;border-bottom:1px solid {COLORS["border"]};font-family:Consolas,monospace}}tr:hover{{background:{COLORS["bg_hover"]}}}tr:nth-child(even){{background:{COLORS["bg_surface"]}}}</style></head><body>')
                    f.write(f'<h1>🔬 {get_plugin_friendly_name(self.plugin_name)}</h1>')
                    f.write(f'<p style="color:{COLORS["text_muted"]}">Exported: {datetime.datetime.now():%Y-%m-%d %H:%M:%S} • Rows: {len(self.rows)}</p>')
                    f.write('<table><thead><tr>' + ''.join(f'<th>{c}</th>' for c in self.friendly_columns) + '</tr></thead><tbody>')
                    for row in self.rows: f.write('<tr>' + ''.join(f'<td>{c}</td>' for c in row) + '</tr>')
                    f.write('</tbody></table></body></html>')
            self.export_done.emit(fmt)
            main_win = self.window()
            if hasattr(main_win, '_toast'): main_win._toast(f"Exported to {os.path.basename(filepath)}", "success")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Error: {str(e)}")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION: HEX VIEWER
# ═════════════════════════════════════════════════════════════════════════════

class HexViewerWidget(QWidget):
    hex_viewed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._file_path = None; self._file_size = 0; self._offset = 0
        self._bytes_per_line = 16; self._lines_per_page = 32; self._data = b""
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self); layout.setContentsMargins(8,8,8,8); layout.setSpacing(8)
        ctrl = QHBoxLayout(); ctrl.setSpacing(8)
        lbl = QLabel("🔍 Hex Viewer"); lbl.setStyleSheet(f"color: {COLORS['primary']}; font-size: 14px; font-weight: 700;")
        ctrl.addWidget(lbl); ctrl.addStretch()
        ctrl.addWidget(QLabel("Go to offset:"))
        self.offset_input = QLineEdit(); self.offset_input.setPlaceholderText("0x0"); self.offset_input.setFixedWidth(140)
        self.offset_input.returnPressed.connect(self._goto_offset); ctrl.addWidget(self.offset_input)
        go = QPushButton("Go"); go.setFixedWidth(50); go.clicked.connect(self._goto_offset); ctrl.addWidget(go)
        ctrl.addWidget(QLabel("Search hex:"))
        self.search_input = QLineEdit(); self.search_input.setPlaceholderText("e.g. 4D 5A 90"); self.search_input.setFixedWidth(180)
        self.search_input.returnPressed.connect(self._search_hex); ctrl.addWidget(self.search_input)
        sb = QPushButton("🔎 Find"); sb.setFixedWidth(70); sb.clicked.connect(self._search_hex); ctrl.addWidget(sb)
        layout.addLayout(ctrl)
        self.info_label = QLabel("No file loaded"); self.info_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;"); layout.addWidget(self.info_label)
        self.hex_display = QPlainTextEdit(); self.hex_display.setReadOnly(True); self.hex_display.setFont(QFont("Consolas", 11))
        self.hex_display.setStyleSheet(f"QPlainTextEdit {{ background-color: {COLORS['bg_darkest']}; color: {COLORS['text_secondary']}; border: 1px solid {COLORS['border']}; border-radius: 8px; padding: 8px; }}")
        layout.addWidget(self.hex_display)
        nav = QHBoxLayout()
        self.prev_btn = QPushButton("◀  Previous"); self.prev_btn.clicked.connect(self._prev_page); self.prev_btn.setEnabled(False); nav.addWidget(self.prev_btn)
        nav.addStretch(); self.page_label = QLabel(""); self.page_label.setStyleSheet(f"color: {COLORS['text_muted']};"); nav.addWidget(self.page_label); nav.addStretch()
        self.next_btn = QPushButton("Next  ▶"); self.next_btn.clicked.connect(self._next_page); self.next_btn.setEnabled(False); nav.addWidget(self.next_btn)
        layout.addLayout(nav)

    def load_file(self, fp):
        self._file_path = fp; self._file_size = os.path.getsize(fp); self._offset = 0; self._read_and_display(); self.hex_viewed.emit()

    def _read_and_display(self):
        if not self._file_path: return
        cs = self._bytes_per_line * self._lines_per_page
        try:
            with open(self._file_path, "rb") as f: f.seek(self._offset); self._data = f.read(cs)
        except Exception as e: self.hex_display.setPlainText(f"Error: {e}"); return
        lines = [f"{'OFFSET':<12}  {'00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F':<52}  {'ASCII':>16}", "─" * 82]
        for i in range(0, len(self._data), self._bytes_per_line):
            chunk = self._data[i:i+self._bytes_per_line]
            hp = []
            for j, b in enumerate(chunk):
                hp.append(f"{b:02X}")
                if j == 7: hp.append("")
            hs = " ".join(hp).ljust(50)
            asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"0x{(self._offset+i):08X}   {hs}  {asc}")
        self.hex_display.setPlainText("\n".join(lines))
        end = self._offset + len(self._data)
        self.info_label.setText(f"File: {os.path.basename(self._file_path)} • Size: {self._fmt_size(self._file_size)} • 0x{self._offset:X} – 0x{end:X}")
        self.prev_btn.setEnabled(self._offset > 0); self.next_btn.setEnabled(end < self._file_size)
        pn = self._offset // (self._bytes_per_line * self._lines_per_page) + 1
        tp = max(1, (self._file_size + self._bytes_per_line * self._lines_per_page - 1) // (self._bytes_per_line * self._lines_per_page))
        self.page_label.setText(f"Page {pn} / {tp}")

    def _prev_page(self): self._offset = max(0, self._offset - self._bytes_per_line * self._lines_per_page); self._read_and_display()
    def _next_page(self): self._offset = min(self._file_size, self._offset + self._bytes_per_line * self._lines_per_page); self._read_and_display()

    def _goto_offset(self):
        t = self.offset_input.text().strip()
        try:
            o = int(t, 16) if t.lower().startswith("0x") else int(t)
            self._offset = max(0, min(o, self._file_size)); self._read_and_display()
        except: pass

    def _search_hex(self):
        p = self.search_input.text().strip()
        if not p or not self._file_path: return
        try: hb = bytes.fromhex(p.replace(" ", ""))
        except: QMessageBox.warning(self, "Invalid", "Enter hex like: 4D 5A 90"); return
        try:
            with open(self._file_path, "rb") as f:
                f.seek(self._offset + 1); data = f.read(1024*1024); pos = data.find(hb)
                if pos >= 0:
                    self._offset = ((self._offset + 1 + pos) // self._bytes_per_line) * self._bytes_per_line
                    self._read_and_display()
                    mw = self.window()
                    if hasattr(mw, '_toast'): mw._toast(f"Found at 0x{self._offset:X}", "success")
                else:
                    mw = self.window()
                    if hasattr(mw, '_toast'): mw._toast("Not found in next 1MB", "warning")
        except Exception as e: QMessageBox.warning(self, "Error", str(e))

    def _fmt_size(self, s):
        for u in ["B","KB","MB","GB","TB"]:
            if abs(s) < 1024.0: return f"{s:.1f} {u}"
            s /= 1024.0
        return f"{s:.1f} PB"


# ═════════════════════════════════════════════════════════════════════════════
# SECTION: FORENSIC NOTES
# ═════════════════════════════════════════════════════════════════════════════

class ForensicNotesPanel(QWidget):
    note_added = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent); self.notes = []; self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0); layout.setSpacing(6)
        hdr = QHBoxLayout()
        lbl = QLabel("📝  FORENSIC NOTES"); lbl.setObjectName("sectionTitle"); hdr.addWidget(lbl); hdr.addStretch()
        eb = QPushButton("💾"); eb.setFixedSize(28,28); eb.setToolTip("Export notes"); eb.clicked.connect(self._export_notes); hdr.addWidget(eb)
        cb = QPushButton("🗑"); cb.setFixedSize(28,28); cb.setToolTip("Clear all"); cb.clicked.connect(self._clear_notes); hdr.addWidget(cb)
        layout.addLayout(hdr)
        ib = QHBoxLayout()
        self.note_input = QLineEdit(); self.note_input.setPlaceholderText("Type a forensic note... (Ctrl+N)")
        self.note_input.returnPressed.connect(self._add_note); ib.addWidget(self.note_input, 1)
        ab = QPushButton("+ Add"); ab.setFixedWidth(60); ab.clicked.connect(self._add_note); ib.addWidget(ab)
        layout.addLayout(ib)
        self.notes_display = QTextEdit(); self.notes_display.setReadOnly(True)
        self.notes_display.setStyleSheet(f"QTextEdit {{ background-color: {COLORS['bg_darkest']}; color: {COLORS['text_secondary']}; border: 1px solid {COLORS['border']}; border-radius: 6px; font-size: 12px; padding: 8px; }}")
        self.notes_display.setHtml(f'<div style="color: {COLORS["text_muted"]}; padding: 16px; text-align: center;"><p style="font-size: 24px;">📝</p><p>No notes yet</p><p style="font-size: 11px;">Press <b>Ctrl+N</b> to add a note.</p></div>')
        layout.addWidget(self.notes_display)

    def _add_note(self):
        t = self.note_input.text().strip()
        if not t: return
        self.notes.append({"time": datetime.datetime.now().strftime("%H:%M:%S"), "text": t})
        self.note_input.clear(); self._refresh(); self.note_added.emit()

    def add_auto_note(self, text):
        self.notes.append({"time": datetime.datetime.now().strftime("%H:%M:%S"), "text": f"[AUTO] {text}"}); self._refresh()

    def _refresh(self):
        parts = []
        for n in reversed(self.notes):
            bc = COLORS['text_muted'] if n['text'].startswith("[AUTO]") else COLORS['primary_dim']
            parts.append(f'<div style="margin-bottom: 8px; padding: 8px; border-left: 3px solid {bc}; background: {COLORS["bg_surface"]}; border-radius: 4px;"><span style="color: {COLORS["text_muted"]}; font-size: 11px;">[{n["time"]}]</span> <span style="color: {COLORS["text_primary"]};">{n["text"]}</span></div>')
        self.notes_display.setHtml("".join(parts) if parts else f'<div style="color: {COLORS["text_muted"]}; padding: 16px; text-align: center;">No notes yet.</div>')

    def _export_notes(self):
        if not self.notes: return
        fp, _ = QFileDialog.getSaveFileName(self, "Export Notes", f"notes_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt", "Text Files (*.txt)")
        if fp:
            with open(fp, "w", encoding="utf-8") as f:
                f.write(f"Forensic Case Notes\n{'='*40}\n")
                for n in self.notes: f.write(f"[{n['time']}] {n['text']}\n")

    def _clear_notes(self):
        if not self.notes: return
        if QMessageBox.question(self, "Clear Notes", "Clear all notes?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.notes.clear(); self._refresh()

    def get_notes_data(self): return self.notes
    def load_notes_data(self, notes): self.notes = notes; self._refresh()


# ═════════════════════════════════════════════════════════════════════════════
# SECTION: WELCOME SCREEN
# ═════════════════════════════════════════════════════════════════════════════

class WelcomeWidget(QWidget):
    open_image_clicked = pyqtSignal()
    recent_file_clicked = pyqtSignal(str)

    def __init__(self, recent_mgr, parent=None):
        super().__init__(parent); self.recent_mgr = recent_mgr; self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self); layout.setContentsMargins(20,20,20,20); layout.setSpacing(8)
        logo = QLabel("🔬"); logo.setAlignment(Qt.AlignmentFlag.AlignCenter); logo.setStyleSheet("font-size: 36px; background: transparent;"); layout.addWidget(logo)
        title = QLabel("VOLATILITY 3"); title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f"color: {COLORS['primary']}; font-size: 22px; font-weight: 800; letter-spacing: 3px; background: transparent;"); layout.addWidget(title)
        sub = QLabel("Memory Forensic Workstation"); sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 14px; background: transparent;"); layout.addWidget(sub)
        layout.addSpacing(20)
        ob = QPushButton("📂  Open Memory Image")
        ob.setStyleSheet(f"QPushButton {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {COLORS['primary_dim']},stop:1 {COLORS['primary']}); color: {COLORS['bg_darkest']}; border: none; font-weight: 700; font-size: 15px; padding: 14px 40px; border-radius: 10px; min-width: 260px; }} QPushButton:hover {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {COLORS['primary']},stop:1 {COLORS['accent']}); }}")
        ob.setCursor(Qt.CursorShape.PointingHandCursor); ob.clicked.connect(self.open_image_clicked.emit)
        layout.addWidget(ob, alignment=Qt.AlignmentFlag.AlignCenter)
        dh = QLabel("or drag & drop a memory dump file anywhere"); dh.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dh.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; background: transparent;"); layout.addWidget(dh)
        layout.addSpacing(16)
        self.recent_container = QWidget(); self.recent_container.setStyleSheet("background: transparent;")
        self.recent_layout = QVBoxLayout(self.recent_container); self.recent_layout.setContentsMargins(0,0,0,0); self.recent_layout.setSpacing(4)
        layout.addWidget(self.recent_container); self._populate_recent()
        layout.addSpacing(16)
        layout.addStretch()
        ft = QLabel(f"Volatility Framework {APP_VERSION} • F1 for shortcuts • Ctrl+O to open"); ft.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; background: transparent;"); layout.addWidget(ft)

    def _populate_recent(self):
        while self.recent_layout.count():
            c = self.recent_layout.takeAt(0)
            if c.widget(): c.widget().deleteLater()
        recent = [f for f in self.recent_mgr.get() if os.path.isfile(f)]
        if not recent: return
        h = QLabel("📋  Recent Files"); h.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px; font-weight: 700; background: transparent;"); self.recent_layout.addWidget(h)
        for fp in recent[:5]:
            fn = os.path.basename(fp)
            try: sz = self._fmt(os.path.getsize(fp))
            except: sz = "?"
            b = QPushButton(f"  📄  {fn}   ({sz})")
            b.setStyleSheet(f"QPushButton {{ background: {COLORS['bg_surface']}; color: {COLORS['text_secondary']}; border: 1px solid {COLORS['border']}; border-radius: 6px; padding: 8px 16px; font-size: 12px; text-align: left; }} QPushButton:hover {{ background: {COLORS['bg_hover']}; color: {COLORS['accent']}; border-color: {COLORS['primary_dim']}; }}")
            b.setCursor(Qt.CursorShape.PointingHandCursor); b.setToolTip(fp)
            b.clicked.connect(lambda _, p=fp: self.recent_file_clicked.emit(p)); self.recent_layout.addWidget(b)

    def refresh_recent(self): self._populate_recent()

    def _fmt(self, s):
        for u in ["B","KB","MB","GB"]:
            if abs(s) < 1024.0: return f"{s:.1f} {u}"
            s /= 1024.0
        return f"{s:.1f} TB"


# ═════════════════════════════════════════════════════════════════════════════
# SECTION: PLUGIN CONFIG FORM
# ═════════════════════════════════════════════════════════════════════════════

class PluginConfigForm(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent); self.config_widgets = {}; self._current_plugin = None; self._setup_ui()

    def _setup_ui(self):
        self.layout = QVBoxLayout(self); self.layout.setContentsMargins(0,0,0,0); self.layout.setSpacing(4)
        self.plugin_label = QLabel("No plugin selected"); self.plugin_label.setObjectName("sectionTitle"); self.layout.addWidget(self.plugin_label)
        self.plugin_desc = QLabel(""); self.plugin_desc.setObjectName("subtitleLabel"); self.plugin_desc.setWordWrap(True); self.layout.addWidget(self.plugin_desc)
        self.scroll = QScrollArea(); self.scroll.setWidgetResizable(True); self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.form_container = QWidget(); self.form_layout = QFormLayout(self.form_container)
        self.form_layout.setContentsMargins(4,8,4,8); self.form_layout.setSpacing(8); self.form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.scroll.setWidget(self.form_container); self.layout.addWidget(self.scroll)

    def load_plugin(self, plugin_name, plugin_class):
        self._current_plugin = plugin_class; self.config_widgets.clear()
        parts = plugin_name.split('.')
        disp = f"{parts[0]}.{parts[-1]}" if len(parts) >= 2 else parts[-1]
        desc = get_plugin_description(plugin_name, plugin_class)
        self.plugin_label.setText(f"⚙  {disp}")
        self.plugin_desc.setText(desc or "")
        while self.form_layout.count():
            c = self.form_layout.takeAt(0)
            if c.widget(): c.widget().deleteLater()
        try: reqs = plugin_class.get_requirements()
        except: reqs = []
        has = False
        for req in reqs:
            w = self._create_widget(req)
            if w:
                lbl = QLabel(req.name.replace("_"," ").title())
                lbl.setToolTip(req.description or "")
                if not req.optional: lbl.setText(lbl.text() + " *"); lbl.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: 600;")
                else: lbl.setStyleSheet(f"color: {COLORS['text_secondary']};")
                self.form_layout.addRow(lbl, w); self.config_widgets[req.name] = (w, req); has = True
        if not has:
            np = QLabel("No parameters needed.\nJust click Run ▶ to execute."); np.setStyleSheet(f"color: {COLORS['text_muted']}; padding: 12px;"); np.setWordWrap(True)
            self.form_layout.addRow(np)

    def _create_widget(self, req):
        if isinstance(req, requirements.BooleanRequirement):
            cb = QCheckBox(); cb.setChecked(bool(req.default)); return cb
        elif isinstance(req, requirements.IntRequirement):
            sb = QSpinBox(); sb.setMinimum(-2147483648); sb.setMaximum(2147483647); sb.setSpecialValueText("(not set)")
            sb.setValue(int(req.default) if req.default is not None else sb.minimum()); return sb
        elif isinstance(req, requirements.ChoiceRequirement):
            cb = QComboBox()
            if req.optional: cb.addItem("(not set)", None)
            for c in req.choices: cb.addItem(c, c)
            if req.default:
                idx = cb.findText(str(req.default))
                if idx >= 0: cb.setCurrentIndex(idx)
            return cb
        elif isinstance(req, requirements.ListRequirement):
            le = QLineEdit(); le.setPlaceholderText("Comma-separated values...")
            if req.default: le.setText(", ".join(str(x) for x in req.default))
            return le
        elif isinstance(req, requirements.URIRequirement):
            c = QWidget(); h = QHBoxLayout(c); h.setContentsMargins(0,0,0,0); h.setSpacing(4)
            le = QLineEdit(); le.setPlaceholderText("Path or URL...")
            if req.default: le.setText(str(req.default))
            btn = QPushButton("📂"); btn.setFixedWidth(36)
            btn.clicked.connect(lambda _, l=le: (lambda p: l.setText(p) if p else None)(QFileDialog.getOpenFileName(self, "Select File")[0]))
            h.addWidget(le, 1); h.addWidget(btn); c._line_edit = le; return c
        elif isinstance(req, (requirements.StringRequirement,)):
            le = QLineEdit(); le.setPlaceholderText(req.description or "")
            if req.default: le.setText(str(req.default)); return le
        elif isinstance(req, interfaces.configuration.SimpleTypeRequirement):
            le = QLineEdit(); le.setPlaceholderText(req.description or "")
            if req.default is not None: le.setText(str(req.default)); return le
        return None

    def get_config(self):
        config = {}
        for name, (w, req) in self.config_widgets.items():
            val = None
            if isinstance(req, requirements.BooleanRequirement): val = w.isChecked()
            elif isinstance(req, requirements.IntRequirement):
                if w.value() != w.minimum(): val = w.value()
            elif isinstance(req, requirements.ChoiceRequirement): val = w.currentData()
            elif isinstance(req, requirements.ListRequirement):
                t = w.text().strip()
                if t: val = [req.element_type(x.strip()) for x in t.split(",") if x.strip()]
            elif isinstance(req, requirements.URIRequirement):
                le = w._line_edit if hasattr(w, '_line_edit') else w
                t = le.text().strip()
                if t: val = t
            elif isinstance(w, QLineEdit):
                t = w.text().strip()
                if t: val = t
            if val is not None: config[name] = val
        return config


# ═════════════════════════════════════════════════════════════════════════════
# SECTION: MAIN APPLICATION
# ═════════════════════════════════════════════════════════════════════════════

class VolatilityGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME); self.setMinimumSize(641, 500); self.resize(900, 700)
        self.setAcceptDrops(True)
        self.image_path = None; self.plugin_list = {}; self.current_worker = None
        self._worker_pool = []  # Track all worker threads for safe cleanup
        self._analysis_count = 0; self._start_time = None; self._completed_plugins = set()
        self._elapsed_timer = QTimer(); self._elapsed_timer.timeout.connect(self._update_elapsed)
        self.bookmarks_mgr = BookmarksManager(); self.recent_files_mgr = RecentFilesManager(); self.recent_plugins_mgr = RecentPluginsManager()
        self._setup_logging(); self._init_volatility()
        self._create_menus(); self._create_toolbar(); self._create_ui(); self._create_statusbar(); self._setup_shortcuts()
        self._clock_timer = QTimer(); self._clock_timer.timeout.connect(self._update_clock); self._clock_timer.start(1000)
        self._mem_timer = QTimer(); self._mem_timer.timeout.connect(self._update_memory); self._mem_timer.start(5000); self._update_memory()
        self._log("Application initialized."); self._log(f"Volatility Framework {APP_VERSION}"); self._log(f"Loaded {len(self.plugin_list)} plugins")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                p = url.toLocalFile().lower()
                if any(p.endswith(e) for e in ['.vmem','.raw','.mem','.dmp','.img','.bin','.lime','.elf','.aff4']):
                    event.acceptProposedAction(); return

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            p = url.toLocalFile()
            if os.path.isfile(p): self._load_image(p); break

    def _setup_logging(self): logging.getLogger().setLevel(logging.INFO)

    def _init_volatility(self):
        try:
            framework.require_interface_version(2, 0, 0)
            framework.import_files(volatility3.plugins, True)
            self.plugin_list = framework.list_plugins()
        except Exception as e: self.plugin_list = {}; print(f"Error: {e}")

    def _setup_shortcuts(self):
        for key, fn in [("F1",self._show_shortcuts),("Ctrl+N",self._focus_notes),("Ctrl+H",self._open_hex_viewer),("Ctrl+B",self._toggle_bookmark),("Ctrl+S",self._save_session),("Ctrl+F",self._focus_filter),("Ctrl+W",self._close_current_tab),("Ctrl+Shift+W",self._clear_results),("Ctrl+Shift+C",self._copy_current_selection),("Ctrl+E",lambda: self._export_current("csv")),("Ctrl+D",self._dump_and_hash)]:
            QShortcut(QKeySequence(key), self, fn)

    def _create_menus(self):
        mb = self.menuBar()
        fm = mb.addMenu("&File")
        oa = QAction("📂  Open Memory Image...", self); oa.setShortcut("Ctrl+O"); oa.triggered.connect(self._open_image); fm.addAction(oa)
        self.recent_menu = QMenu("📋  Recent Files", self); self._update_recent_menu(); fm.addMenu(self.recent_menu)
        fm.addSeparator()
        sa = QAction("💾  Save Session...", self); sa.setShortcut("Ctrl+S"); sa.triggered.connect(self._save_session); fm.addAction(sa)
        la = QAction("📁  Load Session...", self); la.triggered.connect(self._load_session); fm.addAction(la)
        fm.addSeparator()
        ea = QAction("✖  Exit", self); ea.setShortcut("Ctrl+Q"); ea.triggered.connect(self.close); fm.addAction(ea)
        am = mb.addMenu("&Analysis")
        ra = QAction("▶  Run Plugin", self); ra.setShortcut("F5"); ra.triggered.connect(self._run_analysis); am.addAction(ra)
        sta = QAction("⏹  Stop Analysis", self); sta.setShortcut("Shift+F5"); sta.triggered.connect(self._stop_analysis); am.addAction(sta)
        am.addSeparator()
        ha = QAction("🔬  Hex Viewer", self); ha.setShortcut("Ctrl+H"); ha.triggered.connect(self._open_hex_viewer); am.addAction(ha)
        dha = QAction("🔑  Dump & Hash...", self); dha.setShortcut("Ctrl+D"); dha.triggered.connect(self._dump_and_hash); am.addAction(dha)
        am.addSeparator()
        wm = QMenu("⚡  Quick Workflows", self)
        for wn, wp in [("🔍 Full Triage",["windows.pslist.PsList","windows.netscan.NetScan","windows.cmdline.CmdLine"]),("🦠 Malware Hunt",["windows.malfind.Malfind","windows.dlllist.DllList","windows.handles.Handles"]),("📡 Network",["windows.netscan.NetScan","windows.netstat.NetStat"]),("🗝️ Registry",["windows.registry.hivelist.HiveList","windows.registry.printkey.PrintKey"])]:
            wa = QAction(wn, self); wa.triggered.connect(lambda _,pl=wp: self._run_workflow(pl)); wm.addAction(wa)
        am.addMenu(wm); am.addSeparator()
        ca = QAction("🗑  Clear All Results", self); ca.triggered.connect(self._clear_results); am.addAction(ca)
        hm = mb.addMenu("&Help")
        ska = QAction("⌨  Keyboard Shortcuts", self); ska.setShortcut("F1"); ska.triggered.connect(self._show_shortcuts); hm.addAction(ska)
        aba = QAction("ℹ  About", self); aba.triggered.connect(self._show_about); hm.addAction(aba)

    def _create_toolbar(self):
        tb = QToolBar("Main Toolbar"); tb.setIconSize(QSize(18,18)); tb.setMovable(False); self.addToolBar(tb)
        for label, tip, fn in [("📂 Open","Open image (Ctrl+O)",self._open_image)]:
            a = QAction(label, self); a.setToolTip(tip); a.triggered.connect(fn); tb.addAction(a)
        tb.addSeparator()
        self.toolbar_run = QAction("▶ Run", self); self.toolbar_run.setToolTip("Run plugin (F5)"); self.toolbar_run.triggered.connect(self._run_analysis); tb.addAction(self.toolbar_run)
        self.toolbar_stop = QAction("⏹ Stop", self); self.toolbar_stop.setToolTip("Stop (Shift+F5)"); self.toolbar_stop.triggered.connect(self._stop_analysis); self.toolbar_stop.setEnabled(False); tb.addAction(self.toolbar_stop)
        tb.addSeparator()
        for label, tip, fn in [("🔬 Hex","Hex viewer (Ctrl+H)",self._open_hex_viewer),("🔑 Hash","Dump & Hash (Ctrl+D)",self._dump_and_hash),("🗑 Clear","Clear results",self._clear_results)]:
            a = QAction(label, self); a.setToolTip(tip); a.triggered.connect(fn); tb.addAction(a)
            if label == "🔑 Hash": tb.addSeparator()

    def _create_statusbar(self):
        sb = QStatusBar(); self.setStatusBar(sb)
        self.status_image = QLabel("  No image loaded"); self.status_image.setStyleSheet(f"color: {COLORS['text_muted']};"); sb.addWidget(self.status_image, 1)
        self.status_elapsed = QLabel(""); self.status_elapsed.setStyleSheet(f"color: {COLORS['text_muted']};"); sb.addPermanentWidget(self.status_elapsed)
        self.status_mem = QLabel(""); self.status_mem.setStyleSheet(f"color: {COLORS['text_muted']}; padding: 0 8px;"); sb.addPermanentWidget(self.status_mem)
        self.status_plugins = QLabel(f"  Plugins: {len(self.plugin_list)}  "); self.status_plugins.setStyleSheet(f"color: {COLORS['primary']};"); sb.addPermanentWidget(self.status_plugins)
        self.status_clock = QLabel(""); self.status_clock.setStyleSheet(f"color: {COLORS['text_muted']}; padding: 0 4px;"); sb.addPermanentWidget(self.status_clock); self._update_clock()

    def _update_clock(self): self.status_clock.setText(f"🕐 {datetime.datetime.now():%H:%M:%S}")
    def _update_memory(self):
        try: self.status_mem.setText(f"💾 {psutil.Process(os.getpid()).memory_info().rss / (1024*1024):.0f} MB")
        except: pass

    def _create_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        ml = QVBoxLayout(central); ml.setContentsMargins(0,0,0,0); ml.setSpacing(0)
        # Image bar
        ib = QWidget(); ib.setStyleSheet(f"QWidget {{ background-color: {COLORS['bg_darkest']}; border-bottom: 1px solid {COLORS['border']}; }}")
        ibl = QHBoxLayout(ib); ibl.setContentsMargins(10,6,10,6); ibl.setSpacing(8)
        logo = QLabel("🔬"); logo.setStyleSheet("font-size: 18px; background: transparent; border: none;"); ibl.addWidget(logo)
        tl = QLabel("VOLATILITY 3"); tl.setStyleSheet(f"color: {COLORS['primary']}; font-size: 14px; font-weight: 800; letter-spacing: 2px; background: transparent; border: none;"); ibl.addWidget(tl)
        ibl.addStretch()
        self.img_icon = QLabel("⚠"); self.img_icon.setStyleSheet(f"font-size: 14px; color: {COLORS['warning']}; background: transparent; border: none;"); ibl.addWidget(self.img_icon)
        self.img_path = QLabel("No image — Ctrl+O"); self.img_path.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; background: transparent; border: none;"); ibl.addWidget(self.img_path)
        oib = QPushButton("📂 Open"); oib.setStyleSheet(f"background: {COLORS['bg_surface_alt']}; border: 1px solid {COLORS['border_light']}; border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;")
        oib.clicked.connect(self._open_image); ibl.addWidget(oib)
        ml.addWidget(ib)
        # Main splitter
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal); self.main_splitter.setHandleWidth(2)
        # LEFT: Plugin Browser
        lp = QWidget(); ll = QVBoxLayout(lp); ll.setContentsMargins(8,8,4,8); ll.setSpacing(6)
        lph = QHBoxLayout()
        lbl = QLabel("🧩  PLUGINS"); lbl.setObjectName("sectionTitle"); lph.addWidget(lbl); lph.addStretch()
        self.plugin_badge = QLabel(f"{len(self.plugin_list)}"); self.plugin_badge.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 10px; font-weight: 700; background: {COLORS['bg_surface']}; border: 1px solid {COLORS['border']}; border-radius: 8px; padding: 1px 8px;")
        lph.addWidget(self.plugin_badge)
        bfb = QPushButton("⭐"); bfb.setFixedSize(28,28); bfb.setToolTip("Bookmarks only"); bfb.setCheckable(True); bfb.clicked.connect(self._toggle_bm_filter); self._bm_filter = False; lph.addWidget(bfb)
        ll.addLayout(lph)
        self.plugin_search = QLineEdit(); self.plugin_search.setPlaceholderText("🔍  Search plugins..."); self.plugin_search.setClearButtonEnabled(True)
        self.plugin_search.textChanged.connect(self._filter_plugins); ll.addWidget(self.plugin_search)
        self.plugin_tree = QTreeWidget(); self.plugin_tree.setHeaderLabels(["Plugin"]); self.plugin_tree.setRootIsDecorated(True); self.plugin_tree.setAnimated(True)
        self.plugin_tree.itemClicked.connect(self._on_plugin_selected); self.plugin_tree.itemDoubleClicked.connect(self._on_plugin_dbl)
        self.plugin_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu); self.plugin_tree.customContextMenuRequested.connect(self._plugin_ctx)
        ll.addWidget(self.plugin_tree); self._populate_plugin_tree()
        self.main_splitter.addWidget(lp)
        # CENTER: Config + Results + Bottom Panels (2-panel layout)
        cp = QWidget(); cl = QVBoxLayout(cp); cl.setContentsMargins(3,6,6,6); cl.setSpacing(4)
        cg = QGroupBox("PLUGIN CONFIGURATION"); ci = QVBoxLayout(cg); ci.setContentsMargins(6,6,6,6); ci.setSpacing(4)
        self.config_form = PluginConfigForm(); ci.addWidget(self.config_form)
        ctrl = QHBoxLayout(); ctrl.setSpacing(6)
        self.run_btn = QPushButton("▶ RUN"); self.run_btn.setObjectName("runButton"); self.run_btn.clicked.connect(self._run_analysis); self.run_btn.setEnabled(False); ctrl.addWidget(self.run_btn)
        self.stop_btn = QPushButton("⏹ STOP"); self.stop_btn.setObjectName("stopButton"); self.stop_btn.clicked.connect(self._stop_analysis); self.stop_btn.setEnabled(False); self.stop_btn.setFixedWidth(80); ctrl.addWidget(self.stop_btn)
        ci.addLayout(ctrl)
        self.progress_bar = QProgressBar(); self.progress_bar.setRange(0,100); self.progress_bar.setValue(0); self.progress_bar.setTextVisible(True); self.progress_bar.setFormat("%p%"); ci.addWidget(self.progress_bar)
        self.progress_label = QLabel(""); self.progress_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;"); ci.addWidget(self.progress_label)
        cs = QSplitter(Qt.Orientation.Vertical); cs.addWidget(cg)
        self.results_stack = QStackedWidget()
        self.welcome_widget = WelcomeWidget(self.recent_files_mgr); self.welcome_widget.open_image_clicked.connect(self._open_image); self.welcome_widget.recent_file_clicked.connect(self._load_recent)
        self.results_stack.addWidget(self.welcome_widget)
        rc = QWidget(); rl = QVBoxLayout(rc); rl.setContentsMargins(0,0,0,0); rl.setSpacing(2)
        rh = QHBoxLayout()
        rlbl = QLabel("📊 RESULTS"); rlbl.setObjectName("sectionTitle"); rh.addWidget(rlbl); rh.addStretch()
        ctb = QPushButton("✖ Close"); ctb.setFixedHeight(24); ctb.clicked.connect(self._close_current_tab); rh.addWidget(ctb)
        rl.addLayout(rh)
        self.results_tabs = QTabWidget(); self.results_tabs.setTabsClosable(True); self.results_tabs.tabCloseRequested.connect(self._close_tab); rl.addWidget(self.results_tabs)
        self.results_stack.addWidget(rc); self.results_stack.setCurrentIndex(0)
        cs.addWidget(self.results_stack)
        # Bottom tabs: Image Info | History | Notes | Log
        self.bottom_tabs = QTabWidget()
        iw = QWidget(); iwl = QVBoxLayout(iw); iwl.setContentsMargins(4,4,4,4)
        self.info_display = QTextEdit(); self.info_display.setReadOnly(True)
        self.info_display.setStyleSheet(f"QTextEdit {{ background-color: {COLORS['bg_surface']}; border: none; font-family: Consolas, monospace; font-size: 11px; }}")
        self.info_display.setHtml(f'<div style="color: {COLORS["text_muted"]}; padding: 8px; text-align: center;">📂 No image loaded</div>')
        iwl.addWidget(self.info_display); self.bottom_tabs.addTab(iw, "📂 Image")
        hw = QWidget(); hwl = QVBoxLayout(hw); hwl.setContentsMargins(4,4,4,4)
        self.history_list = QTreeWidget(); self.history_list.setHeaderLabels(["#","Plugin","Status","Time"]); self.history_list.setRootIsDecorated(False)
        self.history_list.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents); self.history_list.header().setStretchLastSection(True)
        hwl.addWidget(self.history_list); self.bottom_tabs.addTab(hw, "📋 History")
        self.notes_panel = ForensicNotesPanel(); self.bottom_tabs.addTab(self.notes_panel, "📝 Notes")
        lw = QWidget(); lwl = QVBoxLayout(lw); lwl.setContentsMargins(4,4,4,4)
        lch = QHBoxLayout(); lch.addStretch()
        clb = QPushButton("🗑 Clear"); clb.setFixedHeight(22); clb.setFixedWidth(60); lch.addWidget(clb); lwl.addLayout(lch)
        self.log_viewer = QTextEdit(); self.log_viewer.setReadOnly(True)
        self.log_viewer.setStyleSheet(f"QTextEdit {{ background-color: {COLORS['bg_darkest']}; color: {COLORS['text_secondary']}; border: 1px solid {COLORS['border']}; border-radius: 6px; font-family: Consolas, monospace; font-size: 11px; padding: 4px; }}")
        clb.clicked.connect(lambda: self.log_viewer.clear()); lwl.addWidget(self.log_viewer)
        self.bottom_tabs.addTab(lw, "📄 Log")
        gh = QTextEditLogHandler(self.log_viewer); gh.setLevel(logging.INFO); logging.getLogger().addHandler(gh)
        cs.addWidget(self.bottom_tabs)
        cs.setStretchFactor(0, 0); cs.setStretchFactor(1, 3); cs.setStretchFactor(2, 1)
        cl.addWidget(cs); self.main_splitter.addWidget(cp)
        self.main_splitter.setSizes([220, 680])
        ml.addWidget(self.main_splitter, 1)

    # ─── Plugin Tree: Functional Categories with Friendly Names ─────────
    def _populate_plugin_tree(self):
        self.plugin_tree.clear()
        # Recently Used
        recent = [n for n in self.recent_plugins_mgr.get() if n in self.plugin_list]
        if recent:
            ri = QTreeWidgetItem([f"🕐  Recently Used  ({len(recent)})"]); ri.setFlags(ri.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            f = ri.font(0); f.setBold(True); f.setPointSize(11); ri.setFont(0, f); ri.setForeground(0, QColor(COLORS['accent']))
            for n in recent:
                p = n.split('.'); disp = f"{p[0]}.{p[-1]}" if len(p) >= 2 else p[-1]
                pi = QTreeWidgetItem([f"  🕐 {disp}"]); pi.setData(0, Qt.ItemDataRole.UserRole, n); pi.setData(0, Qt.ItemDataRole.UserRole+1, self.plugin_list[n])
                pi.setToolTip(0, n); ri.addChild(pi)
            self.plugin_tree.addTopLevelItem(ri); ri.setExpanded(True)
        # Bookmarks
        bms = [n for n in self.bookmarks_mgr.bookmarks if n in self.plugin_list]
        if bms:
            bi = QTreeWidgetItem([f"⭐  Bookmarks  ({len(bms)})"]); bi.setFlags(bi.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            f = bi.font(0); f.setBold(True); f.setPointSize(11); bi.setFont(0, f); bi.setForeground(0, QColor(COLORS['warning']))
            for n in bms:
                p = n.split('.'); disp = f"{p[0]}.{p[-1]}" if len(p) >= 2 else p[-1]
                pi = QTreeWidgetItem([f"  ⭐ {disp}"]); pi.setData(0, Qt.ItemDataRole.UserRole, n); pi.setData(0, Qt.ItemDataRole.UserRole+1, self.plugin_list[n])
                pi.setToolTip(0, n); bi.addChild(pi)
            self.plugin_tree.addTopLevelItem(bi); bi.setExpanded(True)
        # Functional categories
        cats = {}
        for name, cls in sorted(self.plugin_list.items()):
            cat = get_plugin_category(name)
            if cat not in cats: cats[cat] = []
            cats[cat].append((name, cls))
        cat_order = ["🔍 Process Analysis", "🌐 Network Analysis", "🦠 Malware Detection", "🗝️ Registry", "🔐 Credentials", "📁 File System", "💾 Memory Analysis", "ℹ️ System Info"]
        for cat in cat_order:
            if cat not in cats: continue
            plugins = cats[cat]
            ci = QTreeWidgetItem([f"{cat}  ({len(plugins)})"]); ci.setFlags(ci.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            f = ci.font(0); f.setBold(True); f.setPointSize(11); ci.setFont(0, f); ci.setForeground(0, QColor(COLORS['primary']))
            for pn, pc in sorted(plugins, key=lambda x: x[0]):
                p = pn.split('.'); disp = f"{p[0]}.{p[-1]}" if len(p) >= 2 else p[-1]
                star = "⭐ " if self.bookmarks_mgr.is_bookmarked(pn) else "  "
                pi = QTreeWidgetItem([f"{star}{disp}"]); pi.setData(0, Qt.ItemDataRole.UserRole, pn); pi.setData(0, Qt.ItemDataRole.UserRole+1, pc)
                pi.setToolTip(0, pn); ci.addChild(pi)
            self.plugin_tree.addTopLevelItem(ci)
        # Uncategorized
        remaining = {cat: plugins for cat, plugins in cats.items() if cat not in cat_order}
        for cat, plugins in remaining.items():
            ci = QTreeWidgetItem([f"{cat}  ({len(plugins)})"]); ci.setFlags(ci.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            f = ci.font(0); f.setBold(True); ci.setFont(0, f); ci.setForeground(0, QColor(COLORS['text_secondary']))
            for pn, pc in sorted(plugins, key=lambda x: x[0]):
                p = pn.split('.'); disp = f"{p[0]}.{p[-1]}" if len(p) >= 2 else p[-1]
                star = "⭐ " if self.bookmarks_mgr.is_bookmarked(pn) else "  "
                pi = QTreeWidgetItem([f"{star}{disp}"]); pi.setData(0, Qt.ItemDataRole.UserRole, pn); pi.setData(0, Qt.ItemDataRole.UserRole+1, pc)
                pi.setToolTip(0, pn); ci.addChild(pi)
            self.plugin_tree.addTopLevelItem(ci)
        for i in range(self.plugin_tree.topLevelItemCount()): self.plugin_tree.topLevelItem(i).setExpanded(True)

    def _filter_plugins(self, text):
        text = text.lower().strip()
        def filt(item):
            if item.childCount() == 0:
                pn = item.data(0, Qt.ItemDataRole.UserRole)
                if pn:
                    match = text in pn.lower() or text in item.text(0).lower() or text in pn.split('.')[-1].lower()
                    if self._bm_filter: match = match and self.bookmarks_mgr.is_bookmarked(pn)
                    item.setHidden(not match); return match
                return False
            any_vis = False
            for i in range(item.childCount()):
                if filt(item.child(i)): any_vis = True
            item.setHidden(not any_vis and bool(text))
            if any_vis and text: item.setExpanded(True)
            return any_vis
        for i in range(self.plugin_tree.topLevelItemCount()): filt(self.plugin_tree.topLevelItem(i))
        if text:
            vis = sum(1 for n in self.plugin_list if text in n.lower() or text in n.split('.')[-1].lower())
            self.plugin_badge.setText(str(vis))
        else: self.plugin_badge.setText(str(len(self.plugin_list)))

    def _toggle_bm_filter(self): self._bm_filter = not self._bm_filter; self._filter_plugins(self.plugin_search.text())

    def _plugin_ctx(self, pos):
        item = self.plugin_tree.itemAt(pos)
        if not item: return
        pn = item.data(0, Qt.ItemDataRole.UserRole)
        if not pn: return
        menu = QMenu(self)
        is_bm = self.bookmarks_mgr.is_bookmarked(pn)
        ba = menu.addAction("★ Remove Bookmark" if is_bm else "☆ Add Bookmark"); ba.triggered.connect(lambda: self._toggle_bm_for(pn))
        ra = menu.addAction("▶ Run Plugin"); ra.triggered.connect(lambda: (self._on_plugin_selected(item, 0), self._run_analysis())); ra.setEnabled(self.image_path is not None)
        menu.exec(self.plugin_tree.viewport().mapToGlobal(pos))

    def _toggle_bm_for(self, pn):
        added = self.bookmarks_mgr.toggle(pn); self._populate_plugin_tree()
        self._toast(f"⭐ Bookmarked: {get_plugin_friendly_name(pn)}" if added else f"Removed: {get_plugin_friendly_name(pn)}", "success" if added else "info")

    def _toggle_bookmark(self):
        if hasattr(self, '_selected_plugin_name'): self._toggle_bm_for(self._selected_plugin_name)

    def _on_plugin_selected(self, item, col):
        pn = item.data(0, Qt.ItemDataRole.UserRole); pc = item.data(0, Qt.ItemDataRole.UserRole+1)
        if pn and pc:
            self.config_form.load_plugin(pn, pc); self._selected_plugin_name = pn; self._selected_plugin_class = pc
            self.run_btn.setEnabled(self.image_path is not None)

    def _on_plugin_dbl(self, item, col):
        self._on_plugin_selected(item, col)
        if self.image_path and hasattr(self, '_selected_plugin_name'): self._run_analysis()

    # ─── Image Loading ──────────────────────────────────────────────────
    def _open_image(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Open Memory Image", "", "Memory Dumps (*.vmem *.raw *.mem *.dmp *.img *.bin *.lime *.elf *.aff4);;All Files (*.*)")
        if fp: self._load_image(fp)

    def _load_image(self, fp):
        if not os.path.isfile(fp): return
        self.image_path = fp; fn = os.path.basename(fp); fs = os.path.getsize(fp); sz = self._fmt_size(fs)
        self.img_path.setText(fp); self.img_path.setStyleSheet(f"color: {COLORS['accent']}; font-family: Consolas, monospace; font-size: 12px; background: transparent; border: none;")
        self.img_icon.setText("✅"); self.img_icon.setStyleSheet(f"font-size: 16px; color: {COLORS['success']}; background: transparent; border: none;")
        self.status_image.setText(f"  Image: {fn} ({sz})"); self.status_image.setStyleSheet(f"color: {COLORS['success']};")
        mod = datetime.datetime.fromtimestamp(os.path.getmtime(fp))
        try:
            h = hashlib.md5(); f = open(fp, "rb"); h.update(f.read(65536)); f.close(); md5 = h.hexdigest()
        except: md5 = "Error"
        self.info_display.setHtml(f'<div style="padding: 4px;"><table style="color: {COLORS["text_secondary"]}; font-size: 12px; width: 100%;"><tr><td style="color: {COLORS["text_muted"]}; padding: 3px 8px 3px 0;">File:</td><td style="color: {COLORS["accent"]};">{fn}</td></tr><tr><td style="color: {COLORS["text_muted"]}; padding: 3px 8px 3px 0;">Size:</td><td>{sz} ({fs:,} bytes)</td></tr><tr><td style="color: {COLORS["text_muted"]}; padding: 3px 8px 3px 0;">Modified:</td><td>{mod:%Y-%m-%d %H:%M:%S}</td></tr><tr><td style="color: {COLORS["text_muted"]}; padding: 3px 8px 3px 0;">MD5 (64K):</td><td style="font-family: Consolas; font-size: 11px;">{md5}</td></tr></table></div>')
        if hasattr(self, '_selected_plugin_name'): self.run_btn.setEnabled(True)
        self.recent_files_mgr.add(fp); self._update_recent_menu(); self.welcome_widget.refresh_recent()
        self.notes_panel.add_auto_note(f"Loaded: {fn} ({sz})")
        self._log(f"Image loaded: {fn} ({sz})"); self._toast(f"Image loaded: {fn}", "success")

    def _update_recent_menu(self):
        self.recent_menu.clear(); files = self.recent_files_mgr.get()
        if not files: na = self.recent_menu.addAction("No recent files"); na.setEnabled(False); return
        for fp in files:
            a = self.recent_menu.addAction(f"📄 {os.path.basename(fp)}"); a.setToolTip(fp); a.triggered.connect(lambda _, p=fp: self._load_recent(p))
        self.recent_menu.addSeparator()
        ca = self.recent_menu.addAction("🗑 Clear"); ca.triggered.connect(self._clear_recent)

    def _load_recent(self, fp):
        if os.path.isfile(fp): self._load_image(fp)
        else: self._toast(f"File not found: {fp}", "error")

    def _clear_recent(self): self.recent_files_mgr.clear(); self._update_recent_menu(); self.welcome_widget.refresh_recent()

    # ─── Analysis ───────────────────────────────────────────────────────
    def _cleanup_finished_workers(self):
        """Remove references to workers that have finished, preventing memory leaks and crashes."""
        still_alive = []
        for w in self._worker_pool:
            try:
                if w.isRunning():
                    still_alive.append(w)
                else:
                    w.deleteLater()  # Schedule safe C++ object deletion
            except RuntimeError:
                pass  # Already deleted
        self._worker_pool = still_alive

    def _run_analysis(self):
        if not self.image_path: self._toast("Load a memory image first (Ctrl+O)", "warning"); return
        if not hasattr(self, '_selected_plugin_name'): self._toast("Select a plugin from the browser", "warning"); return
        if self.current_worker and self.current_worker.isRunning(): self._toast("Analysis already running (Shift+F5 to stop)", "warning"); return
        # Clean up any finished workers before starting a new one
        self._cleanup_finished_workers()
        pn = self._selected_plugin_name; pc = self._selected_plugin_class; ec = self.config_form.get_config()
        friendly = get_plugin_friendly_name(pn)
        self.progress_bar.setValue(0); self.progress_label.setText(f"Running {friendly}..."); self.progress_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")
        self.run_btn.setEnabled(False); self.stop_btn.setEnabled(True); self.toolbar_run.setEnabled(False); self.toolbar_stop.setEnabled(True)
        self._start_time = datetime.datetime.now(); self._elapsed_timer.start(1000)
        self._analysis_count += 1
        hi = QTreeWidgetItem([str(self._analysis_count), friendly, "🔄 Running", datetime.datetime.now().strftime("%H:%M:%S")])
        hi.setForeground(2, QColor(COLORS['warning'])); self.history_list.addTopLevelItem(hi); self.history_list.scrollToItem(hi)
        self.recent_plugins_mgr.add(pn)
        worker = AnalysisWorker(pc, self.image_path, pn, ec)
        worker.progress_update.connect(self._on_progress)
        worker.analysis_finished.connect(lambda p,c,r: self._on_finished(p,c,r,hi))
        worker.analysis_error.connect(lambda p,e: self._on_error(p,e,hi))
        worker.log_message.connect(self._log)
        # Use finished signal to schedule safe cleanup
        worker.finished.connect(lambda: self._on_worker_thread_finished(worker))
        self.current_worker = worker
        self._worker_pool.append(worker)
        worker.start()

    def _on_worker_thread_finished(self, worker):
        """Called when the QThread's event loop exits. Safely disconnects all signals."""
        # Generically disconnect all custom signals on any worker type
        signal_names = ['progress_update', 'analysis_finished', 'analysis_error',
                        'log_message', 'dump_finished', 'dump_error']
        for name in signal_names:
            try:
                sig = getattr(worker, name, None)
                if sig is not None:
                    sig.disconnect()
            except (TypeError, RuntimeError):
                pass  # Already disconnected or object deleted

    def _stop_analysis(self):
        if self.current_worker:
            try:
                if self.current_worker.isRunning():
                    self.current_worker.cancel(); self._toast("Stopping...", "warning")
            except RuntimeError:
                pass  # Worker already deleted

    def _run_workflow(self, pns):
        if not self.image_path: self._toast("Load a memory image first", "warning"); return
        avail = [n for n in pns if n in self.plugin_list]
        if not avail: self._toast("No plugins from this workflow available", "warning"); return
        self._toast(f"Starting workflow: {len(avail)} plugins...", "info")
        n = avail[0]; self._selected_plugin_name = n; self._selected_plugin_class = self.plugin_list[n]
        self.config_form.load_plugin(n, self.plugin_list[n]); self._run_analysis()
        self._workflow_queue = avail[1:]

    def _on_progress(self, val, desc):
        self.progress_bar.setValue(min(100, max(0, int(val))))
        if desc: self.progress_label.setText(desc)

    def _on_finished(self, pn, cols, rows, hi):
        self._elapsed_timer.stop(); elapsed = self._get_elapsed()
        friendly = get_plugin_friendly_name(pn)
        self.run_btn.setEnabled(True); self.stop_btn.setEnabled(False); self.toolbar_run.setEnabled(True); self.toolbar_stop.setEnabled(False)
        self.progress_bar.setValue(100); self.progress_label.setText(f"✅ {friendly} — {len(rows)} results in {elapsed}")
        hi.setText(2, f"✅ {len(rows)} rows"); hi.setForeground(2, QColor(COLORS['success'])); hi.setText(3, elapsed)
        tab = ResultsTab(pn, cols, rows)
        idx = self.results_tabs.addTab(tab, f"📊 {friendly}"); self.results_tabs.setCurrentIndex(idx)
        self.results_stack.setCurrentIndex(1); self._completed_plugins.add(pn); self._populate_plugin_tree()
        self.notes_panel.add_auto_note(f"{friendly}: {len(rows)} results ({elapsed})")
        self._log(f"Complete: {friendly} — {len(rows)} results in {elapsed}"); self._toast(f"✅ {friendly}: {len(rows)} results", "success")
        # Suggest related plugins
        self._suggest_related(pn)
        # Continue workflow
        if hasattr(self, '_workflow_queue') and self._workflow_queue:
            np = self._workflow_queue.pop(0)
            if np in self.plugin_list:
                self._selected_plugin_name = np; self._selected_plugin_class = self.plugin_list[np]
                self.config_form.load_plugin(np, self.plugin_list[np])
                # Wait enough time for the current worker thread to fully stop before starting the next
                QTimer.singleShot(1500, self._run_workflow_next)

    def _run_workflow_next(self):
        """Safely start the next workflow plugin after ensuring the previous worker is done."""
        if self.current_worker:
            try:
                if self.current_worker.isRunning():
                    # Previous worker still running, retry after a delay
                    QTimer.singleShot(1000, self._run_workflow_next)
                    return
            except RuntimeError:
                pass
        self._cleanup_finished_workers()
        self._run_analysis()

    def _suggest_related(self, pn):
        """Suggest related plugins after analysis completes."""
        suggestions = {
            "windows.pslist.PsList": ["Try 🌳 Process Tree for parent→child view, or Command Lines for arguments"],
            "windows.pstree.PsTree": ["Try Loaded DLLs or Open Handles for deeper process analysis"],
            "windows.netscan.NetScan": ["Try Network Status for active connections"],
            "windows.malfind.Malfind": ["Try Hidden Modules or SSDT Hooks for more IOCs"],
            "windows.registry.hivelist.HiveList": ["Try Registry Keys to browse specific hive contents"],
        }
        if pn in suggestions:
            self._log(f"💡 Suggestion: {suggestions[pn][0]}")

    def _on_error(self, pn, err, hi):
        self._elapsed_timer.stop(); elapsed = self._get_elapsed(); friendly = get_plugin_friendly_name(pn)
        self.run_btn.setEnabled(True); self.stop_btn.setEnabled(False); self.toolbar_run.setEnabled(True); self.toolbar_stop.setEnabled(False)
        self.progress_bar.setValue(0); self.progress_label.setText(f"❌ {friendly} failed"); self.progress_label.setStyleSheet(f"color: {COLORS['error']}; font-size: 11px;")
        hi.setText(2, "❌ Failed"); hi.setForeground(2, QColor(COLORS['error'])); hi.setText(3, elapsed)
        et = QWidget(); el = QVBoxLayout(et); el.setContentsMargins(16,16,16,16)
        etl = QLabel(f"❌  {friendly} Failed"); etl.setStyleSheet(f"color: {COLORS['error']}; font-size: 16px; font-weight: 700;"); el.addWidget(etl)
        hint = QLabel("Common causes: wrong OS plugin for image, missing symbols, unsupported format, or insufficient memory.")
        hint.setWordWrap(True); hint.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px; margin-bottom: 8px;"); el.addWidget(hint)
        ep = QPlainTextEdit(); ep.setReadOnly(True); ep.setPlainText(err)
        ep.setStyleSheet(f"QPlainTextEdit {{ background-color: {COLORS['bg_darkest']}; color: {COLORS['error']}; border: 1px solid {COLORS['error']}; border-radius: 8px; padding: 12px; font-family: Consolas; font-size: 12px; }}")
        el.addWidget(ep)
        idx = self.results_tabs.addTab(et, f"❌ {friendly}"); self.results_tabs.setCurrentIndex(idx); self.results_stack.setCurrentIndex(1)
        self._log(f"Error in {friendly}: {err.split(chr(10))[0]}"); self._toast(f"❌ {friendly} failed", "error")
        if hasattr(self, '_workflow_queue') and self._workflow_queue:
            np = self._workflow_queue.pop(0)
            if np in self.plugin_list:
                self._selected_plugin_name = np; self._selected_plugin_class = self.plugin_list[np]
                self.config_form.load_plugin(np, self.plugin_list[np])
                QTimer.singleShot(1500, self._run_workflow_next)

    # ─── Tab / Hex / Session ────────────────────────────────────────────
    def _close_tab(self, idx):
        self.results_tabs.removeTab(idx)
        if self.results_tabs.count() == 0: self.results_stack.setCurrentIndex(0)

    def _close_current_tab(self):
        idx = self.results_tabs.currentIndex()
        if idx >= 0: self._close_tab(idx)

    def _clear_results(self):
        while self.results_tabs.count() > 0: self.results_tabs.removeTab(0)
        self.results_stack.setCurrentIndex(0); self._log("Results cleared.")

    def _open_hex_viewer(self):
        if not self.image_path: self._toast("Load an image first (Ctrl+O)", "warning"); return
        for i in range(self.results_tabs.count()):
            if self.results_tabs.tabText(i).startswith("🔬"): self.results_tabs.setCurrentIndex(i); return
        hw = HexViewerWidget(); hw.load_file(self.image_path)
        idx = self.results_tabs.addTab(hw, "🔬 Hex Viewer"); self.results_tabs.setCurrentIndex(idx); self.results_stack.setCurrentIndex(1)

    def _dump_and_hash(self):
        """Open Dump & Hash dialog to extract executables and compute hashes."""
        if not self.image_path:
            self._toast("Load a memory image first (Ctrl+O)", "warning")
            return

        dialog = DumpHashDialog(self)
        self._dump_hash_dialog = dialog  # prevent garbage collection

        def _is_dialog_alive():
            """Check if the dialog widget is still valid."""
            try:
                dialog.isVisible()  # Will throw RuntimeError if C++ object is deleted
                return True
            except RuntimeError:
                return False

        def _start_dump():
            target_val = dialog.target_input.text().strip()
            mode_idx = dialog.mode_combo.currentIndex()
            
            # Map index to mode
            modes = ["pid", "virtaddr", "physaddr", "filter"]
            mode = modes[mode_idx]
            
            target = None
            if target_val:
                target = target_val
            
            dialog.dump_btn.setEnabled(False)
            dialog.progress_label.setText("⏳ Starting dump...")
            dialog.progress_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")

            worker = DumpHashWorker(self.image_path, self.plugin_list, mode=mode, target=target)
            dialog._worker = worker  # prevent garbage collection
            self._worker_pool.append(worker)

            def _on_progress(msg):
                if _is_dialog_alive():
                    dialog.progress_label.setText(f"⏳ {msg}")

            worker.progress_update.connect(_on_progress)
            worker.dump_finished.connect(lambda results: _on_finished(results))
            worker.dump_error.connect(lambda err: _on_error(err))
            worker.finished.connect(lambda: self._on_worker_thread_finished(worker))
            worker.start()

        def _on_finished(results):
            if _is_dialog_alive():
                dialog.dump_btn.setEnabled(True)
                dialog.populate_results(results)
            self._toast(f"🔑 Dumped & hashed {len(results)} file(s)", "success")
            self._log(f"Dump & Hash: {len(results)} file(s) processed")
            if results:
                self.notes_panel.add_auto_note(
                    f"Dump & Hash: {len(results)} files. SHA1 of first: {results[0]['sha1']}")

        def _on_error(err):
            if _is_dialog_alive():
                dialog.dump_btn.setEnabled(True)
                dialog.progress_label.setText(f"❌ {err.split(chr(10))[0]}")
                dialog.progress_label.setStyleSheet(f"color: {COLORS['error']}; font-size: 11px;")
            self._toast(f"Dump failed: {err.split(chr(10))[0]}", "error")
            self._log(f"Dump & Hash error: {err.split(chr(10))[0]}")

        dialog.dump_btn.clicked.connect(_start_dump)
        # Cancel the worker if the dialog is closed before it finishes
        dialog.finished.connect(lambda: dialog._worker.cancel() if dialog._worker and dialog._worker.isRunning() else None)
        dialog.show()

    def _save_session(self):
        fp, _ = QFileDialog.getSaveFileName(self, "Save Session", f"vol3_session_{datetime.datetime.now():%Y%m%d_%H%M%S}.json", "JSON Files (*.json)")
        if not fp: return
        try:
            with open(fp, "w", encoding="utf-8") as f:
                json.dump({"version":"1.0","saved_at":datetime.datetime.now().isoformat(),"image_path":self.image_path,"notes":self.notes_panel.get_notes_data(),"bookmarks":self.bookmarks_mgr.bookmarks}, f, indent=2)
            self._toast("Session saved!", "success")
        except Exception as e: self._toast(f"Save failed: {e}", "error")

    def _load_session(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Load Session", "", "JSON Files (*.json)")
        if not fp: return
        try:
            with open(fp, "r", encoding="utf-8") as f: s = json.load(f)
            if s.get("image_path") and os.path.isfile(s["image_path"]): self._load_image(s["image_path"])
            if s.get("notes"): self.notes_panel.load_notes_data(s["notes"])
            self._toast("Session loaded!", "success")
        except Exception as e: self._toast(f"Load failed: {e}", "error")

    def _copy_current_selection(self):
        tab = self.results_tabs.currentWidget()
        if isinstance(tab, ResultsTab): tab._copy_selected()

    def _focus_notes(self): self.notes_panel.note_input.setFocus()
    def _focus_filter(self):
        tab = self.results_tabs.currentWidget()
        if isinstance(tab, ResultsTab): tab.search_input.setFocus()
        else: self.plugin_search.setFocus()

    def _export_current(self, fmt):
        tab = self.results_tabs.currentWidget()
        if isinstance(tab, ResultsTab): tab._export(fmt)

    def _log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_viewer.append(f'<span style="color:{COLORS["text_muted"]};">[{ts}]</span> <span style="color:{COLORS["text_secondary"]};">{msg}</span>')

    def _toast(self, msg, tt="info", dur=3000):
        try: ToastNotification(self, msg, tt, dur)
        except: pass

    def _fmt_size(self, s):
        for u in ["B","KB","MB","GB","TB"]:
            if abs(s) < 1024.0: return f"{s:.1f} {u}"
            s /= 1024.0
        return f"{s:.1f} PB"

    def _update_elapsed(self):
        if self._start_time:
            e = datetime.datetime.now() - self._start_time; s = int(e.total_seconds()); m, s = divmod(s, 60); h, m = divmod(m, 60)
            self.status_elapsed.setText(f"⏱ {h:02d}:{m:02d}:{s:02d}" if h else f"⏱ {m:02d}:{s:02d}")

    def _get_elapsed(self):
        if self._start_time:
            s = int((datetime.datetime.now() - self._start_time).total_seconds())
            if s < 60: return f"{s}s"
            m, s = divmod(s, 60)
            if m < 60: return f"{m}m {s}s"
            h, m = divmod(m, 60); return f"{h}h {m}m"
        return ""

    def _show_shortcuts(self): ShortcutsDialog(self).exec()

    def _show_about(self):
        msg = QMessageBox(self); msg.setWindowTitle("About"); msg.setIcon(QMessageBox.Icon.Information)
        msg.setText(f"<h2 style='color: {COLORS['primary']};'>🔬 Volatility 3 GUI</h2><p>Version: {APP_VERSION}</p><p>Professional memory forensics workstation.</p><p><b>Features:</b></p><ul><li>Smart plugin browser with categories</li><li>Process tree with suspicious detection</li><li>Results filtering, sorting & export</li><li>Hex viewer & forensic notes</li><li>Quick workflows & session management</li></ul><p style='color:{COLORS['text_muted']};'>Built with PyQt6 • Python {sys.version.split()[0]}</p><hr><p style='font-size:11px;'>© Volatility Foundation</p>")
        msg.exec()


def main():
    os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"
    app = QApplication(sys.argv); app.setStyle("Fusion"); app.setStyleSheet(DARK_THEME_QSS)
    window = VolatilityGUI(); window.show()
    exit_code = app.exec()
    # Ensure all worker threads are stopped before exiting to prevent crash-on-close
    if window.current_worker:
        try:
            if window.current_worker.isRunning():
                window.current_worker.cancel()
                window.current_worker.wait(5000)  # Wait up to 5 seconds
        except RuntimeError:
            pass
    for w in window._worker_pool:
        try:
            if w.isRunning():
                w.cancel()
                w.wait(3000)
        except RuntimeError:
            pass
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
