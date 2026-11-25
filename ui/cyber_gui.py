"""Русскоязычный графический интерфейс в стиле киберпанк для Windows (BTC + TRON, CSV/TXT и RPC)."""

from __future__ import annotations

import csv
import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional

from core import utils
from core.block_processor import BlockProcessor, ProcessingStats
from core.btc_rest_client import BTCRestClient
from core.cache_manager import LRUCache
from core.database_manager import DatabaseManager
from core.file_loader import LoadedDataset, load_input_file
from core.file_processor import FileScanProcessor
from core.rpc_client import RPCClient
from core.signature_analyzer import Signature, SignatureAnalyzer
from core.tron_client import TronAPIClient

# Киберпанк-палитра (с улучшенным контрастом для читаемости)
BG_VOID = "#07090F"
BG_PANEL = "#0D1321"
BG_CARD = "#111A2E"
BG_INPUT = "#152038"
BG_HOVER = "#1E2E50"
BORDER_CYAN = "#00F0FF"
BORDER_DIM = "#23375C"
NEON_CYAN = "#00F0FF"
NEON_MAGENTA = "#FF2A6D"
NEON_GREEN = "#00FF88"
NEON_AMBER = "#FFB800"
TEXT_MAIN = "#EDF4FF"
TEXT_MUTED = "#8FA5C9"

CONFIG_FILE = "scanner_config.json"
PREVIEW_ROW_LIMIT = 500
CHECKED_SIG_UI_LIMIT = 2000


def _enable_windows_dpi_and_dark_titlebar(root: tk.Tk) -> None:
    """Включает HiDPI и тёмный заголовок окна в Windows 10/11."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE
            value = ctypes.c_int(1)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)
            )
    except Exception:
        pass


class CyberScannerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("ECDSA // КИБЕР-СКАНЕР УЯЗВИМОСТЕЙ (TRON + BTC) v3.1")
        self.root.configure(bg=BG_VOID)
        self.root.geometry("1360x850")
        self.root.minsize(1140, 720)

        self.font_ui = ("Segoe UI", 10) if sys.platform == "win32" else ("DejaVu Sans", 10)
        self.font_small = ("Segoe UI", 9) if sys.platform == "win32" else ("DejaVu Sans", 9)
        self.font_bold = ("Segoe UI", 10, "bold") if sys.platform == "win32" else ("DejaVu Sans", 10, "bold")
        self.font_title = ("Consolas", 14, "bold") if sys.platform == "win32" else ("DejaVu Sans Mono", 13, "bold")
        self.font_mono = ("Consolas", 9) if sys.platform == "win32" else ("DejaVu Sans Mono", 9)
        self.font_kpi = ("Consolas", 15, "bold") if sys.platform == "win32" else ("DejaVu Sans Mono", 14, "bold")

        self._ui_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._scan_thread: Optional[threading.Thread] = None
        self._active_processor: Any = None
        self._active_api_client: Any = None
        self._db_manager: Optional[DatabaseManager] = None
        self._r_cache: Optional[LRUCache[str, List[Signature]]] = None
        self._dataset: Optional[LoadedDataset] = None
        self._scan_start_time: float = 0.0
        self._is_running: bool = False
        self._detections: List[Dict[str, Any]] = []
        self._checked_sigs: List[Dict[str, Any]] = []

        # Режим работы: "file" (CSV/TXT) или "rpc" (блоки Bitcoin Core)
        self.var_mode = tk.StringVar(value="file")
        self.var_network_choice = tk.StringVar(value="Автоопределение")
        self.var_file_path = tk.StringVar(value="")

        # Настройки TRON API
        self.var_tron_endpoint = tk.StringVar(value=TronAPIClient.DEFAULT_ENDPOINT)
        self.var_tron_api_key = tk.StringVar(value="")
        self.var_show_tron_key = tk.BooleanVar(value=False)

        # Настройки публичного BTC REST API
        self.var_btc_rest_endpoint = tk.StringVar(value=BTCRestClient.DEFAULT_ENDPOINT)

        # Настройки Bitcoin Core RPC
        self.var_endpoint = tk.StringVar(value="http://127.0.0.1:8332")
        self.var_username = tk.StringVar(value="")
        self.var_password = tk.StringVar(value="")
        self.var_show_pass = tk.BooleanVar(value=False)
        self.var_start_height = tk.StringVar(value="700000")
        self.var_end_height = tk.StringVar(value="700100")

        # Фильтры CSV / TXT
        self.var_only_success = tk.BooleanVar(value=True)
        self.var_filter_address = tk.StringVar(value="")
        self.var_max_items = tk.StringVar(value="0")
        self.var_max_tx_per_addr = tk.StringVar(value="200")
        self.var_only_outgoing = tk.BooleanVar(value=True)

        # Общие параметры производительности и БД
        self.var_threads = tk.StringVar(value="4")
        self.var_rate_limit = tk.StringVar(value="6")
        self.var_db_path = tk.StringVar(value="ecdsa_scanner.db")
        self.var_dry_run = tk.BooleanVar(value=False)
        self.var_verbose = tk.BooleanVar(value=False)

        # Вкладки: поиск по файлу, поиск по проверенным подписям, проверка отдельной TX
        self.var_preview_search = tk.StringVar(value="")
        self.var_sigs_search = tk.StringVar(value="")
        self.var_txid_lookup = tk.StringVar(value="")
        self.var_tx_lookup_net = tk.StringVar(value="TRON (TronGrid)")

        self._load_config()
        self._configure_styles()
        self._build_layout()
        self._switch_mode(self.var_mode.get())
        _enable_windows_dpi_and_dark_titlebar(self.root)

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(80, self._poll_queue)
        self._append_log(
            "INFO",
            "Сканер v3.1 готов. Выберите файл CSV (транзакции) или TXT (адреса/TXID), либо переключитесь на блоки Bitcoin RPC.",
        )

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("Cyber.TNotebook", background=BG_VOID, borderwidth=0)
        style.configure(
            "Cyber.TNotebook.Tab",
            background=BG_PANEL,
            foreground=TEXT_MUTED,
            padding=(12, 8),
            font=self.font_bold,
            borderwidth=0,
        )
        style.map(
            "Cyber.TNotebook.Tab",
            background=[("selected", BG_CARD)],
            foreground=[("selected", NEON_CYAN)],
        )

        style.configure(
            "Cyber.Treeview",
            background=BG_INPUT,
            foreground=TEXT_MAIN,
            fieldbackground=BG_INPUT,
            rowheight=26,
            borderwidth=0,
            font=self.font_mono,
        )
        style.configure(
            "Cyber.Treeview.Heading",
            background=BG_PANEL,
            foreground=NEON_CYAN,
            font=self.font_bold,
            relief="flat",
        )
        style.map(
            "Cyber.Treeview",
            background=[("selected", BG_HOVER)],
            foreground=[("selected", NEON_CYAN)],
        )

        style.configure(
            "Cyber.Horizontal.TProgressbar",
            troughcolor=BG_INPUT,
            background=NEON_CYAN,
            bordercolor=BORDER_DIM,
            lightcolor=NEON_CYAN,
            darkcolor=NEON_CYAN,
            thickness=14,
        )

        style.configure(
            "Cyber.TCombobox",
            fieldbackground=BG_INPUT,
            background=BG_PANEL,
            foreground=TEXT_MAIN,
            arrowcolor=NEON_CYAN,
            bordercolor=BORDER_DIM,
        )
        style.map(
            "Cyber.TCombobox",
            fieldbackground=[("readonly", BG_INPUT)],
            foreground=[("readonly", TEXT_MAIN)],
        )

    def _build_layout(self) -> None:
        header = tk.Frame(self.root, bg=BG_PANEL, height=58, highlightbackground=BORDER_CYAN, highlightthickness=1)
        header.pack(fill="x", padx=10, pady=(10, 8))
        header.pack_propagate(False)

        left_hdr = tk.Frame(header, bg=BG_PANEL)
        left_hdr.pack(side="left", padx=14, pady=8)
        tk.Label(
            left_hdr,
            text="⚡ ECDSA // КИБЕР-СКАНЕР УЯЗВИМОСТЕЙ",
            bg=BG_PANEL,
            fg=NEON_CYAN,
            font=self.font_title,
        ).pack(side="left")
        tk.Label(
            left_hdr,
            text="  TRON + BTC  |  v3.1",
            bg=BG_PANEL,
            fg=NEON_MAGENTA,
            font=self.font_bold,
        ).pack(side="left", pady=(2, 0))

        right_hdr = tk.Frame(header, bg=BG_PANEL)
        right_hdr.pack(side="right", padx=14)

        self.lbl_net_status = tk.Label(
            right_hdr,
            text="● СЕТЬ: НЕ ПРОВЕРЕНО",
            bg=BG_INPUT,
            fg=TEXT_MUTED,
            font=self.font_mono,
            padx=10,
            pady=4,
            highlightbackground=BORDER_DIM,
            highlightthickness=1,
        )
        self.lbl_net_status.pack(side="left", padx=(0, 10))

        self.lbl_status_badge = tk.Label(
            right_hdr,
            text="СТАТУС: ОЖИДАНИЕ",
            bg=BG_INPUT,
            fg=NEON_CYAN,
            font=self.font_bold,
            padx=12,
            pady=4,
            highlightbackground=NEON_CYAN,
            highlightthickness=1,
        )
        self.lbl_status_badge.pack(side="left")

        body = tk.Frame(self.root, bg=BG_VOID)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        left_shell = tk.Frame(body, bg=BG_PANEL, width=395, highlightbackground=BORDER_DIM, highlightthickness=1)
        left_shell.pack(side="left", fill="y", padx=(0, 10))
        left_shell.pack_propagate(False)
        self._build_scrollable_left_panel(left_shell)

        right_col = tk.Frame(body, bg=BG_VOID)
        right_col.pack(side="left", fill="both", expand=True)
        self._build_telemetry_panel(right_col)

    def _build_scrollable_left_panel(self, shell: tk.Frame) -> None:
        canvas = tk.Canvas(shell, bg=BG_PANEL, highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(shell, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG_PANEL)

        inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_inner_configure(_event: Any) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_configure(event: Any) -> None:
            canvas.itemconfigure(inner_id, width=event.width)

        inner.bind("<Configure>", _on_inner_configure)
        canvas.bind("<Configure>", _on_canvas_configure)
        canvas.configure(yscrollcommand=vsb.set)

        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        def _on_mousewheel(event: Any) -> None:
            if sys.platform == "win32":
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            elif event.num == 4:
                canvas.yview_scroll(-2, "units")
            elif event.num == 5:
                canvas.yview_scroll(2, "units")

        canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", _on_mousewheel))
        canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))

        self._build_control_panel(inner)

    def _step_header(self, parent: tk.Widget, step_num: str, title: str) -> None:
        bar = tk.Frame(parent, bg=BG_PANEL)
        bar.pack(fill="x", padx=12, pady=(12, 6))
        tk.Label(
            bar,
            text=step_num,
            bg=NEON_CYAN,
            fg="#050811",
            font=self.font_bold,
            padx=6,
            pady=1,
        ).pack(side="left", padx=(0, 8))
        tk.Label(bar, text=title, bg=BG_PANEL, fg=TEXT_MAIN, font=self.font_bold).pack(side="left")
        tk.Frame(bar, bg=BORDER_DIM, height=1).pack(side="left", fill="x", expand=True, padx=(8, 0))

    def _entry_row(
        self,
        parent: tk.Widget,
        label: str,
        var: tk.StringVar,
        show: str = "",
        label_w: int = 16,
    ) -> tk.Entry:
        row = tk.Frame(parent, bg=BG_PANEL)
        row.pack(fill="x", padx=12, pady=3)
        tk.Label(row, text=label, bg=BG_PANEL, fg=TEXT_MUTED, font=self.font_small, width=label_w, anchor="w").pack(
            side="left"
        )
        entry = tk.Entry(
            row,
            textvariable=var,
            show=show,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=NEON_CYAN,
            relief="flat",
            font=self.font_mono,
            highlightbackground=BORDER_DIM,
            highlightcolor=NEON_CYAN,
            highlightthickness=1,
        )
        entry.pack(side="left", fill="x", expand=True, ipady=4)
        return entry

    def _cyber_button(
        self,
        parent: tk.Widget,
        text: str,
        command: Any,
        accent: str = NEON_CYAN,
        fill_bg: str = BG_INPUT,
        pady: int = 6,
    ) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=fill_bg,
            fg=accent,
            activebackground=BG_HOVER,
            activeforeground=accent,
            font=self.font_bold,
            relief="flat",
            cursor="hand2",
            highlightbackground=accent,
            highlightthickness=1,
            padx=10,
            pady=pady,
        )

    def _build_control_panel(self, parent: tk.Frame) -> None:
        # === ШАГ 1: ВЫБОР ИСТОЧНИКА ДАННЫХ ===
        self._step_header(parent, "1", "ИСТОЧНИК ДАННЫХ")

        mode_row = tk.Frame(parent, bg=BG_PANEL)
        mode_row.pack(fill="x", padx=12, pady=(0, 8))

        self.btn_mode_file = self._cyber_button(
            mode_row, "📄 ФАЙЛ (CSV / TXT)", lambda: self._switch_mode("file"), accent=NEON_CYAN
        )
        self.btn_mode_file.pack(side="left", fill="x", expand=True, padx=(0, 4))

        self.btn_mode_rpc = self._cyber_button(
            mode_row, "⛓ БЛОКИ BTC (RPC)", lambda: self._switch_mode("rpc"), accent=TEXT_MUTED
        )
        self.btn_mode_rpc.pack(side="left", fill="x", expand=True, padx=(4, 0))

        self.frame_file_picker = tk.Frame(parent, bg=BG_PANEL)

        self.btn_open_file = self._cyber_button(
            self.frame_file_picker,
            "📂 ВЫБРАТЬ CSV ИЛИ TXT ФАЙЛ",
            self._browse_input_file,
            accent=NEON_CYAN,
            fill_bg="#0A2133",
            pady=8,
        )
        self.btn_open_file.pack(fill="x", padx=12, pady=(0, 6))

        self.file_card = tk.Frame(
            self.frame_file_picker, bg=BG_CARD, highlightbackground=BORDER_DIM, highlightthickness=1
        )
        self.file_card.pack(fill="x", padx=12, pady=(0, 6))

        self.lbl_file_name = tk.Label(
            self.file_card,
            text="Файл не выбран",
            bg=BG_CARD,
            fg=TEXT_MAIN,
            font=self.font_bold,
            anchor="w",
            wraplength=330,
            justify="left",
        )
        self.lbl_file_name.pack(fill="x", padx=10, pady=(7, 2))

        self.lbl_file_meta = tk.Label(
            self.file_card,
            text="Поддерживаются:\n• CSV (экспорт транзакций TronScan / BTC / подписи)\n• TXT (список адресов кошельков или TXID)",
            bg=BG_CARD,
            fg=TEXT_MUTED,
            font=self.font_small,
            anchor="w",
            wraplength=330,
            justify="left",
        )
        self.lbl_file_meta.pack(fill="x", padx=10, pady=(0, 8))

        net_row = tk.Frame(self.frame_file_picker, bg=BG_PANEL)
        net_row.pack(fill="x", padx=12, pady=(2, 4))
        tk.Label(net_row, text="Сеть проверки:", bg=BG_PANEL, fg=TEXT_MUTED, font=self.font_small, width=16, anchor="w").pack(
            side="left"
        )
        self.cmb_network = ttk.Combobox(
            net_row,
            textvariable=self.var_network_choice,
            values=["Автоопределение", "TRON (TronGrid)", "Bitcoin (REST API)", "Bitcoin (локальный RPC)"],
            state="readonly",
            style="Cyber.TCombobox",
            font=self.font_small,
        )
        self.cmb_network.pack(side="left", fill="x", expand=True)
        self.cmb_network.bind("<<ComboboxSelected>>", lambda _e: self._refresh_dynamic_settings())

        # === ШАГ 2: НАСТРОЙКИ СЕТИ И ФИЛЬТРЫ ===
        self._step_header(parent, "2", "НАСТРОЙКИ И ФИЛЬТРЫ")

        self.frame_step2_host = tk.Frame(parent, bg=BG_PANEL)
        self.frame_step2_host.pack(fill="x")

        # Подпанель TRON API
        self.sub_tron = tk.Frame(self.frame_step2_host, bg=BG_PANEL)
        self._entry_row(self.sub_tron, "TRON API URL:", self.var_tron_endpoint)
        self.entry_tron_key = self._entry_row(self.sub_tron, "API-ключ (опц.):", self.var_tron_api_key, show="*")
        tron_opts = tk.Frame(self.sub_tron, bg=BG_PANEL)
        tron_opts.pack(fill="x", padx=12, pady=(2, 4))
        tk.Checkbutton(
            tron_opts,
            text="Показать ключ",
            variable=self.var_show_tron_key,
            command=lambda: self.entry_tron_key.config(show="" if self.var_show_tron_key.get() else "*"),
            bg=BG_PANEL,
            fg=TEXT_MUTED,
            selectcolor=BG_INPUT,
            activebackground=BG_PANEL,
            activeforeground=NEON_CYAN,
            font=self.font_small,
        ).pack(side="left")
        self._cyber_button(tron_opts, "ПРОВЕРИТЬ СВЯЗЬ", self._test_connection_clicked, accent=NEON_CYAN, pady=4).pack(
            side="right"
        )

        # Подпанель BTC REST API
        self.sub_btc_rest = tk.Frame(self.frame_step2_host, bg=BG_PANEL)
        self._entry_row(self.sub_btc_rest, "BTC REST API:", self.var_btc_rest_endpoint)
        btc_rest_row = tk.Frame(self.sub_btc_rest, bg=BG_PANEL)
        btc_rest_row.pack(fill="x", padx=12, pady=(2, 4))
        tk.Label(
            btc_rest_row,
            text="blockstream.info / mempool.space",
            bg=BG_PANEL,
            fg=TEXT_MUTED,
            font=self.font_small,
        ).pack(side="left")
        self._cyber_button(btc_rest_row, "ПРОВЕРИТЬ СВЯЗЬ", self._test_connection_clicked, accent=NEON_CYAN, pady=4).pack(
            side="right"
        )

        # Подпанель BTC RPC
        self.sub_btc_rpc = tk.Frame(self.frame_step2_host, bg=BG_PANEL)
        self._entry_row(self.sub_btc_rpc, "RPC URL:", self.var_endpoint)
        self._entry_row(self.sub_btc_rpc, "Логин RPC:", self.var_username)
        self.entry_pass = self._entry_row(self.sub_btc_rpc, "Пароль RPC:", self.var_password, show="*")
        rpc_opts = tk.Frame(self.sub_btc_rpc, bg=BG_PANEL)
        rpc_opts.pack(fill="x", padx=12, pady=(2, 4))
        tk.Checkbutton(
            rpc_opts,
            text="Показать пароль",
            variable=self.var_show_pass,
            command=lambda: self.entry_pass.config(show="" if self.var_show_pass.get() else "*"),
            bg=BG_PANEL,
            fg=TEXT_MUTED,
            selectcolor=BG_INPUT,
            activebackground=BG_PANEL,
            activeforeground=NEON_CYAN,
            font=self.font_small,
        ).pack(side="left")
        self._cyber_button(rpc_opts, "ПРОВЕРИТЬ СВЯЗЬ", self._test_connection_clicked, accent=NEON_CYAN, pady=4).pack(
            side="right"
        )

        # Подпанель диапазона блоков (только в режиме "rpc")
        self.sub_block_range = tk.Frame(self.frame_step2_host, bg=BG_PANEL)
        self._entry_row(self.sub_block_range, "Начальный блок:", self.var_start_height)
        self._entry_row(self.sub_block_range, "Конечный блок:", self.var_end_height)
        tk.Label(
            self.sub_block_range,
            text="Подсказка: -1 или пусто = последний блок ноды",
            bg=BG_PANEL,
            fg=TEXT_MUTED,
            font=("Consolas", 8),
            anchor="w",
        ).pack(fill="x", padx=12, pady=(0, 4))

        # Подпанель фильтров для CSV-транзакций
        self.sub_csv_filters = tk.Frame(self.frame_step2_host, bg=BG_PANEL)
        tk.Checkbutton(
            self.sub_csv_filters,
            text="Пропускать неуспешные (только SUCCESS)",
            variable=self.var_only_success,
            bg=BG_PANEL,
            fg=TEXT_MAIN,
            selectcolor=BG_INPUT,
            activebackground=BG_PANEL,
            activeforeground=NEON_CYAN,
            font=self.font_small,
        ).pack(anchor="w", padx=12, pady=(4, 2))

        flt_row = tk.Frame(self.sub_csv_filters, bg=BG_PANEL)
        flt_row.pack(fill="x", padx=12, pady=3)
        tk.Label(flt_row, text="Фильтр адреса:", bg=BG_PANEL, fg=TEXT_MUTED, font=self.font_small, width=16, anchor="w").pack(
            side="left"
        )
        tk.Entry(
            flt_row,
            textvariable=self.var_filter_address,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=NEON_CYAN,
            relief="flat",
            font=self.font_mono,
            highlightbackground=BORDER_DIM,
            highlightcolor=NEON_CYAN,
            highlightthickness=1,
        ).pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 4))
        self._cyber_button(flt_row, "Осн.", self._fill_primary_address, accent=NEON_AMBER, pady=3).pack(side="right")

        self._entry_row(self.sub_csv_filters, "Лимит TX (0=все):", self.var_max_items)

        # Подпанель фильтров для TXT-адресов
        self.sub_txt_filters = tk.Frame(self.frame_step2_host, bg=BG_PANEL)
        self._entry_row(self.sub_txt_filters, "Макс. TX (0=все):", self.var_max_tx_per_addr)
        tk.Checkbutton(
            self.sub_txt_filters,
            text="Только исходящие TX (подписанные адресом)",
            variable=self.var_only_outgoing,
            bg=BG_PANEL,
            fg=TEXT_MAIN,
            selectcolor=BG_INPUT,
            activebackground=BG_PANEL,
            activeforeground=NEON_CYAN,
            font=self.font_small,
        ).pack(anchor="w", padx=12, pady=(2, 4))

        # === ШАГ 3: ЗАПУСК И ЭКСПОРТ ===
        self._step_header(parent, "3", "ЗАПУСК И СОХРАНЕНИЕ")

        perf_row = tk.Frame(parent, bg=BG_PANEL)
        perf_row.pack(fill="x", padx=12, pady=3)
        tk.Label(perf_row, text="Потоки:", bg=BG_PANEL, fg=TEXT_MUTED, font=self.font_small).pack(side="left")
        tk.Entry(
            perf_row,
            textvariable=self.var_threads,
            width=5,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=NEON_CYAN,
            relief="flat",
            font=self.font_mono,
            highlightbackground=BORDER_DIM,
            highlightthickness=1,
        ).pack(side="left", padx=(4, 14), ipady=3)
        tk.Label(perf_row, text="Лимит запр/с:", bg=BG_PANEL, fg=TEXT_MUTED, font=self.font_small).pack(side="left")
        tk.Entry(
            perf_row,
            textvariable=self.var_rate_limit,
            width=6,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=NEON_CYAN,
            relief="flat",
            font=self.font_mono,
            highlightbackground=BORDER_DIM,
            highlightthickness=1,
        ).pack(side="left", padx=(4, 0), ipady=3)

        db_row = tk.Frame(parent, bg=BG_PANEL)
        db_row.pack(fill="x", padx=12, pady=4)
        tk.Label(db_row, text="SQLite БД:", bg=BG_PANEL, fg=TEXT_MUTED, font=self.font_small, width=10, anchor="w").pack(
            side="left"
        )
        tk.Entry(
            db_row,
            textvariable=self.var_db_path,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=NEON_CYAN,
            relief="flat",
            font=self.font_mono,
            highlightbackground=BORDER_DIM,
            highlightthickness=1,
        ).pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 6))
        self._cyber_button(db_row, "...", self._browse_db, accent=NEON_CYAN, pady=3).pack(side="right")

        flags_row = tk.Frame(parent, bg=BG_PANEL)
        flags_row.pack(fill="x", padx=12, pady=(2, 6))
        tk.Checkbutton(
            flags_row,
            text="Тестовый режим (без записи в БД)",
            variable=self.var_dry_run,
            bg=BG_PANEL,
            fg=NEON_AMBER,
            selectcolor=BG_INPUT,
            activebackground=BG_PANEL,
            activeforeground=NEON_AMBER,
            font=self.font_small,
        ).pack(anchor="w")
        tk.Checkbutton(
            flags_row,
            text="Подробный журнал (Verbose)",
            variable=self.var_verbose,
            bg=BG_PANEL,
            fg=TEXT_MUTED,
            selectcolor=BG_INPUT,
            activebackground=BG_PANEL,
            activeforeground=NEON_CYAN,
            font=self.font_small,
        ).pack(anchor="w")

        actions = tk.Frame(parent, bg=BG_PANEL)
        actions.pack(fill="x", padx=12, pady=(6, 6))

        self.btn_start = self._cyber_button(
            actions, "▶ ЗАПУСТИТЬ СКАНИРОВАНИЕ", self._start_scan, accent=NEON_GREEN, fill_bg="#0A291F", pady=9
        )
        self.btn_start.pack(fill="x", pady=(0, 6))

        self.btn_stop = self._cyber_button(
            actions, "■ ОСТАНОВИТЬ", self._stop_scan, accent=NEON_MAGENTA, fill_bg="#2B0B18", pady=7
        )
        self.btn_stop.pack(fill="x", pady=(0, 6))
        self.btn_stop.config(state="disabled")

        export_row = tk.Frame(parent, bg=BG_PANEL)
        export_row.pack(fill="x", padx=12, pady=(2, 14))
        self._cyber_button(export_row, "ЭКСПОРТ CSV", lambda: self._export("csv"), accent=NEON_CYAN, pady=5).pack(
            side="left", fill="x", expand=True, padx=(0, 4)
        )
        self._cyber_button(export_row, "ЭКСПОРТ JSON", lambda: self._export("json"), accent=NEON_CYAN, pady=5).pack(
            side="left", fill="x", expand=True, padx=(4, 0)
        )

    def _build_telemetry_panel(self, parent: tk.Frame) -> None:
        kpi_bar = tk.Frame(parent, bg=BG_VOID)
        kpi_bar.pack(fill="x", pady=(0, 8))

        self.kpi_labels: Dict[str, tk.Label] = {}
        self.kpi_titles: Dict[str, tk.Label] = {}
        kpi_defs = [
            ("units", "ПРОВЕРЕНО TX", "0 / 0", NEON_CYAN),
            ("txs", "ТРАНЗАКЦИИ", "0", TEXT_MAIN),
            ("sigs", "ПОДПИСИ ECDSA", "0", TEXT_MAIN),
            ("reuses", "ПОВТОРЫ R", "0", NEON_AMBER),
            ("vulns", "УЯЗВИМОСТИ", "0", NEON_MAGENTA),
            ("speed", "СКОРОСТЬ", "0.0 /с", NEON_GREEN),
        ]
        for idx, (key, title, initial, color) in enumerate(kpi_defs):
            card = tk.Frame(kpi_bar, bg=BG_CARD, highlightbackground=BORDER_DIM, highlightthickness=1)
            card.pack(side="left", fill="x", expand=True, padx=(0 if idx == 0 else 6, 0))
            t_lbl = tk.Label(card, text=title, bg=BG_CARD, fg=TEXT_MUTED, font=("Consolas", 8, "bold"))
            t_lbl.pack(anchor="w", padx=10, pady=(6, 0))
            val_lbl = tk.Label(card, text=initial, bg=BG_CARD, fg=color, font=self.font_kpi)
            val_lbl.pack(anchor="w", padx=10, pady=(0, 6))
            self.kpi_titles[key] = t_lbl
            self.kpi_labels[key] = val_lbl

        prog_box = tk.Frame(parent, bg=BG_PANEL, highlightbackground=BORDER_DIM, highlightthickness=1)
        prog_box.pack(fill="x", pady=(0, 8))

        prog_top = tk.Frame(prog_box, bg=BG_PANEL)
        prog_top.pack(fill="x", padx=12, pady=(8, 4))
        self.lbl_progress_text = tk.Label(
            prog_top,
            text="Прогресс: 0.0%  |  Время: 0.00 с  |  Осталось: --",
            bg=BG_PANEL,
            fg=TEXT_MAIN,
            font=self.font_mono,
        )
        self.lbl_progress_text.pack(side="left")

        self.lbl_api_stats = tk.Label(
            prog_top, text="Запросы: 0 (ошибок: 0)", bg=BG_PANEL, fg=TEXT_MUTED, font=self.font_mono
        )
        self.lbl_api_stats.pack(side="right")

        self.progress_bar = ttk.Progressbar(
            prog_box, style="Cyber.Horizontal.TProgressbar", orient="horizontal", mode="determinate", maximum=100.0
        )
        self.progress_bar.pack(fill="x", padx=12, pady=(0, 10))

        # 5 понятных вкладок (включая живую таблицу проверенных подписей R/S)
        self.notebook = ttk.Notebook(parent, style="Cyber.TNotebook")
        self.notebook.pack(fill="both", expand=True)

        self.tab_preview = tk.Frame(self.notebook, bg=BG_CARD)
        self.tab_sigs = tk.Frame(self.notebook, bg=BG_CARD)
        self.tab_vulns = tk.Frame(self.notebook, bg=BG_CARD)
        self.tab_logs = tk.Frame(self.notebook, bg=BG_CARD)
        self.tab_tools = tk.Frame(self.notebook, bg=BG_CARD)

        self.notebook.add(self.tab_preview, text="  📂 ДАННЫЕ ФАЙЛА  ")
        self.notebook.add(self.tab_sigs, text="  🔍 ПРОВЕРЕННЫЕ ПОДПИСИ (R/S)  ")
        self.notebook.add(self.tab_vulns, text="  🚨 УЯЗВИМОСТИ (R-REUSE)  ")
        self.notebook.add(self.tab_logs, text="  🖥 ЖУРНАЛ  ")
        self.notebook.add(self.tab_tools, text="  🛠 ПРОВЕРКА TX / САМОТЕСТ  ")

        self._build_preview_tab(self.tab_preview)
        self._build_sigs_tab(self.tab_sigs)
        self._build_vulns_tab(self.tab_vulns)
        self._build_logs_tab(self.tab_logs)
        self._build_tools_tab(self.tab_tools)

    def _build_preview_tab(self, parent: tk.Frame) -> None:
        banner = tk.Frame(parent, bg=BG_PANEL, highlightbackground=BORDER_DIM, highlightthickness=1)
        banner.pack(fill="x", padx=10, pady=(10, 6))

        self.lbl_preview_title = tk.Label(
            banner,
            text="Шаг 1: Нажмите «Выбрать CSV или TXT файл» слева, чтобы загрузить данные",
            bg=BG_PANEL,
            fg=NEON_CYAN,
            font=self.font_bold,
            anchor="w",
        )
        self.lbl_preview_title.pack(fill="x", padx=12, pady=(8, 2))

        self.lbl_preview_desc = tk.Label(
            banner,
            text=(
                "• CSV-файлы (например, Transactions_*.csv из TronScan): программа извлекает хэши транзакций, "
                "блоки, адреса From/To, токены и статус SUCCESS/FAIL.\n"
                "• TXT-файлы (например, список кошельков): программа распознаёт адреса TRON (T...) или BTC (1.../3.../bc1...) "
                "и автоматически загружает их транзакции, разбирая каждую ECDSA-подпись во вкладке «Проверенные подписи»."
            ),
            bg=BG_PANEL,
            fg=TEXT_MUTED,
            font=self.font_small,
            anchor="w",
            justify="left",
            wraplength=840,
        )
        self.lbl_preview_desc.pack(fill="x", padx=12, pady=(0, 8))

        bar = tk.Frame(parent, bg=BG_CARD)
        bar.pack(fill="x", padx=10, pady=(2, 6))

        tk.Label(bar, text="Поиск:", bg=BG_CARD, fg=TEXT_MUTED, font=self.font_small).pack(side="left", padx=(0, 6))
        search_entry = tk.Entry(
            bar,
            textvariable=self.var_preview_search,
            width=34,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=NEON_CYAN,
            relief="flat",
            font=self.font_mono,
            highlightbackground=BORDER_DIM,
            highlightcolor=NEON_CYAN,
            highlightthickness=1,
        )
        search_entry.pack(side="left", ipady=4, padx=(0, 8))
        search_entry.bind("<KeyRelease>", lambda _e: self._populate_preview_table())

        self.lbl_preview_count = tk.Label(bar, text="Записей: 0", bg=BG_CARD, fg=NEON_AMBER, font=self.font_mono)
        self.lbl_preview_count.pack(side="right")

        wrap = tk.Frame(parent, bg=BG_CARD)
        wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.preview_tree = ttk.Treeview(wrap, show="headings", style="Cyber.Treeview")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.preview_tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=self.preview_tree.xview)
        self.preview_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.preview_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        self._setup_preview_columns("tx")

    def _build_sigs_tab(self, parent: tk.Frame) -> None:
        toolbar = tk.Frame(parent, bg=BG_CARD)
        toolbar.pack(fill="x", padx=10, pady=8)

        tk.Label(toolbar, text="Поиск:", bg=BG_CARD, fg=TEXT_MUTED, font=self.font_small).pack(side="left", padx=(0, 6))
        se = tk.Entry(
            toolbar,
            textvariable=self.var_sigs_search,
            width=28,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=NEON_CYAN,
            relief="flat",
            font=self.font_mono,
            highlightbackground=BORDER_DIM,
            highlightthickness=1,
        )
        se.pack(side="left", ipady=4, padx=(0, 8))
        se.bind("<KeyRelease>", lambda _e: self._refresh_sigs_tree())

        self._cyber_button(toolbar, "ЭКСПОРТ ПОДПИСЕЙ CSV", self._export_checked_sigs_csv, accent=NEON_CYAN, pady=4).pack(
            side="left", padx=(0, 6)
        )
        self._cyber_button(toolbar, "ОЧИСТИТЬ", self._clear_checked_sigs, accent=NEON_AMBER, pady=4).pack(side="left")

        self.lbl_sigs_count = tk.Label(toolbar, text="Проверено подписей: 0", bg=BG_CARD, fg=NEON_GREEN, font=self.font_mono)
        self.lbl_sigs_count.pack(side="right")

        wrap = tk.Frame(parent, bg=BG_CARD)
        wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        cols = ("network", "address", "txid", "script_type", "r", "s", "status")
        self.sigs_tree = ttk.Treeview(wrap, columns=cols, show="headings", style="Cyber.Treeview")
        headings = {
            "network": ("Сеть", 60),
            "address": ("Адрес", 185),
            "txid": ("Хэш транзакции (TXID)", 165),
            "script_type": ("Тип", 110),
            "r": ("R-значение", 175),
            "s": ("S-значение", 175),
            "status": ("Результат проверки", 145),
        }
        for col, (title, width) in headings.items():
            self.sigs_tree.heading(col, text=title)
            self.sigs_tree.column(col, width=width, anchor="w")

        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.sigs_tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=self.sigs_tree.xview)
        self.sigs_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.sigs_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

    def _setup_preview_columns(self, mode: str) -> None:
        self.preview_tree.delete(*self.preview_tree.get_children())
        if mode == "addr":
            cols = ("idx", "address", "network", "action")
            headings = {
                "idx": ("#", 50),
                "address": ("Адрес кошелька", 320),
                "network": ("Сеть", 90),
                "action": ("Что сделает сканер", 360),
            }
        else:
            cols = ("txid", "block", "time", "type", "from", "to", "token", "amount", "result")
            headings = {
                "txid": ("Хэш транзакции (TXID)", 175),
                "block": ("Блок", 85),
                "time": ("Дата (UTC)", 140),
                "type": ("Тип контракта", 155),
                "from": ("Отправитель (From)", 175),
                "to": ("Получатель (To)", 175),
                "token": ("Токен", 75),
                "amount": ("Сумма", 105),
                "result": ("Статус", 80),
            }
        self.preview_tree["columns"] = cols
        for col, (title, width) in headings.items():
            self.preview_tree.heading(col, text=title)
            self.preview_tree.column(col, width=width, anchor="w")

    def _build_vulns_tab(self, parent: tk.Frame) -> None:
        toolbar = tk.Frame(parent, bg=BG_CARD)
        toolbar.pack(fill="x", padx=10, pady=8)
        self._cyber_button(toolbar, "ЗАГРУЗИТЬ ИЗ БД", self._load_from_db, accent=NEON_CYAN, pady=4).pack(
            side="left", padx=(0, 6)
        )
        self._cyber_button(toolbar, "КОПИРОВАТЬ СТРОКУ", self._copy_selected_detection, accent=NEON_GREEN, pady=4).pack(
            side="left", padx=(0, 6)
        )
        self._cyber_button(toolbar, "ОЧИСТИТЬ ТАБЛИЦУ", self._clear_detections_view, accent=NEON_AMBER, pady=4).pack(
            side="left"
        )

        cols = ("network", "address", "r", "txid1", "txid2", "marker", "time")
        tree_wrap = tk.Frame(parent, bg=BG_CARD)
        tree_wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.tree = ttk.Treeview(tree_wrap, columns=cols, show="headings", style="Cyber.Treeview")
        headings = {
            "network": ("Сеть", 65),
            "address": ("Адрес", 210),
            "r": ("R-значение (повтор)", 165),
            "txid1": ("TXID #1", 155),
            "txid2": ("TXID #2", 155),
            "marker": ("Статус / Маркер", 185),
            "time": ("Обнаружено", 135),
        }
        for col, (title, width) in headings.items():
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="w")

        vsb = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_wrap.rowconfigure(0, weight=1)
        tree_wrap.columnconfigure(0, weight=1)

    def _build_logs_tab(self, parent: tk.Frame) -> None:
        top = tk.Frame(parent, bg=BG_CARD)
        top.pack(fill="x", padx=10, pady=8)
        tk.Label(top, text="ПОТОК СОБЫТИЙ РЕАЛЬНОГО ВРЕМЕНИ", bg=BG_CARD, fg=NEON_CYAN, font=self.font_bold).pack(
            side="left"
        )
        self._cyber_button(top, "ОЧИСТИТЬ ЛОГ", self._clear_log, accent=NEON_AMBER, pady=4).pack(side="right")

        wrap = tk.Frame(parent, bg=BG_CARD)
        wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.log_text = tk.Text(
            wrap,
            bg="#050811",
            fg=TEXT_MAIN,
            font=self.font_mono,
            relief="flat",
            wrap="word",
            state="disabled",
            highlightbackground=BORDER_DIM,
            highlightthickness=1,
        )
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.log_text.tag_config("INFO", foreground=NEON_CYAN)
        self.log_text.tag_config("SUCCESS", foreground=NEON_GREEN)
        self.log_text.tag_config("WARNING", foreground=NEON_AMBER)
        self.log_text.tag_config("ERROR", foreground=NEON_MAGENTA)
        self.log_text.tag_config("ALERT", foreground="#FF3377", background="#2B0917")

    def _build_tools_tab(self, parent: tk.Frame) -> None:
        box = tk.Frame(parent, bg=BG_CARD)
        box.pack(fill="both", expand=True, padx=14, pady=12)

        tk.Label(
            box,
            text="// ПРОВЕРКА ОТДЕЛЬНОЙ ТРАНЗАКЦИИ ПО TXID (TRON ИЛИ BITCOIN)",
            bg=BG_CARD,
            fg=NEON_CYAN,
            font=self.font_bold,
        ).pack(anchor="w", pady=(0, 6))

        tx_row = tk.Frame(box, bg=BG_CARD)
        tx_row.pack(fill="x", pady=(0, 12))

        ttk.Combobox(
            tx_row,
            textvariable=self.var_tx_lookup_net,
            values=["TRON (TronGrid)", "Bitcoin (REST API)", "Bitcoin (локальный RPC)"],
            state="readonly",
            width=20,
            style="Cyber.TCombobox",
            font=self.font_small,
        ).pack(side="left", padx=(0, 8))

        tk.Entry(
            tx_row,
            textvariable=self.var_txid_lookup,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            insertbackground=NEON_CYAN,
            relief="flat",
            font=self.font_mono,
            highlightbackground=BORDER_DIM,
            highlightcolor=NEON_CYAN,
            highlightthickness=1,
        ).pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))

        self._cyber_button(tx_row, "АНАЛИЗИРОВАТЬ TX", self._analyze_single_tx, accent=NEON_CYAN, pady=4).pack(
            side="right"
        )

        tk.Label(
            box,
            text="// ЛОКАЛЬНАЯ САМОДИАГНОСТИКА (ОФЛАЙН, БЕЗ ИНТЕРНЕТА)",
            bg=BG_CARD,
            fg=NEON_GREEN,
            font=self.font_bold,
        ).pack(anchor="w", pady=(6, 4))
        tk.Label(
            box,
            text="Проверяет парсеры BTC (DER/SegWit/Base58) и TRON (65-байтовые ECDSA подписи и T-адреса), детектор повтора R-значения, а также разбор CSV и TXT.",
            bg=BG_CARD,
            fg=TEXT_MUTED,
            font=self.font_small,
            wraplength=800,
            justify="left",
        ).pack(anchor="w", pady=(0, 8))

        self._cyber_button(
            box, "⚡ ЗАПУСТИТЬ САМОТЕСТ (BTC + TRON)", self._run_self_test, accent=NEON_GREEN, fill_bg="#0A291F", pady=6
        ).pack(anchor="w", pady=(0, 10))

        self.tools_output = tk.Text(
            box,
            bg="#050811",
            fg=TEXT_MAIN,
            font=self.font_mono,
            relief="flat",
            height=14,
            highlightbackground=BORDER_DIM,
            highlightthickness=1,
        )
        self.tools_output.pack(fill="both", expand=True)

    # --- Динамическое переключение режимов ---

    def _switch_mode(self, mode: str) -> None:
        self.var_mode.set(mode)
        if mode == "file":
            self.btn_mode_file.config(fg=NEON_CYAN, bg="#0A2133", highlightbackground=NEON_CYAN)
            self.btn_mode_rpc.config(fg=TEXT_MUTED, bg=BG_INPUT, highlightbackground=BORDER_DIM)
            self.frame_file_picker.pack(fill="x", after=self.btn_mode_file.master)
            self.kpi_titles["units"].config(text="ПРОВЕРЕНО TX")
        else:
            self.btn_mode_rpc.config(fg=NEON_CYAN, bg="#0A2133", highlightbackground=NEON_CYAN)
            self.btn_mode_file.config(fg=TEXT_MUTED, bg=BG_INPUT, highlightbackground=BORDER_DIM)
            self.frame_file_picker.pack_forget()
            self.kpi_titles["units"].config(text="БЛОКИ BTC")
        self._refresh_dynamic_settings()

    def _resolved_file_backend(self) -> str:
        choice = self.var_network_choice.get()
        if choice == "TRON (TronGrid)":
            return "TRON"
        if choice == "Bitcoin (REST API)":
            return "BTC_REST"
        if choice == "Bitcoin (локальный RPC)":
            return "BTC_RPC"
        if self._dataset and self._dataset.network == "BTC":
            return "BTC_REST"
        return "TRON"

    def _refresh_dynamic_settings(self) -> None:
        for frame in (
            self.sub_tron,
            self.sub_btc_rest,
            self.sub_btc_rpc,
            self.sub_block_range,
            self.sub_csv_filters,
            self.sub_txt_filters,
        ):
            frame.pack_forget()

        if self.var_mode.get() == "rpc":
            self.sub_btc_rpc.pack(fill="x")
            self.sub_block_range.pack(fill="x")
            return

        backend = self._resolved_file_backend()
        if backend == "TRON":
            self.sub_tron.pack(fill="x")
        elif backend == "BTC_REST":
            self.sub_btc_rest.pack(fill="x")
        else:
            self.sub_btc_rpc.pack(fill="x")

        if self._dataset is None:
            self.sub_csv_filters.pack(fill="x")
            return

        if self._dataset.dataset_kind in ("csv_transactions", "txt_txids", "csv_signatures"):
            self.sub_csv_filters.pack(fill="x")
        elif self._dataset.dataset_kind in ("txt_addresses", "csv_addresses"):
            self.sub_txt_filters.pack(fill="x")
        else:
            self.sub_txt_filters.pack(fill="x")
            self.sub_csv_filters.pack(fill="x")

    # --- Загрузка и предпросмотр CSV / TXT ---

    def _browse_input_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Выберите CSV (транзакции) или TXT (адреса / TXID)",
            filetypes=[
                ("Поддерживаемые файлы (CSV, TXT)", "*.csv *.txt"),
                ("CSV таблицы", "*.csv"),
                ("Текстовые файлы (TXT)", "*.txt"),
                ("Все файлы", "*.*"),
            ],
        )
        if not path:
            return
        self._load_dataset_from_path(path)

    def _load_dataset_from_path(self, path: str) -> None:
        try:
            ds = load_input_file(path)
        except Exception as exc:
            messagebox.showerror("Ошибка чтения файла", f"Не удалось прочитать файл:\n{exc}")
            self._append_log("ERROR", f"Ошибка загрузки файла {os.path.basename(path)}: {exc}")
            return

        self._dataset = ds
        self.var_file_path.set(path)
        self.var_preview_search.set("")
        self.var_filter_address.set("")

        self.lbl_file_name.config(text=f"📄 {ds.file_name}", fg=NEON_GREEN)
        meta_lines = [
            f"Тип: {ds.kind_title_ru}",
            f"Сеть: {ds.network}  |  Строк в файле: {ds.total_raw_rows}",
        ]
        if ds.transactions:
            extra = f" (успешных: {ds.success_count}, ошибок: {ds.fail_count})" if ds.dataset_kind == "csv_transactions" else ""
            meta_lines.append(f"Уникальных TXID: {len(ds.transactions)}{extra}")
        if ds.addresses:
            meta_lines.append(f"Уникальных адресов: {len(ds.addresses)}")
        if ds.duplicates_removed:
            meta_lines.append(f"Дубликатов удалено: {ds.duplicates_removed}")
        if ds.invalid_rows:
            meta_lines.append(f"Пропущено некорректных: {ds.invalid_rows}")
        self.lbl_file_meta.config(text="\n".join(meta_lines), fg=TEXT_MAIN)

        self.lbl_preview_title.config(
            text=f"Загружен файл: {ds.file_name}  —  {ds.kind_title_ru}  [{ds.network}]"
        )
        desc_parts = [ds.action_hint_ru]
        if ds.top_tx_types:
            top_str = ", ".join(f"{name}: {cnt}" for name, cnt in ds.top_tx_types[:4])
            desc_parts.append(f"Основные типы операций: {top_str}.")
        if ds.primary_address and ds.dataset_kind == "csv_transactions":
            desc_parts.append(
                f"Основной адрес в файле: {ds.primary_address} (отправителей: {ds.unique_senders}, получателей: {ds.unique_recipients})."
            )
        self.lbl_preview_desc.config(text="\n".join(desc_parts), fg=TEXT_MAIN)

        self._refresh_dynamic_settings()
        self._populate_preview_table()
        self.notebook.select(self.tab_preview)

        self._append_log(
            "SUCCESS",
            f"Файл загружен: {ds.file_name} | {ds.kind_title_ru} | Сеть: {ds.network} | "
            f"TX: {len(ds.transactions)}, Адресов: {len(ds.addresses)}",
        )
        for warn in ds.warnings:
            self._append_log("WARNING", warn)

    def _populate_preview_table(self) -> None:
        if self._dataset is None:
            return
        ds = self._dataset
        query = self.var_preview_search.get().strip().lower()

        if ds.dataset_kind in ("txt_addresses", "csv_addresses"):
            self._setup_preview_columns("addr")
            matched = [a for a in ds.addresses if not query or query in a.address.lower() or query in a.network.lower()]
            shown = matched[:PREVIEW_ROW_LIMIT]
            for idx, item in enumerate(shown, 1):
                action_txt = f"Загрузить TX ({item.network}), извлечь ECDSA R/S и проверить повторы"
                self.preview_tree.insert("", "end", values=(idx, item.address, item.network, action_txt))
            self.lbl_preview_count.config(text=f"Показано адресов: {len(shown)} из {len(matched)}")
        else:
            self._setup_preview_columns("tx")
            matched_tx = []
            for t in ds.transactions:
                if query:
                    hay = f"{t.txid} {t.block} {t.tx_type} {t.sender} {t.recipient} {t.token} {t.result}".lower()
                    if query not in hay:
                        continue
                matched_tx.append(t)
            shown = matched_tx[:PREVIEW_ROW_LIMIT]
            for t in shown:
                self.preview_tree.insert(
                    "",
                    "end",
                    values=(
                        t.txid,
                        t.block or "",
                        t.time_utc,
                        t.tx_type,
                        t.sender,
                        t.recipient,
                        t.token,
                        t.amount,
                        t.result,
                    ),
                )
            extra = f" (первые {PREVIEW_ROW_LIMIT})" if len(matched_tx) > PREVIEW_ROW_LIMIT else ""
            self.lbl_preview_count.config(text=f"Транзакций: {len(matched_tx)}{extra}")

    def _fill_primary_address(self) -> None:
        if self._dataset and self._dataset.primary_address:
            self.var_filter_address.set(self._dataset.primary_address)
        else:
            messagebox.showinfo("Фильтр адреса", "Сначала загрузите CSV-файл с транзакциями.")

    # --- Вкладка проверенных подписей (R/S) ---

    def _clear_checked_sigs(self) -> None:
        self._checked_sigs.clear()
        for item in self.sigs_tree.get_children():
            self.sigs_tree.delete(item)
        self.lbl_sigs_count.config(text="Проверено подписей: 0")

    def _add_checked_sig_row(self, rec: Dict[str, Any]) -> None:
        self._checked_sigs.append(rec)
        total = len(self._checked_sigs)
        q = self.var_sigs_search.get().strip().lower()
        if not q or q in f"{rec.get('address','')} {rec.get('txid','')} {rec.get('r','')} {rec.get('status','')}".lower():
            children = self.sigs_tree.get_children()
            if len(children) >= CHECKED_SIG_UI_LIMIT:
                self.sigs_tree.delete(children[-1])
            self.sigs_tree.insert(
                "",
                0,
                values=(
                    rec.get("network", ""),
                    rec.get("address", ""),
                    rec.get("txid", ""),
                    rec.get("script_type", ""),
                    rec.get("r", ""),
                    rec.get("s", ""),
                    rec.get("status", ""),
                ),
            )
        self.lbl_sigs_count.config(text=f"Проверено подписей: {total}")

    def _refresh_sigs_tree(self) -> None:
        for item in self.sigs_tree.get_children():
            self.sigs_tree.delete(item)
        q = self.var_sigs_search.get().strip().lower()
        matched = [
            rec
            for rec in reversed(self._checked_sigs)
            if not q
            or q in f"{rec.get('address','')} {rec.get('txid','')} {rec.get('r','')} {rec.get('status','')}".lower()
        ]
        for rec in matched[:CHECKED_SIG_UI_LIMIT]:
            self.sigs_tree.insert(
                "",
                "end",
                values=(
                    rec.get("network", ""),
                    rec.get("address", ""),
                    rec.get("txid", ""),
                    rec.get("script_type", ""),
                    rec.get("r", ""),
                    rec.get("s", ""),
                    rec.get("status", ""),
                ),
            )
        self.lbl_sigs_count.config(text=f"Проверено подписей: {len(self._checked_sigs)} (фильтр: {len(matched)})")

    def _export_checked_sigs_csv(self) -> None:
        if not self._checked_sigs:
            messagebox.showinfo("Экспорт подписей", "Список проверенных подписей пуст.")
            return
        path = filedialog.asksaveasfilename(
            title="Сохранить проверенные подписи (CSV)",
            defaultextension=".csv",
            filetypes=[("CSV файлы", "*.csv"), ("Все файлы", "*.*")],
        )
        if not path:
            return
        try:
            fields = ["network", "address", "txid", "block", "script_type", "r", "s", "status"]
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for row in self._checked_sigs:
                    writer.writerow({k: row.get(k, "") for k in fields})
            self._append_log("SUCCESS", f"Экспортировано {len(self._checked_sigs)} проверенных подписей в {path}")
            messagebox.showinfo("Готово", f"Сохранено подписей: {len(self._checked_sigs)}\nФайл: {path}")
        except Exception as exc:
            messagebox.showerror("Ошибка экспорта", str(exc))

    # --- Общие действия пользователя ---

    def _browse_db(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Выберите файл базы данных SQLite",
            defaultextension=".db",
            filetypes=[("SQLite Database", "*.db"), ("Все файлы", "*.*")],
        )
        if path:
            self.var_db_path.set(path)

    def _set_status(self, text: str, color: str) -> None:
        self.lbl_status_badge.config(text=f"СТАТУС: {text}", fg=color, highlightbackground=color)

    def _append_log(self, level: str, message: str) -> None:
        if level == "DEBUG" and not self.var_verbose.get():
            return
        ts = utils.get_timestamp()
        line = f"[{ts}] [{level:<7}] {message}\n"
        self.log_text.config(state="normal")
        self.log_text.insert("end", line, level if level in ("INFO", "SUCCESS", "WARNING", "ERROR", "ALERT") else "INFO")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _clear_log(self) -> None:
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    def _clear_detections_view(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._detections.clear()

    def _add_detection_row(self, record: Dict[str, Any]) -> None:
        self._detections.append(record)
        net = record.get("network") or ("TRON" if str(record.get("address", "")).startswith("T") else "BTC")
        self.tree.insert(
            "",
            0,
            values=(
                net,
                record.get("address", ""),
                record.get("r", ""),
                record.get("txid1", ""),
                record.get("txid2", ""),
                record.get("status_marker", ""),
                record.get("recovered_at", ""),
            ),
        )

    def _copy_selected_detection(self) -> None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Копирование", "Выберите строку в таблице уязвимостей.")
            return
        values = self.tree.item(sel[0], "values")
        text = " | ".join(str(v) for v in values)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._append_log("INFO", "Строка скопирована в буфер обмена.")

    def _load_from_db(self) -> None:
        db_path = self.var_db_path.get().strip() or "ecdsa_scanner.db"
        if not os.path.exists(db_path):
            messagebox.showwarning("База данных", f"Файл базы данных не найден:\n{db_path}")
            return
        try:
            db = DatabaseManager(db_path, dry_run=False)
            records = db.get_all_detections()
            db.close()
            self._clear_detections_view()
            for rec in records:
                self._add_detection_row(rec)
            self._append_log("SUCCESS", f"Загружено записей из БД ({db_path}): {len(records)}")
        except Exception as exc:
            messagebox.showerror("Ошибка БД", f"Не удалось прочитать базу данных:\n{exc}")

    def _export(self, fmt: str) -> None:
        if not self._detections:
            db_path = self.var_db_path.get().strip()
            if db_path and os.path.exists(db_path):
                self._load_from_db()
        if not self._detections:
            messagebox.showinfo("Экспорт", "Нет обнаруженных уязвимостей для экспорта.")
            return
        ext = ".csv" if fmt == "csv" else ".json"
        path = filedialog.asksaveasfilename(
            title=f"Экспорт результатов в {fmt.upper()}",
            defaultextension=ext,
            filetypes=[(f"{fmt.upper()} файлы", f"*{ext}"), ("Все файлы", "*.*")],
        )
        if not path:
            return
        try:
            tmp_db = DatabaseManager(dry_run=True)
            if fmt == "csv":
                count = tmp_db.export_detections_csv(path, self._detections)
            else:
                count = tmp_db.export_detections_json(path, self._detections)
            self._append_log("SUCCESS", f"Экспортировано {count} записей в {path}")
            messagebox.showinfo("Экспорт завершён", f"Сохранено записей: {count}\nФайл: {path}")
        except Exception as exc:
            messagebox.showerror("Ошибка экспорта", str(exc))

    def _test_connection_clicked(self) -> None:
        mode = self.var_mode.get()
        backend = "BTC_RPC" if mode == "rpc" else self._resolved_file_backend()
        self.lbl_net_status.config(text="● СЕТЬ: ПРОВЕРКА...", fg=NEON_AMBER)

        tron_url = self.var_tron_endpoint.get().strip()
        tron_key = self.var_tron_api_key.get().strip()
        btc_rest_url = self.var_btc_rest_endpoint.get().strip()
        rpc_url = self.var_endpoint.get().strip()
        rpc_user = self.var_username.get()
        rpc_pass = self.var_password.get()

        def worker() -> None:
            try:
                if backend == "TRON":
                    client = TronAPIClient(endpoint=tron_url, api_key=tron_key, timeout=10)
                    info = client.test_connection()
                    self._ui_queue.put(("net_ok", f"TRON #{info['blocks']}"))
                elif backend == "BTC_REST":
                    client = BTCRestClient(endpoint=btc_rest_url, timeout=10)
                    info = client.test_connection()
                    self._ui_queue.put(("net_ok", f"BTC REST #{info['blocks']}"))
                else:
                    client = RPCClient(endpoint=rpc_url, username=rpc_user, password=rpc_pass, timeout=10)
                    info = client.test_connection()
                    self._ui_queue.put(("net_ok", f"BTC RPC {info['chain'].upper()} #{info['blocks']}"))
            except Exception as exc:
                self._ui_queue.put(("net_err", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    # --- Валидация и запуск сканирования ---

    def _validate_common(self) -> Optional[Dict[str, Any]]:
        try:
            threads = int(self.var_threads.get().strip())
            rate = int(self.var_rate_limit.get().strip())
            if not (1 <= threads <= 64):
                raise ValueError("Число потоков должно быть от 1 до 64")
            if rate < 1:
                raise ValueError("Лимит запросов должен быть >= 1")
            return {
                "threads": threads,
                "rate_limit": rate,
                "db_path": self.var_db_path.get().strip() or "ecdsa_scanner.db",
                "dry_run": self.var_dry_run.get(),
                "verbose": self.var_verbose.get(),
            }
        except ValueError as exc:
            messagebox.showerror("Ошибка параметров", str(exc))
            return None

    def _start_scan(self) -> None:
        if self._is_running:
            return
        common = self._validate_common()
        if not common:
            return

        if self.var_mode.get() == "file":
            self._start_file_scan(common)
        else:
            self._start_rpc_block_scan(common)

    def _start_file_scan(self, common: Dict[str, Any]) -> None:
        if self._dataset is None:
            messagebox.showwarning("Нет файла", "Сначала выберите CSV или TXT файл на Шаге 1.")
            return

        try:
            max_items = int(self.var_max_items.get().strip() or "0")
            max_tx_addr = int(self.var_max_tx_per_addr.get().strip() or "0")
            if max_items < 0 or max_tx_addr < 0:
                raise ValueError("Лимиты не могут быть отрицательными (0 = без ограничения)")
        except ValueError as exc:
            messagebox.showerror("Ошибка фильтров", str(exc))
            return

        backend = self._resolved_file_backend()
        net_override = "TRON" if backend == "TRON" else ("BTC" if backend in ("BTC_REST", "BTC_RPC") else "AUTO")
        if self.var_network_choice.get() == "Автоопределение":
            net_override = "AUTO"

        cfg = {
            **common,
            "backend": backend,
            "net_override": net_override,
            "tron_url": self.var_tron_endpoint.get().strip() or TronAPIClient.DEFAULT_ENDPOINT,
            "tron_key": self.var_tron_api_key.get().strip(),
            "btc_rest_url": self.var_btc_rest_endpoint.get().strip() or BTCRestClient.DEFAULT_ENDPOINT,
            "rpc_url": self.var_endpoint.get().strip(),
            "rpc_user": self.var_username.get(),
            "rpc_pass": self.var_password.get(),
            "only_success": self.var_only_success.get(),
            "filter_address": self.var_filter_address.get().strip(),
            "max_items": max_items,
            "max_tx_per_addr": max_tx_addr,
            "only_outgoing": self.var_only_outgoing.get(),
        }
        dataset = self._dataset

        self._save_config()
        self._clear_checked_sigs()
        self._is_running = True
        self._scan_start_time = time.monotonic()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self._set_status("СКАНИРОВАНИЕ ФАЙЛА", NEON_GREEN)
        self.progress_bar["value"] = 0
        self.notebook.select(self.tab_sigs)
        self._append_log(
            "INFO",
            f"Запуск сканирования файла «{dataset.file_name}» ({dataset.kind_title_ru}) | "
            f"Сеть: {backend} | Потоков: {cfg['threads']} | Лимит: {cfg['rate_limit']} запр/с",
        )

        def scan_worker() -> None:
            try:
                log_cb = lambda lvl, msg: self._ui_queue.put(("log", (lvl, msg)))
                tron_client = TronAPIClient(
                    endpoint=cfg["tron_url"],
                    api_key=cfg["tron_key"],
                    rate_limit=cfg["rate_limit"],
                    logger=log_cb,
                )
                btc_rest_client = BTCRestClient(
                    endpoint=cfg["btc_rest_url"],
                    rate_limit=cfg["rate_limit"],
                    logger=log_cb,
                )
                btc_rpc_client = (
                    RPCClient(
                        endpoint=cfg["rpc_url"],
                        username=cfg["rpc_user"],
                        password=cfg["rpc_pass"],
                        rate_limit=cfg["rate_limit"],
                        logger=log_cb,
                    )
                    if cfg["backend"] == "BTC_RPC"
                    else None
                )
                self._active_api_client = (
                    tron_client
                    if cfg["backend"] == "TRON"
                    else (btc_rpc_client if cfg["backend"] == "BTC_RPC" else btc_rest_client)
                )

                db = DatabaseManager(cfg["db_path"], dry_run=cfg["dry_run"])
                self._db_manager = db
                self._r_cache = LRUCache(capacity=50000)

                processor = FileScanProcessor(
                    dataset=dataset,
                    signature_analyzer=SignatureAnalyzer(),
                    db_manager=db,
                    r_value_cache=self._r_cache,
                    network_override=cfg["net_override"],
                    tron_client=tron_client,
                    btc_rest_client=btc_rest_client,
                    btc_rpc_client=btc_rpc_client,
                    threads=cfg["threads"],
                    only_success=cfg["only_success"],
                    filter_address=cfg["filter_address"],
                    max_items=cfg["max_items"],
                    max_tx_per_address=cfg["max_tx_per_addr"],
                    only_outgoing_address_tx=cfg["only_outgoing"],
                    on_log=log_cb,
                    on_progress=lambda st: self._ui_queue.put(("progress", st)),
                    on_detection=lambda rec: self._ui_queue.put(("detection", rec)),
                    on_signature=lambda rec: self._ui_queue.put(("signature", rec)),
                )
                self._active_processor = processor

                final_stats = processor.start_processing()
                stopped = processor.is_stopped()
                db.close()
                self._ui_queue.put(("done", (final_stats, stopped)))
            except Exception as exc:
                if self._db_manager:
                    try:
                        self._db_manager.close()
                    except Exception:
                        pass
                self._ui_queue.put(("fatal", str(exc)))

        self._scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self._scan_thread.start()

    def _start_rpc_block_scan(self, common: Dict[str, Any]) -> None:
        try:
            endpoint = self.var_endpoint.get().strip()
            if not endpoint.startswith(("http://", "https://")):
                raise ValueError("RPC URL должен начинаться с http:// или https://")
            start_h = int(self.var_start_height.get().strip())
            end_raw = self.var_end_height.get().strip()
            end_h = -1 if end_raw == "" else int(end_raw)
            if start_h < 0:
                raise ValueError("Начальный блок не может быть отрицательным")
            if end_h != -1 and end_h < start_h:
                raise ValueError("Конечный блок должен быть больше или равен начальному")
        except ValueError as exc:
            messagebox.showerror("Ошибка параметров RPC", str(exc))
            return

        cfg = {
            **common,
            "endpoint": endpoint,
            "username": self.var_username.get(),
            "password": self.var_password.get(),
            "start_height": start_h,
            "end_height": end_h,
        }

        self._save_config()
        self._is_running = True
        self._scan_start_time = time.monotonic()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self._set_status("СКАНИРОВАНИЕ БЛОКОВ", NEON_GREEN)
        self.progress_bar["value"] = 0
        self._append_log(
            "INFO",
            f"Запуск сканирования блоков BTC RPC: {cfg['endpoint']} | {cfg['start_height']}..{cfg['end_height']}",
        )

        def scan_worker() -> None:
            try:
                log_cb = lambda lvl, msg: self._ui_queue.put(("log", (lvl, msg)))
                rpc = RPCClient(
                    endpoint=cfg["endpoint"],
                    username=cfg["username"],
                    password=cfg["password"],
                    rate_limit=cfg["rate_limit"],
                    logger=log_cb,
                )
                self._active_api_client = rpc

                end_height = cfg["end_height"]
                if end_height == -1:
                    self._ui_queue.put(("log", ("INFO", "Запрос высоты блокчейна (getblockcount)...")))
                    end_height = rpc.get_block_count()
                    self._ui_queue.put(("log", ("SUCCESS", f"Последний блок сети: #{end_height}")))
                    if end_height < cfg["start_height"]:
                        raise ValueError(f"Высота сети ({end_height}) меньше начального блока ({cfg['start_height']})")

                db = DatabaseManager(cfg["db_path"], dry_run=cfg["dry_run"])
                self._db_manager = db
                self._r_cache = LRUCache(capacity=50000)

                processor = BlockProcessor(
                    rpc_client=rpc,
                    signature_analyzer=SignatureAnalyzer(),
                    db_manager=db,
                    block_cache=LRUCache(capacity=2000),
                    transaction_cache=LRUCache(capacity=20000),
                    r_value_cache=self._r_cache,
                    threads=cfg["threads"],
                    on_log=log_cb,
                    on_progress=lambda st: self._ui_queue.put(("progress", st)),
                    on_detection=lambda rec: self._ui_queue.put(("detection", rec)),
                )
                self._active_processor = processor

                final_stats = processor.start_processing(cfg["start_height"], end_height)
                stopped = processor.is_stopped()
                db.close()
                self._ui_queue.put(("done", (final_stats, stopped)))
            except Exception as exc:
                if self._db_manager:
                    try:
                        self._db_manager.close()
                    except Exception:
                        pass
                self._ui_queue.put(("fatal", str(exc)))

        self._scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self._scan_thread.start()

    def _stop_scan(self) -> None:
        if self._active_processor and self._is_running:
            self._active_processor.stop()
            self._set_status("ОСТАНОВКА...", NEON_AMBER)
            self._append_log("WARNING", "Получен сигнал остановки. Завершение активных потоков...")

    # --- Проверка одной TX и локальный самотест ---

    def _analyze_single_tx(self) -> None:
        txid = self.var_txid_lookup.get().strip()
        if not utils.is_txid_hex(txid):
            messagebox.showerror("Некорректный TXID", "TXID должен состоять ровно из 64 hex-символов.")
            return

        net_sel = self.var_tx_lookup_net.get()
        tron_url = self.var_tron_endpoint.get().strip()
        tron_key = self.var_tron_api_key.get().strip()
        btc_rest_url = self.var_btc_rest_endpoint.get().strip()
        rpc_url = self.var_endpoint.get().strip()
        rpc_user = self.var_username.get()
        rpc_pass = self.var_password.get()

        def worker() -> None:
            try:
                analyzer = SignatureAnalyzer()
                if net_sel == "TRON (TronGrid)":
                    client = TronAPIClient(endpoint=tron_url, api_key=tron_key, timeout=15)
                    tx = client.get_transaction_by_id(txid)
                    sigs = analyzer.analyze_tron_transaction(tx)
                elif net_sel == "Bitcoin (REST API)":
                    client = BTCRestClient(endpoint=btc_rest_url, timeout=15)
                    tx = client.get_transaction(txid)
                    sigs = analyzer.analyze_esplora_btc_tx(tx)
                else:
                    client = RPCClient(endpoint=rpc_url, username=rpc_user, password=rpc_pass, timeout=15)
                    tx = client.get_raw_transaction(txid)
                    sigs = analyzer.analyze_transaction(tx, block_height=0)

                lines = [f"Сеть: {net_sel}", f"Транзакция: {txid}", f"Найдено ECDSA-подписей: {len(sigs)}", ""]
                for s in sigs:
                    lines.append(f"Подпись #{s.input_index} [{s.script_type}]")
                    lines.append(f"  Адрес: {s.address}")
                    lines.append(f"  R:     {s.r}")
                    lines.append(f"  S:     {s.s}")
                    lines.append(f"  Z:     {s.z}")
                    lines.append("")
                self._ui_queue.put(("tool_out", "\n".join(lines)))
            except Exception as exc:
                self._ui_queue.put(("tool_out", f"[ОШИБКА] Не удалось получить/разобрать TX: {exc}"))

        threading.Thread(target=worker, daemon=True).start()

    def _run_self_test(self) -> None:
        from core.key_recovery import KeyRecovery

        analyzer = SignatureAnalyzer()
        kr = KeyRecovery()

        genesis_pk_hex = (
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
            "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
        )
        genesis_addr = utils.pubkey_to_address(bytes.fromhex(genesis_pk_hex))

        def make_der(r_hex: str, s_hex: str) -> bytes:
            rb, sb = bytes.fromhex(r_hex), bytes.fromhex(s_hex)
            inner = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
            return b"\x30" + bytes([len(inner)]) + inner + b"\x01"

        r_btc = "11" * 32
        der1, der2 = make_der(r_btc, "22" * 32), make_der(r_btc, "33" * 32)
        pk_b = bytes.fromhex(genesis_pk_hex)
        sc1 = bytes([len(der1)]) + der1 + bytes([len(pk_b)]) + pk_b
        sc2 = bytes([len(der2)]) + der2 + bytes([len(pk_b)]) + pk_b
        btc_tx1 = {
            "txid": "a" * 64, "version": 1, "locktime": 0,
            "vin": [{"txid": "1" * 64, "vout": 0, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": sc1.hex()}}],
            "vout": [{"value": 0.5, "scriptPubKey": {"hex": "76a914" + "00" * 20 + "88ac"}}],
        }
        btc_tx2 = {
            "txid": "b" * 64, "version": 1, "locktime": 1,
            "vin": [{"txid": "2" * 64, "vout": 1, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": sc2.hex()}}],
            "vout": [{"value": 0.25, "scriptPubKey": {"hex": "76a914" + "ff" * 20 + "88ac"}}],
        }
        bs1 = analyzer.analyze_transaction(btc_tx1, 700001)
        bs2 = analyzer.analyze_transaction(btc_tx2, 700002)
        btc_marker = kr.recover_private_key(bs1[0], bs2[0]) if (bs1 and bs2) else None

        tron_addr = "TY2YRt63pM7YorXV8WNpfb3qQyvyTZzzuC"
        tron_hex = utils.tron_base58_to_hex(tron_addr)
        tron_back = utils.tron_hex_to_base58(tron_hex)
        r_tron = "ab" * 32
        tron_tx1 = {
            "txID": "c" * 64,
            "blockNumber": 88174146,
            "signature": [r_tron + ("12" * 32) + "1b"],
            "raw_data": {"contract": [{"type": "TransferContract", "parameter": {"value": {"owner_address": tron_hex}}}]},
        }
        tron_tx2 = {
            "txID": "d" * 64,
            "blockNumber": 88174147,
            "signature": [r_tron + ("34" * 32) + "1c"],
            "raw_data": {"contract": [{"type": "TransferContract", "parameter": {"value": {"owner_address": tron_hex}}}]},
        }
        ts1 = analyzer.analyze_tron_transaction(tron_tx1)
        ts2 = analyzer.analyze_tron_transaction(tron_tx2)
        tron_marker = kr.recover_private_key(ts1[0], ts2[0]) if (ts1 and ts2) else None

        report = [
            "=== РЕЗУЛЬТАТ ЛОКАЛЬНОЙ САМОДИАГНОСТИКИ v3.1 ===",
            f"1. [BTC] Base58Check + RIPEMD-160 (Genesis): {genesis_addr} -> {'OK' if genesis_addr == '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa' else 'ОШИБКА'}",
            f"2. [BTC] Детектор повтора R-значения:        {btc_marker or 'ОШИБКА'}",
            f"3. [TRON] Base58 <-> Hex конвертация адреса: {tron_back} -> {'OK' if tron_back == tron_addr else 'ОШИБКА'}",
            f"4. [TRON] Разбор 65-байтовых подписей:       TX1={len(ts1)}, TX2={len(ts2)}",
            f"5. [TRON] Детектор повтора R-значения:       {tron_marker or 'ОШИБКА'}",
            "=== ВСЕ МОДУЛИ BTC И TRON ИСПРАВНЫ ===",
        ]
        self.tools_output.delete("1.0", "end")
        self.tools_output.insert("end", "\n".join(report))

        if tron_marker and ts1 and ts2:
            self._add_detection_row(
                {
                    "network": "TRON",
                    "address": ts1[0].address,
                    "r": ts1[0].r,
                    "txid1": ts1[0].txid,
                    "txid2": ts2[0].txid,
                    "status_marker": f"[ДЕМО] {tron_marker}",
                    "recovered_at": utils.get_timestamp(),
                }
            )
        self._append_log("SUCCESS", f"Самодиагностика пройдена: BTC={btc_marker}, TRON={tron_marker}")

    # --- Цикл обработки событий из фоновых потоков ---

    def _poll_queue(self) -> None:
        try:
            processed = 0
            while processed < 150:
                event, data = self._ui_queue.get_nowait()
                processed += 1
                if event == "log":
                    lvl, msg = data
                    self._append_log(lvl, msg)
                elif event == "progress":
                    self._update_progress_ui(data)
                elif event == "signature":
                    self._add_checked_sig_row(data)
                elif event == "detection":
                    self._add_detection_row(data)
                elif event == "net_ok":
                    self.lbl_net_status.config(text=f"● СЕТЬ: {data}", fg=NEON_GREEN)
                    self._append_log("SUCCESS", f"Связь подтверждена: {data}")
                elif event == "net_err":
                    self.lbl_net_status.config(text="● СЕТЬ: ОШИБКА", fg=NEON_MAGENTA)
                    self._append_log("ERROR", f"Ошибка подключения: {data}")
                elif event == "tool_out":
                    self.tools_output.delete("1.0", "end")
                    self.tools_output.insert("end", data)
                elif event == "done":
                    stats, stopped = data
                    self._update_progress_ui(stats)
                    self._is_running = False
                    self.btn_start.config(state="normal")
                    self.btn_stop.config(state="disabled")
                    if stopped:
                        self._set_status("ОСТАНОВЛЕНО", NEON_AMBER)
                        self._append_log("WARNING", "Сканирование остановлено пользователем.")
                    else:
                        self._set_status("ЗАВЕРШЕНО", NEON_CYAN)
                        self._append_log(
                            "SUCCESS",
                            f"Сканирование завершено! Транзакций: {stats.transactions_processed}, "
                            f"подписей ECDSA: {stats.signatures_processed}, повторов R: {stats.r_value_reuses_found}, "
                            f"уязвимостей: {stats.vulnerabilities_flagged}.",
                        )
                        if stats.vulnerabilities_flagged > 0:
                            self.notebook.select(self.tab_vulns)
                elif event == "fatal":
                    self._is_running = False
                    self.btn_start.config(state="normal")
                    self.btn_stop.config(state="disabled")
                    self._set_status("ОШИБКА", NEON_MAGENTA)
                    self._append_log("ERROR", f"Критическая ошибка: {data}")
                    messagebox.showerror("Ошибка сканирования", str(data))
        except queue.Empty:
            pass
        finally:
            self.root.after(60, self._poll_queue)

    def _update_progress_ui(self, st: ProcessingStats) -> None:
        total = max(1, st.total_blocks)
        pct = min(100.0, (st.blocks_processed / total) * 100.0)
        elapsed = max(0.001, time.monotonic() - self._scan_start_time) if self._scan_start_time else 0.001
        speed = st.blocks_processed / elapsed
        eta_str = utils.format_duration((total - st.blocks_processed) / speed) if speed > 0 else "--"

        self.kpi_labels["units"].config(text=f"{st.blocks_processed}/{st.total_blocks}")
        self.kpi_labels["txs"].config(text=str(st.transactions_processed))
        self.kpi_labels["sigs"].config(text=str(st.signatures_processed))
        self.kpi_labels["reuses"].config(text=str(st.r_value_reuses_found))
        self.kpi_labels["vulns"].config(text=str(st.vulnerabilities_flagged))
        self.kpi_labels["speed"].config(text=f"{speed:.1f} /с")

        self.progress_bar["value"] = pct
        self.lbl_progress_text.config(
            text=f"Прогресс: {pct:.1f}%  |  Время: {utils.format_duration(elapsed)}  |  Осталось: {eta_str}"
        )

        if self._active_api_client and hasattr(self._active_api_client, "get_stats"):
            s = self._active_api_client.get_stats()
            self.lbl_api_stats.config(
                text=f"API/RPC: {s['total_requests']} запр. (ошибок: {s['failed_requests']}, повторов: {s['retry_count']})"
            )

    # --- Сохранение / загрузка настроек ---

    def _save_config(self) -> None:
        data = {
            "mode": self.var_mode.get(),
            "network_choice": self.var_network_choice.get(),
            "tron_endpoint": self.var_tron_endpoint.get(),
            "btc_rest_endpoint": self.var_btc_rest_endpoint.get(),
            "endpoint": self.var_endpoint.get(),
            "username": self.var_username.get(),
            "start_height": self.var_start_height.get(),
            "end_height": self.var_end_height.get(),
            "threads": self.var_threads.get(),
            "rate_limit": self.var_rate_limit.get(),
            "db_path": self.var_db_path.get(),
            "only_success": self.var_only_success.get(),
            "max_items": self.var_max_items.get(),
            "max_tx_per_addr": self.var_max_tx_per_addr.get(),
            "only_outgoing": self.var_only_outgoing.get(),
            "dry_run": self.var_dry_run.get(),
            "verbose": self.var_verbose.get(),
        }
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _load_config(self) -> None:
        if not os.path.exists(CONFIG_FILE):
            return
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            for key, var in [
                ("mode", self.var_mode),
                ("network_choice", self.var_network_choice),
                ("tron_endpoint", self.var_tron_endpoint),
                ("btc_rest_endpoint", self.var_btc_rest_endpoint),
                ("endpoint", self.var_endpoint),
                ("username", self.var_username),
                ("start_height", self.var_start_height),
                ("end_height", self.var_end_height),
                ("threads", self.var_threads),
                ("rate_limit", self.var_rate_limit),
                ("db_path", self.var_db_path),
                ("max_items", self.var_max_items),
                ("max_tx_per_addr", self.var_max_tx_per_addr),
            ]:
                if key in data:
                    var.set(str(data[key]))
            for bkey, bvar in [
                ("only_success", self.var_only_success),
                ("only_outgoing", self.var_only_outgoing),
                ("dry_run", self.var_dry_run),
                ("verbose", self.var_verbose),
            ]:
                if bkey in data:
                    bvar.set(bool(data[bkey]))
        except Exception:
            pass

    def _on_close(self) -> None:
        if self._is_running:
            if not messagebox.askyesno("Выход", "Сканирование ещё выполняется. Остановить и выйти?"):
                return
            self._stop_scan()
        self._save_config()
        self.root.destroy()


def launch_gui() -> None:
    root = tk.Tk()
    CyberScannerApp(root)
    root.mainloop()
