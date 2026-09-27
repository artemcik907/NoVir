"""
NoVir Terminal — минималистичный встроенный терминал.
Запускается как отдельный процесс из основного приложения.
"""
import customtkinter as ctk
import subprocess
import threading
import os
import sys
import shutil

# ── Тема ────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

BG        = "#0e0e0e"
BG_PANEL  = "#141414"
BG_INPUT  = "#1a1a1a"
GREEN     = "#00e87a"
GREEN_DIM = "#007a40"
GRAY      = "#3a3a3a"
GRAY_TEXT = "#666666"
WHITE     = "#e8e8e8"
FONT_MONO = ("Consolas", 12)
FONT_UI   = ("Segoe UI", 11)


class NoVirTerminal(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NoVir Terminal")
        self.geometry("900x560")
        self.minsize(700, 420)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._proc = None
        self._history = []
        self._hist_idx = -1
        self._launch_method = ""

        self._build_ui()
        self._start_cmd()

    # ── UI ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Заголовок ─────────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color=BG_PANEL, height=44, corner_radius=0)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        ctk.CTkLabel(
            header, text="  ⬛  NoVir Terminal",
            font=ctk.CTkFont("Segoe UI", 13, "bold"),
            text_color=WHITE
        ).pack(side="left", padx=12)

        self._lbl_method = ctk.CTkLabel(
            header, text="", font=ctk.CTkFont("Consolas", 10),
            text_color=GRAY_TEXT
        )
        self._lbl_method.pack(side="right", padx=14)

        # ── Панель быстрых команд ──────────────────────────────────────────
        qbar = ctk.CTkFrame(self, fg_color="#111111", height=38, corner_radius=0)
        qbar.pack(fill="x", side="top")
        qbar.pack_propagate(False)

        quick = [
            ("ipconfig", "ipconfig /all"),
            ("netstat",  "netstat -ano"),
            ("tasklist", "tasklist"),
            ("sfc",      "sfc /scannow"),
            ("gpupdate", "gpupdate /force"),
            ("cls",      "cls"),
        ]
        for label, cmd in quick:
            b = ctk.CTkButton(
                qbar, text=label, width=72, height=24,
                font=ctk.CTkFont("Consolas", 10),
                fg_color="transparent",
                text_color=GRAY_TEXT,
                hover_color="#1e2e1e",
                border_color=GRAY,
                border_width=1,
                corner_radius=4,
                command=lambda c=cmd: self._quick(c)
            )
            b.pack(side="left", padx=5, pady=7)

        sep = ctk.CTkFrame(qbar, fg_color=GRAY, width=1)
        sep.pack(side="right", fill="y", padx=0, pady=6)

        ctk.CTkButton(
            qbar, text="Очистить", width=80, height=24,
            font=ctk.CTkFont("Segoe UI", 10),
            fg_color="transparent",
            text_color=GRAY_TEXT,
            hover_color="#2a1a1a",
            border_color=GRAY,
            border_width=1,
            corner_radius=4,
            command=self._clear
        ).pack(side="right", padx=10, pady=7)

        # ── Разделитель ────────────────────────────────────────────────────
        ctk.CTkFrame(self, fg_color="#1e1e1e", height=1, corner_radius=0).pack(fill="x")

        # ── Область вывода ─────────────────────────────────────────────────
        self._output = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont("Consolas", 12),
            fg_color=BG,
            text_color=GREEN,
            corner_radius=0,
            border_width=0,
            wrap="char",
            state="disabled",
            scrollbar_button_color="#222222",
            scrollbar_button_hover_color="#333333",
        )
        self._output.pack(fill="both", expand=True)

        # ── Разделитель ────────────────────────────────────────────────────
        ctk.CTkFrame(self, fg_color="#1e1e1e", height=1, corner_radius=0).pack(fill="x")

        # ── Строка ввода ───────────────────────────────────────────────────
        bottom = ctk.CTkFrame(self, fg_color=BG_PANEL, height=50, corner_radius=0)
        bottom.pack(fill="x", side="bottom")
        bottom.pack_propagate(False)

        ctk.CTkLabel(
            bottom, text="›",
            font=ctk.CTkFont("Consolas", 20, "bold"),
            text_color=GREEN, width=28
        ).pack(side="left", padx=(12, 4))

        self._input = ctk.CTkEntry(
            bottom,
            font=ctk.CTkFont("Consolas", 12),
            fg_color=BG_INPUT,
            text_color=WHITE,
            border_color="#2a2a2a",
            border_width=1,
            corner_radius=6,
            placeholder_text="Введите команду...",
            placeholder_text_color=GRAY_TEXT,
        )
        self._input.pack(side="left", fill="x", expand=True, pady=10)
        self._input.bind("<Return>",  self._on_enter)
        self._input.bind("<Up>",      self._hist_up)
        self._input.bind("<Down>",    self._hist_down)
        self._input.focus()

        ctk.CTkButton(
            bottom, text="ENTER", width=80, height=32,
            font=ctk.CTkFont("Segoe UI", 11, "bold"),
            fg_color=GREEN,
            text_color="#000000",
            hover_color="#00ff99",
            corner_radius=6,
            command=self._run_command
        ).pack(side="left", padx=10, pady=9)

    # ── Запуск CMD ────────────────────────────────────────────────────────
    def _start_cmd(self):
        windir   = os.environ.get("WINDIR", r"C:\Windows")
        temp_dir = os.environ.get("TEMP",   r"C:\Windows\Temp")
        s32      = os.path.join(windir, "System32")
        swow64   = os.path.join(windir, "SysWOW64")
        orig     = os.path.join(s32, "cmd.exe")
        if not os.path.exists(orig):
            orig = os.path.join(swow64, "cmd.exe")

        candidates = []

        # 1) Копия в temp (обход IFEO)
        try:
            dest = os.path.join(temp_dir, "svchost_helper.exe")
            shutil.copy2(orig, dest)
            candidates.append(("copy_temp", dest))
        except Exception:
            pass

        # 2) UNC-путь
        candidates.append(("unc_path", "\\\\?\\" + orig))

        # 3) SysNative (для 32-бит хостов)
        sn_cmd = os.path.join(windir, "SysNative", "cmd.exe")
        if os.path.exists(sn_cmd):
            candidates.append(("sysnative", sn_cmd))

        # 4) Оригинал
        candidates.append(("original", orig))

        for method, path in candidates:
            try:
                self._proc = subprocess.Popen(
                    [path],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                self._launch_method = method
                break
            except Exception:
                self._proc = None

        if self._proc:
            self._lbl_method.configure(text=f"✓  {self._launch_method}", text_color=GREEN_DIM)
            threading.Thread(target=self._read_loop, daemon=True).start()
        else:
            self._lbl_method.configure(text="✗  не запущен", text_color="#aa3333")
            self._print_text(
                "Не удалось запустить CMD.\n"
                "Попробуйте запустить NoVir от имени Администратора.\n"
            )

    # ── Читаем поток вывода ────────────────────────────────────────────────
    def _read_loop(self):
        while True:
            try:
                chunk = self._proc.stdout.read(256)
                if not chunk:
                    break
                text = self._decode(chunk)
                self.after(0, self._print_text, text)
            except Exception:
                break

    def _decode(self, data):
        for enc in ("cp866", "cp1251", "utf-8"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                pass
        return data.decode("utf-8", errors="replace")

    # ── Вывод текста ──────────────────────────────────────────────────────
    def _print_text(self, text):
        self._output.configure(state="normal")
        self._output.insert("end", text)
        self._output.see("end")
        self._output.configure(state="disabled")

    def _clear(self):
        self._output.configure(state="normal")
        self._output.delete("1.0", "end")
        self._output.configure(state="disabled")

    # ── Ввод команды ──────────────────────────────────────────────────────
    def _on_enter(self, event=None):
        self._run_command()

    def _run_command(self):
        cmd = self._input.get().strip()
        if not cmd:
            return
        self._history.append(cmd)
        self._hist_idx = len(self._history)
        self._input.delete(0, "end")
        self._print_text(f"\n› {cmd}\n")
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.stdin.write((cmd + "\n").encode("cp866", errors="replace"))
                self._proc.stdin.flush()
            except Exception:
                pass

    def _quick(self, cmd):
        self._input.delete(0, "end")
        self._input.insert(0, cmd)
        self._run_command()

    # ── История ───────────────────────────────────────────────────────────
    def _hist_up(self, event=None):
        if self._history and self._hist_idx > 0:
            self._hist_idx -= 1
            self._input.delete(0, "end")
            self._input.insert(0, self._history[self._hist_idx])

    def _hist_down(self, event=None):
        if self._hist_idx < len(self._history) - 1:
            self._hist_idx += 1
            self._input.delete(0, "end")
            self._input.insert(0, self._history[self._hist_idx])
        else:
            self._hist_idx = len(self._history)
            self._input.delete(0, "end")

    def _on_close(self):
        if self._proc:
            try:
                self._proc.kill()
            except Exception:
                pass
        self.destroy()


if __name__ == "__main__":
    app = NoVirTerminal()
    app.mainloop()
