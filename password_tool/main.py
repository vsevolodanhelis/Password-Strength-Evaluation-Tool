"""
Password Strength Analyzer — GUI Interface
============================================
A hybrid password strength evaluation system combining rule-based
analysis, entropy estimation, dictionary comparison, and pattern detection.

Built with CustomTkinter for a modern, dark-themed dashboard interface.

Usage:
    python -m password_tool
"""

import sys
import math
import tkinter as tk

try:
    import customtkinter as ctk
except ImportError:
    print(
        "Error: 'customtkinter' is not installed.\n"
        "Install it by running:\n"
        "    pip install customtkinter\n"
        "Or install all dependencies:\n"
        "    pip install -r requirements.txt"
    )
    sys.exit(1)

from password_tool.evaluator import (
    evaluate_password, EvaluationResult, generate_password,
    MAX_LENGTH_SCORE, MAX_DIVERSITY_SCORE, MAX_ENTROPY_SCORE,
    PATTERN_PENALTY_TOTAL, SIMILAR_PENALTY, DICT_WORD_PENALTY,
)


# ---------------------------------------------------------------------------
# Theme & colour palette (unified)
# ---------------------------------------------------------------------------

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_BG_PRIMARY    = "#0f172a"
_BG_PANEL      = "#16213e"
_ACCENT        = "#3b82f6"
_SUCCESS       = "#22c55e"
_WARNING       = "#f59e0b"
_DANGER        = "#ef4444"
_ORANGE        = "#f97316"
_TEXT_PRIMARY   = "#f1f5f9"
_TEXT_SECONDARY = "#9ca3af"
_GAUGE_BG      = "#1e293b"
_DIVIDER       = "#1e293b"

_STRENGTH_COLORS = {
    "Very Weak": _DANGER,
    "Weak":      _ORANGE,
    "Moderate":  _WARNING,
    "Strong":    _SUCCESS,
}

_FONT_FAMILY = "Segoe UI"


# ---------------------------------------------------------------------------
# Spacing scale (8px base)
# ---------------------------------------------------------------------------

_SP_4  = 4
_SP_8  = 8
_SP_12 = 12
_SP_16 = 16
_SP_20 = 20
_SP_24 = 24

_CONTENT_PADX = 40
_CARD_PADX    = 20


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class PasswordAnalyzerApp(ctk.CTk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()

        self.title("Password Strength Analyzer")
        self.resizable(False, False)
        self.configure(fg_color=_BG_PRIMARY)

        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        win_w, win_h = 1000, 780
        x = (screen_w - win_w) // 2
        y = (screen_h - win_h) // 2
        self.geometry(f"{win_w}x{win_h}+{x}+{y}")

        self._debounce_id: str | None = None
        self._password_visible = False
        self._breakdown_visible = False

        # Animation state
        self._anim_target_score = 0
        self._anim_current_score = 0.0
        self._anim_target_color = _GAUGE_BG
        self._anim_id: str | None = None

        # Meter animation state
        self._meter_anim_target = 0.0
        self._meter_anim_current = 0.0
        self._meter_anim_color = _GAUGE_BG
        self._meter_anim_id: str | None = None

        self._build_ui()

    # =================================================================== UI
    def _build_ui(self) -> None:

        # --- Header -------------------------------------------------------
        header = ctk.CTkFrame(self, fg_color=_BG_PANEL, corner_radius=0, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)

        header_inner = ctk.CTkFrame(header, fg_color="transparent")
        header_inner.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            header_inner,
            text="Password Strength Analyzer",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=24, weight="bold"),
            text_color=_TEXT_PRIMARY,
        ).pack()

        ctk.CTkLabel(
            header_inner,
            text="Evaluate password security using hybrid analysis",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
            text_color=_TEXT_SECONDARY,
        ).pack(pady=(_SP_4, 0))

        # --- Scrollable body ----------------------------------------------
        body = ctk.CTkScrollableFrame(
            self, fg_color=_BG_PRIMARY, corner_radius=0,
            scrollbar_button_color=_BG_PANEL,
            scrollbar_button_hover_color=_ACCENT,
        )
        body.pack(fill="both", expand=True, padx=0, pady=0)

        content = ctk.CTkFrame(body, fg_color="transparent")
        content.pack(expand=True, fill="x", padx=_CONTENT_PADX)

        # --- Input card ---------------------------------------------------
        input_card = self._card(content)
        input_card.pack(fill="x", pady=(_SP_16, 0))

        ctk.CTkLabel(
            input_card,
            text="Enter your password",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
            text_color=_TEXT_SECONDARY,
        ).pack(anchor="w", padx=_CARD_PADX, pady=(_SP_16, _SP_4))

        row = ctk.CTkFrame(input_card, fg_color="transparent")
        row.pack(fill="x", padx=_CARD_PADX)

        self._entry = ctk.CTkEntry(
            row,
            placeholder_text="Enter password\u2026",
            show="\u2022",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=15),
            height=48,
            corner_radius=10,
            fg_color="#0f172a",
            border_color="#334155",
            text_color=_TEXT_PRIMARY,
        )
        self._entry.pack(side="left", fill="x", expand=True, padx=(0, _SP_8))
        self._entry.bind("<KeyRelease>", self._on_key)

        self._toggle_btn = ctk.CTkButton(
            row, text="\u25ce", width=46, height=46, corner_radius=10,
            font=ctk.CTkFont(size=18),
            fg_color="#334155", hover_color="#475569",
            command=self._toggle_visibility,
        )
        self._toggle_btn.pack(side="left")

        # Strength meter bar under input
        meter_frame = ctk.CTkFrame(input_card, fg_color="transparent")
        meter_frame.pack(fill="x", padx=_CARD_PADX, pady=(_SP_8, 0))

        self._meter_canvas = tk.Canvas(
            meter_frame, height=6, bg=_BG_PANEL,
            highlightthickness=0, bd=0,
        )
        self._meter_canvas.pack(fill="x")
        self._meter_canvas.bind("<Configure>", lambda e: self._draw_meter(
            self._meter_anim_current, self._meter_anim_color))

        # Generate Strong Password button (full-width, primary)
        self._generate_btn = ctk.CTkButton(
            input_card,
            text="Generate Strong Password",
            height=44,
            corner_radius=10,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=14, weight="bold"),
            fg_color=_ACCENT,
            hover_color="#2563eb",
            command=self._generate_and_analyze,
        )
        self._generate_btn.pack(fill="x", padx=_CARD_PADX, pady=(_SP_12, _SP_16))

        # --- Analysis card (two-column) ----------------------------------
        analysis_card = self._card(content)
        analysis_card.pack(fill="both", expand=True, pady=(_SP_16, _SP_24))

        # -- Left column: Score overview --
        left_col = ctk.CTkFrame(analysis_card, fg_color="transparent")
        left_col.pack(side="left", fill="y", padx=(_CARD_PADX, 0), pady=_SP_16)

        # Gauge
        gauge_container = ctk.CTkFrame(left_col, fg_color="transparent")
        gauge_container.pack(pady=(_SP_4, 0))

        self._gauge_canvas = tk.Canvas(
            gauge_container, width=220, height=130,
            bg=_BG_PANEL, highlightthickness=0,
        )
        self._gauge_canvas.pack()
        self._draw_gauge(0, _GAUGE_BG)

        # Score number
        self._score_label = ctk.CTkLabel(
            left_col, text="\u2014 / 100",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=32, weight="bold"),
            text_color=_TEXT_PRIMARY,
        )
        self._score_label.pack(pady=(_SP_4, 0))

        # Strength label
        self._strength_label = ctk.CTkLabel(
            left_col, text="Start typing to analyze",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=16, weight="bold"),
            text_color=_TEXT_SECONDARY,
        )
        self._strength_label.pack(pady=(0, _SP_8))

        # Entropy & crack time row
        info_row = ctk.CTkFrame(left_col, fg_color="transparent")
        info_row.pack(fill="x", pady=(0, _SP_8))

        entropy_col = ctk.CTkFrame(info_row, fg_color="transparent")
        entropy_col.pack(side="left", expand=True)
        ctk.CTkLabel(
            entropy_col, text="ENTROPY",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
            text_color=_TEXT_SECONDARY,
        ).pack()
        self._entropy_label = ctk.CTkLabel(
            entropy_col, text="\u2014",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=14, weight="bold"),
            text_color=_TEXT_PRIMARY,
        )
        self._entropy_label.pack()

        crack_col = ctk.CTkFrame(info_row, fg_color="transparent")
        crack_col.pack(side="right", expand=True)
        ctk.CTkLabel(
            crack_col, text="CRACK TIME",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=10),
            text_color=_TEXT_SECONDARY,
        ).pack()
        self._crack_label = ctk.CTkLabel(
            crack_col, text="\u2014",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=14, weight="bold"),
            text_color=_TEXT_PRIMARY,
        )
        self._crack_label.pack()

        # -- Vertical divider --
        divider = ctk.CTkFrame(analysis_card, fg_color=_DIVIDER, width=1)
        divider.pack(side="left", fill="y", padx=(_SP_8, _SP_8), pady=_SP_16)

        # -- Right column: Details + Suggestions --
        right_col = ctk.CTkFrame(analysis_card, fg_color="transparent")
        right_col.pack(side="left", fill="both", expand=True, padx=(0, _CARD_PADX), pady=_SP_16)

        # Details section
        ctk.CTkLabel(
            right_col, text="Analysis Details",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=14, weight="bold"),
            text_color=_TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, _SP_4))

        self._details_container = ctk.CTkFrame(right_col, fg_color="transparent")
        self._details_container.pack(fill="x", anchor="w")

        self._show_placeholder(
            self._details_container,
            "Start typing to see analysis.",
        )

        # Horizontal separator
        ctk.CTkFrame(
            right_col, fg_color=_DIVIDER, height=1,
        ).pack(fill="x", pady=_SP_12)

        # Score Breakdown toggle
        self._breakdown_toggle_btn = ctk.CTkButton(
            right_col,
            text="\u25b6  Score Breakdown",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=13, weight="bold"),
            fg_color="transparent",
            hover_color=_BG_PANEL,
            text_color=_TEXT_SECONDARY,
            anchor="w",
            command=self._toggle_breakdown,
        )
        self._breakdown_toggle_btn.pack(fill="x", pady=(0, _SP_4))

        self._breakdown_container = ctk.CTkFrame(right_col, fg_color="transparent")
        self._breakdown_container.pack(fill="x", anchor="w")

        # Horizontal separator (below breakdown)
        self._breakdown_sep = ctk.CTkFrame(
            right_col, fg_color=_DIVIDER, height=1,
        )
        self._breakdown_sep.pack(fill="x", pady=_SP_12)

        # Suggestions section
        ctk.CTkLabel(
            right_col, text="Suggestions",
            font=ctk.CTkFont(family=_FONT_FAMILY, size=14, weight="bold"),
            text_color=_TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, _SP_4))

        self._sugg_container = ctk.CTkFrame(right_col, fg_color="transparent")
        self._sugg_container.pack(fill="x", anchor="w")

        self._show_placeholder(
            self._sugg_container,
            "Start typing to see suggestions.",
        )

    # ============================================================ Helpers

    def _card(self, parent) -> ctk.CTkFrame:
        """Create a card-style panel."""
        return ctk.CTkFrame(
            parent,
            fg_color=_BG_PANEL,
            corner_radius=12,
        )

    @staticmethod
    def _show_placeholder(container, text: str) -> None:
        ctk.CTkLabel(
            container, text=text,
            font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
            text_color=_TEXT_SECONDARY,
        ).pack(anchor="w")

    # ========================================================= Gauge draw

    def _draw_gauge(self, score: float, color: str) -> None:
        c = self._gauge_canvas
        c.delete("all")

        cx, cy = 110, 115
        r_outer = 96
        lw = 16

        c.create_arc(
            cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer,
            start=0, extent=180,
            outline=_GAUGE_BG, width=lw, style="arc",
        )

        extent = (score / 100) * 180
        if extent > 0.5:
            c.create_arc(
                cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer,
                start=180, extent=-extent,
                outline=color, width=lw, style="arc",
            )

    # ======================================================= Meter bar

    def _draw_meter(self, score: float, color: str) -> None:
        c = self._meter_canvas
        c.delete("all")
        w = c.winfo_width()
        h = c.winfo_height()

        c.create_rectangle(0, 0, w, h, fill=_GAUGE_BG, outline="")

        fill_w = int((score / 100) * w)
        if fill_w > 0:
            c.create_rectangle(0, 0, fill_w, h, fill=color, outline="")

    def _animate_meter(self) -> None:
        diff = self._meter_anim_target - self._meter_anim_current
        if abs(diff) < 0.5:
            self._meter_anim_current = self._meter_anim_target
            self._draw_meter(self._meter_anim_current, self._meter_anim_color)
            self._meter_anim_id = None
            return

        self._meter_anim_current += diff * 0.15
        self._draw_meter(self._meter_anim_current, self._meter_anim_color)
        self._meter_anim_id = self.after(16, self._animate_meter)

    def _start_meter_animation(self, target: int, color: str) -> None:
        if self._meter_anim_id:
            self.after_cancel(self._meter_anim_id)
        self._meter_anim_target = target
        self._meter_anim_color = color
        self._animate_meter()

    # ====================================================== Gauge animation

    def _animate_gauge(self) -> None:
        diff = self._anim_target_score - self._anim_current_score
        if abs(diff) < 0.5:
            self._anim_current_score = self._anim_target_score
            self._draw_gauge(self._anim_current_score, self._anim_target_color)
            self._anim_id = None
            return

        self._anim_current_score += diff * 0.15
        self._draw_gauge(self._anim_current_score, self._anim_target_color)
        self._anim_id = self.after(16, self._animate_gauge)

    def _start_gauge_animation(self, target: int, color: str) -> None:
        if self._anim_id:
            self.after_cancel(self._anim_id)
        self._anim_target_score = target
        self._anim_target_color = color
        self._animate_gauge()

    # ====================================================== Toggle

    def _toggle_visibility(self) -> None:
        self._password_visible = not self._password_visible
        if self._password_visible:
            self._entry.configure(show="")
            self._toggle_btn.configure(text="\u25c9")
        else:
            self._entry.configure(show="\u2022")
            self._toggle_btn.configure(text="\u25ce")

    # ====================================================== Breakdown toggle

    def _toggle_breakdown(self) -> None:
        self._breakdown_visible = not self._breakdown_visible
        if self._breakdown_visible:
            self._breakdown_toggle_btn.configure(text="\u25bc  Score Breakdown")
            if hasattr(self, "_last_result"):
                self._render_breakdown(self._last_result)
        else:
            self._breakdown_toggle_btn.configure(text="\u25b6  Score Breakdown")
            for w in self._breakdown_container.winfo_children():
                w.destroy()

    def _render_breakdown(self, result: EvaluationResult) -> None:
        for w in self._breakdown_container.winfo_children():
            w.destroy()

        if not self._breakdown_visible:
            return

        dimensions = [
            ("Length", result.length_pts, MAX_LENGTH_SCORE),
            ("Diversity", result.diversity_pts, MAX_DIVERSITY_SCORE),
            ("Entropy", result.entropy_pts, MAX_ENTROPY_SCORE),
            ("Pattern", result.pattern_pts, abs(PATTERN_PENALTY_TOTAL)),
            ("Dictionary", result.dict_pts, max(abs(SIMILAR_PENALTY), abs(DICT_WORD_PENALTY))),
        ]

        for name, pts, max_abs in dimensions:
            row = ctk.CTkFrame(self._breakdown_container, fg_color="transparent")
            row.pack(fill="x", pady=1)

            is_penalty = pts < 0
            pts_color = _DANGER if is_penalty else _SUCCESS if pts > 0 else _TEXT_SECONDARY
            sign = "+" if pts > 0 else ""

            ctk.CTkLabel(
                row, text=name,
                font=ctk.CTkFont(family=_FONT_FAMILY, size=12),
                text_color=_TEXT_SECONDARY, width=80, anchor="w",
            ).pack(side="left")

            bar_frame = ctk.CTkFrame(row, fg_color=_GAUGE_BG, height=10, corner_radius=5)
            bar_frame.pack(side="left", fill="x", expand=True, padx=(_SP_8, _SP_8))
            bar_frame.pack_propagate(False)

            if pts != 0:
                fill_pct = min(abs(pts) / max_abs, 1.0) if max_abs > 0 else 0
                fill_color = _DANGER if is_penalty else pts_color
                fill_bar = ctk.CTkFrame(
                    bar_frame, fg_color=fill_color, height=10, corner_radius=5,
                )
                fill_bar.place(relwidth=fill_pct, relheight=1.0)

            ctk.CTkLabel(
                row, text=f"{sign}{pts}",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=12, weight="bold"),
                text_color=pts_color, width=40, anchor="e",
            ).pack(side="right")

    # ====================================================== Debounce

    def _on_key(self, event=None) -> None:
        if self._debounce_id:
            self.after_cancel(self._debounce_id)
        self._debounce_id = self.after(300, self._analyze)

    # ====================================================== Analysis

    def _analyze(self) -> None:
        password = self._entry.get()
        if not password:
            self._reset_display()
            return
        result = evaluate_password(password)
        self._update_display(result)

    def _generate_and_analyze(self) -> None:
        pw = generate_password()
        self._entry.delete(0, "end")
        self._entry.insert(0, pw)
        if not self._password_visible:
            self._password_visible = True
            self._entry.configure(show="")
            self._toggle_btn.configure(text="\u25c9")
        result = evaluate_password(pw)
        self._update_display(result)

    # ====================================================== Display update

    def _update_display(self, result: EvaluationResult) -> None:
        self._last_result = result
        score = result.score
        label = result.label
        color = _STRENGTH_COLORS.get(label, _TEXT_SECONDARY)

        self._start_gauge_animation(score, color)

        self._score_label.configure(text=f"{score} / 100")
        self._strength_label.configure(text=label, text_color=color)

        self._start_meter_animation(score, color)

        self._entropy_label.configure(
            text=f"{result.entropy_bits:.1f} bits",
        )
        self._crack_label.configure(text=result.crack_time)

        # ---- Details ----
        for w in self._details_container.winfo_children():
            w.destroy()

        for line in result.details:
            if line.startswith("\u2713"):
                col = _SUCCESS
            elif line.startswith("\u2717"):
                col = _DANGER
            else:
                col = _TEXT_SECONDARY

            ctk.CTkLabel(
                self._details_container, text=f"  {line}",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                text_color=col, anchor="w", wraplength=400,
            ).pack(anchor="w", pady=1)

        # ---- Suggestions ----
        for w in self._sugg_container.winfo_children():
            w.destroy()

        if result.suggestions:
            for tip in result.suggestions:
                ctk.CTkLabel(
                    self._sugg_container,
                    text=f"  \u2022  {tip}",
                    font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                    text_color=_TEXT_PRIMARY, anchor="w", wraplength=400,
                ).pack(anchor="w", pady=1)
        else:
            ctk.CTkLabel(
                self._sugg_container,
                text="\u2714  No suggestions \u2014 your password looks great!",
                font=ctk.CTkFont(family=_FONT_FAMILY, size=13),
                text_color=_SUCCESS,
            ).pack(anchor="w")

        # ---- Breakdown ----
        self._render_breakdown(result)

    # ====================================================== Reset

    def _reset_display(self) -> None:
        self._start_gauge_animation(0, _GAUGE_BG)
        self._score_label.configure(text="\u2014 / 100")
        self._strength_label.configure(
            text="Start typing to analyze", text_color=_TEXT_SECONDARY,
        )
        self._entropy_label.configure(text="\u2014")
        self._crack_label.configure(text="\u2014")

        self._start_meter_animation(0, _GAUGE_BG)

        for w in self._details_container.winfo_children():
            w.destroy()
        self._show_placeholder(
            self._details_container,
            "Start typing to see analysis.",
        )

        for w in self._sugg_container.winfo_children():
            w.destroy()
        self._show_placeholder(
            self._sugg_container,
            "Start typing to see suggestions.",
        )

        for w in self._breakdown_container.winfo_children():
            w.destroy()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = PasswordAnalyzerApp()
    app.mainloop()
