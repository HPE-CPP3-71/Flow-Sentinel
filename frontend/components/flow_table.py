"""
FlowTable — a lightweight, column-configurable data grid.

The Figma uses two different tables (the Overview "Live Capture Stats" grid
and the Traffic "Flow Predictions" grid) with different columns and cell
styling, so this component is generic: the page supplies a column spec and
rows, and each cell is either a plain string or a style dict.

Column spec entry:
    {"key": "src", "title": "SOURCE IP", "weight": 3, "align": "w"}

Cell value — a plain str, or a dict with any of:
    {"text": str, "color": hex, "bold": bool,
     "dot": hex,          # leading status dot in this colour
     "badge": bool,       # render as a pill (protocol tag)
     "badge_fg": hex, "badge_text": hex,   # custom pill colours
     "trailing": glyph, "trailing_color": hex}   # glyph pinned far right

Row-level keys:
    "_fill"   — static highlighted background (e.g. the suspicious flow)
    "_dim"    — render the whole row muted (anomaly rows on the Traffic table)

Optional behaviours (opt-in per page):
    separators  — full-width hairline beneath every row (Overview grid)
    scrollable  — rows live in a scrollable body (Traffic grid)
    selectable  — rows are clickable; on_select(index) fires and the clicked
                  row stays highlighted (drives the feature inspector)

The table renders header + rows only; the surrounding panel chrome (title,
export button, pagination, ...) is the page's responsibility.
"""

import customtkinter as ctk

from frontend import theme

_UNIFORM = "flowcol"


class FlowTable(ctk.CTkFrame):
    def __init__(self, parent, app, columns: list[dict], rows: list[dict],
                 row_height: int = 44, font_key: str = "mono_md",
                 cell_pad: int = 8, separators: bool = False,
                 scrollable: bool = False, selectable: bool = False,
                 on_select=None):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.fonts = app.fonts
        self.columns = columns
        self.row_height = row_height
        self.cell_font = app.fonts[font_key]
        self.cell_pad = cell_pad
        self.separators = separators
        self.selectable = selectable
        self.on_select = on_select

        self._rows: list[ctk.CTkFrame] = []
        self._base_fills: list[str] = []
        self._base_borders: list[str] = []
        self._selected: int | None = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header(scrollable)

        if scrollable:
            self.body = ctk.CTkScrollableFrame(self, fg_color="transparent",
                                               corner_radius=0)
            try:
                self.body._scrollbar.configure(width=10)
            except Exception:
                pass
        else:
            self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.grid(row=2, column=0, sticky="nsew")
        self.body.grid_columnconfigure(0, weight=1)

        for i, row in enumerate(rows):
            self._build_row(row, i)

    # ── grid helpers ─────────────────────────────────────────────────────
    def _configure_columns(self, frame: ctk.CTkFrame) -> None:
        for c, col in enumerate(self.columns):
            frame.grid_columnconfigure(c, weight=col.get("weight", 1),
                                       uniform=_UNIFORM)

    # ── header ───────────────────────────────────────────────────────────
    def _build_header(self, scrollable: bool) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent", height=34)
        header.grid(row=0, column=0, sticky="ew",
                    padx=(0, 12 if scrollable else 0))  # offset the scrollbar gutter
        header.grid_propagate(False)
        self._configure_columns(header)

        for c, col in enumerate(self.columns):
            align = col.get("align", "w")
            ctk.CTkLabel(
                header, text=col["title"], font=self.fonts["mono_xs"],
                text_color=theme.COLORS["text_muted"], anchor=align,
            ).grid(row=0, column=c, sticky="ew", padx=(0, self.cell_pad), pady=(2, 6))

        ctk.CTkFrame(self, fg_color=theme.COLORS["border_subtle"], height=2
                     ).grid(row=1, column=0, sticky="ew")

    # ── data rows ────────────────────────────────────────────────────────
    def _build_row(self, row: dict, index: int) -> None:
        fill = row.get("_fill") or "transparent"
        # A 1px border is present from creation (matched to the row's own fill,
        # so it's invisible) — selection only recolours it, never toggles the
        # width. Toggling border_width on a live CTkFrame leaves the rounded
        # outline half-drawn; recolouring an existing border redraws cleanly.
        base_border = fill if fill != "transparent" else theme.COLORS["bg_card"]
        rf = ctk.CTkFrame(self.body, fg_color=fill, height=self.row_height,
                          corner_radius=8, border_width=1, border_color=base_border)
        rf.grid(row=index, column=0, sticky="ew", pady=1)
        rf.grid_propagate(False)
        self._configure_columns(rf)

        rf.grid_rowconfigure(0, weight=1)
        dim = row.get("_dim", False)
        ncols = len(self.columns)
        for c, col in enumerate(self.columns):
            cell = row.get(col["key"], "")
            # inset the first/last cells so content never sits on the row's
            # rounded corners / vertical border edges
            left = 14 if c == 0 else 0
            right = 14 if c == ncols - 1 else self.cell_pad
            self._build_cell(rf, cell, c, col.get("align", "w"), dim, (left, right))

        if self.separators:
            ctk.CTkFrame(rf, fg_color=theme.COLORS["border_subtle"], height=2
                         ).place(relx=0.00, rely=1.0, relwidth=0.96, anchor="sw")

        self._rows.append(rf)
        self._base_fills.append(fill)
        self._base_borders.append(base_border)

        if self.selectable:
            self._bind_click(rf, index)

    def _build_cell(self, parent, cell, col_index, align, dim, pad) -> None:
        spec = cell if isinstance(cell, dict) else {"text": str(cell)}
        text = spec.get("text", "")
        font = self.cell_font
        color = spec.get("color", theme.COLORS["text_body"])
        if dim:
            color = spec.get("dim_color", theme.COLORS["text_muted"])
        side = "left" if align == "w" else "right"

        # Protocol pill
        if spec.get("badge"):
            holder = ctk.CTkFrame(parent, fg_color="transparent")
            holder.grid(row=0, column=col_index, sticky="ew", padx=pad)
            ctk.CTkLabel(
                holder, text=f" {text} ", font=self.fonts["mono_xs"],
                fg_color=spec.get("badge_fg", theme.COLORS["badge_bg"]),
                text_color=spec.get("badge_text", theme.COLORS["badge_text"]),
                corner_radius=6, height=22,
            ).pack(side=side)
            return

        # Status dot + text (and/or trailing glyph pinned right)
        if spec.get("dot") or spec.get("trailing"):
            holder = ctk.CTkFrame(parent, fg_color="transparent")
            holder.grid(row=0, column=col_index, sticky="nsew", padx=pad)
            if spec.get("trailing"):
                ctk.CTkLabel(holder, text=spec["trailing"], font=self.cell_font,
                             text_color=spec.get("trailing_color", color)
                             ).pack(side="right", padx=(8, 4))
            inner = ctk.CTkFrame(holder, fg_color="transparent")
            inner.pack(side=side)
            if spec.get("dot"):
                ctk.CTkLabel(inner, text="●", font=self.fonts["mono_xs"],
                             text_color=color if dim else spec["dot"]
                             ).pack(side="left", padx=(0, 7))
            ctk.CTkLabel(inner, text=text, font=font, text_color=color).pack(side="left")
            return

        # Plain cell
        if spec.get("bold"):
            font = ctk.CTkFont(family=font.cget("family"), size=font.cget("size"),
                               weight="bold")
        ctk.CTkLabel(parent, text=text, font=font, text_color=color, anchor=align,
                     ).grid(row=0, column=col_index, sticky="nsew", padx=pad)

    # ── selection ────────────────────────────────────────────────────────
    def _bind_click(self, widget, index: int) -> None:
        widget.configure(cursor="hand2")
        widget.bind("<Button-1>", lambda _e, i=index: self.select(i))
        for child in widget.winfo_children():
            self._bind_click(child, index)

    def select(self, index: int) -> None:
        if index == self._selected:
            return
        self._selected = index
        for i, rf in enumerate(self._rows):
            if i == index:
                rf.configure(fg_color=theme.COLORS["row_selected"])
            else:
                rf.configure(fg_color=self._base_fills[i])
        if callable(self.on_select):
            self.on_select(index)
