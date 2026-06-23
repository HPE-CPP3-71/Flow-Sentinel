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
                 on_select=None, max_rows: int = 0):
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
        # max_rows=0 means unlimited (Overview's paginated table).
        # Traffic page passes 500 so the scrollable body never grows unbounded.
        self._max_rows = max_rows

        self._rows: list[ctk.CTkFrame] = []
        self._base_fills: list[str] = []
        self._base_borders: list[str] = []
        # Per-row list of per-column widget descriptors, so update_data() can
        # reconfigure cells in place (no destroy/recreate → no flicker).
        self._row_cells: list[list[dict]] = []
        self._selected: int | None = None
        self._bold_font = ctk.CTkFont(family=self.cell_font.cget("family"),
                                      size=self.cell_font.cget("size"), weight="bold")

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
        cells: list[dict] = []
        for c, col in enumerate(self.columns):
            cell = row.get(col["key"], "")
            # inset the first/last cells so content never sits on the row's
            # rounded corners / vertical border edges
            left = 14 if c == 0 else 0
            right = 14 if c == ncols - 1 else self.cell_pad
            cells.append(self._build_cell(rf, cell, c, col.get("align", "w"),
                                          dim, (left, right)))

        if self.separators:
            ctk.CTkFrame(rf, fg_color=theme.COLORS["border_subtle"], height=2
                         ).place(relx=0.00, rely=1.0, relwidth=0.96, anchor="sw")

        self._rows.append(rf)
        self._base_fills.append(fill)
        self._base_borders.append(base_border)
        self._row_cells.append(cells)

        if self.selectable:
            self._bind_click(rf, rf)   # bind to frame ref, not index

    def _build_cell(self, parent, cell, col_index, align, dim, pad) -> dict:
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
            pill = ctk.CTkLabel(
                holder, text=f" {text} ", font=self.fonts["mono_xs"],
                fg_color=spec.get("badge_fg", theme.COLORS["badge_bg"]),
                text_color=spec.get("badge_text", theme.COLORS["badge_text"]),
                corner_radius=6, height=22,
            )
            pill.pack(side=side)
            return {"kind": "badge", "label": pill}

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
            dot_lbl = None
            if spec.get("dot"):
                dot_lbl = ctk.CTkLabel(inner, text="●", font=self.fonts["mono_xs"],
                                       text_color=color if dim else spec["dot"])
                dot_lbl.pack(side="left", padx=(0, 7))
            text_lbl = ctk.CTkLabel(inner, text=text, font=font, text_color=color)
            text_lbl.pack(side="left")
            return {"kind": "dotted", "text": text_lbl, "dot": dot_lbl}

        # Plain cell
        if spec.get("bold"):
            font = self._bold_font
        lbl = ctk.CTkLabel(parent, text=text, font=font, text_color=color, anchor=align)
        lbl.grid(row=0, column=col_index, sticky="nsew", padx=pad)
        return {"kind": "plain", "label": lbl}

    # ── selection ────────────────────────────────────────────────────────
    def _bind_click(self, widget, row_frame: ctk.CTkFrame) -> None:
        # Bind to the frame object, not a captured index. After push_row()
        # drops old rows and re-grids the rest, _select_by_frame still
        # finds the correct current position via self._rows.index().
        widget.configure(cursor="hand2")
        widget.bind("<Button-1>", lambda _e, rf=row_frame: self._select_by_frame(rf))
        for child in widget.winfo_children():
            self._bind_click(child, row_frame)

    def _select_by_frame(self, row_frame: ctk.CTkFrame) -> None:
        try:
            index = self._rows.index(row_frame)
        except ValueError:
            return   # frame was dropped (max_rows trim) before click resolved
        self.select(index)

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

    # ── in-place refresh (no flicker) ─────────────────────────────────────
    def update_data(self, new_rows: list[dict]) -> None:
        """
        Reconcile the table against `new_rows` by reconfiguring existing row
        widgets in place. Rows are only created/destroyed when the row *count*
        changes; otherwise nothing is rebuilt, so periodic refreshes don't
        flicker. Used by the Overview "Live Capture Stats" table.
        """
        n_new = len(new_rows)

        # Trim surplus rows from the end.
        while len(self._rows) > n_new:
            rf = self._rows.pop()
            self._base_fills.pop()
            self._base_borders.pop()
            self._row_cells.pop()
            rf.destroy()
        if self._selected is not None and self._selected >= n_new:
            self._selected = None

        # Update the rows that already exist, in place.
        common = len(self._rows)
        for i in range(common):
            if not self._update_row_inplace(i, new_rows[i]):
                self._rebuild_all(new_rows)   # structural change → safe fallback
                return

        # Append any extra rows.
        for i in range(common, n_new):
            self._build_row(new_rows[i], i)

    def _update_row_inplace(self, i: int, row: dict) -> bool:
        """Reconfigure row i to match `row`. Returns False if a cell's widget
        kind changed (then the caller rebuilds — never happens for stable
        column layouts like the Overview table)."""
        new_fill = row.get("_fill") or "transparent"
        if new_fill != self._base_fills[i]:
            base_border = new_fill if new_fill != "transparent" else theme.COLORS["bg_card"]
            self._base_fills[i] = new_fill
            self._base_borders[i] = base_border
            if self._selected != i:
                self._rows[i].configure(fg_color=new_fill, border_color=base_border)
            else:
                self._rows[i].configure(border_color=base_border)

        dim = row.get("_dim", False)
        descs = self._row_cells[i]
        for c, col in enumerate(self.columns):
            cell = row.get(col["key"], "")
            spec = cell if isinstance(cell, dict) else {"text": str(cell)}
            if self._cell_kind(spec) != descs[c]["kind"]:
                return False
            self._apply_cell_inplace(descs[c], spec, dim)
        return True

    @staticmethod
    def _cell_kind(spec: dict) -> str:
        if spec.get("badge"):
            return "badge"
        if spec.get("dot") or spec.get("trailing"):
            return "dotted"
        return "plain"

    def _apply_cell_inplace(self, desc: dict, spec: dict, dim: bool) -> None:
        color = spec.get("color", theme.COLORS["text_body"])
        if dim:
            color = spec.get("dim_color", theme.COLORS["text_muted"])
        kind = desc["kind"]
        if kind == "plain":
            font = self._bold_font if spec.get("bold") else self.cell_font
            desc["label"].configure(text=spec.get("text", ""), text_color=color, font=font)
        elif kind == "badge":
            desc["label"].configure(
                text=f" {spec.get('text', '')} ",
                fg_color=spec.get("badge_fg", theme.COLORS["badge_bg"]),
                text_color=spec.get("badge_text", theme.COLORS["badge_text"]))
        else:  # dotted
            desc["text"].configure(text=spec.get("text", ""), text_color=color)
            if desc["dot"] is not None and spec.get("dot"):
                desc["dot"].configure(text_color=color if dim else spec["dot"])

    def _rebuild_all(self, rows: list[dict]) -> None:
        for rf in self._rows:
            rf.destroy()
        self._rows.clear()
        self._base_fills.clear()
        self._base_borders.clear()
        self._row_cells.clear()
        self._selected = None
        for i, row in enumerate(rows):
            self._build_row(row, i)

    # ── live append ───────────────────────────────────────────────────────
    def push_row(self, row: dict) -> None:
        """
        Append one row at runtime — used by TrafficPage.poll() to stream
        live FlowEvents into the grid without rebuilding the whole table.

        When max_rows > 0 and the table is full, the oldest row is destroyed
        and remaining rows are shifted up one grid slot. Selection index is
        adjusted so the highlighted row stays on the correct frame.
        """
        if self._max_rows and len(self._rows) >= self._max_rows:
            oldest = self._rows.pop(0)
            self._base_fills.pop(0)
            self._base_borders.pop(0)
            self._row_cells.pop(0)
            oldest.destroy()
            for i, rf in enumerate(self._rows):
                rf.grid(row=i, column=0, sticky="ew", pady=1)
            if self._selected is not None:
                self._selected = None if self._selected == 0 else self._selected - 1

        self._build_row(row, len(self._rows))

        if isinstance(self.body, ctk.CTkScrollableFrame):
            self.after(15, self._scroll_to_bottom)

    def _scroll_to_bottom(self) -> None:
        try:
            self.body._parent_canvas.yview_moveto(1.0)
        except Exception:
            pass