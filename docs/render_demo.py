"""Render captured honeyrun terminal output (ANSI) to docs/demo.svg.

    FORCE_COLOR=1 honeyrun ./mcp-weather-pro > out.ansi
    python docs/render_demo.py out.ansi '$ honeyrun ./mcp-weather-pro' docs/demo.svg
"""
import html
import re
import sys

PALETTE = {"0": None, "1": "bold", "2": "#7d8590", "31": "#ff7b72", "32": "#3fb950", "33": "#d29922",
           "36": "#79c0ff", "97": "#ffffff", "41": "bg:#da3633"}
FG = "#e6edf3"
CW, LH, PAD, TOP = 8.4, 20, 20, 44


def spans(line):
    state = {"fg": FG, "bold": False, "bg": None}
    out, pos = [], 0
    for m in re.finditer(r"\x1b\[([\d;]*)m", line):
        if m.start() > pos:
            out.append((line[pos:m.start()], dict(state)))
        for code in (m.group(1) or "0").split(";"):
            if code == "0":
                state = {"fg": FG, "bold": False, "bg": None}
            elif PALETTE.get(code) == "bold":
                state["bold"] = True
            elif (PALETTE.get(code) or "").startswith("bg:"):
                state["bg"] = PALETTE[code][3:]
            elif PALETTE.get(code):
                state["fg"] = PALETTE[code]
        pos = m.end()
    if pos < len(line):
        out.append((line[pos:], dict(state)))
    return out


def main(src, prompt, dest):
    lines = [prompt] + open(src, encoding="utf-8").read().rstrip("\n").split("\n")
    cols = max(len(re.sub(r"\x1b\[[\d;]*m", "", l)) for l in lines)
    width = int(PAD * 2 + cols * CW) + 10
    height = TOP + LH * len(lines) + PAD
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
           '<style>text{font:14px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre}</style>',
           f'<rect width="{width}" height="{height}" rx="10" fill="#0d1117"/>',
           '<circle cx="20" cy="20" r="6" fill="#ff5f57"/><circle cx="40" cy="20" r="6" fill="#febc2e"/>'
           '<circle cx="60" cy="20" r="6" fill="#28c840"/>']
    for i, line in enumerate(lines):
        y = TOP + LH * i + 14
        x = PAD
        parts = [(line[2:], {"fg": FG, "bold": True, "bg": None})] if i == 0 else spans(line)
        if i == 0:
            svg.append(f'<text x="{x}" y="{y}" fill="#3fb950">$</text>')
            x += CW * 2
        for text, st in parts:
            if not text:
                continue
            w = CW * len(text)
            if st["bg"]:
                svg.append(f'<rect x="{x - 2:.1f}" y="{y - 14}" width="{w + 4:.1f}" height="19" rx="3" fill="{st["bg"]}"/>')
            weight = ' font-weight="700"' if st["bold"] else ""
            svg.append(f'<text x="{x:.1f}" y="{y}" fill="{st["fg"]}"{weight}>{html.escape(text)}</text>')
            x += w
    svg.append("</svg>")
    open(dest, "w").write("\n".join(svg) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:4])
