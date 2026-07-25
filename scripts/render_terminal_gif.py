#!/usr/bin/env python3
"""Render captured terminal output as an animated GIF or static PNG.

Input is a real transcript captured from a running stack. Nothing here
synthesises output; it only typesets text that was actually produced.

Usage:
    python3 scripts/render_terminal_gif.py transcript.txt docs/demo.gif
    python3 scripts/render_terminal_gif.py transcript.txt docs/demo.png --static
"""

import argparse
import re
import sys

from PIL import Image, ImageDraw, ImageFont

BG = (13, 17, 23)
CHROME = (22, 27, 34)
FG = (201, 209, 217)
DIM = (110, 118, 129)
PALETTE = {
    "critical": (255, 123, 114),
    "high": (255, 166, 87),
    "medium": (210, 168, 255),
    "ok": (86, 211, 100),
    "info": (121, 192, 255),
}
DOTS = [(255, 95, 86), (255, 189, 46), (39, 201, 63)]

FONT_PATH = "/System/Library/Fonts/Menlo.ttc"
FONT_SIZE = 15
LINE_H = 21
PAD = 16
TITLE_H = 30


def colour_for(line: str):
    lowered = line.lower()
    if "critical" in lowered:
        return PALETTE["critical"]
    if "high" in lowered:
        return PALETTE["high"]
    if "medium" in lowered:
        return PALETTE["medium"]
    if line.lstrip().startswith(("$", "#")):
        return PALETTE["ok"]
    if re.match(r"\s*(=+|-+)\s*$", line) or line.startswith("  "):
        return DIM
    if "[*]" in line or "OK" in line or "passed" in line:
        return PALETTE["info"]
    return FG


def measure(lines, font):
    probe = Image.new("RGB", (10, 10))
    draw = ImageDraw.Draw(probe)
    width = max(draw.textlength(line, font=font) for line in lines) if lines else 0
    return int(width) + PAD * 2, len(lines) * LINE_H + PAD * 2 + TITLE_H


def frame(lines, size, font, title):
    img = Image.new("RGB", size, BG)
    draw = ImageDraw.Draw(img)

    draw.rectangle([0, 0, size[0], TITLE_H], fill=CHROME)
    for i, colour in enumerate(DOTS):
        x = PAD + i * 18
        draw.ellipse([x, 11, x + 9, 20], fill=colour)
    draw.text((PAD + 66, 8), title, font=font, fill=DIM)

    y = TITLE_H + PAD
    for line in lines:
        draw.text((PAD, y), line, font=font, fill=colour_for(line))
        y += LINE_H
    return img


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("transcript")
    parser.add_argument("output")
    parser.add_argument("--static", action="store_true")
    parser.add_argument("--title", default="siem-alert-triage")
    parser.add_argument("--ms", type=int, default=260, help="per-line delay")
    args = parser.parse_args()

    with open(args.transcript) as handle:
        lines = [line.rstrip("\n") for line in handle if line.strip() or True]
    lines = [line for line in lines if line.strip() != ""] or ["(empty)"]

    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    size = measure(lines, font)

    if args.static:
        frame(lines, size, font, args.title).save(args.output)
        print(f"wrote {args.output} ({size[0]}x{size[1]})")
        return 0

    frames, durations = [], []
    for count in range(1, len(lines) + 1):
        frames.append(frame(lines[:count], size, font, args.title))
        # Linger on detections; scroll past routine lines.
        text = lines[count - 1].lower()
        durations.append(900 if ("critical" in text or "alert" in text) else args.ms)
    durations[-1] = 3200

    frames[0].save(
        args.output,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    print(f"wrote {args.output} ({size[0]}x{size[1]}, {len(frames)} frames)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
