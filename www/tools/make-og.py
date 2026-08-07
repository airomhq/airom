#!/usr/bin/env python3
"""Generate www/og.png, the 1200x630 social preview card.

Committed as a script rather than just a PNG so the image is reproducible: when
the tagline or the mark changes, this regenerates it instead of someone having
to reverse-engineer a binary in the repo.

    python3 www/tools/make-og.py

Requires Pillow. Uses only fonts that ship with macOS; falls back to DejaVu
(present on most Linux CI images) so it also runs in a container.
"""

from __future__ import annotations

import pathlib
import sys

from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H = 1200, 630

BG = (12, 14, 19)
FG = (232, 234, 240)
MUTED = (154, 163, 178)
ACCENT = (139, 147, 255)
INDIGO = (79, 70, 229)
BORDER = (35, 40, 51)

OUT = pathlib.Path(__file__).resolve().parents[1] / "og.png"

# (path, index-within-collection). macOS ships variable/collection fonts, so the
# bold face is selected by index rather than by a separate file.
FONT_CANDIDATES = {
    "bold": [
        ("/System/Library/Fonts/SFNSDisplay.ttf", 0),
        ("/System/Library/Fonts/Helvetica.ttc", 1),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 0),
    ],
    "regular": [
        ("/System/Library/Fonts/SFNSText.ttf", 0),
        ("/System/Library/Fonts/Helvetica.ttc", 0),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 0),
    ],
    "mono": [
        ("/System/Library/Fonts/Menlo.ttc", 0),
        ("/System/Library/Fonts/Monaco.ttf", 0),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 0),
    ],
}


def font(kind: str, size: int) -> ImageFont.FreeTypeFont:
    for path, index in FONT_CANDIDATES[kind]:
        if pathlib.Path(path).exists():
            try:
                return ImageFont.truetype(path, size, index=index)
            except OSError:
                continue
    print(f"warning: no {kind} font found; falling back to the PIL default", file=sys.stderr)
    return ImageFont.load_default(size)


def rounded(draw: ImageDraw.ImageDraw, box, radius, **kw) -> None:
    draw.rounded_rectangle(box, radius=radius, **kw)


def mark(draw: ImageDraw.ImageDraw, x: int, y: int, size: int) -> None:
    """The AIROM mark: an 'A' over the evidence baseline, matching favicon.svg."""
    s = size / 32.0
    rounded(draw, (x, y, x + size, y + size), radius=int(7 * s), fill=INDIGO)

    # Outer triangle of the 'A', then the counter punched back out in the
    # background colour — the same two-path construction as the SVG.
    draw.polygon(
        [(x + 16 * s, y + 7 * s), (x + 23 * s, y + 22 * s), (x + 19.6 * s, y + 22 * s),
         (x + 18.3 * s, y + 19.1 * s), (x + 13.7 * s, y + 19.1 * s),
         (x + 12.4 * s, y + 22 * s), (x + 9 * s, y + 22 * s)],
        fill=(255, 255, 255),
    )
    draw.polygon(
        [(x + 14.9 * s, y + 16.4 * s), (x + 17.1 * s, y + 16.4 * s), (x + 16 * s, y + 13.6 * s)],
        fill=INDIGO,
    )
    rounded(
        draw,
        (x + 9 * s, y + 24 * s, x + 23 * s, y + 25.8 * s),
        radius=int(0.9 * s),
        fill=(203, 203, 235),
    )


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # A soft indigo wash behind the headline. One ellipse blurred hard, rather
    # than a stack of translucent ones: stacking leaves a visible seam at the
    # outermost radius, which reads as a hard circular edge on a dark card.
    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse((-260, -170, 900, 770), fill=(79, 70, 229, 46))
    glow = glow.filter(ImageFilter.GaussianBlur(190))
    img = Image.alpha_composite(img.convert("RGBA"), glow).convert("RGB")
    d = ImageDraw.Draw(img)

    pad = 84

    mark(d, pad, pad - 6, 60)
    d.text((pad + 78, pad + 6), "AIROM", font=font("bold", 42), fill=FG)

    d.text(
        (pad, 224),
        "Find the AI in your code,",
        font=font("bold", 68),
        fill=FG,
    )
    d.text(
        (pad, 304),
        "and prove it.",
        font=font("bold", 68),
        fill=FG,
    )

    d.text(
        (pad, 412),
        "An AI Bill of Materials scanner. Every component carries",
        font=font("regular", 27),
        fill=MUTED,
    )
    d.text(
        (pad, 450),
        "the file:line it was seen at.",
        font=font("regular", 27),
        fill=MUTED,
    )

    # Install pill.
    chip = font("mono", 25)
    text = "$ pip install airom"
    tw = d.textlength(text, font=chip)
    box = (pad, 522, pad + tw + 56, 522 + 62)
    rounded(d, box, radius=12, fill=(20, 23, 31), outline=BORDER, width=1)
    d.text((pad + 28, 522 + 17), text, font=chip, fill=ACCENT)

    d.text(
        (W - pad, 556),
        "airom.dev",
        font=font("regular", 25),
        fill=MUTED,
        anchor="rs",
    )

    # A hairline accent along the bottom edge — the "evidence baseline" again.
    d.rectangle((0, H - 6, W, H), fill=INDIGO)

    img.save(OUT, "PNG", optimize=True)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
