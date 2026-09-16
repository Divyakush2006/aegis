"""Draw the Prahari logo and write every form the applications need.

The mark is a sentinel's shield carrying the thing that makes this project what
it is: a dataflow path. Two nodes joined by one link run from the top-left to
the bottom-right -- source, then sink -- and the sink is amber, because reaching
it is what a finding *is*. It is the findings panel's trace, reduced to a logo.

Two nodes rather than three on purpose. A three-node path reads well at 32px and
smears into a diagonal streak at 16px, where a taskbar actually draws it, and a
mark that needs a different shape at each size is too busy to be a mark. Two
large nodes survive every size from 16px to 512px unchanged.

One geometry, two renderers. The shape is described once as path segments, then
emitted as SVG (for the in-application logo, embedded in CSS so no bundler has
to resolve a URL) and rasterised with Pillow (for the Windows icon and the
favicons). They cannot drift apart.

Outputs, all committed:

    electron-app/resources/prahari.ico    the desktop application and its shortcut
    electron-app/resources/prahari.png    512px, for platforms wanting a PNG
    browser-app/resources/favicon.ico     the browser tab
    browser-app/resources/favicon.png     64px
    prahari-ide/src/browser/style/logo.css  the top-left logo, in both applications

Run after changing the mark:

    python scripts/make-app-icon.py

Requires Pillow. Nothing in the build or the applications depends on it.
"""

from __future__ import annotations

import base64
import pathlib

from PIL import Image, ImageDraw

# -- palette ------------------------------------------------------------------
# Blue carries over from the first mark; amber is new, and marks the sink.
BLUE = (37, 99, 235, 255)      # #2563EB  shield edge
NAVY = (30, 58, 138, 255)      # #1E3A8A  shield field
WHITE = (255, 255, 255, 255)
AMBER = (245, 158, 11, 255)    # #F59E0B  the sink node

SVG_BLUE, SVG_NAVY, SVG_WHITE, SVG_AMBER = "#2563EB", "#1E3A8A", "#FFFFFF", "#F59E0B"

# -- geometry -----------------------------------------------------------------
# A 100x100 space, scaled by each renderer.
NODES = ((36, 35), (64, 63))
NODE_RADIUS = 9.5
LINK_WIDTH = 8.0

IDE = pathlib.Path(__file__).resolve().parent.parent


def shield(left: float, right: float, top: float, bottom: float, radius: float) -> list[tuple]:
    """Shield outline: flat top with rounded corners, shoulders, then a point.

    Returned as drawing operations -- ('L', point) and ('C', c1, c2, point) --
    so both renderers consume the same description.
    """
    centre = (left + right) / 2
    shoulder = top + 0.46 * (bottom - top)
    waist = bottom - 0.21 * (bottom - top)
    reach = 0.42 * (right - left)
    return [
        ("M", (left + radius, top)),
        ("L", (right - radius, top)),
        ("C", (right - radius / 2, top), (right, top + radius / 2), (right, top + radius)),
        ("L", (right, shoulder)),
        ("C", (right, waist), (centre + reach, bottom - 0.07 * (bottom - top)), (centre, bottom)),
        ("C", (centre - reach, bottom - 0.07 * (bottom - top)), (left, waist), (left, shoulder)),
        ("L", (left, top + radius)),
        ("C", (left, top + radius / 2), (left + radius / 2, top), (left + radius, top)),
        ("Z",),
    ]


OUTER = shield(11, 89, 8, 95, 6)
INNER = shield(16.5, 83.5, 13.5, 86.5, 5)


def to_svg_path(ops: list[tuple]) -> str:
    out = []
    for op in ops:
        if op[0] == "Z":
            out.append("Z")
        elif op[0] == "C":
            (x1, y1), (x2, y2), (x, y) = op[1], op[2], op[3]
            out.append(f"C{x1:.2f} {y1:.2f} {x2:.2f} {y2:.2f} {x:.2f} {y:.2f}")
        else:
            x, y = op[1]
            out.append(f"{op[0]}{x:.2f} {y:.2f}")
    return "".join(out)


def to_points(ops: list[tuple], scale: float, steps: int = 48) -> list[tuple[float, float]]:
    """Flatten the path to a polygon, for a rasteriser that has no curves."""
    points: list[tuple[float, float]] = []
    current = (0.0, 0.0)
    for op in ops:
        if op[0] == "M" or op[0] == "L":
            current = op[1]
            points.append(current)
        elif op[0] == "C":
            (x0, y0), (x1, y1), (x2, y2), (x3, y3) = current, op[1], op[2], op[3]
            for step in range(1, steps + 1):
                t = step / steps
                u = 1 - t
                a, b, c, d = u * u * u, 3 * u * u * t, 3 * u * t * t, t * t * t
                points.append((a * x0 + b * x1 + c * x2 + d * x3, a * y0 + b * y1 + c * y2 + d * y3))
            current = op[3]
    return [(x * scale, y * scale) for x, y in points]


# -- SVG ----------------------------------------------------------------------

def svg() -> str:
    links = " ".join(f"{x},{y}" for x, y in NODES)
    circles = "".join(
        f'<circle cx="{x}" cy="{y}" r="{NODE_RADIUS}" fill="{SVG_AMBER if index == len(NODES) - 1 else SVG_WHITE}"/>'
        for index, (x, y) in enumerate(NODES)
    )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
        f'<path d="{to_svg_path(OUTER)}" fill="{SVG_BLUE}"/>'
        f'<path d="{to_svg_path(INNER)}" fill="{SVG_NAVY}"/>'
        f'<polyline points="{links}" fill="none" stroke="{SVG_WHITE}" '
        f'stroke-width="{LINK_WIDTH}" stroke-linecap="round" stroke-linejoin="round"/>'
        f"{circles}"
        "</svg>"
    )


# -- raster -------------------------------------------------------------------

def render(size: int) -> Image.Image:
    """Draw at 8x and reduce, so the small sizes keep clean edges."""
    scale = size * 8 / 100
    canvas = size * 8
    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.polygon(to_points(OUTER, scale), fill=BLUE)
    draw.polygon(to_points(INNER, scale), fill=NAVY)

    draw.line([(x * scale, y * scale) for x, y in NODES], fill=WHITE,
              width=round(LINK_WIDTH * scale), joint="curve")
    for index, (x, y) in enumerate(NODES):
        radius = NODE_RADIUS * scale
        draw.ellipse(
            [x * scale - radius, y * scale - radius, x * scale + radius, y * scale + radius],
            fill=AMBER if index == len(NODES) - 1 else WHITE,
        )
    return image.resize((size, size), Image.LANCZOS)


def write_icon(path: pathlib.Path, sizes: tuple[int, ...]) -> None:
    frames = [render(size) for size in sizes]
    frames[-1].save(path, format="ICO", sizes=[(s, s) for s in sizes], append_images=frames[:-1])


def main() -> None:
    electron = IDE / "electron-app" / "resources"
    browser = IDE / "browser-app" / "resources"
    style = IDE / "prahari-ide" / "src" / "browser" / "style"
    for directory in (electron, browser, style):
        directory.mkdir(parents=True, exist_ok=True)

    written: list[pathlib.Path] = []

    write_icon(electron / "prahari.ico", (16, 24, 32, 48, 64, 128, 256))
    render(512).save(electron / "prahari.png", format="PNG", optimize=True)
    written += [electron / "prahari.ico", electron / "prahari.png"]

    write_icon(browser / "favicon.ico", (16, 24, 32, 48, 64))
    render(64).save(browser / "favicon.png", format="PNG", optimize=True)
    written += [browser / "favicon.ico", browser / "favicon.png"]

    # The logo sits in the slot Theia already puts at the far left of the menu
    # bar (`BrowserMenuBarContribution.appendMenu` creates it, and the Electron
    # custom title bar inherits that), so it needs styling rather than a widget.
    # The SVG is inlined: a bundler never has to resolve a URL, and the file
    # stays one self-contained rule.
    encoded = base64.b64encode(svg().encode()).decode()
    css = f"""/* Generated by scripts/make-app-icon.py -- do not edit by hand. */

/*
 * The Prahari logo, top left, in both the desktop and browser applications.
 *
 * Theia creates an empty widget (id `theia:icon`, class `theia-icon`) as the
 * first child of the top panel and leaves it unstyled; this fills it. The
 * Electron custom title bar uses the same slot, so one rule covers both.
 */
.theia-icon {{
    width: 32px;
    min-width: 32px;
    height: 100%;
    background-image: url("data:image/svg+xml;base64,{encoded}");
    background-repeat: no-repeat;
    background-position: center;
    background-size: 19px 19px;
    flex: 0 0 auto;
    -webkit-app-region: drag;
}}
"""
    (style / "logo.css").write_text(css, encoding="utf-8")
    written.append(style / "logo.css")

    for path in written:
        print(f"  {path.relative_to(IDE)}  ({path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
