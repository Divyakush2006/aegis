"""Draw the Prahari shield as a desktop application icon.

The browser application only ever needed a 64-pixel favicon. A desktop
application is shown much larger and in more places -- the taskbar, the window
frame, Alt+Tab, the shortcut on disk -- and Windows picks a different size for
each, so the icon is drawn once here and written as a multi-resolution `.ico`
plus a 512-pixel `.png` for platforms that want one.

The mark is drawn from geometry rather than scaled up from the favicon: an
upscaled 64-pixel bitmap is visibly soft at 256. It is drawn on a large canvas
and reduced with LANCZOS so the small sizes stay legible.

The output is committed, so this script is only run when the mark changes:

    python scripts/make-app-icon.py

Requires Pillow. Nothing in the build or the application depends on it.
"""

from __future__ import annotations

import pathlib

from PIL import Image, ImageDraw

# The palette is the favicon's, so the two marks are the same mark.
BLUE = (37, 99, 235, 255)
NAVY = (30, 58, 138, 255)
WHITE = (255, 255, 255, 255)

CANVAS = 2048
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)

RESOURCES = pathlib.Path(__file__).resolve().parent.parent / "electron-app" / "resources"


def _bezier(points, steps=160):
    """Sample a cubic Bezier, used for the shield's lower curve."""
    (x0, y0), (x1, y1), (x2, y2), (x3, y3) = points
    sampled = []
    for step in range(steps + 1):
        t = step / steps
        u = 1 - t
        a, b, c, d = u * u * u, 3 * u * u * t, 3 * u * t * t, t * t * t
        sampled.append((a * x0 + b * x1 + c * x2 + d * x3, a * y0 + b * y1 + c * y2 + d * y3))
    return sampled


def shield(inset: float) -> list[tuple[float, float]]:
    """The shield outline, inset from the canvas edge by `inset` pixels.

    A flat top with rounded corners, straight shoulders, then both sides curving
    into a point at the bottom -- the shape the favicon already uses.
    """
    left = 0.11 * CANVAS + inset
    right = 0.89 * CANVAS - inset
    top = 0.07 * CANVAS + inset
    bottom = 0.95 * CANVAS - inset * 1.6
    centre = CANVAS / 2
    radius = 0.06 * CANVAS
    shoulder = top + 0.46 * (bottom - top)

    outline: list[tuple[float, float]] = [(left + radius, top), (right - radius, top)]
    # Rounded top-right corner.
    outline += _bezier(
        [(right - radius, top), (right - radius / 2, top), (right, top + radius / 2), (right, top + radius)],
        steps=24,
    )
    outline.append((right, shoulder))
    # Right side sweeping into the point.
    outline += _bezier([(right, shoulder), (right, bottom - 0.18 * CANVAS), (centre + 0.16 * CANVAS, bottom - 0.06 * CANVAS), (centre, bottom)])
    # Left side, mirrored, back up to the shoulder.
    outline += _bezier([(centre, bottom), (centre - 0.16 * CANVAS, bottom - 0.06 * CANVAS), (left, bottom - 0.18 * CANVAS), (left, shoulder)])
    outline.append((left, top + radius))
    # Rounded top-left corner.
    outline += _bezier(
        [(left, top + radius), (left, top + radius / 2), (left + radius / 2, top), (left + radius, top)],
        steps=24,
    )
    return outline


def check(draw: ImageDraw.ImageDraw) -> None:
    """The white check inside the shield."""
    stroke = round(0.085 * CANVAS)
    points = [
        (0.30 * CANVAS, 0.52 * CANVAS),
        (0.435 * CANVAS, 0.655 * CANVAS),
        (0.715 * CANVAS, 0.335 * CANVAS),
    ]
    draw.line(points, fill=WHITE, width=stroke, joint="curve")
    # `joint="curve"` rounds the elbow but leaves the two ends square.
    for point in (points[0], points[-1]):
        draw.ellipse(
            [point[0] - stroke / 2, point[1] - stroke / 2, point[0] + stroke / 2, point[1] + stroke / 2],
            fill=WHITE,
        )


def render() -> Image.Image:
    image = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.polygon(shield(0), fill=BLUE)
    draw.polygon(shield(0.055 * CANVAS), fill=NAVY)
    check(draw)
    return image


def main() -> None:
    RESOURCES.mkdir(parents=True, exist_ok=True)
    art = render()

    # Reduce in one LANCZOS step per size rather than letting the ICO writer
    # resample from the full canvas, which loses the check's thin end at 16px.
    frames = [art.resize((size, size), Image.LANCZOS) for size in ICO_SIZES]
    ico = RESOURCES / "prahari.ico"
    frames[-1].save(ico, format="ICO", sizes=[(size, size) for size in ICO_SIZES], append_images=frames[:-1])

    png = RESOURCES / "prahari.png"
    art.resize((512, 512), Image.LANCZOS).save(png, format="PNG", optimize=True)

    for path in (ico, png):
        print(f"wrote {path.relative_to(RESOURCES.parent.parent)} ({path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
