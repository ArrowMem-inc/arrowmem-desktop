"""Builds the desktop icons from the ArrowMem mark WITHOUT redrawing it.

The mark is the frontend's own file, copied byte for byte into packaging/icons/arrowmem-mark-source.svg (src/theme/arrowmem-mark.svg of web-frontend, commit
165e89e7, sha256 pinned below): one evenodd path, black, viewBox "68 95 793 842". This script takes its `d` attribute verbatim, places it unchanged (only a
uniform scale and a shift, no change of the shape) on a rounded square tile, and writes:

  packaging/icons/arrowmem-desktop.svg                      the scalable icon (installed as hicolor/scalable/apps/arrowmem-desktop.svg)
  packaging/icons/arrowmem-desktop-{48,128,256}.png         hicolor sizes
  src-tauri/icons/32x32.png and icon.png (128)              the window and tray icons the app embeds

TILE (the chosen design): a dark green rounded square (#14231c) behind the white mark. The tile colour and the padding are the only
design choices here (BG, PAD below); the designer can change them in one line. Needs rsvg-convert. The generated files are committed, so a package build needs no tool.
Usage: python3 scripts/make-icons.py
"""
import hashlib
import os
import re
import subprocess
import sys

SOURCE_SHA256 = "cd8a2429b47adaa6b4b7709905c4e4286c7f42ecc5ec2b858b78ef12154932e1"
BG = "#14231c"
PAD = 30  # of 256
RADIUS = 56  # of 256

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
src = open(os.path.join(root, "packaging/icons/arrowmem-mark-source.svg"), "rb").read()
if hashlib.sha256(src).hexdigest() != SOURCE_SHA256:
    sys.exit("the mark source is not the pinned file")
text = src.decode("utf-8")
vb = re.search(r'viewBox="([\d.\s-]+)"', text).group(1).split()
vx, vy, vw, vh = [float(x) for x in vb]
d = re.search(r'<path[^>]*\sd="([^"]+)"', text).group(1)
inner = 256 - 2 * PAD
s = min(inner / vw, inner / vh)
tx = (256 - vw * s) / 2 - vx * s
ty = (256 - vh * s) / 2 - vy * s
svg = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256" role="img" aria-label="ArrowMem">\n'
    '  <title>ArrowMem</title>\n'
    '  <rect width="256" height="256" rx="%d" fill="%s"/>\n'
    '  <path transform="translate(%.4f %.4f) scale(%.6f)" fill="#ffffff" fill-rule="evenodd" d="%s"/>\n'
    '</svg>\n' % (RADIUS, BG, tx, ty, s, d)
)
out = os.path.join(root, "packaging/icons/arrowmem-desktop.svg")
open(out, "w").write(svg)
for size, dest in ((48, "packaging/icons/arrowmem-desktop-48.png"), (128, "packaging/icons/arrowmem-desktop-128.png"), (256, "packaging/icons/arrowmem-desktop-256.png"),
                   (32, "src-tauri/icons/32x32.png"), (128, "src-tauri/icons/icon.png")):
    subprocess.check_call(["rsvg-convert", "-w", str(size), "-h", str(size), out, "-o", os.path.join(root, dest)])
    print("wrote", dest)
