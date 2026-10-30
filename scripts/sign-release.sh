#!/bin/sh
# Prints the minisign command for the release signer to run by hand. It never reads, opens or asks for a key.
# Usage: scripts/sign-release.sh path/to/ArrowMem.AppImage
set -u
if [ "$#" -ne 1 ]; then
  echo "usage: sign-release.sh PATH_TO_APPIMAGE" >&2
  exit 2
fi
echo "Run this yourself, with your own secret key:"
echo "  minisign -S -s <PATH-TO-YOUR-SECRET-KEY> -m '$1' -x '$1.minisig'"
echo "Then verify with the release public key D8844FE7C32F5422, using the copy published on arrowmem.ca saved as ~/arrowmem-release.pub (never the repo copy):"
echo "  minisign -V -p ~/arrowmem-release.pub -m '$1' -x '$1.minisig'"
