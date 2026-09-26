#!/usr/bin/env bash
# Build the firmware and deliver it to the device's SD card, ready for
# Settings → SD card firmware update on the reader.
#
# Usage: ./scripts/build_and_flash.sh [--sd [VOLUME] | --wifi [HOST] | --usb] [ENV]
#
#   ENV            PlatformIO env to build (default: x4pro).
#   --sd [VOLUME]  Copy firmware.bin to the root of a mounted SD card, then eject it.
#                  VOLUME defaults to the first /Volumes/* containing a .crosspoint folder.
#   --wifi [HOST]  Upload firmware.bin over Wi-Fi. Put the reader in File Transfer mode first.
#                  HOST defaults to $CROSSPOINT_HOST, else crosspoint.local.
#   --usb          Legacy: flash over USB and open the serial monitor (USB-unlocked devices only).
#
# With no mode flag: --sd if a CrossPoint SD card is mounted, otherwise --wifi.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

MODE=""
TARGET=""
ENV="x4pro"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sd | --wifi)
      MODE="${1#--}"
      # Optional value: a directory for --sd, a host/IP (has a dot or colon) for --wifi.
      # Anything else is left for the ENV positional.
      if [[ $# -gt 1 && "$2" != -* && ( ("$MODE" == "sd" && -d "$2") || ("$MODE" == "wifi" && "$2" == *[.:]*) ) ]]; then
        TARGET="$2"
        shift
      fi
      ;;
    --usb) MODE="usb" ;;
    -h | --help)
      sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
    *) ENV="$1" ;;
  esac
  shift
done

find_sd_volume() {
  local vol
  for vol in /Volumes/*; do
    [[ -d "$vol/.crosspoint" ]] && { echo "$vol"; return 0; }
  done
  return 1
}

if [[ -z "$MODE" ]]; then
  if TARGET="$(find_sd_volume)"; then MODE="sd"; else MODE="wifi"; TARGET=""; fi
fi

echo "==> Building firmware (env: $ENV)..."
pio run -e "$ENV"
FIRMWARE=".pio/build/$ENV/firmware.bin"
[[ -f "$FIRMWARE" ]] || { echo "Build output not found: $FIRMWARE" >&2; exit 1; }
echo "    $FIRMWARE ($(du -h "$FIRMWARE" | cut -f1 | tr -d ' '))"
echo ""

case "$MODE" in
  sd)
    if [[ -z "$TARGET" ]]; then
      TARGET="$(find_sd_volume)" || {
        echo "No CrossPoint SD card found under /Volumes (looked for a .crosspoint folder)." >&2
        echo "Insert the card, or pass the volume: --sd /Volumes/NAME" >&2
        exit 1
      }
    fi
    echo "==> Copying firmware.bin to SD card ($TARGET)..."
    cp "$FIRMWARE" "$TARGET/firmware.bin"
    # macOS litters FAT volumes with AppleDouble files; drop the one for the firmware.
    rm -f "$TARGET/._firmware.bin"
    sync
    echo "==> Ejecting $TARGET..."
    diskutil eject "$TARGET" >/dev/null
    echo ""
    echo "Done. Put the card back in the reader, then Settings → System → SD card firmware update → firmware.bin."
    ;;

  wifi)
    HOST="${TARGET:-${CROSSPOINT_HOST:-crosspoint.local}}"
    echo "==> Checking reader at http://$HOST ..."
    if ! curl -fsS --max-time 5 "http://$HOST/api/status" >/dev/null; then
      echo "Reader not reachable at $HOST." >&2
      echo "On the reader: File Transfer → join Wi-Fi, keep the screen open. If mDNS fails," >&2
      echo "pass the IP shown on screen: --wifi 192.168.x.y" >&2
      exit 1
    fi
    echo "==> Uploading firmware.bin over Wi-Fi..."
    RESPONSE="$(curl -fsS --max-time 600 -F "file=@$FIRMWARE;filename=firmware.bin" "http://$HOST/upload?path=/")"
    if [[ "$RESPONSE" != *"uploaded successfully"* ]]; then
      echo "Upload failed: $RESPONSE" >&2
      exit 1
    fi
    echo ""
    echo "Done. On the reader: exit File Transfer, then Settings → System → SD card firmware update → firmware.bin."
    ;;

  usb)
    echo "==> Uploading to device over USB (env: $ENV)..."
    pio run -e "$ENV" -t upload
    echo ""
    echo "==> Launching serial monitor..."
    "$HOME/.local/pipx/venvs/platformio/bin/python" scripts/debugging_monitor.py
    ;;
esac
