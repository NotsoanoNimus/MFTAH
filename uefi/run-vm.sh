#!/usr/bin/env bash
#
#

# Change to proper base-dir (this script's folder).
cd -- "$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd -P )"

EFI_FILE="${1:-build/MFTAH.EFI}"
MFTAH_CFG="${2:-mftah.cfg}"

if [[ ! -f "${EFI_FILE}" ]]; then
    echo "ERROR: EFI file '${EFI_FILE}' does not exist."
    exit 1
elif [[ ! -f "${MFTAH_CFG}" ]]; then
    echo "ERROR: MFTAH configuration '${MFTAH_CFG}' does not exist."
    exit 1
fi

mkdir -p hda1/EFI/BOOT/ &>/dev/null
cp -f "${EFI_FILE}" "hda1/EFI/BOOT/BOOTX64.EFI" \
    || { echo "ERROR: Failed to copy EFI file." && exit 1; }
cp -f "${MFTAH_CFG}" "hda1/EFI/BOOT/MFTAH.CFG" \
    || { echo "ERROR: Failed to copy MFTAH configuration." && exit 1; }

set -euo pipefail

docker build -f Dockerfile.run -t mftah_uefi:latest .
docker run -it \
    -v "$(pwd)/hda1:/work/hda1" \
    -v "$(pwd)/logs:/work/logs" \
    mftah_uefi:latest
reset

