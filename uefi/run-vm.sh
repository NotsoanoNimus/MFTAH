#!/usr/bin/env bash
#
#

# Change to proper base-dir (this script's folder).
cd -- "$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd -P )"

EFI_FILE="${1:-build/MFTAH.EFI}"
if [[ ! -f "${EFI_FILE}" ]]; then
    echo "ERROR: EFI file '${EFI_FILE}' does not exist."
    exit 1
fi

mkdir -p hda1/EFI/BOOT/ &>/dev/null
cp -f "${EFI_FILE}" "hda1/EFI/BOOT/BOOTX64.EFI" \
    || { echo "ERROR: Failed to copy EFI file." && exit 1; }

set -euo pipefail

docker build -f Dockerfile.run -t mftah_uefi:latest
docker run -it \
    -v "$(pwd)/hda1:/work/hda1" \
    mftah_uefi:latest
reset

