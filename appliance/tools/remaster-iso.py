#!/usr/bin/python3
"""Use Lorax configuration editing with explicit AlmaLinux 10 GRUB boot records.

The distribution's xorriso cannot replay the ISO's non-file EFI boot entry.
Reconstruct the documented GRUB BIOS entry and new appended EFI entry instead
of ignoring xorriso's error. This adapter targets AlmaLinux 10 x86-64 media.
"""
import os
from pathlib import Path
import runpy
import subprocess

original = subprocess.run
branding = runpy.run_path(str(Path(__file__).with_name('installer-branding.py')))


def brand(path):
    path = Path(path)
    if path.name in ('grub.cfg', 'BOOT.conf'):
        path.write_text(branding['brand_grub'](path.read_text(),
                                              os.environ.get('RIVERLB_INSTALL_MODE', 'installer')))


def run(command, *args, **kwargs):
    if isinstance(command, list) and command and Path(command[0]).name == 'mkefiboot':
        # Lorax copies edited EFI files before calling this tool. Brand that
        # copy before FAT creation so firmware sees the same menu as the ISO.
        for argument in command[1:]:
            candidate = Path(argument)
            if candidate.is_dir() and candidate.name == 'BOOT':
                for name in ('grub.cfg', 'BOOT.conf'):
                    if candidate.joinpath(name).is_file():
                        brand(candidate / name)
    if isinstance(command, list) and command and command[0] == 'xorriso' and '-append_partition' in command:
        command = list(command)
        for index, argument in enumerate(command[:-2]):
            if argument == '-update':
                brand(command[index + 1])
        index = command.index('-boot_image')
        if command[index:index + 3] != ['-boot_image', 'any', 'replay']:
            raise RuntimeError('Unexpected Lorax boot arguments; review tool compatibility')
        iso = command[command.index('-indev') + 1]
        command[index:index + 3] = [
            '-boot_image', 'any', 'discard',
            '-boot_image', 'grub', 'grub2_mbr=--interval:imported_iso:0s-15s:zero_mbrpt,zero_gpt:' + iso,
            '-boot_image', 'any', 'partition_table=on',
            '-boot_image', 'any', 'partition_cyl_align=off',
            '-boot_image', 'any', 'cat_hidden=on',
            '-boot_image', 'grub', 'bin_path=/images/eltorito.img',
            '-boot_image', 'any', 'emul_type=no_emulation',
            '-boot_image', 'any', 'load_size=2048',
            '-boot_image', 'any', 'boot_info_table=on',
            '-boot_image', 'grub', 'grub2_boot_info=on',
        ]
        index = command.index('-append_partition') + 4
        command[index:index] = [
            '-boot_image', 'any', 'next',
            '-boot_image', 'any', 'efi_path=--interval:appended_partition_2:all::',
            '-boot_image', 'any', 'emul_type=no_emulation',
        ]
    return original(command, *args, **kwargs)


if __name__ == '__main__':
    subprocess.run = run
    runpy.run_path('/usr/bin/mkksiso', run_name='__main__')
