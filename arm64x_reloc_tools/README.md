# ARM64X relocation tools

["ARM64X is the resulting binary from linking ARM64 and ARM64EC objs and libs into one."](https://twitter.com/never_released/status/1371546800067346441)
It can be used by multiple processes (ARM64 native processes, ARM64EC processes, and x64 emulation processes) like a fat binary.
If you are not familiar with ARM64X, please check [our blog post](https://ffri.github.io/ProjectChameleon/new_reloc_chpev2/) for more details.

This directory contains [a simple python script](main.py) that:

- [Shows `IMAGE_DYNAMIC_RELOCATION_ARM64X` entries in an ARM64X binary](#show-command)
- [Applies `IMAGE_DYNAMIC_RELOCATION_ARM64X` to an ARM64X binary and save it as a file](#apply-command)
- [Modifies `IMAGE_DYNAMIC_RELOCATION_ARM64X` entries to inject arm64 (or x64) shellcode into an ARM64X binary at runtime.](#inject-command)

## Requirements

- Python 3.8
- [Poetry](https://python-poetry.org/)

## Usage

First, you need to resolve dependencies as follows.

```
$ poetry install
```

Then, you can use three commands.

### `show` command

This command shows `IMAGE_DYNAMIC_RELOCATION_ARM64X` entries and save its result as a JSON file.

```
$ poetry run python main.py show data/ChameleonPacker.exe
CHPE fixup is exported to chpe_fixup.json
$ cat chpe_fixup.json | head -n 30
{
        "header": {
                "version": 1,
                "size": 556,
                "symbol": 6,
                "fixup_info_size": 544
        },
        "blocks": [
                {
                        "base_offset": 0,
                        "block_size": 44,
                        "entries": [
                                {
                                        "meta_and_offset": 20724,
                                        "meta": 5,
                                        "offset": 244,
                                        "reloc_entry_data_size": 2,
                                        "size_to_be_written": 2,
                                        "reloc_type": "ASSIGN_VALUE",
                                        "data_to_be_written": 34404
                                },
                                {
                                        "meta_and_offset": 37144,
                                        "meta": 9,
                                        "offset": 280,
                                        "reloc_entry_data_size": 4,
                                        "size_to_be_written": 4,
                                        "reloc_type": "ASSIGN_VALUE",
                                        "data_to_be_written": 36864
                                },
```

### `apply` command

This command applies `IMAGE_DYNAMIC_RELOCATION_ARM64X` to an ARM64X binary and saves its result as a PE file.

```
$ poetry run python main.py apply data/ChameleonPacker.exe
Patched binary is export to ChameleonPacker.exe_mod
Completed
$ file data/ChameleonPacker.exe
data/ChameleonPacker.exe: PE32+ executable (console) Aarch64, for MS Windows
$ file ChameleonPacker.exe_mod
ChameleonPacker.exe_mod: PE32+ executable (console) x86-64, for MS Windows
```

### `inject` command

This command injects shellcode into an ARM64X binary as `IMAGE_DYNAMIC_RELOCATION_ARM64X` relocation entries.
You can use this command to create a packed binary by `IMAGE_DYNAMIC_RELOCATION_ARM64X`.

```
$ poetry run python main.py inject --help
Usage: main.py inject [OPTIONS] SHELLCODE_PATH INPUT_EXE ARCH:[arm64|x64]
                      [SHELLCODE_ENTRY_OFFSET_HEX] [INJECT_POINT_RVA_HEX]

Arguments:
  SHELLCODE_PATH                [required]
  INPUT_EXE                     [required]
  ARCH:[arm64|x64]              [required]
  [SHELLCODE_ENTRY_OFFSET_HEX]  [default: 0x00]
  [INJECT_POINT_RVA_HEX]
$ poetry run python main.py inject ./data/shellcodex64.bin ./data/ChameleonPacker.exe x64 0x1E0 0x7000
Injection point is set to 0x7000
Load shellcode from ./data/shellcodex64.bin
Convert CHPE fixup entry to raw data
Inject shellcode
Patch entrypoint
rva of x64 entrypoint is 0x2490
Overwrite Hybrid Code Map
Expand relocation section & clear existing relocation entries
Export CHPE fixup header
Export CHPE fixup blocks
Patched binary is export to ChameleonPacker.exe_mod
```

## Author

Koh M. Nakagawa. &copy; FFRI Security, Inc. 2021
