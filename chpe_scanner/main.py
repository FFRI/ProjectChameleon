# (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
import os
from enum import Enum
from pathlib import Path
from typing import Optional

import lief
import typer

app = typer.Typer()


class BinType(Enum):
    CHPE = 1
    CHPEV2_ARM64EC = 2
    CHPEV2_ARM64X = 3
    ARM64 = 4
    AMD64 = 5
    I386 = 6
    ARM = 7
    ARMNT = 8
    THUMB = 9

    @staticmethod
    def is_chpe_type(bin_type: "BinType") -> bool:
        return (
            (bin_type == BinType.CHPE)
            | (bin_type == BinType.CHPEV2_ARM64EC)
            | (bin_type == BinType.CHPEV2_ARM64X)
        )

    @staticmethod
    def has_metadata_pointer(load_config: lief.PE.LoadConfiguration) -> bool:
        return type(load_config) == lief.PE.LoadConfigurationV4 or issubclass(type(load_config), lief.PE.LoadConfigurationV4)

    @staticmethod
    def get_chpe_bintype(bin_: lief.PE) -> "BinType":
        if (
            not bin_.has_configuration
            or (not BinType.has_metadata_pointer(bin_.load_configuration))
            or bin_.load_configuration.hybrid_metadata_pointer == 0
        ):
            if bin_.header.machine == lief.PE.MACHINE_TYPES.ARM64:
                return BinType.ARM64
            elif bin_.header.machine == lief.PE.MACHINE_TYPES.AMD64:
                return BinType.AMD64
            elif bin_.header.machine == lief.PE.MACHINE_TYPES.I386:
                return BinType.I386
            elif bin_.header.machine == lief.PE.MACHINE_TYPES.ARM:
                return BinType.ARM
            elif bin_.header.machine == lief.PE.MACHINE_TYPES.ARMNT:
                return BinType.ARMNT
            elif bin_.header.machine == lief.PE.MACHINE_TYPES.THUMB:
                return BinType.THUMB
            else:
                raise RuntimeError(f"{bin_.name} has an unknown machine type")

        if bin_.header.machine == lief.PE.MACHINE_TYPES.ARM64:
            return BinType.CHPEV2_ARM64X
        elif bin_.header.machine == lief.PE.MACHINE_TYPES.AMD64:
            return BinType.CHPEV2_ARM64EC
        elif bin_.header.machine == lief.PE.MACHINE_TYPES.I386:
            return BinType.CHPE
        else:
            raise RuntimeError(f"{bin_.name} is unknown CHPE")


def check_chpe_type(path: str) -> Optional[BinType]:
    if not os.path.exists(path):
        raise RuntimeError(f"{path} is not found")
    try:
        return BinType.get_chpe_bintype(lief.PE.parse(path))
    except Exception as e:
        typer.secho(str(e), err=True, fg=typer.colors.RED)
        return None


@app.command()
def scan(system_root: str) -> None:
    path_root = Path(system_root)
    if not path_root.exists():
        typer.secho(f"{system_root} does not exist", err=True, fg=typer.colors.RED)
        return
    with open("chpe_list.csv", "w") as fout0, open("non_chpe_list.csv", "w") as fout1:
        for path_name, _, file_names in os.walk(system_root):
            for file_name in file_names:
                full_path = os.path.join(path_name, file_name)
                if not (full_path.endswith(".dll") or full_path.endswith(".exe")):
                    continue
                bin_type = check_chpe_type(full_path)
                if BinType.is_chpe_type(bin_type):
                    typer.echo(full_path)
                    fout0.write(full_path + "," + f"{str(bin_type)}" + "\n")
                else:
                    fout1.write(full_path + "," + f"{str(bin_type)}" "\n")


if __name__ == "__main__":
    app()
