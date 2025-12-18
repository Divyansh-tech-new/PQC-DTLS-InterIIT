#!/usr/bin/env python3

from litex.build.sim import SimPlatform
from litex.soc.integration.soc_core import SoCCore
from litex.soc.integration.builder import Builder
from litex.soc.cores.cpu.vexriscv import VexRiscv
from litex.soc.cores.clock import SimClock
from litespi.modules import W25Q64JV
from liteeth.common import convert_ip

class EthernetSoC(SoCCore):
    def __init__(self):
        platform = SimPlatform("LITEX_SIM", io=[])
        sys_clk_freq = int(1e6)

        SoCCore.__init__(self, platform,
            clk_freq=sys_clk_freq,
            cpu_type="vexriscv",
            integrated_rom_size=0x20000,  # 128 KB
            integrated_sram_size=0x2000,  # 8 KB
            integrated_main_ram_size=0x6400000  # 100MB
        )

        # Add Ethernet w/TAP
        self.add_ethernet(
            phy="tap",
            ip_address="192.168.1.50",
            mac_address=0x10e2d5000001
        )

def main():
    soc = EthernetSoC()
    builder = Builder(soc, output_dir="build_ethernet")
    builder.build(build_sim=True,
                  sim_config={"ethernet": True})

if __name__ == "__main__":
    main()

