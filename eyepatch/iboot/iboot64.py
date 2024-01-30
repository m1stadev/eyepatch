from functools import cached_property
from struct import unpack

from capstone.arm64_const import ARM64_INS_MOV, ARM64_INS_MOVK

from eyepatch import AArch64Patcher, errors
from eyepatch.iboot import types
from eyepatch.iboot.errors import InvalidPlatform, InvalidStage


class iBoot64Patcher(AArch64Patcher):
    def __init__(self, data: bytes):
        super().__init__(data)

    @cached_property
    def base(self) -> int:
        ldr = self.search_insn('ldr')
        addr = ldr.offset + ldr.info.operands[-1].imm
        return unpack('<Q', self.data[addr : addr + 8])[0]

    @cached_property
    def build_style(self) -> str:
        # While the build-style string exists in stage 1, it isn't referenced by anything else.
        if self.stage != types.iBootStage.STAGE_2:
            raise InvalidStage('build-style only available on stage 2 iBoot')

        # Find "_sys_setup_default_environment"
        bs_str = self.search_string('build-style')
        xref = self.search_xref(bs_str.offset)
        ssde_bof = xref.function_begin()

        skip = 0
        while True:
            ldr = self.search_insn('ldr', ssde_bof.offset, skip=skip)
            if ldr is None:
                # TODO: Raise error
                return

            if next(ldr) == xref:
                break

            skip += 1

        iboot_offset = ldr.offset + ldr.info.operands[-1].imm
        offset = unpack('<Q', self.data[iboot_offset : iboot_offset + 8])[0]
        return self.search_string(offset=offset - self.base).string

    @cached_property
    def platform(self) -> int:
        plat_str = self.search_string('platform-name')
        xref = self.search_xref(plat_str.offset)
        adr = self.search_insn('adr', xref.offset, skip=1)

        chip_id = self.search_string(offset=adr.offset + adr.info.operands[-1].imm)

        if chip_id.string.startswith('s5l'):
            return int(chip_id.string[3:-1], 16)
        elif chip_id.string.startswith('t') or chip_id.string.startswith('s'):
            return int(chip_id.string[1:], 16)

        raise InvalidPlatform(f'Unknown platform: "{chip_id.string}"')

    @cached_property
    def stage(self) -> types.iBootStage:
        for stage1 in ('iBootStage1', 'iBSS', 'LLB'):
            try:
                self.search_string(f'{stage1} for ')
                return types.iBootStage.STAGE_1
            except errors.SearchError:
                pass

        for stage2 in ('iBootStage2', 'iBEC', 'iBoot'):
            try:
                self.search_string(f'{stage2} for ')
                return types.iBootStage.STAGE_2
            except errors.SearchError:
                pass

    @cached_property
    def version(self) -> types.iBootVersion:
        version_str = self.search_string('iBoot-')
        major, minor, patch = version_str.string[6:].split('.', maxsplit=2)
        return types.iBootVersion(int(major), int(minor), int(patch))

    def patch_freshnonce(self) -> None:
        if self.stage != types.iBootStage.STAGE_2:
            raise InvalidStage('freshnonce patch only available on stage 2 iBoot')

        # Find "platform_get_usb_more_other_string" function
        nonc_str = self.search_string(' NONC:', exact=True)
        nonc_xref = self.search_xref(nonc_str.offset)

        # Find "platform_get_nonce" function
        cbz = self.search_insn('cbz', nonc_xref.offset, reverse=True)
        pgn_func = self.search_insn('bl', cbz.offset).follow_call()

        # Ensure "platform_consume_nonce" always gets called
        insn = self.search_insn('tbnz', pgn_func.offset)
        insn.patch('nop')

    def patch_security_allow_modes(self) -> None:
        # Find "security_allow_modes" function
        dbg_str = self.search_string('debug-enabled')
        dbg_xref = self.search_xref(dbg_str.offset)
        sam_func = self.search_insn('bl', dbg_xref.offset, 1).follow_call()

        # Patch to always return 1
        bne = self.search_insn('b.ne', sam_func.offset)
        bne.patch(f'b #{bne.info.operands[-1].imm}')

        mov = self.search_insn('mov', bne.offset + bne.info.operands[-1].imm)
        mov.patch('mov x0, #0x1')

    def patch_nvram(self):
        if self.stage != types.iBootStage.STAGE_2:
            raise InvalidStage('NVRAM patch only available on stage 2 iBoot')

        # Find "env_blacklist" function
        dbg_str = self.search_string('debug-uarts')
        wl_offset = self.data.find((dbg_str.offset + self.base).to_bytes(0x8, 'little'))
        while True:
            data = self.data[wl_offset : wl_offset + 0x8]
            if unpack('<Q', data)[0] == 0x0:
                wl_offset += 0x8
                break

            wl_offset -= 0x8

        eb_func = self.search_xref(wl_offset).function_begin()
        cbz = self.search_insn('cbz', eb_func.offset)
        cbz.patch(f'b {cbz.info.operands[-1].imm}')

        # Find "env_blacklist_nvram" function
        while True:
            data = self.data[wl_offset : wl_offset + 0x8]
            wl_offset += 0x8
            if unpack('<Q', data)[0] == 0x0:
                break

        ebn_func = self.search_xref(wl_offset).function_begin()
        beq = self.search_insn('b.eq', ebn_func.offset)
        beq.patch(f'b {beq.info.operands[-1].imm}')

        # Find "hide_key" function
        cas_str = self.search_string('com.apple.System.', exact=True)
        hk_func = self.search_xref(cas_str.offset).function_begin()
        bl = self.search_insn('bl', hk_func.offset)
        bl.patch('mov x0, #0x1')

    def patch_sigchecks(self):
        # Find "image4_validate_property_callback" function
        disasm = self.disasm(0x0)
        while True:
            mov = next(disasm)
            if mov.info.mnemonic != 'mov':
                continue

            if (movk := next(disasm)).info.mnemonic != 'movk':
                continue

            if mov.info.operands[-1].imm == 0x4348:
                bnch = (movk.info.operands[-1].imm << 16) | mov.info.operands[-1].imm
            elif mov.info.operands[-1].imm == 0x424E0000:
                bnch = mov.info.operands[-1].imm | movk.info.operands[-1].imm
            else:
                continue

            if bnch == int.from_bytes(b'BNCH', 'big'):
                ivpc_func = mov.function_begin()
                break

        # Patch to always return 0
        ivpc_ret = self.search_insn('ret', ivpc_func.offset)

        for mov_reg in ('x0', 'w0'):
            try:
                branch_to = self.search_insns(f'mov {mov_reg}, #0', 'ret')
                break
            except errors.SearchError:
                pass

        else:
            # Failed to find "mov x0/w0, #0" and "ret" instructions, search for nops we can overwrite
            try:
                branch_to = self.search_insns('nop', 'nop')
                branch_to.patch('mov w0, #0')
                next(branch_to).patch('ret')
            except errors.SearchError:
                # There's somehow not 2 nops that we can overwrite???
                # TODO: Raise error
                return

        ivpc_ret.patch(f'b #{hex(branch_to.offset - ivpc_ret.offset)}')
