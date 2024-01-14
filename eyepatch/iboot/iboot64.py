from functools import cached_property
from struct import unpack

from capstone.arm64_const import ARM64_INS_MOV, ARM64_INS_MOVK

from eyepatch import AArch64Patcher
from eyepatch.iboot import errors, iBootStage, iBootVersion


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
        if self.stage != iBootStage.STAGE_2:  # noqa: F405
            raise errors.InvalidStage('build-style only available on stage 2 iBoot')

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

        raise errors.InvalidPlatform(f'Unknown platform: "{chip_id.string}"')

    @cached_property
    def stage(self) -> iBootStage:
        for stage1 in ('iBootStage1', 'iBSS', 'LLB'):
            if self.search_string(f'{stage1} for ') is not None:
                return iBootStage.STAGE_1

        for stage2 in ('iBootStage2', 'iBEC', 'iBoot'):
            if self.search_string(f'{stage2} for ') is not None:
                return iBootStage.STAGE_2

    @cached_property
    def version(self) -> iBootVersion:
        version_str = self.search_string('iBoot-')
        major, minor, patch = version_str.string[6:].split('.', maxsplit=2)
        return iBootVersion(int(major), int(minor), int(patch))

    def patch_freshnonce(self) -> None:
        if self.stage == iBootStage.STAGE_1:
            raise errors.InvalidStage(
                'freshnonce patch only available on stage 2 iBoot'
            )

        # Find "_UpdateDeviceTree" function
        bn_str = self.search_string('boot-nonce', exact=True)
        bn_xref = self.search_xref(bn_str.offset)
        bl = self.search_insn('bl', bn_xref.offset, skip=1)
        func = bl.follow_call()

        # nop out tbnz instruction
        insn = self.search_insn('tbnz', func.offset)
        insn.patch('nop')

    def patch_kernel_debug(self) -> None:
        debug_str = self.search_string('debug-enabled')
        xref = self.search_xref(debug_str.offset)
        bl_2 = self.search_insn('bl', xref.offset, 1)
        bl_2.patch('mov x0, #1')

    def patch_nvram(self):
        if self.stage == iBootStage.STAGE_1:
            raise errors.InvalidStage('NVRAM patch only available on stage 2 iBoot')

        debug_str = self.search_string('debug-uarts')
        offset = self.data.find((debug_str.offset + self.base).to_bytes(0x8, 'little'))
        while True:
            data = self.data[offset : offset + 0x8]
            if unpack('<Q', data)[0] == 0x8:
                break

            offset -= 0x8

        blacklist1_xref = self.search_xref(offset)
        blacklist1_func = blacklist1_xref.function_begin()
        blacklist1_func.patch('mov x0, #0')
        next(blacklist1_func).patch('ret')

        while True:
            data = self.data[offset : offset + 0x8]
            if unpack('<Q', data)[0] == 0x8:
                break

            offset += 0x8

        blacklist2_xref = self.search_xref(offset)
        blacklist2_bof = blacklist2_xref.function_begin()
        blacklist2_bof.patch('mov x0, #0')
        next(blacklist2_bof).patch('ret')

        cas = self.search_string('com.apple.System.', exact=True)
        cas_xref = self.search_xref(cas.offset)
        cas_bof = cas_xref.function_begin()
        cas_bof.patch('mov x0, #0')
        next(cas_bof).patch('ret')

    def patch_sigchecks(self):
        # find "_image4_validate_property_callback_interposer"
        mov = self.search_insns('mov w8, #0x4348', 'movk w8, #0x424e, lsl #16')
        if mov is None:  # just in case search_insns() fails, try finding it manually
            disasm = self.disasm(0x0)
            while True:
                mov = next(disasm)
                if mov.info.id != ARM64_INS_MOV:
                    continue

                if (movk := next(disasm)).info.id != ARM64_INS_MOVK:
                    continue

                bnch = (movk.info.operands[-1].imm << 16) | mov.info.operands[-1].imm
                if bnch == int.from_bytes(b'BNCH', 'big'):
                    break

        ret = self.search_insn('ret', mov.offset)

        # patch
        # attempt the following:
        # 1. search for the following instructions & replace
        # "_image4_validate_property_callback_interposer" ret with branch
        #   mov x0, #0
        #   ret
        #
        # 2. search for 2 nops & replace them with mov x0, #0, then do 1.
        mov_ret = self.search_insns('mov x0, #0', 'ret')
        if mov_ret is not None:
            ret.patch(f'b #{mov_ret.offset - ret.offset}')
            return

        nops = self.search_insns('nop', 'nop')
        if nops is not None:
            nops.patch('mov x0, #0')
            next(nops).patch('ret')
            ret.patch(f'b #0x{(nops.offset - ret.offset):x}')
            return
