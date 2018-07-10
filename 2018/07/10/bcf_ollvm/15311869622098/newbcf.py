import idaapi


class BCFProcessor:
    def __init__(self):
        def state0(mnem):
            return 1 if mnem in ('LDR.W', 'LDR') else -1
        def state1(mnem):
            return 2 if mnem in ('LDR.W', 'LDR') else -1
        def state2(mnem):
            return 3 if mnem == 'ADD' else -1
        def state3(mnem):
            return 4 if mnem in ('LDR.W', 'LDR') else -1
        def state4(mnem):
            return 5 if mnem in ('LDR.W', 'LDR') else -1
        def state5(mnem):
            return 6 if mnem in ('LDR.W', 'LDR') else -1
        def state6(mnem):
            if mnem == 'SUBS':
                return 7
            elif mnem == 'MOV':
                return 6
            return -1
        def state7(mnem):
            return 8 if mnem == 'MULS' else -1
        def state8(mnem):
            return 9 if mnem == 'TST.W' else -1
        def state9(mnem):
            if mnem == 'IT NE':
                return 10
            elif mnem in ('BEQ', 'BEQ.W'):
                return 11
            elif mnem in ('SUB.W', 'LDR.W', 'MOV', 'STR.W'):
                return 9
            return -1
        def state10(mnem):
            return 15 if mnem == 'CMPNE' else -1
        def state11(mnem):
            return 12 if mnem == 'CMP' else -1
        def state12(mnem):
            if mnem in ('BGT', 'BGT.W'):
                return 15
            elif mnem in ('BLE', 'BLE.W'):
                return 14
            return -1
        def state13(mnem):
            return 3 if mnem in ('LDR.W', 'LDR') else -1

        self.func_maps = []
        for i in xrange(0, 14):
            self.func_maps.append(locals().get('state{}'.format(i)))

    def check(self, ea):
        self.state = -1
        self.patch_ea = []

        state = 0
        new_ea = get_prev_ea(ea, 3)
        if idc.GetMnem(new_ea) not in ('LDR.W', 'LDR'):
            new_ea = get_prev_ea(ea, 1)
            assert(idc.GetMnem(new_ea) in ('LDR.W', 'LDR'))
            state = 13

        ea = new_ea
        while True:
            ori_state = state
            mnem = idc.GetMnem(ea)
            state = self.func_maps[state](mnem)
            if state == -1:
                return False, ea
            elif state in (14, 15):
                break

            if ori_state != state:
                self.patch_ea.append(ea)

            ea += ItemSize(ea)

        self.state = state
        self.end_ea = ea
        return True, ea

    def patch(self): 
        end_size = ItemSize(self.end_ea)
        target_ea = idc.GetOperandValue(self.end_ea, 0)

        self.patch_ea.append(self.end_ea)
        for ea in self.patch_ea:
             ea_size = ItemSize(ea)
             fill_nop(ea, ea_size)
             print('patch: {} - {}'.format(hex(ea), hex(ea + ea_size)))

        if self.state == 14:
            new_ea = self.end_ea
            if end_size == 2:
                new_ea -= 2
            fill_bw(new_ea, target_ea)
            print('new branch: {} -> {}'.format(hex(new_ea), hex(target_ea)))


def is_code(ea):
    return idaapi.getFlags(ea) & idaapi.MS_CLS == idaapi.FF_CODE


def fill_nop(start_ea, size):
    nop_opcode = 0xbf00
    for i in xrange(0, size, 2):
        idc.PatchWord(start_ea + i, nop_opcode)


def fill_bw(ea, target_ea):
    offset = (target_ea - ea - 4) / 2
    imm11 = offset & 0x7ff
    imm10 = offset >> 11 & 0x3ff 
    s = 0 if offset >= 0 else 1
    j1 = offset >> 21 & 1 ^ 1 ^ s
    j2 = offset >> 20 & 1 ^ 1 ^ s

    idc.PatchWord(ea, 0xf000 | s << 10 | imm10)
    idc.PatchWord(ea + 2, 0x9000 | j1 << 13 | j2 << 11 | imm11)


def get_prev_ea(ea, n):
    for _ in range(0, n):
        ea = idc.prev_head(ea)

    assert(ea != idaapi.BADADDR)

    return ea


def match_instruction(inst_list, ea):
    for inst in inst_list:
        if idc.GetMnem(ea) != inst:
            return False, ea

        ea += ItemSize(ea)

    return True, ea


def clean_node(func):
    done = False
    while not done:
        done = True

        q = idaapi.qflow_chart_t("The title", func, 0, 0, idaapi.FC_PREDS)
        assert(q[0].start_ea == func.start_ea)
        for n in xrange(1, q.size()):
            b = q[n]
            if q.npred(n) != 0:
                continue

            done = False
            size = b.end_ea - b.start_ea
            MakeUnknown(b.start_ea, size, idaapi.DOUNK_SIMPLE)
            MakeData(b.start_ea, idaapi.FF_BYTE, size, 0)


def bcf(x, y, cur_func):
    processor = BCFProcessor()
    xrefs = XrefsTo(x)

    for xref in xrefs:
        if xref.frm < cur_func.start_ea or \
            xref.frm > cur_func.end_ea:
            continue

        if not is_code(xref.frm):
            print('{}: expecting code reference, skip.'.format(hex(xref.frm)))
            continue

        ret, ea = processor.check(xref.frm)
        if not ret:
            print('{}: unexpected instruction, skip.'.format(hex(ea)))
            continue

        processor.patch()

    idc.plan_and_wait(cur_func.start_ea, cur_func.end_ea)

    clean_node(cur_func)

def main(cur_func):
    x = 0x597F0
    y = 0x59800
    # x = 0x597F0 
    # y = 0x59800
    bcf(x, y, cur_func)


if __name__ == '__main__':
    main(idaapi.get_func(here()))