# On my honor, I have neither given nor received any unauthorized aid on this assignment.
import sys

# small helpers

MASK32 = 0xFFFFFFFF

# set up the mask so that I can interpret and keep values inside the 32-bit limit

def to_u32(x):
    return x & MASK32

def to_s32(x):
    x &= MASK32
    return x if x < 0x80000000 else x - 0x100000000

# im doing two helper functions, each for the unsigned and signed versions (two's complement)

def sign_extend(val, bits):
    sign = 1 << (bits - 1)
    return (val & (sign - 1)) - (val & sign)

def bits(x, hi, lo):
    return (x >> lo) & ((1 << (hi - lo + 1)) - 1)

def regstr(i):
    return f"x{i}"

# decode tables (the last 2 bits choose category, next 5 bits choose opcode)
CAT1 = 0b00   # beq, bne, blt, sw
CAT2 = 0b01   # add, sub, and, or
CAT3 = 0b10   # addi, andi, ori, sll, sra, lw
CAT4 = 0b11   # jal, break

OPC1 = { 0b00000: 'beq', 0b00001: 'bne', 0b00010: 'blt', 0b00011: 'sw' }
OPC2 = { 0b00000: 'add', 0b00001: 'sub', 0b00010: 'and', 0b00011: 'or' }
OPC3 = { 0b00000: 'addi', 0b00001: 'andi', 0b00010: 'ori', 0b00011: 'sll', 0b00100: 'sra', 0b00101: 'lw' }
OPC4 = { 0b00000: 'jal',  0b11111: 'break' }

# decoded instruction container
def mkinstr(kind, text, rd=None, rs1=None, rs2=None, imm=None, target=None):
    return {"kind": kind, "text": text, "rd": rd, "rs1": rs1, "rs2": rs2, "imm": imm, "target": target}

# for disassembly:

def decode(word, addr):
    cat = word & 0b11
    opc5 = (word >> 2) & 0b11111

    if cat == CAT1:
        rs2 = bits(word, 24, 20)
        rs1 = bits(word, 19, 15)
        imm_lo = bits(word, 11, 7)
        imm_hi = bits(word, 31, 25)
        imm12 = (imm_hi << 5) | imm_lo
        imm_se = sign_extend(imm12, 12)

        m = OPC1.get(opc5, 'ill')
        if m == 'ill':
            return mkinstr('ill', f'.word {word:032b}')

        if m in ('beq', 'bne', 'blt'):
            imm_raw = sign_extend((imm_hi << 5) | imm_lo, 12)
            off = imm_raw << 1
            tgt = addr + off
            txt = f"{m} {regstr(rs1)}, {regstr(rs2)}, #{imm_raw}"
            return mkinstr(m, txt, rs1=rs1, rs2=rs2, imm=imm_raw, target=tgt)
        else:  # sw
            txt = f"sw {regstr(rs2)}, {imm_se}({regstr(rs1)})"
            return mkinstr('sw', txt, rs1=rs1, rs2=rs2, imm=imm_se)

    if cat == CAT2:
        rd  = bits(word, 11, 7)
        rs1 = bits(word, 19, 15)
        rs2 = bits(word, 24, 20)
        m = OPC2.get(opc5, 'ill')
        if m == 'ill':
            return mkinstr('ill', f'.word {word:032b}')
        txt = f"{m} {regstr(rd)}, {regstr(rs1)}, {regstr(rs2)}"
        return mkinstr(m, txt, rd=rd, rs1=rs1, rs2=rs2)

    if cat == CAT3:
        rd  = bits(word, 11, 7)
        rs1 = bits(word, 19, 15)
        imm12 = bits(word, 31, 20)
        imm_se = sign_extend(imm12, 12)
        m = OPC3.get(opc5, 'ill')
        if m == 'ill':
            return mkinstr('ill', f'.word {word:032b}')
        if m == 'addi':
            txt = f"{m} {regstr(rd)}, {regstr(rs1)}, #{imm_se}"
            return mkinstr(m, txt, rd=rd, rs1=rs1, imm=imm_se)
        if m in ('andi', 'ori'):
            imm_u = imm12
            txt = f"{m} {regstr(rd)}, {regstr(rs1)}, #{imm_u}"
            return mkinstr(m, txt, rd=rd, rs1=rs1, imm=imm_u)
        if m in ('sll', 'sra'):
            sh = imm12 & 31
            txt = f"{m} {regstr(rd)}, {regstr(rs1)}, #{sh}"
            return mkinstr(m, txt, rd=rd, rs1=rs1, imm=sh)
        txt = f"lw {regstr(rd)}, {imm_se}({regstr(rs1)})"
        return mkinstr('lw', txt, rd=rd, rs1=rs1, imm=imm_se)

    if cat == CAT4:
        rd = bits(word, 11, 7)
        imm20 = bits(word, 31, 12)
        m = OPC4.get(opc5, 'ill')
        if m == 'ill':
            return mkinstr('ill', f'.word {word:032b}')
        if m == 'jal':
            imm = sign_extend(imm20, 20)
            tgt = addr + (imm << 1)
            txt = f"jal {regstr(rd)}, #{imm}"
            return mkinstr('jal', txt, rd=rd, imm=imm, target=tgt)
        return mkinstr('break', 'break')

    return mkinstr('ill', f'.word {word:032b}')

# handling the input/output of the file

def load_words(path):
    out = []
    with open(path, 'r', newline='') as f:
        for raw in f:
            s = raw.strip()
            if not s:
                continue
            if len(s) != 32 or any(c not in '01' for c in s):
                continue
            out.append(s)
    return out

def disassemble(bitlines):
    # what this returns is:
    # rows -> list of (bit_string, address, asm_text)
    # first_data_addr -> address of the first word after 'break'
    # data_mem -> addr -> signed 32-bit
    rows = []
    base = 256
    addr = base
    data_mem = {}
    in_data = False
    first_data_addr = None

    for b in bitlines:
        if not in_data:
            w = int(b, 2)
            dec = decode(w, addr)
            rows.append((b, addr, dec["text"]))
            if dec["kind"] == 'break':
                in_data = True
            addr += 4
        else:
            if first_data_addr is None:
                first_data_addr = addr
            val = to_s32(int(b, 2))
            rows.append((b, addr, str(val)))
            data_mem[addr] = val
            addr += 4

    if first_data_addr is None:
        first_data_addr = addr
    return rows, first_data_addr, data_mem

def write_disassembly(rows, outpath):
    with open(outpath, 'w') as f:
        for bits32, addr, text in rows:
            f.write(f"{bits32}\t{addr}\t{text}\n")

# simulation

class Simulator:
    def __init__(self, instr_map, data_mem, first_data_addr, last_data_addr):
        self.reg = [0] * 32
        self.pc = 256
        self.instr = instr_map
        self.data = dict(data_mem)
        self.first_data_addr = first_data_addr
        self.last_data_addr = last_data_addr
        self.cycle = 1

    def get_mem(self, addr):
        if addr % 4 != 0:
            addr &= ~0x3
        return to_s32(self.data.get(addr, 0))

    def set_mem(self, addr, val):
        if addr % 4 != 0:
            addr &= ~0x3
        sval = to_s32(val)
        self.data[addr] = sval
        if addr > self.last_data_addr:
            self.last_data_addr = addr
        if addr < self.first_data_addr:
            self.first_data_addr = addr

    def set_reg(self, rd, val):
        if rd == 0:
            return
        self.reg[rd] = to_s32(val)

    def fetch(self):
        w = self.instr.get(self.pc)
        if w is None:
            return 0, mkinstr('break', 'break')
        return w, decode(w, self.pc)

    def step(self):
        _, d = self.fetch()
        next_pc = self.pc + 4
        k = d["kind"]

        if k == 'add':
            self.set_reg(d["rd"], to_s32(self.reg[d["rs1"]] + self.reg[d["rs2"]]))
        elif k == 'sub':
            self.set_reg(d["rd"], to_s32(self.reg[d["rs1"]] - self.reg[d["rs2"]]))
        elif k == 'and':
            self.set_reg(d["rd"], to_s32(to_u32(self.reg[d["rs1"]]) & to_u32(self.reg[d["rs2"]])))
        elif k == 'or':
            self.set_reg(d["rd"], to_s32(to_u32(self.reg[d["rs1"]]) | to_u32(self.reg[d["rs2"]])))
        elif k == 'addi':
            self.set_reg(d["rd"], to_s32(self.reg[d["rs1"]] + d["imm"]))
        elif k == 'andi':
            self.set_reg(d["rd"], to_s32(to_u32(self.reg[d["rs1"]]) & to_u32(d["imm"])))
        elif k == 'ori':
            self.set_reg(d["rd"], to_s32(to_u32(self.reg[d["rs1"]]) | to_u32(d["imm"])))
        elif k == 'sll':
            sh = d["imm"] & 31
            self.set_reg(d["rd"], to_s32(to_u32(self.reg[d["rs1"]]) << sh))
        elif k == 'sra':
            sh = d["imm"] & 31
            self.set_reg(d["rd"], to_s32(self.reg[d["rs1"]] >> sh))
        elif k == 'lw':
            addr = to_s32(self.reg[d["rs1"]] + d["imm"])
            self.set_reg(d["rd"], self.get_mem(addr))
        elif k == 'sw':
            # printed as sw src(rs1), imm(base=rs2)
            addr = to_s32(self.reg[d["rs1"]] + d["imm"])
            self.set_mem(addr, self.reg[d["rs2"]])
        elif k in ('beq', 'bne', 'blt'):
            a = self.reg[d["rs1"]]
            b = self.reg[d["rs2"]]
            take = (k == 'beq' and a == b) or (k == 'bne' and a != b) or (k == 'blt' and a < b)
            if take:
                next_pc = d["target"]
        elif k == 'jal':
            self.set_reg(d["rd"], self.pc + 4)
            next_pc = d["target"]
        elif k == 'break':
            pass
        else:
            pass

        self.pc = next_pc
        return d

    def dump_registers(self):
        out = []
        rows = [(0, 'x00:'), (8, 'x08:'), (16, 'x16:'), (24, 'x24:')]
        for base, label in rows:
            row = [label]
            for i in range(base, base + 8):
                row.append(str(to_s32(self.reg[i])))
            out.append('\t'.join(row))
        return out

    def dump_data(self):
        out = ['Data']
        if self.first_data_addr > self.last_data_addr:
            return out
        addr = self.first_data_addr
        while addr <= self.last_data_addr:
            vals = []
            for i in range(8):
                a = addr + 4 * i
                vals.append(str(to_s32(self.data.get(a, 0))))
            out.append(f"{addr}:\t" + '\t'.join(vals))
            addr += 32
        return out

def write_simulation(machine, outpath):
    with open(outpath, 'w') as f:
        while True:
            _, d = machine.fetch()
            f.write('-' * 20 + '\n')
            f.write(f"Cycle {machine.cycle}:\t{machine.pc}\t{d['text']}\n\n")

            executed = machine.step()

            f.write('Registers\n')
            for line in machine.dump_registers():
                f.write(line + '\n')
            f.write('\n')

            for line in machine.dump_data():
                f.write(line + '\n')

            if executed["kind"] == 'break':
                break
            machine.cycle += 1



def main(argv):
    if len(argv) != 2:
        return

    inpath = argv[1]
    bitlines = load_words(inpath)

    rows, first_data_addr, data_mem = disassemble(bitlines)
    write_disassembly(rows, 'disassembly.txt')

    instr_map = {}
    hit_break = False
    for b, a, text in rows:
        if a < first_data_addr:
            w = int(b, 2)
            instr_map[a] = w
            if text == 'break':
                hit_break = True
        else:
            break
    if not hit_break:
        last_addr = (len(instr_map) * 4) + 256
        instr_map[last_addr] = 0

    last_data_addr = max(data_mem.keys()) if data_mem else first_data_addr - 4

    m = Simulator(instr_map, data_mem, first_data_addr, last_data_addr)
    write_simulation(m, 'simulation.txt')

if __name__ == '__main__':
    main(sys.argv)
