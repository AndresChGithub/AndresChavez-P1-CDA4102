import sys
from typing import Dict, List, Tuple

# () smaller helper functions:

MASK32 = 0xFFFFFFFF

# set up the mask so that I can interpret and keep values inside the 32-bit limit

def to_u32(x: int) -> int:
    return x & MASK32

def to_s32(x: int) -> int:
    x &= MASK32
    return x if x < 0x80000000 else x - 0x100000000

# im doing two helper functions, each for the unsigned and signed versions (two's complement)

def sign_extend(val: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (val & (sign_bit - 1)) - (val & sign_bit)

# sign-extend a value with bitwidth bits to 32-bit signed

def bits(x: int, hi: int, lo: int) -> int:
    return (x >> lo) & ((1 << (hi - lo + 1)) - 1)

# bit slicer


# () decode tables:

# category of instruction is based off of the rightmost bit

CAT1 = 0b00  # beq, bne, blt, sw 
CAT2 = 0b01  # add, sub, and, or 
CAT3 = 0b10  # addi, andi, ori, sll, sra, lw 
CAT4 = 0b11  # jal, break

# Opcodes per category:

OPC1 = {
    0b00000: 'beq',
    0b00001: 'bne',
    0b00010: 'blt',
    0b00011: 'sw',
}

OPC2 = {
    0b00000: 'add',
    0b00001: 'sub',
    0b00010: 'and',
    0b00011: 'or',
}

OPC3 = {
    0b00000: 'addi',
    0b00001: 'andi',
    0b00010: 'ori',
    0b00011: 'slli',
    0b00100: 'srai',
    0b00101: 'lw',
}

OPC4 = {
    0b00000: 'jal',
    0b11111: 'break',
}

# () code for the disassembling side of things:

def int_to_reg_format(idx: int) -> str:
    return f"x{idx}"

class Decoded:
    def __init__(self, kind: str, text: str, 
                 rd=None, rs1=None, rs2=None, imm=None, target=None):
        self.kind = kind            # the kind of mnemonic, like 'add' or 'DATA' or 'break'
        self.text = text            # pretty-printed assembly text (for disassembly + simulation header)
        self.rd = rd; self.rs1 = rs1; self.rs2 = rs2
        self.imm = imm              # signed int for immediates (already sign-extended)
        self.target = target        # computed target address for branches/jal (int)


def parse_word(bitstr: str) -> int:
    return int(bitstr, 2)


def decode_instr(word: int, addr: int) -> Decoded:
    # Determine category by the 2 LSBs
    cat = word & 0b11
    opc5 = (word >> 2) & 0b11111

    if cat == CAT1:
        # S-type layout for fields: imm[11:5]=[31:25], rs2=[24:20], rs1=[19:15], func3=[14:12]==000, imm[4:0]=[11:7]
        rs2 = bits(word, 24, 20)
        rs1 = bits(word, 19, 15)
        imm_low = bits(word, 11, 7)
        imm_high = bits(word, 31, 25)
        imm12 = (imm_high << 5) | imm_low  # 12-bit
        imm_se = sign_extend(imm12, 12)

        mnem = OPC1.get(opc5, 'ill')
        if mnem == 'ill':
            return Decoded('ill', f'.word {word:032b}')

        if mnem in ('beq', 'bne', 'blt'):
            imm_raw = sign_extend(((imm_high << 5) | imm_low), 12)
            br_off = imm_raw << 1
            target = addr + br_off
            text = f"{mnem} {int_to_reg_format(rs1)}, {int_to_reg_format(rs2)}, #{imm_raw}"
            return Decoded(mnem, text, rs1=rs1, rs2=rs2, imm=imm_raw, target=target)
        elif mnem == 'sw':
            # store word: print as source, offset(base) with offset w/o '#'
            # Expected disassembly uses first reg as source and second as base.
            text = f"sw {int_to_reg_format(rs1)}, {imm_se}({int_to_reg_format(rs2)})"
            return Decoded('sw', text, rs1=rs1, rs2=rs2, imm=imm_se)

    elif cat == CAT2:
        # R-type: rd=[11:7], rs1=[19:15], rs2=[24:20]
        rd = bits(word, 11, 7)
        rs1 = bits(word, 19, 15)
        rs2 = bits(word, 24, 20)
        mnem = OPC2.get(opc5, 'ill')
        if mnem == 'ill':
            return Decoded('ill', f'.word {word:032b}')
        text = f"{mnem} {int_to_reg_format(rd)}, {int_to_reg_format(rs1)}, {int_to_reg_format(rs2)}"
        return Decoded(mnem, text, rd=rd, rs1=rs1, rs2=rs2)

    elif cat == CAT3:
        # I-type: rd=[11:7], rs1=[19:15], imm[11:0]=[31:20]
        rd = bits(word, 11, 7)
        rs1 = bits(word, 19, 15)
        imm12 = bits(word, 31, 20)
        imm_se = sign_extend(imm12, 12)
        mnem = OPC3.get(opc5, 'ill')
        if mnem == 'ill':
            return Decoded('ill', f'.word {word:032b}')
        if mnem in ('addi', 'andi', 'ori'):
            text = f"{mnem} {int_to_reg_format(rd)}, {int_to_reg_format(rs1)}, #{imm_se}"
            return Decoded(mnem, text, rd=rd, rs1=rs1, imm=imm_se)
        elif mnem in ('slli', 'srai'):
            shamt = imm12 & 0x1F
            text = f"{mnem} {int_to_reg_format(rd)}, {int_to_reg_format(rs1)}, #{shamt}"
            return Decoded(mnem, text, rd=rd, rs1=rs1, imm=shamt)
        elif mnem == 'lw':
            # lw prints offset(base) with no '#'
            text = f"lw {int_to_reg_format(rd)}, {imm_se}({int_to_reg_format(rs1)})"
            return Decoded('lw', text, rd=rd, rs1=rs1, imm=imm_se)

    elif cat == CAT4:
        # U-type per spec: rd=[11:7], imm[19:0]=[31:12]
        rd = bits(word, 11, 7)
        imm20 = bits(word, 31, 12)
        mnem = OPC4.get(opc5, 'ill')
        if mnem == 'ill':
            return Decoded('ill', f'.word {word:032b}')
        if mnem == 'jal':
            imm_se = sign_extend(imm20, 20)
            off = imm_se << 1
            target = addr + off
            # Disassembly prints the immediate (not absolute target)
            text = f"jal {int_to_reg_format(rd)}, #{imm_se}"
            return Decoded('jal', text, rd=rd, imm=imm_se, target=target)
        elif mnem == 'break':
            return Decoded('break', 'break')

    # Fallback: illegal
    return Decoded('ill', f'.word {word:032b}')


# ------------------------- File I/O and Disassembly pass -------------------------

def load_words(path: str) -> List[str]:
    lines: List[str] = []
    with open(path, 'r', newline='') as f:
        for raw in f:
            s = raw.strip()  # handles both \n and \r\n
            if not s:
                continue
            if len(s) != 32 or any(c not in '01' for c in s):
                # ignore invalid lines silently (spec says input file is proper)
                continue
            lines.append(s)
    return lines


def disassemble(bitlines: List[str]) -> Tuple[List[Tuple[str,int,str]], int, Dict[int,int]]:
    """
    Returns:
      rows: list of (bitstr, addr, asm_text)
      first_data_addr: address where data starts
      data_mem: {addr: signed_int}
    """
    rows = []
    base_addr = 256
    addr = base_addr
    data_mem: Dict[int, int] = {}

    in_data = False
    first_data_addr = None

    for i, b in enumerate(bitlines):
        if not in_data:
            w = parse_word(b)
            dec = decode_instr(w, addr)
            rows.append((b, addr, dec.text))
            if dec.kind == 'break':
                in_data = True
            addr += 4
        else:
            # data section: each 32-bit word is a signed integer (2's complement)
            if first_data_addr is None:
                first_data_addr = addr
            val = to_s32(int(b, 2))
            rows.append((b, addr, str(val)))
            data_mem[addr] = val
            addr += 4

    if first_data_addr is None:
        first_data_addr = addr  # no data present

    return rows, first_data_addr, data_mem


def write_disassembly(rows: List[Tuple[str,int,str]], outpath: str) -> None:
    with open(outpath, 'w') as f:
        for bits32, addr, text in rows:
            f.write(f"{bits32}\t{addr}\t{text}\n")


# ------------------------- Simulation -------------------------

class Simulator:
    def __init__(self, instr_map: Dict[int, int], data_mem: Dict[int, int], first_data_addr: int, last_data_addr: int):
        self.reg = [0] * 32
        self.pc = 256
        self.instr = instr_map   # addr -> 32-bit word
        self.data = dict(data_mem)  # addr -> signed int
        self.first_data_addr = first_data_addr
        self.last_data_addr = last_data_addr
        self.cycle = 1

    def get_mem(self, addr: int) -> int:
        # return signed 32-bit at address (word-aligned). Unassigned -> 0
        if addr % 4 != 0:
            # Align down silently per project leniency; real ISA would trap
            addr &= ~0x3
        return to_s32(self.data.get(addr, 0))

    def set_mem(self, addr: int, val: int) -> None:
        if addr % 4 != 0:
            addr &= ~0x3
        sval = to_s32(val)
        self.data[addr] = sval
        if addr > self.last_data_addr:
            self.last_data_addr = addr
        if addr < self.first_data_addr:
            self.first_data_addr = addr

    def set_reg(self, rd: int, val: int) -> None:
        if rd == 0:
            return  # x0 stays 0
        self.reg[rd] = to_s32(val)

    def fetch(self) -> Tuple[int, Decoded]:
        w = self.instr.get(self.pc, None)
        if w is None:
            # Treat missing as break to avoid infinite run
            return 0, Decoded('break', 'break')
        d = decode_instr(w, self.pc)
        return w, d

    def step(self) -> Decoded:
        _, d = self.fetch()
        # Execute
        next_pc = self.pc + 4
        k = d.kind

        if k == 'add':
            self.set_reg(d.rd, to_s32(self.reg[d.rs1] + self.reg[d.rs2]))
        elif k == 'sub':
            self.set_reg(d.rd, to_s32(self.reg[d.rs1] - self.reg[d.rs2]))
        elif k == 'and':
            self.set_reg(d.rd, to_s32(to_u32(self.reg[d.rs1]) & to_u32(self.reg[d.rs2])))
        elif k == 'or':
            self.set_reg(d.rd, to_s32(to_u32(self.reg[d.rs1]) | to_u32(self.reg[d.rs2])))
        elif k == 'addi':
            self.set_reg(d.rd, to_s32(self.reg[d.rs1] + d.imm))
        elif k == 'andi':
            self.set_reg(d.rd, to_s32(to_u32(self.reg[d.rs1]) & to_u32(d.imm)))
        elif k == 'ori':
            self.set_reg(d.rd, to_s32(to_u32(self.reg[d.rs1]) | to_u32(d.imm)))
        elif k == 'sll':
            sh = d.imm & 31
            self.set_reg(d.rd, to_s32(to_u32(self.reg[d.rs1]) << sh))
        elif k == 'sra':
            sh = d.imm & 31
            self.set_reg(d.rd, to_s32(self.reg[d.rs1] >> sh))  # Python >> is arithmetic for negatives
        elif k == 'lw':
            addr = to_s32(self.reg[d.rs1] + d.imm)
            val = self.get_mem(addr)
            self.set_reg(d.rd, val)
        elif k == 'sw':
            addr = to_s32(self.reg[d.rs1] + d.imm)
            self.set_mem(addr, self.reg[d.rs2])
        elif k in ('beq', 'bne', 'blt'):
            a = self.reg[d.rs1]
            b = self.reg[d.rs2]
            take = False
            if k == 'beq':
                take = (a == b)
            elif k == 'bne':
                take = (a != b)
            elif k == 'blt':
                take = (a < b)
            if take:
                next_pc = d.target
        elif k == 'jal':
            # rd gets PC+4, then PC = target
            self.set_reg(d.rd, self.pc + 4)
            next_pc = d.target
        elif k == 'break':
            pass  # fall through; will stop in run loop
        else:
            pass  # ill: do nothing, advance

        self.pc = next_pc
        return d

    def dump_registers(self) -> List[str]:
        out = []
        linespecs = [
            (0, 'x00:'), (8, 'x08:'), (16, 'x16:'), (24, 'x24:')
        ]
        for base, label in linespecs:
            row = [label]
            for i in range(base, base + 8):
                row.append(str(to_s32(self.reg[i])))
            out.append('\t'.join(row))
        return out

    def dump_data(self) -> List[str]:
        out = ['Data']
        if self.first_data_addr > self.last_data_addr:
            return out
        addr = self.first_data_addr
        while addr <= self.last_data_addr:
            row_vals = []
            for i in range(8):
                a = addr + 4 * i
                row_vals.append(str(to_s32(self.data.get(a, 0))))
            out.append(f"{addr}:\t" + '\t'.join(row_vals))
            addr += 32  # 8 words * 4 bytes
        return out


def write_simulation(machine: Simulator, outpath: str) -> None:
    with open(outpath, 'w') as f:
        while True:
            w, d = machine.fetch()
            # Header per cycle
            f.write('-' * 20 + '\n')
            f.write(f"Cycle {machine.cycle}:\t{machine.pc}\t{d.text}\n\n")

            # Execute one step (changes registers/memory/pc)
            d_exec = machine.step()

            # Registers
            f.write('Registers\n')
            for line in machine.dump_registers():
                f.write(line + '\n')
            f.write('\n')

            # Data
            for line in machine.dump_data():
                f.write(line + '\n')

            # End cycle
            if d_exec.kind == 'break':
                break
            machine.cycle += 1


# ------------------------- Main -------------------------

def main(argv: List[str]) -> None:
    if len(argv) != 2:
        return  # silent exit per grading script; no stdout prints

    inpath = argv[1]

    bitlines = load_words(inpath)

    # Disassembly pass (and collect initial data memory)
    rows, first_data_addr, data_mem = disassemble(bitlines)

    # Write disassembly.txt
    write_disassembly(rows, 'disassembly.txt')

    # Build instruction memory map (up to and including break)
    instr_map: Dict[int, int] = {}
    addr = 256
    hit_break = False
    for b, a, text in rows:
        if a < first_data_addr:
            w = parse_word(b)
            instr_map[a] = w
            if text == 'break':
                hit_break = True
        else:
            break
    if not hit_break:
        # Ensure there is a synthetic break after the last instruction to avoid runaway
        last_addr = (len(instr_map) * 4) + 256
        instr_map[last_addr] = 0  # decodes to ill; safety not strictly necessary

    # Determine last data addr for printing (include any existing data words)
    last_data_addr = max(data_mem.keys()) if data_mem else first_data_addr - 4

    # Simulation
    m = Simulator(instr_map, data_mem, first_data_addr, last_data_addr)
    write_simulation(m, 'simulation.txt')

if __name__ == '__main__':
    main(sys.argv)
