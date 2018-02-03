#!/usr/bin/env python

import struct

from capstone import *

md = Cs(CS_ARCH_X86, CS_MODE_32)

def read_format(_format, trace_file):
    size = struct.calcsize(_format)
    buf = trace_file.read(size)
    result = struct.unpack(_format, buf)
    return result, size

class ProcRecord30(object):
# typedef struct _process_record {
#     char name[32]; 
#     uint32_t pid; 
#     int  n_mods; 
# } ProcRecord; 
    def __init__(self, trace_file):
        result, size = read_format('<32sII', trace_file)
        self.name, self.pid, self.n_mods = result
        self.size = size
        self.mods = []
        for mod_id in range(self.n_mods):
            mod = ModRecord30(trace_file)
            self.mods.append(mod)
            self.size += mod.size

    def __repr__(self):
        repr_string = '''
        Name: {}
        PID: {}
        n_mods: {}
        '''.format(self.name, self.pid, self.n_mods)
        return repr_string

class ModRecord30(object):
# typedef struct _module_record {
#     char name[32]; 
#     uint32_t base; 
#     uint32_t size; 
# } ModuleRecord; 
    def __init__(self, trace_file):
        result, size = read_format('<32sII', trace_file)
        self.name, self.base, self.mod_size = result
        self.size = size

class EntryHeader30(object):
# typedef struct {
#     uint32_t addr; 
#     char rawbytes[15]; 
#     ZL: 1 byte padding here (found in temu_trace.ml)
#     OperandVal operand[5];
#     OperandVal memregs[3][3];
#     OperandVal esp; 
#     uint32_t eflags; 
#     uint32_t cc_op; 
#     uint32_t df; 
#     uint32_t hflags; 
#     uint32_t ldt; 
#     uint32_t gdt;
#     uint32_t tr; 
#     uint32_t idt; 
# } EntryHeader; 
    def __init__(self, trace_file):
        result, size = read_format('<I16s', trace_file)
        self.addr, self.rawbytes = result
        self.size = size
        print('SSize:{}'.format(size))
        self.ops = []
        for _ in range(5):
            op = OpVal30(trace_file)
            self.ops.append(op)
            self.size += op.size
        self.memregs = []
        for x in range(3):
            self.memregs.append([])
            for _ in range(3):
                op = OpVal30(trace_file)
                self.memregs[x].append(op)
                self.size += op.size
        self.esp = OpVal30(trace_file)
        self.size += op.size
        result, size = read_format('<IIIIIIII', trace_file)
        self.eflags, self.cc_op, self.df, self.hflags, self.ldt, self.gdt, self.tr, self.idt = result
        self.size += size

    def __repr__(self):
        for (address, size, mnemonic, op_str) in md.disasm_lite(self.rawbytes, self.addr):
            self.asm = '{} {}'.format(mnemonic, op_str)
            print(self.asm)
        repr_string = '''
        Addr: {}
        Rawbytes: {}
        ASM: {}
        Ops: {}
        Memregs: {}
        ESP: {}
        '''.format(hex(self.addr), self.rawbytes.encode('hex'), self.asm, self.ops, self.memregs, self.esp)
        return repr_string

class OpVal30(object):
# typedef struct {
#     enum OpType type; 
#     uint32_t addr;
#     uint32_t value; 
#     uint64_t tainted;
#     uint32_t origin[4]; 
#     uint32_t offset[4]; 
#     uint32_t source_id[4]; 
#     char new_id[4]; 
# } OperandVal; 
    def __init__(self, trace_file):
        result, size = read_format('<IIIQ', trace_file)
        self.type, self.addr, self.value, self.tainted = result
        self.size = size
        result, size = read_format('<4I', trace_file)
        self.origin = result
        self.size += size
        result, size = read_format('<4I', trace_file)
        self.offset = result
        self.size += size
        result, size = read_format('<4I', trace_file)
        self.source_id = result
        self.size += size
        result, size = read_format('<4B', trace_file)
        print(size)
        self.new_id = result
        self.size += size

    def __repr__(self):
        repr_string = '''
        Type: {}
        Addr: {}
        Value: {}
        Tainted: {}
        Origin: {}
        Offset: {}
        SourceID: {}
        NewID: {}
        '''.format(self.type, self.addr, self.value, self.tainted, self.origin, self.offset, self.source_id, self.new_id)
        return repr_string

class TraceInstruction(object):
    # TraceInstruction takes in the ascii trace format which Yanhao wrote using PinTool
    def __init__(self, data):
        self.cpu_state = {}
        self.mem_read = []
        self.mem_write = []

    def parse_bitblaze_trace(self, entry_header):
        self.insn_bytes = entry_header.rawbytes.encode('hex')
        self.pc = entry_header.addr
        for (address, size, mnemonic, op_str) in md.disasm_lite(raw_bytes.decode('hex'), IE.arch.code_addr):
            self.asm = '{} {}'.format(mnemonic, op_str)


    def parse_yh_pintool_trace(self, data):
        for line in data:
            temp = line.split('|')
            if temp[0] == 'ins':
                self.insn_bytes = temp[2]
                self.pc = int(temp[3],16)
                self.asm = temp[4]
            elif temp[0] == 'memreg':
                # memreg always have 6 entries if it is a valid mem op
                if len(temp) == 6:
                    self.is_mem = True
                    mem_addr = int(temp[2], 16)
                    mem_size_bytes = int(temp[3], 16)
                    mem_idx = int(temp[4])
                    mem_val = int(temp[5], 16)
                    if temp[1] == '0':
                        # this is a memory read, we'll put it in here
                        self.mem_read.insert(mem_idx, ((mem_addr, mem_size_bytes, mem_val)))
                    else:
                        # this is a memory write, we'll put it here
                        self.mem_write.insert(mem_idx, ((mem_addr, mem_size_bytes, mem_val)))
                # don't do anything if not a valid mem op
            else:
                # for all other register values, we'll store into a dict
                self.cpu_state[temp[0]] = int(temp[1], 16)

    def __repr__(self):
        return '{} : {}'.format(self.insn_bytes, self.asm)

    def __hash__(self):
        return hash(self.insn_bytes)

    def __eq__(self, other):
        return (self.insn_bytes == other.insn_bytes)

    def __ne__(self, other):
        return not(self == other)


class BitblazeTrace(object):
    def __init__(self, path):
        # initialize the supported versions
        self._read_header = {30: self._read_header_30}
        self._read_procs = {30: self._read_procs_30}
        self._read_instruction = {30: self._read_instruction_30}

        self.trace_file = open(path, 'rb')
        # get magicnumber and version
        buf = self.trace_file.read(8)
        self.magic_number, self.version = struct.unpack("II", buf)
        self._read_header[self.version]()
        self._read_procs[self.version]()

        print(self.magic_number)
        print(self.version)
        print(self.n_procs)
        print(self.procs)
        #self._read_procs[version]()

    def _read_header_30(self):
        buf = self.trace_file.read(4)
        self.n_procs = struct.unpack("I", buf)[0]

    def _read_procs_30(self):
        self.procs = []
        for proc_id in range(self.n_procs):
            self.procs.append(ProcRecord30(self.trace_file))

    def _read_instruction_30(self):
        eh = EntryHeader30(self.trace_file)
        print(eh)
        #for x in range(3):
        #    for y in range(3):
        #        print(eh.memregs[x][y])

    def ReadInstruction(self):
        self._read_instruction[self.version]()

