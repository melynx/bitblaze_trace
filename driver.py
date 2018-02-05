#!/usr/bin/env python

from BitblazeTrace import *

import sys

def main():
    trace = BitblazeTrace(sys.argv[1])
    eh = trace.ReadInstruction()
    count = 1
    while eh:
        print('TraceInsn:{}'.format(count))
        print(eh, 'ESP:{}'.format(hex(eh.esp.value)))
        print(hex(eh.eflags), eh.cc_op, eh.df, eh.hflags, eh.ldt, eh.gdt, eh.tr, eh.idt)
        for idx in range(3):
            op = eh.ops[idx]
            if op.type_str == 'TRegister':
                if op.addr in BitblazeReg.reg_name[30]:
                    print(op.type_str, BitblazeReg.reg_name[30][op.addr], hex(op.value), bin(op.tainted))
                else:
                    print(op.type_str, op.addr, hex(op.value), bin(op.tainted))
            else:
                print(op.type_str, hex(op.addr), hex(op.value), bin(op.tainted))
            print(op.origin, op.offset, op.source_id, op.new_id)
            if op.type_str == 'TMemLoc':
                for idx2 in range(3):
                    op = eh.memregs[idx][idx2]
                    sys.stdout.write('{}:'.format(idx2))
                    if op.type_str == 'TRegister':
                        if op.addr in BitblazeReg.reg_name[30]:
                            print(op.type_str, BitblazeReg.reg_name[30][op.addr], hex(op.value), bin(op.tainted))
                        else:
                            print(op.type_str, op.addr, hex(op.value), bin(op.tainted))
                    else:
                        sys.stdout.write('BASE:')
                        print(op.type_str, hex(op.addr), hex(op.value), bin(op.tainted))
        print('')
        eh = trace.ReadInstruction()
        count += 1

if __name__ == '__main__':
    main()

