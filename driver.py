from BitblazeTrace import BitblazeTrace

import sys

def main():
    trace = BitblazeTrace(sys.argv[1])
    eh = trace.ReadInstruction()
    while eh:
        print(eh)
        print(hex(eh.eflags), eh.cc_op, eh.df, eh.hflags, eh.ldt, eh.gdt, eh.tr, eh.idt)
        for idx, op in enumerate(eh.ops):
            print(op.type_str, hex(op.addr), hex(op.value), bin(op.tainted))
            print(op.origin, op.offset, op.source_id, op.new_id)
            if op.type_str == 'TMemLoc':
                if idx < 3:
                    print(eh.memregs[idx])
                #print(eh.memregs[idx])
        print('')
        eh = trace.ReadInstruction()

if __name__ == '__main__':
    main()

