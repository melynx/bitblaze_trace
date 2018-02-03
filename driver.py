from BitblazeTrace import BitblazeTrace

import sys

def main():
    trace = BitblazeTrace(sys.argv[1])
    eh = trace.ReadInstruction()
    while eh:
        print(eh)
        eh = trace.ReadInstruction()

if __name__ == '__main__':
    main()

