from BitblazeTrace import BitblazeTrace
import sys

def main():
    trace = BitblazeTrace(sys.argv[1])
    trace.ReadInstruction()

if __name__ == '__main__':
    main()

