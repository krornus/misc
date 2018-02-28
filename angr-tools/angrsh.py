#!/home/spowell/penetration/tool/angr-dev/angr/bin/python
import argparse
import angr, claripy, simuvex
import re
import sys
import shlex

write = sys.stdout.write
error = sys.stderr.write

def main():
    args = parse_args()

    p = angr.Project(
        args.path,
        support_selfmodifying_code=args.modifying,
        load_options={'auto_load_libs': args.auto_load_libs}
    )

    state=None

    symv = {}

    prg_args = [ p.filename ] + shlex.split(args.args)

    if args.symargs:
        for name in args.symargs:
            varg=angr.claripy.BVS(name, 0xf * 8)
            symv[name]=varg
            prg_args += [varg]

    init=init_state(p, prg_args, args.no_unicorn)

    if args.find:
        state=explore(p, init, args.find, args.avoid)

    print_results(args, state, symv)


def print_results(args, state, sim):
    if not state or not state.found:
        error("[-] No states found.\n")

    if args.print_handle > -1:
        write(state.found[0].state.posix.dumps(args.print_handle))

    for v in args.any_str:
        write(state.found[0].state.se.any_str(sim[v]))

    for v in args.any_int:
        write(state.found[0].state.se.any_int(sim[v]))


def posix_fh(s):
    strpatt = re.compile("^\s*(std(?:in|out|err))\s*$")
    intpatt = re.compile("^\s*[0-9]+\s*$")

    strfh = {"stdin": 0, "stdout": 1, "stderr": 2}
    strm=strpatt.match(s)
    if strm:
        return strfh[strm.group(1)]
    intm=intpatt.match(s)
    if intm:
        return int(s)
    raise argparse.ArgumentTypeError("Value must be stdin, stderr, stdout, or a positive integer")


def sim_char_register(proj, state, reg):
    state.mem[reg:].char = state.se.BVS('foodlededoop', proj.arch.bits)


def hex_address_list(s):
    patt = re.compile("^\s+|\s*,\s*|\s+$")
    return [int(x,16) for x in patt.split(s) if x]


def positive_int(s):
    n=int(s)
    if n > 0:
        return n
    else:
        return 0


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="File name")
    parser.add_argument("-f", "--find",
        type=hex_address_list,
        help="Addresses to find, comma delimited")
    parser.add_argument("-a", "--avoid",
        type=hex_address_list,
        help="Addresses to avoid, comma delimited")
    parser.add_argument("-p", "--print-handle",
        default=-1, type=posix_fh,
        help="Print output from either: stdin, stdout, stderr, or and integer value")
    parser.add_argument("--args", default="", help="Arguments to pass to the program")
    parser.add_argument("--symargs",
        action="append", default=[],
        help="Adds named symbolic argument to the program")
    parser.add_argument("--any-str",
        default=[], action="append",
        help="Prints any string from given named symbolic argument")
    parser.add_argument("--any-int",
        default=[], action="append",
        help="Prints any integer from given named symbolic argument")
    parser.add_argument("--auto-load-libs",
        default=False, action="store_true",
        help="Notify angr to load dynamic libraries")
    parser.add_argument("--modifying",
        default=False, action="store_true",
        help="Notifies angr that the binary modifies itself")
    parser.add_argument("--no-unicorn",
        default=False, action="store_true",
        help="Stops angr from using simuvex.o.unicorn")


    args=parser.parse_args()
    print args.find
    print args.avoid


    return args

def dereference(state, mem, addend=0, little_endian=True):
    if little_endian:
        return state.se.any_int(state.memory.load(state.se.any_int(mem)+addend).reversed)
    else:
        return state.se.any_int(state.memory.load(state.se.any_int(mem)+addend))


def explore(proj, state, find, avoid):
    pg = proj.factory.path_group(state)
    res = pg.explore(find=find, avoid=avoid)
    return res


def init_state(proj, args, unicorn):

    init_state = None
    if not unicorn:
        init_state = proj.factory.entry_state(args=args, add_options=simuvex.o.unicorn)
    else:
        init_state = proj.factory.entry_state(args=args)

    return init_state


if __name__ == "__main__":
    main()
