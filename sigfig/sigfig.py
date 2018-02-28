#!/usr/bin/env python2

import re
from decimal import Decimal

validate=re.compile("^(?:-?[0-9]*\.[0-9]+)|(?:-?[0-9]+\.[0-9]*)|(?:-?[0-9]+)$")
lzero = re.compile("^.*?([1-9])([0-9]*)\.?([0-9]*)$")
tene = re.compile("e(-?)([0-9]+)")
rzero = re.compile(".*?(0+)$")

def main():
    test_sigfigs()

def test_sigfigs():
    data = [
        (0.000065,2),
        (1.00065,6),
        (1,1),
        ("1.",1),
        (112000,3),
    ]
    data = []

    for n,a in data:
        assert(check_fig(n,a))

def check_fig(n,a):
    if sigfigs(n) == a:
        return True
    else:
        print "sigfigs({}) != {}, ({})".format(n,a,sigfigs(n))
        return False


def sigfigs(n):

    if isinstance(n,float):
        print "WARNING:\n\tFLOAT {} SENT TO SIGFIG FUNCTION".format(n)
        n = ftos(n)
    elif isinstance(n,str):
        if not n or not validate.match(n):
            return -1
    elif isinstance(n,int):
        n = str(n)
    else:
        print "not accepted type", type(n)
        return -1


    m = lzero.match(n)

    if not m or not m.group(1):
        return 0

    cn = m.group(1)+m.group(2)+m.group(3)

    if "." not in n:
        rz = rzero.search(cn)
        if rz and rz.group(1):
            cn=cn[:rz.start(1)]

    return len(cn)

def sdigits(n):

    m = lzero.match(n)
    return m.group(1)+m.group(2)+m.group(3)


def ftos(n):
    s=str(n)
    m = tene.search(s)

    if m and m.group(2):
        p = int(m.group(2))+1
        f = "%0.{}f" if m.group(1) else "%{}f"

        return f.format(p) % n
    else:
        return s

if __name__ == "__main__":
    main()
