#!/home/spowell/penetration/tool/angr-dev/angr/bin/python
import sys
import angr, simuvex

sys.path.append("../")
import angrsh

def bomb():
    
    p = angr.Project('../binaries/bomb')

    state = p.factory.entry_state(addr=0x400ee0)
    nbytes = p.factory.entry_state()
    
    nbytes_path = p.factory.path(nbytes)
    nbytes_pg = p.factory.path_group(nbytes_path)

    ex = nbytes_pg.explore(find=0x00400e32)

    print ex.found[0].state.se.any_int(ex.active[0].state.regs.rdx) 
    return

    symin = state.se.BVS("in")

    pg = p.factory.path_group()

    ex=pg.explore(find=0x400ef7, avoid=0x400ef2)
    print ex.found[0].state.regs.rsi
    

if __name__ in '__main__':
    bomb()
