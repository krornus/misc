#!/home/spowell/penetration/tool/angr-dev/angr/bin/python
import angr, simuvex, angrsh
import sys

def narnia0():
    narnia0_path_step()
    narnia0_easy()
    narnia0_bvs()


def narnia0_easy():
    
    p = angr.Project('./narnia0')

    init = p.factory.entry_state()
    pg = p.factory.path_group()

    ex=pg.explore(find=0x804856c)
    print ex.found[0].state.posix.dumps(0)
    

def narnia0_path_step():

    p = angr.Project('./narnia0')

    init = p.factory.entry_state()
    path = p.factory.path(init)
    pg = p.factory.path_group(path)

    # Step until two valid paths are found in the program
    pg.step(until=lambda lpg: len(lpg.active) > 1)

    found = None

    # Loop active paths
    for active in pg.active:
        # Dereference [esp + 0x2c], check for == 0xdeadbeef
        if angrsh.dereference(active.state, active.state.regs.esp, addend=0x2c) == 0xdeadbeef:
            found=active
    if found:
        print found.state.posix.dumps(0)

if __name__ in '__main__':
    narnia0_bvs()
    #narnia0() 
