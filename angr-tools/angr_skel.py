#!/home/spowell/penetration/tool/angr-dev/angr/bin/python
import angr, simuvex
import sys

def main():
    p = angr.Project('', load_options={'auto_load_libs': False})
	
    main        = 0 
    find        = []
    avoid       = [] 

	posixfd = {
		"stdin": 0,
		"stdout": 1,
		"stderr": 2
	}

    init = p.factory.entry_state(add_options=simuvex.o.unicorn)

    pg = p.factory.path_group(init)
    ex = pg.explore(find=find, avoid=avoid)

    print ex.found[0].state.posix.dumps(posixfd["stdin"])


if __name__ in '__main__':
    main() 
