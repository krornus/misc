from glob import glob
from string import printable

lines = ""
for n in range(1,14):
    with open("{}.txt".format(n),'r') as f:
        for c in f.read():
            if c in printable:
                lines+=c

print lines
