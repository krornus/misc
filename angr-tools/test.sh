#!/bin/sh
./angrsh.py narnia0 -f 0x804856c -a 0x804857a -p 0 2> /dev/null
echo 
./angrsh.py fairlight --symargs argv1 --any-str argv1 -f 0x4018f7 -a 0x4018f9 2> /dev/null
echo
