#!/usr/bin/env python2
import json
from random import choice
import argparse

import sys

from colorama import init
init(strip=not sys.stdout.isatty())
from termcolor import cprint
from pyfiglet import figlet_format

with open("esv", "r") as f:
    bible = json.loads(f.read())


def book(v):
    if v.lower() not in bible:
        raise argparse.ArgumentTypeError("invalid book: '{}'".format(v))
    return v.lower()

def chapter(b, c):

    chapt = bible[b][str(c)]

    res = []
    for x in range(len(chapt)):
        res.append(chapt[str(x+1)])

    return "\n".join(res)

parser = argparse.ArgumentParser()
parser.add_argument("--book", "-b", type=book)
parser.add_argument("--random", "-r", action="store_true", default=False)
parser.add_argument("--chapter", "-c", type=int, default=-1)
args = parser.parse_args()

if args.random:
    args.book = choice(bible.keys())
    args.chapter = choice(bible[args.book].keys())

if args.chapter == -1 or str(args.chapter) not in bible[args.book]:
    for c in range(len(bible[args.book])):
        cprint(figlet_format(str(c+1), font="smkeyboard"), 'blue', attrs=['bold'])
        print chapter(args.book, c+1)
else:
    cprint(figlet_format(str(args.chapter), font="smkeyboard"), 'blue', attrs=['bold'])
    print chapter(args.book, args.chapter)

#book = choice(bible.keys())
#chapter = choice(bible[book].keys())

