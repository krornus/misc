import re
from shlex import split

import pterm
import argparse

class Command():
    def __init__(self, cmd, fcn, argv=[], re=False):

        self.command = cmd
        self.function = fcn
        self.argv = argv
        self.re=re

    def __repr__ (self):

        if not self.re:
            return str(self.command)
        else:
            return "Regular expression: {}".format(str(self.command))


class CLI(object):

    def __init__(self, prompt="$ "):
        self.commands = {}
        self.re_commands = {}

        self.re_command_flags = re.IGNORECASE

        self.prompt = prompt

        self.run = True

        self.command("help", self.help)
        self.command(["quit","exit"], self.quit)

        self.terminal = pterm.Terminal(self.handle, self.prompt)

    def __del__(self):
        self.terminal.teardown()

    def re_command(self, s, f):

        if isinstance(s, list):
            if isinstance(f, list):
                for c,fcn in zip(s,f):
                    self.re_commands[re.compile(c, flags=self.re_command_flags)] = fcn
            else:
                for c in s:
                    self.re_commands[re.compile(c, flags=self.re_command_flags)] = f
        else:
            self.re_commands[re.compile(s, flags=self.re_command_flags)] = f

        return self

    def command(self, s, f):

        if isinstance(s, list):
            if isinstance(f, list):
                for c,fcn in zip(s,f):
                    self.commands[c] = fcn
            else:
                for c in s:
                    self.commands[c] = f
        else:
            self.commands[s] = f

        return self

    def help(self, _):
        return str(self.commands.keys())

    def quit(self, _):
        self.terminal.exit = True
        return ""

    def repl(self):
        try:
            self.terminal.run()
        except:
            self.terminal.teardown()
            raise

    def handle(self, cmd):

        argv=split(cmd)

        action=self.get_command(argv[0])

        if len(action) == 1:
            action = action[0]
            argv[0] = action.command
            return action.function(argv)

        elif len(action) > 1:
            return ("Error: Multiple possible commands found."
                "\tSpecify one of {}".format(action))
        else:
            return ("Error: Command not found"
                "\t'{}'".format(argv[0]))

    def get_command(self,cmd):

        cmd = cmd.strip()
        std_commands = []

        for (c,f) in self.commands.iteritems():
            if c.startswith(cmd):
                std_commands.append(Command(c,f))

        if std_commands:
            return std_commands

        re_commands = []
        for (re,f) in self.re_commands.iteritems():
            if re.match(cmd):
                re_commands.append(Command(cmd, f, re=True))

        return re_commands


if __name__ == "__main__":

    def test(argv):

        class ArgumentParserError(Exception): pass

        class ThrowingArgumentParser(argparse.ArgumentParser):
            def error(self, message):
                ArgumentParserError(message)

        parser = ThrowingArgumentParser()
        parser.add_argument("len", type=int)

        try:
            args = parser.parse_args(argv[1:])

            return 'test called, len = {}'.format(args.len)
        except Exception as e:
            return e.message


    def test_re(argv):
        return 'test re called {}'.format(argv)

    cli = CLI(prompt="$ ")
    cli.command("test", test)
    cli.re_command("^[0-9]+$", test)

    cli.repl()
