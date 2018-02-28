import curses

class Terminal():

    def __init__(self, handler, prompt):

        self.stdscr = curses.initscr()

        self.history = []
        self.sub_history = []
        self.hist_pos = 0
        self.save_cmd = ""
        self.line = 0
        self.cmd = ""

        self.exit = False

        curses.echo()
        curses.cbreak()

        self.halt = False

        self.stdscr.keypad(True)
        self.stdscr.idlok(True)
        self.stdscr.scrollok(True)
        self.stdscr.nodelay(1)

        self.prompt = prompt
        self.handler = handler

    def run(self):

        try:
            self.main_loop()
        except KeyboardInterrupt:
            self.teardown()
            pass
        except:
            self.teardown()
            raise

    def main_loop(self):

        clen = 0

        stdscr = self.stdscr
        prompt = self.prompt

        while True:

            height, width = stdscr.getmaxyx()


            stdscr.addstr(self.line, 0, prompt)
            self.line += 1

            if self.line > height - 1:
                self.scrolldown()
                self.line = height - 1

            c = 0

            while c != 0xa:

                c = stdscr.getch()

                if c == 12:
                    self.clear()
                    break
                elif c == 21:
                    self.cln()
                    break
                elif c == 4:
                    if not self.eol():
                        return
                elif c == curses.KEY_BACKSPACE or c == 127:
                    self.backspace()
                    continue
                elif c == 0x1b:
                    self.escape()
                    continue
                elif c == curses.KEY_UP:
                    if not self.up():
                        continue
                elif c == curses.KEY_DOWN:
                    if not self.down():
                        continue
                elif c == curses.KEY_LEFT:
                    self.left()
                elif c == curses.KEY_RIGHT:
                    self.right()
                elif c in range(1,256):
                    self.cmd += chr(c)
                elif c >= 0:
                    print hex(c)


            self.sub_history = []

            if self.exit:
                return

            if self.halt or len(self.cmd) == 1:
                self.halt = False
                self.cmd = ""
                continue

            self.history.append(self.cmd)
            output = self.handler(self.cmd)

            if self.exit:
                return

            self.cmd = ""

            stdscr.addstr(self.line, 0, output)

            for out in output.split('\n'):
                self.line += len(out)/width + 1

            if self.line > height - 1:
                self.scrolldown()
                self.line = height - 1

    def clear(self):
        self.stdscr.clear()
        self.halt = True
        self.line = 0

    def cln(self):
        self.stdscr.deleteln()
        self.halt = True
        self.line -= 1

    def eol(self):
        self.delchrs(2)

        if len(self.cmd) == 0:
            self.exit = False
        else:
            return True

        return False

    def escape(self):
        self.delchrs(2)

    def backspace(self):

        (y,x) = self.stdscr.getyx()

        if x == len(self.prompt) + 2:
            x = x - 2
        else:
            x = x - 3
            idx = x - len(self.prompt)
            self.cmd = self.cmd[:idx] + self.cmd[idx+1:]

        self.repace_line(self.cmd)
        self.stdscr.move(y,x)

    def left(self):
        (y,x) = stdscr.getyx()
        mx = max(x-1, len(prompt))
        stdscr.move(y,mx)

    def right(self):
        (y,x) = stdscr.getyx()
        mx = min(x+1, len(prompt+self.cmd))
        stdscr.move(y,mx)

    def down(self):

        if self.hist_pos <= 0:
            return False

        if self.hist_pos == 1:
            self.cmd = self.save_cmd
            self.repace_line(self.cmd)
            self.hist_pos = 0
            self.sub_history = []
            return True

        self.hist_pos-=1

        self.cmd = self.sub_history[len(self.sub_history)-self.hist_pos]
        self.repace_line(self.cmd[:-1])


        return True

    def up(self):

        if self.hist_pos > len(self.history) - 1:
            return False

        if self.hist_pos == 0:
            self.save_cmd = self.cmd

            if len(self.save_cmd) == 0:
                self.sub_history = self.history
            else:
                self.sub_history = []
                for x in self.history:
                    if x.startswith(self.save_cmd):
                        self.sub_history.append(x)

        if self.hist_pos > len(self.sub_history) - 1:
            return False

        self.hist_pos+=1

        self.cmd = self.sub_history[len(self.sub_history)-self.hist_pos]
        self.repace_line(self.cmd[:-1])

        return True

    def show_history(self):

        height, width = self.stdscr.getmaxyx()
        lx = int(width*.65)

        (oy,ox) = self.stdscr.getyx()

        for (i,x) in enumerate(self.sub_history):
            self.stdscr.addstr(5+i, lx, "{}: '{}'".format(i-len(self.sub_history),x[:-1]))
            self.stdscr.addstr(5+len(self.sub_history)-1-i, lx-5, "  ")

        self.stdscr.addstr(5+len(self.sub_history), lx-5, "  ")

        self.stdscr.addstr(5+len(self.sub_history)-self.hist_pos, lx-5, "->")

        self.stdscr.addstr(height-1, lx-5, "save_cmd: {}".format(self.save_cmd))
        self.stdscr.addstr(height-2, lx-5, "cmd: {}".format(self.cmd[:-1]))

        self.stdscr.move(oy,ox)

    def teardown(self):
        curses.nocbreak()
        curses.endwin()

        self.stdscr.keypad(False)
        self.stdscr.idlok(False)
        self.stdscr.scrollok(False)
        self.stdscr.nodelay(0)

    def repace_line(self, value):

        self.stdscr.deleteln()
        self.line -= 1

        out = self.prompt+value
        outlen = len(out)

        self.stdscr.addstr(self.line, 0, out)

        self.line += 1

        (y,x) = self.stdscr.getyx()
        self.stdscr.move(y,outlen)

    def scrolldown(self):

        self.stdscr.scroll()

        (y,x) = self.stdscr.getyx()

        height, _ = self.stdscr.getmaxyx()
        y = min(y-1,height)

        self.stdscr.move(y,x)


    def delchrs(self,n=1):

        m = len(self.prompt)
        (y,x) = self.stdscr.getyx()

        n = min(x-m,n)

        if x <= m:
            return

        for i in range(n):
            self.stdscr.delch(y,x-1-i)


if __name__ == "__main__":

    def plumber(s):
        return str([hex(ord(c)) for c in s])

    t=Terminal(plumber, "litespeed -> ")
    t.run()
