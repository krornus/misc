#!/usr/bin/env python2
import socket
import json
import argparse
import time

def main():
  parser=argparse.ArgumentParser()
  parser.add_argument("--cycle", "-c", action="store_true", default=False)
  parser.add_argument("cmd", nargs="?", default="next")
  parser.add_argument("args", nargs="*")
  args=parser.parse_args()

  if args.cycle:
    while(True):
      try:
        interval=int(command("setting\xffinterval"))
      except socket.error:
        continue
      time.sleep(interval)
      command("next")

  print command(args.cmd+"\xff"+"\xff".join(args.args))

def command(cmd):
  client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  client.connect("/tmp/backgrounder")
  client.send(cmd)
  res = client.recv(1024)
  client.close()
  return res

def get_config():
  return json.loads(command("get_config"))

def close_server():
  command("close")

if __name__ == "__main__":
  main()
