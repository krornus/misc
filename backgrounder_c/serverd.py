#!/usr/bin/env python2
import imghdr
import imgur
import random
import glob
import ConfigParser
import backgroundconfig as bcfg
import pyinotify
import json
import os
import socket
import subprocess
import requests


class Server(object):
  
  def __init__(self):
    self.usocket="/tmp/backgrounder"
    random.seed()

    self.cmd={
      "help":self.help,
			"next":self.nextbg,
			"prev":self.prevbg,
			"sleep":self.sleepbg,
			"remove":self.removebg,
			"save":self.savebg,
			"close":self.finish,
			"directory":self.pwd,
			"refresh":self.load_config,
      "undo":self.undoremove,
      "lsbg":self.get_backgrounds,
      "loadbg":self.set_backgrounds,
      "online":self.is_online,
      "setimgur":self.load_imgur,
      "appendimgur":self.append_imgur,
      "setting":self.setting
		}
  
    self.fill={
      "background":"--bg",
      "center":"--bg-center",
      "fill":"--bg-fill",
      "scale":"--bg-scale",
      "seamless":"--bg-seamless",
      "tile":"--bg-tile",
      "max":"--bg-max"
    }

    self.cycle=0

  def begin(self):
    if os.path.exists(self.usocket):
      print "socket file already in use"
      exit(1)

    self.load_config()
    server=self.init_server()
    self.set_backgrounds()
    self.nextbg()

    while True:
      con,addr=server.accept()
      fcn=con.recv(1024).split("\xff")
      if fcn[0] in self.cmd:
        print "executing " + fcn[0] 
        con.send(str(self.cmd[fcn[0]](fcn[1:])))
      else:
        con.send("unrecognized command '{}'".format(fcn[0]))
      con.close()

  def init_server(self):
    server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    server.bind(self.usocket)
    server.listen(5)
    server.setblocking(1)
    return server

  def finish(self, args=None):
    os.remove(self.usocket)
    exit(0)

  def nextbg(self, args=None):
    if self.cfg.get("shuffle"):
      i=random.randint(0,len(self.backgrounds)-1)
      self.background=self.backgrounds[i]
    else:
      i=self.cycle
      self.cycle=(self.cycle + 1)%len(self.backgrounds)
      self.background=self.backgrounds[i]
    
    self.setbg()
    return self.background

  def setbg(self, args=None):
    if self.is_online():
      tmp=self.cfg.get("tempfile")
      with open(tmp, "wb") as f:
        f.write(requests.get(self.background).content)
      subprocess.call(['feh', self.mode, tmp])
    else:
      subprocess.call(['feh', self.mode, self.background])
  
  def prevbg(self, args=None):
    raise NotImplementedError 
    
  def sleepbg(self, args=None):
    raise NotImplementedError 
    
  def removebg(self, args=None):
    print "removing " + self.background
    self.previous=self.background
    self.backgrounds.remove(self.background)  
    self.nextbg()

  def undoremove(self, args=None):
    print "readding " + self.background
    self.backgrounds.append(self.background)
    sel.nextbg()
    
  def savebg(self, args):
    if not args[0] or not self.is_online():
      return False
    if args[0].startswith("/"):
      directory=args[0]
    else:
      directory=self.cfg.get("directory") 
      if not directory.endswith("/"):
        directory+="/"
      directory+=args[0]

    if directory:
      with open(directory,"w") as f:
        for i in self.backgrounds:
          f.write(i+"\n")
      return True
    return False

  def pwd(self, args=None):
    return self.cfg.get("directory")

  def setting(self, args):
    return self.cfg.get(args[0])

  # pretty expensive
  def load_config(self, args=None):
    rc=None
    home=None

    if "BACKGROUNDRC" in os.environ:
      rc=os.environ["BACKGROUNDRC"]
    if "HOME" in os.environ:
      home=os.environ["HOME"]

    home=os.environ["HOME"]
    paths=[
      rc,
      home+"/.backgroundrc",
      "/etc/backgroundrc"
    ]
    
    config=None
    for path in paths:
      if path and os.path.exists(path):
        config=path
        break
    if not config:
      return False

    parser=ConfigParser.ConfigParser()
    parser.read(config)

    self.cfg=bcfg.BackgroundParser(parser, path=config)
    
    mode=self.cfg.get("mode").lower()
    if mode in self.fill:
      self.mode=self.fill[mode]
    else:
      # default
      self.mode=self.fill["fill"]
    
    return True

  def is_online(self, args=None):
    return self.cfg.connected() and bool(self.backgrounds)
  
  def load_backgrounds(self):
    directory=self.cfg.get("directory")
    res=[]
    if directory:
      if self.cfg.connected():
        choice=self.cfg.get("imagelist") + "*" or "*"
        imlist=[]
        for f in glob.glob(directory+"/"+choice):
          with open(f,"r") as ls:
            imlist+=ls.read().splitlines()
        return imlist
      else:
        for f in glob.glob(directory+"/*"):
          res.append(f)
        return res

  def set_backgrounds(self, args=None):
    self.backgrounds=self.load_backgrounds()

  def get_backgrounds(self, args=None):
    return self.backgrounds
  
  def append_imgur(self, args=None):
    if not args:
      return None
    self.backgrounds+=imgur.get_images(args[0])
    self.nextbg()
    self.setbg()

  def load_imgur(self, args=None):
    if not args:
      return None
    self.backgrounds=imgur.get_images(args[0])
    self.nextbg()
    self.setbg()

  def help(self, args=None):
    s="Available Commands:\n"
    for k in self.cmd.keys():
      s+="\t{}\n".format(k)
    return s


  def refresh(self, args=None):
    self.load_config()

if __name__ == "__main__":
  s = Server()
  try:
    s.begin()
  except KeyboardInterrupt:
    s.finish()
  except Exception as e:
    print e.message
    s.finish()
