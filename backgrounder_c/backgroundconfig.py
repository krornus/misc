import socket

class BackgroundParser(object):

  def __init__(self, config, path=None):

    self.path=path
    # defaults
    self.general_options={
      "online":True,
      "directory":None,
      "shuffle":False,
      "interval":30,
      "mode":"fill",
      "cycle":True
    }
    self.online_options={
      "shuffle":False,
      "interval":30,
      "tempfile":"/tmp/.tmp",
      "mode":"fill",
      "cycle":True,
      "imagelist":None,
      "directory":None
    }
    self.offline_options={
      "shuffle":False,
      "interval":30,
      "mode":"fill",
      "cycle":True,
      "directory":None
    }

    # parse functions
    section_parsers={
      "general":self.parse_gen,
      "offline":self.parse_off,
      "online":self.parse_on
    }

    # data types
    self.cast={
      "online":self.boolean,
      "directory":self.string,
      "shuffle":self.boolean,
      "interval":int,
      "mode":self.string,
      "cycle":self.boolean,
      "imagelist":self.string,
      "tempfile":self.string
    }

    # parse
    for section in config.sections():
      section_parsers[section.lower()](config._sections[section])


  def parse_gen(self, section):
    section=dict(section)
    section.pop("__name__")
    for k,v in section.items():
      if k in self.online_options:
        self.general_options[k]=self.cast[k](v)
        self.online_options[k]=self.cast[k](v)
        self.offline_options[k]=self.cast[k](v)
      else:
        print k
        self.general_options[k]=self.cast[k](v)

  def parse_off(self, section):
    section=dict(section)
    section.pop("__name__")
    for k,v in section.items():
      self.offline_options[k]=self.cast[k](v)

  def parse_on(self, section):
    section=dict(section)
    section.pop("__name__")
    for k,v in section.items():
      self.online_options[k]=self.cast[k](v)

  def boolean(self, s):
    return s.lower() == "true" or s == "1"

  def string(self, s):
    if not s:
      return ""

    if s[0] == '"' and s[-1] == '"':
      s=s[1:-1]

    if s[0] == "'" and s[-1] == "'":
      s=s[1:-1]
    return s

  def connected(self, host="8.8.8.8", port=53, timeout=2):
    try:
      socket.setdefaulttimeout(timeout)
      socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
      return self.general_options['online']
    except Exception as e:
      print e.message
      return False

  def get(self,key):
    default=self.general_options.get(key,None)
    if self.connected():
      return self.online_options.get(key, default)
    return self.offline_options.get(key, default)

  def set(self,key,value,online=None):
    if online == None:
      self.general_options[key]=value
    if online == True:
      self.online_options[key]=value
    if online == False:
      self.offline_options[key]=value
