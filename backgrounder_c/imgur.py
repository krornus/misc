import requests
import argparse
import json
from bs4 import BeautifulSoup
import re


def get_images(url, min_height=0, min_width=0, 
                    max_height=-1, max_width=-1, 
                    height=-1, width=-1):

  gallery_base="http://imgur.com/ajaxalbums/getimages/{}/hit.json"

  routes = [
    "^https?://imgur.com/gallery/([^/]+)$",
    "^https?://imgur.com/r/[^/]+/([^/]+)$",
    "^https?://imgur.com/([^/]+)$",
    "^https?://imgur.com/t/[^/]+/([^/]+)$",
    "^https?://imgur.com/a/([^/]+)$",
    "^https?://(?:i\.)?imgur.com/([^/]+)$",
  ]

  response = requests.get(url)
  html = response.text

  rel = ""

  for route in routes:
    m = re.search(route, url)
    if m:
      rel=m.group(1)

  if not rel:
    print "Couldn't find imgur id from url {}".format(url)
    print "If the id is in the url, add a regular expression to routes"
    exit(1)

  soup = BeautifulSoup(html, "lxml")
  images=[]

  gallery_url = gallery_base.format(rel)
  gallery_base.format(rel)
  json_res = requests.get(gallery_url)
  gallery = json.loads(json_res.text)
  
  if gallery['data']:
    if 'images' in gallery['data']:
      images=gallery['data']['images']
    images=[ 'http://i.imgur.com/'+x['hash']+x['ext'] for x in images ]
  else:
    images = []
    for img in soup.find_all("div", {"class":"post-image-container"}):
      soup=BeautifulSoup(str(img), "lxml")
      image=soup.find("img")
      if image:
        images.append("http:"+image["src"])
      elif img:
        #slow last resort
        images+=get_images("http://i.imgur.com/" + img['id'])

  return images 


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("url")
  args = parser.parse_args()

  for img in get_images(args.url):
    print img

