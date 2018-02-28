import requests
from bs4 import BeautifulSoup

url="http://www.garykessler.net/library/file_sigs.html"
r=requests.get(url)
soup=BeautifulSoup(r.text,"lxml")

table=soup.find("table")
rows=table.find_all("tr")[2::]
for (sig,ftype) in zip(rows[::2], rows[1::2]):
    print "-"*80
    print "{},\n\t{}".format(sig,ftype)
    print "-"*80
    break
