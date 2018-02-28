import urlparse
import urllib

from lxml import etree
import requests

from selenium import webdriver

from subprocess import Popen
from os import devnull

browser = None

def empty(html):
    return html

class Path:
    def __init__(self, xpath, link=False, parse=empty, default=None, children=[], single=False):
        self.xpath = xpath
        self.children = children
        self.link = link
        self.parse = parse
        self.default = default
        self.single = single

class Page:
    def __init__(self, url, params={}, headers=None, js=False, load=False, tree=None):
        self.url = add_params(url,params)
        self.html = None
        self.tree = tree
        self.js = js
        self.params = params

        # better to warn than to fix right
        if js and headers:
            print "[-] Warning: Javascript enabled, headers ignored"

        if headers == None:
            self.headers = {
                "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                "Accept-Encoding":"gzip, deflate",
                "Accept-Language":"en-US,en;q=0.8",
                "Cache-Control":"max-age=0",
                "Connection":"keep-alive",
                "Upgrade-Insecure-Requests":"1",
                "User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
            }
        else:
            self.headers = headers

        if load:
            self.load()



    def load(self):
        global browser

        if self.html is None:
            if not self.js:
                res = requests.get(self.url, headers=self.headers)
                if res.status_code == 200:
                    self.html = res.text
            else:
                if not browser:
                    init_browser()

                browser.get(self.url)
                self.html = browser.execute_script("return document.body.innerHTML")

        if self.html and self.tree == None:
            self.tree = etree.HTML(self.html)

        return self.html

    def scroll_bottom(self):

        global browser

        if not browser:
            return

        browser\
            .execute_script("window.scrollTo(0, document.body.scrollHeight);")

        return browser.execute_script("return document.body.innerHTML")

    def reload_html(self):
        self.html = browser.execute_script("return document.body.innerHTML")
        self.tree = etree.HTML(self.html)
        return self.html


    def scroll(self, x, y):
        global browser

        if not browser:
            return

        browser\
            .execute_script("scroll({},{});".format(x,y))

        return browser.execute_script("return document.body.innerHTML")


def init_browser():

    global browser

    options = webdriver.ChromeOptions()
    options.add_argument('headless')
    options.add_argument("--window-size=1920x1080")

    browser = webdriver.Chrome(chrome_options=options)
    #browser = webdriver.Chrome()

init_browser()

def is_absolute(url):
    return bool(urlparse.urlparse(url).netloc)

def get_element(page,p,e):
    if not p.link or is_absolute(e):
        return p.parse(e)
    else:
        return p.parse(urlparse.urljoin(page.url,e))

def search(page,xpath):

    if page.tree == None:
        return []

    single = not isinstance(xpath,list)

    if single:
        xpath = [xpath]

    res = []
    for p in xpath:
        out = []
        for e in page.tree.xpath(p.xpath):

            tree=get_element(page,p,e)

            if p.children:
                out.append(search(Page(page.url,tree=tree),p.children))
            else:
                out.append(tree)

        if p.single:
            if len(out) > 0:
                out = out[0]
            else:
                out = ""

        res.append(out)

    if single:
        res = res[0]


    return res


def get(url,xpath,params={},js=False):

    page = Page(url,load=True)
    return search(page, xpath)

def add_params(url, params):

    urllib.unquote(url)
    parsed = urlparse.urlparse(url)
    args = parsed.query

    dargs = dict(urlparse.parse_qsl(args))
    dargs.update(params)
    dargs.update(
        {k: dumps(v) for k,v in dargs.iteritems()
            if isinstance(v, (bool,dict))}
    )

    enc = urllib.urlencode(dargs, doseq=True)

    return urlparse.ParseResult(
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, enc, parsed.fragment
    ).geturl()

def get_params(url):
    return dict(urlparse.parse_qs(urlparse.urlparse(url).query))


def open_url(url, options=[]):

    FNULL = open(devnull, 'w')

    args = ["google-chrome-stable", url]
    args.extend(options)

    Popen(
        args,
        stdout=FNULL,
        stderr=FNULL
    )

    FNULL.close()

def get_cookies():
    if not browser:
        return

    return browser.get_cookies()

def add_cookie(c):
    if not browser:
        return

    return browser.add_cookie(c)
