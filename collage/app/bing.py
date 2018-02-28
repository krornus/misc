from time import sleep
from json import loads
from itertools import chain
import engine

class Bing:
    def __init__(self, query):
        self.base = "https://www.bing.com/images/search"
        self.query = query
        self.images = []

        self.page = None

        self.path = engine.Path('//li/div/div[@class="imgpt"]',
            children=[
                engine.Path('./a/@m', parse=lambda x: loads(x)['murl'])
            ],
        )

    def get_images(self):

        self.page = engine.Page(self.base, params={"q": self.query}, js=True, load=True)
        self.images = self.search_page()

        return self.images

    def toggle(self):

        if not self.page:
            self.get_images()

        cname = "SRCHHPGUSR"

        cookie = None
        for c in engine.get_cookies():
            if c['name'] == cname:
                cookie=c

        if not cookie:
                engine.add_cookie({
                    'name' : cname,
                    'value' : 'ADLT=OFF',
                    'domain' : ".bing.com",
                })
        else:
            raise NotImplementedError


    def search_page(self):

        return [str(x[0][0]) for x in engine.search(self.page,self.path)]

    def scroll_images(self, wait=1):

        images = self.images

        delta = len(images)
        self.page.scroll_bottom()

        while len(images) == delta:
            self.page.reload_html()
            images = self.search_page()
            sleep(wait)

        self.images = images
        return images[delta:]

