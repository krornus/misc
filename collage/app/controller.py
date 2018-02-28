from flask import Flask, url_for, render_template, redirect, session, request
from app import app

from bing import Bing
import os

bing = Bing(None)
bing.toggle()

@app.route('/search', methods=["GET"])
def search():
    query = request.args.get("q")

    if not query:
        redirect('/index')

    bing.query = query
    images = bing.get_images()

    return render_template(
        "search.html",
        images=images,
        cache_bust=os.path.getmtime("app/static/style.css")
    )

@app.route('/index', methods=["GET"])
@app.route('/', methods=["GET"])
def index():
    return render_template(
        "search.html",
        images=[],
        cache_bust=os.path.getmtime("app/static/style.css")
    )

