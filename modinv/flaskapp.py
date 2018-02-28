import os
from datetime import datetime
from flask import Flask, request, flash, url_for, redirect, \
     render_template, abort, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):

    if not a or not m:
        return "Both numbers are required"
    try:
        a,m = int(a),int(m)
    except:
        return "Input values must be integers!"

    print a,m
    g, x, y = egcd(a, m)

    if g != 1:
        return 'Modular inverse does not exist!'
    else:
        return x % m


class MMIForm(FlaskForm):
    exp = StringField('exp', validators=[DataRequired()])
    mod = StringField('mod', validators=[DataRequired()])


app = Flask(__name__)
app.config.from_pyfile('flaskapp.cfg')

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/mmi", methods=["GET","POST"])
def mmi():
    form = MMIForm()

    return render_template('index.html', d=modinv(form.exp.data,form.mod.data))

if __name__ == '__main__':
    app.run()
