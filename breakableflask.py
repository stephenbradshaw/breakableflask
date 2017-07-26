#!/usr/bin/env python

import ssl
import os
import pickle
from base64 import b64decode,b64encode
from os import popen
from lxml import etree
import cgi

from flask import Flask, request, make_response


app = Flask(__name__)


def rp(command):
    return popen(command).read()


@app.route('/')
def index():
    return """
    <html>
    <head><title>Vulnerable Flask App</title></head>
    <body>
        <p><h3>Functions</h3></p>
        <a href="/cookie">Set and get cookie value</a><br>
        <a href="/lookup">Do DNS lookup on address</a><br>
        <a href="/evaluate">Evaluate expression</a><br>
        <a href="/xml">Parse XML</a><br>
    </body>
    </html>
    """


# code injection
@app.route('/evaluate', methods = ['POST', 'GET'])
def evaluate():
    expression = None
    if request.method == 'POST':
        expression = request.form['expression']
    return """
    <html>
       <body>""" + "Result: " + (str(eval(expression)).replace('\n', '\n<br>')  if expression else "") + """
          <form action = "/evaluate" method = "POST">
             <p><h3>Enter expression to evaluate</h3></p>
             <p><input type = 'text' name = 'expression'/></p>
             <p><input type = 'submit' value = 'Evaluate'/></p>
          </form>
       </body>
    </html>
    """



# os command injection
@app.route('/lookup', methods = ['POST', 'GET'])
def lookup():
    address = None
    if request.method == 'POST':
        address = request.form['address']
    return """
    <html>
       <body>""" + "Result:\n<br>\n" + (rp("nslookup " + address).replace('\n', '\n<br>')  if address else "") + """
          <form action = "/lookup" method = "POST">
             <p><h3>Enter address to lookup</h3></p>
             <p><input type = 'text' name = 'address'/></p>
             <p><input type = 'submit' value = 'Lookup'/></p>
          </form>
       </body>
    </html>
    """

    

# deserialisation vulnerability
@app.route('/cookie', methods = ['POST', 'GET'])
def cookie():
    cookieValue = None
    value = None
    
    if request.method == 'POST':
        cookieValue = request.form['value']
        value = cookieValue
    elif 'value' in request.cookies:
        cookieValue = pickle.loads(b64decode(request.cookies['value'])) 
    
        
    form = """
    <html>
       <body>Cookie value: """ + str(cookieValue) +"""
          <form action = "/cookie" method = "POST">
             <p><h3>Enter value to be stored in cookie</h3></p>
             <p><input type = 'text' name = 'value'/></p>
             <p><input type = 'submit' value = 'Set Cookie'/></p>
          </form>
       </body>
    </html>
    """
    resp = make_response(form)
    
    if value:
        resp.set_cookie('value', b64encode(pickle.dumps(value)))

    return resp


# xml external entities and DTD
@app.route('/xml', methods = ['POST', 'GET'])
def xml():
    parsed_xml = None
    if request.method == 'POST':
        xml = request.form['xml']
        parser = etree.XMLParser(no_network=False, dtd_validation=True)
        try:
            doc = etree.fromstring(str(xml), parser)
            parsed_xml = etree.tostring(doc)
        except:
           pass
    return """
    <html>
       <body>""" + "Result:\n<br>\n" + cgi.escape(parsed_xml)  if parsed_xml else "" + """
          <form action = "/xml" method = "POST">
             <p><h3>Enter xml to parse</h3></p>
             <textarea class="input" name="xml" cols="40" rows="5"></textarea>
             <p><input type = 'submit' value = 'Parse'/></p>
          </form>
       </body>
    </html>
    """


app.run('localhost', 4000, app)

