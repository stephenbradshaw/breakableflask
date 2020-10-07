#!/usr/bin/env python3
import os
import pickle
from base64 import b64decode,b64encode
from binascii import hexlify, unhexlify
from os import popen
from lxml import etree
import html
from Crypto.Cipher import AES
from Crypto import Random


from flask import Flask, request, make_response, render_template_string


app = Flask(__name__)

# Config stuff
KEY=Random.new().read(32) # 256 bit key for extra security!!!
BLOCKSIZE=AES.block_size
ADMIN_SECRET=Random.new().read(32) # need to keep this secret
APP_NAME = 'My First App'
APP_VERSION = '0.1 pre pre pre alpha'
APP_PHILOSOPHY = 'If at first you dont succeed, try, try again!'

CONFIG = {
    'encrypto_key' : b64encode(KEY),
    'secret_admin_value' : b64encode(ADMIN_SECRET),
    'app_name' : APP_NAME,
    'app_version' : APP_VERSION,
    'app_philosophy' : APP_PHILOSOPHY
}


def unpad(value, bs=BLOCKSIZE):
    #pv = ord(value[-1])
    pv = value[-1]
    if pv > bs:
        raise Exception('Bad padding')
    padding = value[-pv:]
    if len(padding) != pv or len(set([a for a in padding])) != 1:
        raise Exception('Bad padding')
    return value[:-pv]


def pad(value, bs=BLOCKSIZE):
    pv = bs - (len(value) % bs)
    return value + (chr(pv) * pv).encode()


def encrypt(value, key):
    iv = Random.new().read(BLOCKSIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_value = pad(value)
    return iv + cipher.encrypt(padded_value)


def decrypt(value, key):
    iv = value[:BLOCKSIZE]
    decrypt_value = value[BLOCKSIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(decrypt_value)
    return unpad(decrypted)



def rp(command):
    return popen(command).read()


@app.route('/')
def index():
    return """
    <html>
    <head><title>Vulnerable Flask App: """ + CONFIG['app_name'] +"""</title></head>
    <body>
        <p><h3>Functions</h3></p>
        <a href="/cookie">Set and get cookie value</a><br>
        <a href="/lookup">Do DNS lookup on address</a><br>
        <a href="/evaluate">Evaluate expression</a><br>
        <a href="/xml">Parse XML</a><br>
        <a href="/config">View some config items</a><br>
        <a href="/sayhi">Receive a personalised greeting</a><br>
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
        parser = etree.XMLParser(no_network=False, dtd_validation=False, load_dtd=True, huge_tree=True)
        #try:
        doc = etree.fromstring(xml.encode(), parser)
        parsed_xml = etree.tostring(doc).decode('utf8')
        #except:
            #pass
    return """
       <html>
          <body>""" + "Result:\n<br>\n" + html.escape(parsed_xml) if parsed_xml else "" + """
             <form action = "/xml" method = "POST">
                <p><h3>Enter xml to parse</h3></p>
                <textarea class="input" name="xml" cols="40" rows="5"></textarea>
                <p><input type = 'submit' value = 'Parse'/></p>
             </form>
          </body>
       </html>
       """


# padding oracle
@app.route('/config', methods = ['GET'])
def config():
    key = None
    config_out = None
    decrypted_key = None
    key = request.args.get('key')
    viewable = [a for a in CONFIG.keys() if a.startswith('app_')]
    crypt = lambda x : hexlify(encrypt(x.encode(), KEY)).decode('utf8')
    configs = '\n'.join(['<a href="/config?key=%s">%s</a><br>' %(crypt(a), a ) for a in viewable])
    unviewable = [a for a in CONFIG.keys() if not a.startswith('app_')]
    nconfigs = '\n'.join(['%s - Not Viewable<br>' %(a) for a in unviewable])
    if key:
        try:
            kv = unhexlify(key)
            decrypted_key = decrypt(kv, KEY).decode('utf8')
        except Exception as e:
            return str(e)
        
        if decrypted_key and decrypted_key in CONFIG.keys():
            config_out = CONFIG[decrypted_key]

    return """
    <html>
      <body>
         <p><h3>Select config value to view</h3></p>
        """ + configs + "\n" + nconfigs + """
        """ + ('\n<br><br>Config value:<br><b>' + decrypted_key + '</b>: <i>' + config_out + '</i><br>\n' if decrypted_key else '') + """
      </body>
    </html>
    """


# server side template injection
@app.route('/sayhi', methods = ['POST', 'GET'])
def sayhi():
   name = ''
   if request.method == 'POST':
      name = '<br>Hello %s!<br><br>' %(request.form['name'])

   template = """
   <html>
      <body>
         <form action = "/sayhi" method = "POST">
            <p><h3>What is your name?</h3></p>
            <p><input type = 'text' name = 'name'/></p>
            <p><input type = 'submit' value = 'Submit'/></p>
         </form>
      %s
      </body>
   </html>
   """ %(name)
   return render_template_string(template)


if __name__ == "__main__":
    app.run(host='localhost', port=4000)

