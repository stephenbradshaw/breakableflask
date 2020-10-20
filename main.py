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
import argparse
import sys


from flask import Flask, request, make_response, render_template_string

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

DATABASE_NAME = 'breakdb'

DATABASE_TABLES = [
    {
        'table_name' : 'public_stuff',
        'columns': [
            {'name' : 'id', 'datatype' : 'integer', 'nullable': False},
            {'name' : 'name', 'datatype' : 'varchar(40)', 'nullable': True},
            {'name' : 'category', 'datatype' : 'varchar(20)', 'nullable': False},
            {'name' : 'description', 'datatype' : 'varchar(400)', 'nullable': True}
        ]
    },
    {
        'table_name' : 'secret_stuff',
        'columns' : [
            {'name' : 'name', 'datatype' : 'varchar(40)', 'nullable': True},
            {'name' : 'description', 'datatype' : 'varchar(400)', 'nullable': True}
        ]
    }
]

# table columns must be specified in DATABASE_TABLES structure with column names in the list in the same order as below
DATABASE_CONTENTS = {
    'public_stuff' : [
        (1, 'Military grade encryption', 'products', 'Dont let your data be compromised, use our patented exabit encryption technology that secures your data so well even you cant read it'),
        (2, 'Advanced APT Detection', 'products', 'Fully next-gen big-data backed threat analysis with extra AI that detects TTPs, C2s, Malwares and SIEMs'),
        (3, 'Internet of things', 'whitepapers', 'Check out our cyber strategies to survive the next cyber fight on the new cyber battleground in the ongoing cyber war'),
        (4, 'Enterprise version', 'solutions', 'Our most cost efficient solution for all your cyber concerns featuring the best value for money, the most effective breaking of the kill chain and the greatest ROI'),
        (5, 'Zero trust network', 'whitepapers', 'Secure your network from those with nefarious intent, like cyber criminals, cyber spies, cyber hackers and your own internal staff'),
    ],
    'secret_stuff' : [
        ('My first secret', 'None of these things actually work'),
        ('Second secret', 'Our DLP product is a single regex'),
        ('Secret three', 'Its too secret to even include here')
    ]
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


app = Flask(__name__)

# Main index
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
        <a href="/listservices">List our products and services</a><br>
    </body>
    </html>
    """


# 1. Cookie setter/getter
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



# 2. DNS lookup
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

    
# 3. Python expression evaluation
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



# 4. XML Parser
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


# 5. View application configuration settings 
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


# 6. Receive personalised greeting
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


# 7. List products and services
@app.route('/listservices', methods = ['GET'])
def listservices():
    param = 'category'
    category = None
    category = request.args.get(param)
    columns = [b['name'] for b in [a for a in DATABASE_TABLES if a['table_name'] == 'public_stuff'][0]['columns']]
    column_html = '\n'.join(['<th>{}</th>'.format(a) for a in columns])
    where = ''
    if category:
        where = " WHERE {} = '{}'".format(param, category)
    
    try:
        cursor.execute(query_build('SELECT * from public_stuff{}'.format(where)))
        results = cursor.fetchall()
    except Exception as e:
        return str(e)
    
    linker = lambda x,y : '<a href="/listservices?{}={}">{}</a>'.format(param, y, y) if x==columns.index(param) else str(y)
    results_html = '<tr>\n<td>' + '</tr>\n<tr>\n<td>'.join(['</td>\n<td>'.join([linker(c, b) for b, c in zip(a, range(0,len(a)))]) for a in results]) + '\n</tr>'
    
    return """
    <html>
        <body>
        <h1>Products and services</h1><br>
        <p>See below for our list of products and services. Click on a category to filter results.</p>
        <br><br>
        <table>
        <tr>""" + column_html + """
        </tr>""" + results_html + """
        </table>
        </body>
    </html>
    """
    

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, help='Listen port. Default: 4000', default=4000)
    parser.add_argument('-a', '--address', type=str, help='Listen address. Default: 127.0.0.1', default='127.0.0.1')
    parser.add_argument('-d', help='Debug level', action="count", default=0)
    parser.add_argument('--database_type', help='Database type. Default: sqlite', default='sqlite', choices=['postgres', 'oracle', 'mysql', 'mssql', 'sqlite'])
    parser.add_argument('--database_user', type=str, help='Database username. Default: None', default=None)
    parser.add_argument('--database_password', type=str, help='Database username.  Default: None', default=None)
    parser.add_argument('--database_host', type=str, help='Database hostname. Default: None', default=None)
    parser.add_argument('--database_port', type=int, help='Database port. Default: None', default=None)
    parser.add_argument('--database_filename', type=str, help='Database filename (sqlite only). Default: :memory:', default=':memory:')
    parser.add_argument('--oracle_lib_dir', type=str, help='Location of Oracle client libraries, needed for Oracle database connectivity', default='/opt/local/lib/oracle')


    args = parser.parse_args()

    query_build = lambda x: x if args.database_type == 'oracle' else x + ';' # why must you be this way Oracle?

    if args.database_type in ['mysql', 'mssql']:
        autocommit = lambda x : x.autocommit(True)
    if args.database_type == 'postgres':
        import psycopg2 as dbmodule
        def autocommit(x):
            x.autocommit = True
        list_databases_query = 'SELECT datname FROM pg_database;'
        list_tables_query = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name;"
    if args.database_type == 'mysql':
        import pymysql as dbmodule
        list_databases_query = 'SHOW databases;'
        list_tables_query = 'SHOW tables;'
    if args.database_type == 'mssql':
        import pymssql as dbmodule
        list_databases_query = 'SELECT name FROM sys.databases;'
        list_tables_query = 'SELECT name FROM sys.tables;'
    if args.database_type == 'sqlite':
        import sqlite3 as dbmodule
        list_tables_query = "SELECT name FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';"
    if args.database_type == 'oracle':
        import cx_Oracle as dbmodule
        dbmodule.init_oracle_client(args.oracle_lib_dir)
        list_tables_query = 'SELECT table_name FROM all_tables'

    try:
        if args.database_type not in ['sqlite', 'oracle']:
            connection_params = {a.replace('database_', ''): getattr(args, a) for a in dir(args) if a in ['database_user', 'database_host', 'database_password', 'database_port']}
            connection = dbmodule.connect(**connection_params)
            autocommit(connection)
            cursor = connection.cursor()
            cursor.execute(list_databases_query)
            r = [a[0] for a in cursor.fetchall() if a[0] == DATABASE_NAME]
            if not r: # create database if it doesnt exist
                cursor.execute("CREATE DATABASE {};".format(DATABASE_NAME))
            cursor.close()
            connection.close()
            connection_params['database'] = DATABASE_NAME
            connection = dbmodule.connect(**connection_params) # reconnect in new database context
            autocommit(connection)
        elif args.database_type == 'oracle': 
            connection_params = {a.replace('database_', ''): getattr(args, a) for a in dir(args) if a in ['database_user', 'database_password']}
            connection_params['dsn'] = '{}:{}'.format(args.database_host, args.database_port)
            connection = dbmodule.connect(**connection_params)
            connection.autocommit = 1
        elif args.database_type == 'sqlite':
            connection = dbmodule.connect(args.database_filename, check_same_thread=False)
            connection.isolation_level = None # autocommit
        else: # shouldnt happen
            print('Invalid database type selected: {}'.format(args.database_type))
            sys.exit(1)

        cursor = connection.cursor()
        cursor.execute(list_tables_query)
        existing_tables = [a[0].lower() for a in cursor.fetchall()]
        for table in [a for a in DATABASE_TABLES if a['table_name'].lower() not in existing_tables]: # create missing tables
            inner = ', '.join([' '.join([ (lambda x : x if isinstance(x, str) else 'NULL' if x else 'NOT NULL')(a[b]) for b in ['name', 'datatype', 'nullable'] ]) for a in table['columns'] ])
            cursor.execute(query_build('CREATE TABLE {} ({})'.format(table['table_name'].lower(), inner)))
            for data in DATABASE_CONTENTS[table['table_name']]: # insert data into table 
                columns = ', '.join([a['name'] for a in table['columns']])
                values = ', '.join([(lambda x: str(x) if isinstance(x, int) else "'{}'".format(x.replace("'", "\\'")))(a) for a in data])
                cursor.execute(query_build('INSERT INTO {} ({}) VALUES ({})'.format(table['table_name'], columns, values)))
    except Exception as e:
        print('An error ocured during database connection/setup: {}'.format(e))
        sys.exit(1)
    
    app.run(host=args.address, port=args.port)
