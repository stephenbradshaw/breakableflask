# Breakable Flask


A simple vulnerable Flask application.

This can be used to test out and learn exploitation of common web application vulnerabilities. 

Originally written because I wanted a very simple, single file vulnerable app that I could quickly run up to perform exploitation checks against. 

At the moment, the following vulnerabilities are present:
* Python code injection
* Operating System command injection
* Python deserialisation of arbitrary data (pickle)
* XXE injection
* Padding oracle
* Server side template injection
* SQL injection


New vulnerabilities may be added from time to time as I have need of them.

## Installing dependant Python modules

There is a "requirements.txt" file included so you can install the required Python modules, but you can also just check the code or watch errors when starting to work this out. The code has recently been updated for Python3.

You can install the modules using pip like so:

    pip install -r requirements.txt


## Running the server

If you want to take advantage of the SQL injection vulnerability, you will need to be running an appropriate database server and run the program with options similar to those below:


    /main.py --database_type=postgres --database_user='postgres' --database_pass=password --database_host=127.0.0.1 --database_port=5432


Otherwise run like so to do without SQL injection (and without the database server requirement):

    /main.py


The server will start at `http://127.0.0.1:4000`. There is a help option `--help` to see supported options, which will allow you to change bind details, etc.


If youre using the database, on initial run the server will populate it with some data.


## Run the database server using docker


You can use docker to create a suitable postgres server like so

    docker run -d --name postgres -e POSTGRES_PASSWORD=password -p 5432:5432 postgres


Use the following to run the server after the initial launch. 

    docker start postgres
