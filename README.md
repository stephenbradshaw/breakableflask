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


## Running breakableflask

Basic exeuction of the program is like so, this runs the web server at the default location of `http://127.0.0.1:4000` without connection to a database server for the SQL injection vulnerability.

    ./main.py

If you want to take advantage of the SQL injection vulnerability, you will need to run the program with database connection options. The full list of options can be found by running the program with the `--help` option, but as example, here is how you could connect to a PostgreSQL server:

    ./main.py --database_type=postgres --database_user='postgres' --database_pass=password --database_host=127.0.0.1 --database_port=5432

Breakableflask will attempt to populate the database server with the needed data to provide the SQL injection test bed. You can see the included `docker_database_setup.md` file for instructions on easily running various supported database engines using Docker. 

