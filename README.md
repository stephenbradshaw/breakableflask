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


New vulnerabilities may be added from time to time as I have need of them.

Theres a "requirements.txt" file included so you can install the required Python modules. The code has recently been updated for Python3.

Install using:

    pip install -r requirements.txt
