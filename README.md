# PeaPass
<br><br>




## Description
<br>
PeaPass is an open source password manager that is licensed under The
MIT License (see LICENSE.txt). It allows the user to securely store 
a password under a single keyword (i.e. the website name).

## Installation and Usage

<Br>
Installation is fairly straight forward: clone the repository. To run the
program first pip install the required modules (see dependancies), then 
run main.py (make sure you have Python3 installed on your system). You can 
also specify the storage directory to put the database by replacing the path 
under the "directory" variable. 

## Dependencies
<br>
There's a few Python Modules that this software requires. Namely, it needs
the cryptography, argon2, bcrypt, tkinter, and pyautogui. To install these via pip,
run the following lines in the command line:
<br><br>
pip3 install cryptography <br>
pip3 install argon2-cffi <br>
pip3 install bcrypt <br>
pip3 install pyautogui <br> 
pip3 install tk <br>

## Security details
PeaPass uses the ARGON2-ID hashing algorithm to store the master password. 
The parameters for the hashing are as follows: <br> <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;time_cost=8 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;memory_cost=102400 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;parallelism=8 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;hash_len=18 <br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;salt_len=16

These parameters in ARGON2-ID should be more than sufficient to protect 
against many (if not all) brute force, dictionary, or rainbow table attacks.
Argon2 essentially does this by requiring certain amounts of resources for 
every hash, such as requiring ~104 MB per hash. This is simply too expensive
for hash cracking. For more details, [See the documentation on argon2](https://argon2-cffi.readthedocs.io/en/stable/parameters.html)

All other passwords are encrypted using the cryptography module. The 
encryption key is generated processing the master password through the PBKDF2 
algorithm. Passwords and Keywords are both encrypted via fernet and stored in 
the directory alongside the master.PeaPass file. 