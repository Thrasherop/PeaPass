# Misc imports
import cryptography
import os
import hashlib
import pyautogui as py
from time import sleep
import subprocess

# Modules for passwordToKey()
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Modules for encrypting
from cryptography.fernet import Fernet

# Modules for hashing
import argon2
from argon2 import PasswordHasher

import bcrypt

# Modules for overwriting memory (nuke function)
import sys
import ctypes


# Tutorial: https://nitratine.net/blog/post/encryption-and-decryption-in-python/

directory = "C:\\.PeaPass\\"


def nuke(var_to_nuke):
    """
    Nukes a variable by overwritting
    the location in memory with 0's
    """

    strlen = len(var_to_nuke)
    offset = sys.getsizeof(var_to_nuke) - strlen - 1
    ctypes.memset(id(var_to_nuke) + offset, 0, strlen)


def nukeDatabase():
    """
    Nukes a file by overwritting all data
    (name and contents) with o's
    Then it deletes the data
    """

    overWriteStr = 'lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll' * 30  # Creates a super long useless string

    db = getDB()

    # For each database entry
    for file in db:

        # Overwrites the contents
        with open(directory + file + '.peapass', 'w+') as f:
            f.write(overWriteStr)
            f.close()

        # Overwrites the name
        try:
            newDir = directory.replace('\\\\', '\\')
            newName = directory + 'oooooo' * 40
            curPath = newDir + file + '.peapass'
            os.rename(curPath, newName)
        except Exception as e:
            pass

        # Deletes reference
        try:
            os.remove(newName)
        except Exception as e:
            pass

    os.rmdir(directory)

    py.alert(text='Entire database has been deleted. PeaPass will now close', title='PeaPass')

    return 0


def passToKey(password):
    """
    Returns PBKDF2 key as a bytes object
    Using an inputed password
    This code is taken from the tutorial
    mentioned at the top of this file
    """

    password = password.encode()
    salt = b'{\x93\xecz\xac\x0b\xb9\x18\x83\x08\x81\xe87\xa6c\xbc'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once

    # nukes password
    nuke(password)

    return key


def encrypt(key, string):
    """
    Returns encrypted string using fernet
    This code is taken from the
    tutorial mentioned at the top
    of this file
    """

    message = string.encode()

    fernetObj = Fernet(key)
    encryptedBytes = fernetObj.encrypt(message)

    enString = encryptedBytes.decode()

    # Nukes the plaintext string
    nuke(string)
    del string

    return enString


def decrypt(key, string):
    """
    Decrypts a string via fernet
    and the inputed key
    This code is taken from the
    tutorial mentioned at the top
    of this file
    """

    # Encodes message to bytes
    # to please fernet
    message = string.encode()

    # Actually attempts to decrypt
    # If it fails it returns 255
    try:
        fernetObj = Fernet(key)
        decrypted = fernetObj.decrypt(message)
    except Exception as e:
        return str(e)

    # Decrypts the bytes string
    # so that a string is returned
    finalMessage = decrypted.decode()

    # Nukes sensitive vars
    nuke(key)
    del key

    return finalMessage


def argon2Hash(string):
    """
    Takes in a string
    and then hashes it
    using argon2
    """

    ph = PasswordHasher(time_cost=8, memory_cost=102400, parallelism=8, hash_len=18, salt_len=16, encoding='utf-8',
                        type=argon2.Type.ID)
    hash = ph.hash(string.encode())

    # nukes sensitive info
    nuke(string)
    del string

    return hash


def hash(string):
    """
    Returns string object of hash
    """

    salt = b'$2b$12$.TevUokdqIW6QCTu.zPf8e'
    hash = bcrypt.hashpw(string.encode(), salt)

    newHash = hash.decode()

    finalHash = sanitize(newHash)

    # Nuking variables right here means that the inputted strings
    # Are destroyed on a global basis. this causes issues since we
    # Still need these Vars. So don't nuke em


    return finalHash


def sanitize(string):
    # Replaces bad characters with
    # the following (to satisfy window's
    # rules):

    #       Essentially Binary wrapped in ! (0=!, 1=b)

    # /  -> !!!!!
    # \  -> !!!b!
    # :  -> !!b!!
    # *  -> !!bb!
    # ?  -> !b!!!
    # <  -> !b!b!
    # >  -> !bb!!
    # |  -> !bbb!

    sanStr = string

    # performs sanitization
    sanStr = sanStr.replace("/", "!!!!!")
    sanStr = sanStr.replace("\\", "!!!b!")
    sanStr = sanStr.replace(":", "!!b!!")
    sanStr = sanStr.replace("*", "!!bb!")
    sanStr = sanStr.replace("?", "!b!!!")
    sanStr = sanStr.replace("<", "!b!b!")
    sanStr = sanStr.replace(">", "!bb!!")
    sanStr = sanStr.replace("|", "!bbb!")

    return sanStr


def reverseSanitize(inStr):
    # Reverses the effects of the
    # function called sanitize()

    #       Essentially Binary wrapped in ! (0=!, 1=b)

    # /  <- !!!!!
    # \  <- !!!b!
    # :  <- !!b!!
    # *  <- !!bb!
    # ?  <- !b!!!
    # <  <- !b!b!
    # >  <- !bb!!
    # |  <- !bbb!

    # Performs sanitization
    sanStr = inStr.replace("!!!!!", "/")
    sanStr = sanStr.replace("!!!b!", "\\")
    sanStr = sanStr.replace("!!b!!", ":")
    sanStr = sanStr.replace("!!bb!", "*")
    sanStr = sanStr.replace("!b!!!", "?")
    sanStr = sanStr.replace("!b!b!", "<")
    sanStr = sanStr.replace("!bb!!", ">")
    sanStr = sanStr.replace("!bbb!", "|")


    return sanStr


def getDB():
    """
    Returns a list
    of all the encrypted
    database entries
    """

    # gets array of files
    fileList = os.listdir(directory)

    # Strips all fileNames of the
    # file extension ".peapass"

    # finishes process
    finalList = []
    for fileName in fileList:
        finalList.append(fileName.replace(".peapass", ""))

    return finalList


def login():
    """
    Performs a login attempt. If
    successful, it returns an
    encryption key
    """

    # Performs login inside a loop
    while True:

        inPassword = py.password(title="Input password", text="Please re-input your master password", mask="*")

        # Checks for exit
        if inPassword == None:
            return 0

        # Reads in master hash and checks if inPassword is correct
        f = open(directory + "master.peapass", "r")
        masterHash = f.read()
        f.close()

        # Attempts to verify hash
        try:
            PasswordHasher().verify(masterHash, inPassword)
            break
        except:
            usrChoice = py.confirm(text='Could not verify password', title='Access denied',
                                   buttons=['Try again', 'Exit'])
            if usrChoice == 'Exit' or usrChoice == None:
                return 0

    # Checks to see if rehash is needed
    if PasswordHasher().check_needs_rehash(masterHash):
        # Rehashes
        newHash = PasswordHasher().hash(inPassword)
        # Saves new hash
        f = open(directory + "master.peapass", "w+")
        f.write(newHash)
        f.close()

    key = passToKey(inPassword)

    return key


def addPassword():
    """
    Adds a password to the
    database
    """

    # gets list of encrypted database keywords
    db = getDB()

    # Handles login
    loginCode = login()
    if type(loginCode) == int:
        return loginCode
    elif type(loginCode) != bytes:
        return 255
    else:
        key = loginCode



    # Gets the Keyword & gets an encrypted version
    keyword = py.prompt(title='Input keyword',
                        text='Input the keyword for the password. This is what you will use to find the password in the database. This will usually be the website or company the password is for')

    # checks to see if user closed
    # the tab
    if keyword == None:
        return 0

    # Hashes enKeyword
    enKeyword = hash(
        keyword)  # NOTE: Fernet will generate a different string each time, even if the given string and key are the same. This means keywords need to be hashed instead of encrypted

    # Checks to make sure keyword doesn't already exist
    while enKeyword in db:

        # TODO:
        # Add an option to overwrite old keyword with new password

        keyword = py.prompt(title='Invalid keyword',
                            text='That keyword is already in the database. Please choose a different one')

        if keyword == None:
            return 0
        # Hashes new keyword
        enKeyword = hash(keyword)  # encrypt(key, keyword)

    # Gets new inputted password
    while True:

        pass1 = py.password(title='Input password', text='Input the password for "' + keyword + '"', mask='*')

        if pass1 == None:
            return 0

        pass2 = py.password(title='Confirm password', text='Please confirm your password for "' + keyword + '"',
                            mask='*')

        if pass1 == pass2:
            break
        elif pass1 == None:
            break
        else:
            exitCode = py.confirm(title='Passwords do not match', text='Passwords do not match',
                                  buttons=['Try again', 'Cancel'])

            if exitCode == 'Try again':
                continue
            else:
                return 0

    # Nukes keyword
    nuke(keyword)
    del keyword

    # Nukes pass2 cause its no longer needed
    nuke(pass2)
    del pass2

    # Encrypts the password and then
    # writes it to its file in database
    print(key)
    print(type(key))
    enPass = encrypt(key, pass1)

    # nukes pass1 and key
    nuke(pass1)
    del pass1

    nuke(key)
    del key

    with open(directory + enKeyword + ".peapass", "w+") as f:
        f.write(enPass)

    # Notifies user things were successful
    exitCode = py.alert(title='Success', text='Password added successfully')

    # Exits program if user closed the tab
    if exitCode == None:
        return 0

    # Nukes loginCode
    # NEW NUKE
    nuke(loginCode)
    del loginCode


def accessPassword():
    """
    Accesses a password in database
    """

    db = getDB()

    # Performs login attempt
    # Then processes login attempt
    loginCode = login()

    if type(loginCode) == int:
        return loginCode
    elif type(loginCode) != bytes:
        return 255
    else:
        key = loginCode


    # Gets keyword from user
    while True:

        keyword = py.prompt(title='Input keyword',
                            text='Input the keyword for the password you would like to access. This is usually the name of the website')

        if keyword == None:
            return 0

        enKeyword = hash(keyword)

        if enKeyword not in db:
            response = py.confirm(title='Keyword does not exist', text='Keyword does not exist in the database',
                                  buttons=['Try again', 'Cancel'])

            if response == None:
                return 0
            elif response == 'Cancel':
                return 10
            else:
                continue

        else:
            break

    # Nukes keyword
    nuke(keyword)
    del keyword

    # Opens keyword file and
    # reads in encrypted password
    with open(directory + enKeyword + '.peapass', 'r') as f:
        enPass = f.read()

    # Safely shows password to user
    usrChoice = py.confirm(title='Confirm',
                           text='Your password will be shown on screen. Make sure nobody else can see your screen and that no screen recording software is active',
                           buttons=['Continue', 'Cancel'])


    # NEW NUKES
    # Nukes logincode
    # NEW NUKE

    if usrChoice == None:
        # Nukes sensitive variables
        nuke(enPass)
        nuke(key)
        del key
        del enPass
        nuke(loginCode)
        del loginCode
        return 0
    elif usrChoice == 'Cancel':
        # Nukes sensitive variables
        nuke(enPass)
        nuke(key)
        del key
        del enPass
        nuke(loginCode)
        del loginCode
        return 10
    elif usrChoice == 'Continue':
        dePass = decrypt(key, enPass)
        py.alert(title='PeaPass', text='Password: ' + dePass, button='Done')

        # Nukes sensitive variables
        nuke(enPass)
        nuke(key)
        del key
        del enPass
        nuke(loginCode)
        del loginCode

        return 10


def changePassword():
    """
    Allows user to change a password
    """

    db = getDB()

    # Performs login attempt
    loginCode = login()

    if type(loginCode) == int:
        return loginCode
    elif type(loginCode) != bytes:
        return 255
    else:
        key = loginCode



    # Gets keyword from user
    while True:

        keyword = py.prompt(title='Input keyword', text='Input the keyword for the password you would like to delete.')

        if keyword == None:
            return 0

        # enKeyword = encrypt(key, keyword)
        enKeyword = hash(keyword)

        if enKeyword not in db:
            response = py.confirm(title='Keyword does not exist', text='Keyword does not exist in the database',
                                  buttons=['Try a different one', 'Cancel'])

            if response == None:
                return 0
            elif response == 'Cancel':
                return 10
            else:
                continue

        else:
            break



    # Gets new password and confirms it
    while True:

        pass1 = py.password(title='Input new password', text='Input the new password for ' + keyword, mask='*')

        if pass1 == None:
            return 0

        pass2 = py.password(title='Confirm new password', text='Please confirm new password for ' + keyword, mask='*')

        if pass2 == None:
            return 0

        if pass1 != pass2:
            usrInput = py.confirm(title='Passwords do not match', text='Passwords do not match',
                                  buttons=['Try again', 'Cancel'])

            if usrInput == None or usrInput == 'Cancel':
                return 0
            else:
                continue

        else:
            break

    # Gets confirmation
    confirmation = py.confirm(title='Are you sure?',
                              text='Are you sure you want to change this password? The old password will be lost forever',
                              buttons=['Yes, change password', 'No, keep old password'])

    # Processes confirmation
    if confirmation == None:
        return 0
    elif confirmation == 'Yes, change password':

        enPass = encrypt(key, pass1)

        with open(directory + enKeyword + '.peapass', 'w+') as f:
            f.write(enPass)

            py.alert(title='Password change succesful', text='Password has successfully been changed')

            return 10

    else:
        return 10

    # Nukes the plainText passwords
    nuke(pass1)
    nuke(pass2)
    del pass1
    del pass2

    # Nukes key and loginCode
    nuke(loginCode)
    del loginCode
    nuke(key)
    del key

    # Nukes keyword
    nuke(keyword)
    del keyword


def removePassword():
    """
    Removes a password
    """

    db = getDB()

    # Performs login attempt
    loginCode = login()
    if type(loginCode) == int:
        return loginCode
    elif type(loginCode) != bytes:
        return 255
    else:
        key = loginCode


    # Gets user keyword
    while True:

        keyword = py.prompt(title='Input keyword', text='Input the keyword for the password you would like to delete.')

        if keyword == None:
            return 0

        # enKeyword = encrypt(key, keyword)
        enKeyword = hash(keyword)

        if enKeyword not in db:
            response = py.confirm(title='Keyword does not exist', text='Keyword does not exist in the database',
                                  buttons=['Try a different one', 'Cancel'])

            if response == None:
                return 0
            elif response == 'Cancel':
                return 10
            else:
                continue

        else:
            break

            # Gets confirmation
    answer = py.confirm(title='Confirm', text='Are you sure you would like to delete your password for ' + keyword,
                        buttons=['Delete it', 'Cancel'])

    # Processes confirmation
    if answer == 'Cancel':
        return 10
    elif answer == None:
        return 0
    elif answer == 'Delete it':
        os.system("del " + directory + enKeyword + ".peapass")
        py.alert(title="Password deleted", text='Password has been deleted')
        return 10

    # Nukes key and loginCode
    nuke(loginCode)
    del loginCode
    nuke(key)
    del key
    nuke(keyword)
    del keyword


def verifyDataBase():
    """
    Function that verifies
    PeaPass has been set up
    """

    # Verifies master directory exists
    if not os.path.exists(directory):
        os.system("mkdir " + directory)

    # Verifies master hash file exists.
    # If it does not, then it prompts
    # the user to create one
    if not os.path.exists(directory + "master.peapass"):
        choice = py.confirm(title='Set up database',
                            text='It looks like a database hasn\'t been set up on this computer yet. Would you like to do so now?',
                            buttons=['Yes', 'Not now'])

        if choice == None:
            return 0

        elif choice == 'Not now':
            py.alert(title='Exiting PeaPass', text='Program will exit now')
            return 0

        while True:
            pass1 = py.password(title='Input password',
                                text='Please input your master password. This is the password you will use to access all other passwords, so make sure it is a long & strong password',
                                mask='*')

            pass2 = py.password(title='Confirm password', text='Please confirm your master password', mask='*')

            if pass1 == None or pass2 == None:
                return 0
            elif pass1 == pass2:
                break
            else:
                exitCode = py.confirm(title='Passwords do not match', text='Passwords do not match',
                                      buttons=['Try again', 'Exit'])

                if exitCode == 'Exit' or exitCode == None:
                    return 0
                else:
                    continue

        # Creates masterHash
        masterHash = argon2Hash(pass1)

        with open(directory + "master.peapass", "w+") as f:
            f.write(masterHash)

    # Nukes pass1 and pass2 if they exist

    if 'pass1' in locals():
        nuke(pass1)
        del pass1

    if 'pass2' in locals():
        nuke(pass2)
        del pass2


def deleteDatabase():
    """
    Process to delete entire database
    """

    # Variables to easily store
    # and compare user inputs
    dontDeleteStr = 'Do not delete'
    deleteStr = 'Delete entire database'
    cancelStr = 'Cancel'

    # Gets confirmation and processes it
    confirmation = py.confirm(text='Are you sure you want to delete the entire database?', title='PeaPass',
                              buttons=[dontDeleteStr, deleteStr, cancelStr])

    if confirmation == None:
        return 0
    elif confirmation == cancelStr or confirmation == dontDeleteStr:
        return 10
    elif confirmation == deleteStr:
        # Passes to exit the elif chain
        pass
    else:
        return 10

    # Performs login attempt
    loginCode = login()

    if type(loginCode) == int:
        return loginCode
    elif type(loginCode) != bytes:
        return 255
    else:
        key = loginCode


    # Confirms yet again
    confirmation = py.confirm(
        text='Are you sure you want to delete the entire database? This will delete ALL of your passwords and you will not be able to recover them.',
        title='PeaPass', buttons=[dontDeleteStr, deleteStr, cancelStr])

    if confirmation == None:
        return 0
    elif confirmation == cancelStr or confirmation == dontDeleteStr:
        return 10
    elif confirmation == deleteStr:
        # Passes to exit the elif chain
        pass
    else:
        return 10

    # Does a final check
    choice = py.confirm(text='All passwords will now be deleted pernamently', title='PeaPass',
                        buttons=['Just do it already', 'Cancel'])

    if choice == None:
        return 0
    elif choice == cancelStr or choice == dontDeleteStr:
        return 10
    elif choice == 'Just do it already':
        # Passes to exit elif chainf
        pass
    else:
        return 10

    # Performs the database nuke
    exitCode = nukeDatabase()

    # Nukes key and loginCode
    nuke(key)
    del key
    nuke(loginCode)
    del loginCode

    return exitCode


def databaseOptions():
    """
    Starts database options
    branch
    """

    # Gets mode from user
    mode = py.confirm(text='What would you like to do?', title='PeaPass',
                      buttons=['Delete database', 'Export database', 'Cancel'])

    exitCode = 1

    # Calls respective modes
    if mode == 'Delete database':
        exitCode = deleteDatabase()

    return exitCode


def GUI():
    # TODO
    # Create option for a custom database directory
    # Maybe use an installer to choose the directory
    # and then store that in Program Files

    # Verifies that there is a
    # an account has been set up
    exitCode = verifyDataBase()

    if exitCode == 0:
        return 0
    if exitCode == 255:
        return 255

    # Logs in. Loops if password doesn't match,
    # breaks loop if login is successful
    while True:

        inPassword = py.password(title="Input password", text="Input your master password", mask="*")

        if inPassword == None:
            return 0

        ##Reads in master hash and checks if inPassword is correct
        f = open(directory + "master.peapass", "r")
        masterHash = f.read()
        f.close()

        try:
            PasswordHasher().verify(masterHash, inPassword)
            break
        except:
            usrChoice = py.confirm(text='Could not verify password', title='Access denied',
                                   buttons=['Try again', 'Exit'])
            if usrChoice == 'Exit' or usrChoice == None:
                return 0

    # Checks if rehash is necessary
    if PasswordHasher().check_needs_rehash(masterHash):
        # Rehashes
        newHash = PasswordHasher().hash(inPassword)
        # Saves new hash
        f = open(directory + "master.peapass", "w+")
        f.write(newHash)
        f.close()

    # Deletes inPassword variable &
    # overwrites it to
    # prevent longterm storage of
    # plaintext password
    nuke(inPassword)
    del inPassword

    # Manages user menu
    while True:

        mode = py.confirm(title='Access Granted', text='Access granted. What would you like to do?',
                          buttons=['Log out', 'Add password', 'Access password', 'Remove password', 'Change a password',
                                   'Database options'])

        if mode == None or mode == 'Log out':
            return 0

        # Calls the appropriate function
        # for the user input
        elif mode == 'Add password':
            exitCode = addPassword()
        elif mode == 'Access password':
            exitCode = accessPassword()
        elif mode == 'Remove password':
            exitCode = removePassword()
        elif mode == 'Change a password':
            exitCode = changePassword()
        elif mode == 'Database options':
            # TODO
            # Build this
            # Have this option export
            # or delete entire database

            exitCode = databaseOptions()
            # print('exitCode(): ', exitCode)
            pass

        # Processes the exit code accordingly
        if exitCode == 0:
            return 0
        elif exitCode == 255:
            return 255
        elif exitCode == 10:
            continue


if __name__ == '__main__':

    # TODO:
    # Remove all #print statements
    # Nuke sensitive variables (inPassword, key, etc) as soon as they're not needed
    # Add limit to how many characters a user can input

    # Dictionary to hold all the exit codes
    # Not currently needed, but it looks good
    # in code
    exitCodes = {
        None: "Function ran succesfully",
        0: "User wants to exit program",
        1: "Function ran succesfully",
        4: "Exitcode reserved for handling main try catch near end of program",
        10: "Return to main menu",
        100: "Individual function failed",
        255: "Critical Failure, data intact"
    }

    # Runs GUI(), which is the main function
    try:
        exitCode = GUI()
    except Exception as e:
        py.alert(title='Error', text='A critical system failure has occured. Your data should be intact, but this program must close now\n\nError:' + str(e))
        exitCode = 4

    if exitCode != 0 and exitCode != 10:
        py.alert(title='Error', text='A critical system failure has occured. Your data should be intact, but this program must close now\n\nExitcode: ' + str(exitCode))




