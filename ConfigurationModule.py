import json
import re

bad_passwords = ["123456",
                 "ABCDEF",
                 "abcdef"]

def read_conf():
        return{
            "passwordLength": 10,
            "passwordContent": ["A-Z", "a-z", "0-9", "!@#$%^&*"],
            "history": 3,
            "loginAttempts": 3,
            "dictionaryDenial": False
        }


def check_password(password):
    configuration = read_conf()

    # Make sure the password isnt in the dict if the dict deinal is false
    if(configuration['dictionaryDenial'] == "False" and password in bad_passwords):
        return False


    password_regex_p1 = ('').join('(?=.*[{0}])'.format(w) for w in configuration["passwordContent"])
    password_regex_p2 = '([' + ('').join(configuration["passwordContent"]) + '])+'

    full_regex = password_regex_p1 + password_regex_p2

    return re.fullmatch(full_regex, password) is not None


