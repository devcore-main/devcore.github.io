import re

def validate_email(email):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email)

def validate_password(password):
    return len(password) >= 6

def validate_contact(name, email, msg):
    return all([name.strip(), email.strip(), msg.strip()])
