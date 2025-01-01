import re
import requests

def check_password_strength(password):
    criteria = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "digit": bool(re.search(r'[0-9]', password)),
        "special_char": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    }
    score = sum(criteria.values())
    
if score == 5:
        strength = "Strong"
    elif score >= 3:
        strength = "Medium"
    else:
        strength = "Weak"

    return strength, criteria

def check_password_pwned(password):
    
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1_password[:5], sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{first5_char}"
    response = requests.get(url)

    if response.status_code != 200:
        return False, "Could not check password breach."

    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return True, f"Password found in {count} breaches!"

    return False, "Password is safe."

if __name__ == "__main__":
    import hashlib

    password = input("Enter your password to check: ")

    strength, details = check_password_strength(password)
    print(f"\nPassword Strength: {strength}")
    print("Details:")
    for criteria, passed in details.items():
        print(f"  - {criteria}: {'✔' if passed else '✘'}")

    pwned, message = check_password_pwned(password)
    print(f"\nPassword Breach Check: {'⚠️' if pwned else '✔'} {message}")
