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
	r = requests.get(targetURL)
	print("[*] Target URL:",targetURL)
	print("[*] Response Code:", r.status_code)
except:
	print("[!] Issue with Target URL")
	print("[!] Usage: ./brute-force.py https://target-url")
	print("[!] CHECK YOUR URL!")
