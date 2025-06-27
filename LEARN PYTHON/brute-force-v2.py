#!/usr/bin/env python3

# importing the sys module so that we can
# use command line arguments for targetURL
import sys

try:
	# Banner
	print("""
	--------------------------------
	    Web App Brute Force Tool    
	--------------------------------
	""")

	# Take in Target URL from command line argv[1]
	targetURL = sys.argv[1]

	# Print target URL to terminal
	print("Target URL:",targetURL)

except:
	print("[!] No Target URL Specified!")
	print("[!] Usage: ./brute-force.py http://target-url")
