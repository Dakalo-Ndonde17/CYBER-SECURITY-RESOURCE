
#!/usr/bin/env python3

# importing the sys module so that we can
# use command line arguments for targetURL
import sys

# importing requests library to contact targetURL
import requests

if len(sys.argv) > 1:
	# Banner
	print("""
	--------------------------------
	    Web App Brute Force Tool    
	--------------------------------
	""")

	# Take in Target URL from command line argv[1]
	targetURL = sys.argv[1]
	r = requests.get(targetURL)
	# Print target URL to terminal
	print("[*] Target URL:",targetURL)
	print("[*] Response Code:", r.status_code)

else:
	# Banner
	print("""
	--------------------------------
	    Web App Brute Force Tool    
	--------------------------------
	""")
	
	targetURL = input("Enter Target URL: ")
	r = requests.get(targetURL)
	print("[*] Target URL:",targetURL)
	print("[*] Response Code:", r.status_code)
