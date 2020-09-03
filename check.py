import requests
import hashlib
import sys
import re

# function to send data to api
# returns a tails of password which starts with first_chars
def request_api_data(first_chars):
	url = 'https://api.pwnedpasswords.com/range/' + first_chars
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
	return res

# function to check how many times hash_to_check was found in hashes
def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

# function to check password if it exists in API response
def pwned_api_check(password):
	# hashing password with sha1
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	# checking first 5 letters
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first5_char)
	return get_password_leaks_count(response, tail)

# function to read checking passwords from txt file
def read_from_files(file_name):
	valid_pattern = re.compile(r"[a-zA-Z0-9\.\_\,\-]{1,}\.txt")
	if not valid_pattern.fullmatch(file_name):
		raise Exception(f"Wrong name of file : {file_name}")
	with open(file_name, 'r') as file:
		passwords = file.read()
	return passwords.split()

def main(args):
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times')
		else:
			print(f'{password} was NOT found')
	return 'done!'

if __name__ == '__main__':
	try:
		sys.exit(main(read_from_files(sys.argv[1])))
	except Exception as err:
		print(err)
