import requests, sys, hashlib, json

"""
A client to check securely whether your password has been leaked in plaintext in any of the recent password dumps.
This client uses the concept of key anonymity by sharing with an HTTP GET request just the first 5 hex characters
of the SHA1 hash of your inline password with the pwnedpasswords.com API and then locally checks for matches.
"""

sha_pwd = hashlib.sha1(sys.argv[1].encode())
print('The SHA1 digest of the entered password is {}'.format(sha_pwd.hexdigest()))
key = sha_pwd.hexdigest()[0:5]
url = 'https://api.pwnedpasswords.com/range/'+key

request = requests.get(url)
result = request.text.split('\r\n')
leaked = False
count = 0
for line in result:
    dig = line.split(':')[0].lower()
    if dig == sha_pwd.hexdigest()[5:]:
        leaked = True
        count = line.split(':')[1]

if leaked:
    print("The password has been leaked in plaintext {} times in various password banks. Consider immediately changing your password".format(count))
else:
    print('The password doesn\'t seem to have been leaked yet. Good job!')