# RSA-message-encrypt
Encrypt your messages with RSA, or decrypt messages you got from someone else. Usefull for sending passwords or other private info over insecure platforms.

## Usage

```
usage: main.py [-h] [--priv FILE] [--pub FILE] [--github GITHUB]

Encrypt messages with ssh keys.

optional arguments:
  -h, --help       show this help message and exit
  --priv FILE      The path to the Private ssh key.
  --pub FILE       The path to the Public ssh key of the other correspondent.
  --github GITHUB  A GitHub username to get a public key from.
```

you may be promted to select a specific public key, if github knows multiple for the person

you can also specify the path to a saved key. if you dont have a private key in your .ssh folder it will prompt for that

then you get a simple prompt where you can do a few things, for example

encrypt a message (using the public key) with any of these commands: s, e, send, encrypt
decrypt a message (using your pivate key) with any of these commands: r, d, recieve, decrypt
print your own private key: mine, my_public
exit with: exit, quit
help with: help, h

PS: this was done in a few hours, so its very raw.