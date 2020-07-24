from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import requests
import subprocess
from pathlib import Path
# from utils import sanitised_input
import base64
import argparse

parser = argparse.ArgumentParser(description='Encrypt messages with ssh keys.')
parser.add_argument('--priv', help='The path to the Private ssh key.', metavar='FILE',
                    type=argparse.FileType('r'), default=(Path.home() / ".ssh" / "id_rsa").resolve())
parser.add_argument('--pub', help='The path to the Public ssh key of the other correspondent.',
                    metavar='FILE', type=argparse.FileType('r'), default=None)
parser.add_argument(
    '--github', help='A GitHub username to get a public key from.')
parser.add_argument(
    '--priv_pw', help='Your Private key password (if needed).', default=None)

def get_publickey_from_file(path: Path):
    pKCS8key = subprocess.check_output(
        ["ssh-keygen", "-f", str(path), "-e", "-m", "PKCS8"])
    loaded_key = serialization.load_pem_public_key(
        pKCS8key, backend=default_backend())
    return loaded_key


def get_github_publickey(github_username):
    publickeys = []
    response = requests.get(f"https://github.com/{github_username}.keys")

    for i, line in enumerate(response.text.strip().split("\n")):
        p = Path(f"{github_username}_{i}.pub")
        with p.open("w+") as f:
            f.write(line)
        publickeys.append(get_publickey_from_file(p))
        p.unlink()

    print("Select key")
    for i, key in enumerate(publickeys):
        print(f"\t{i}. {key.key_size} bits")
    #selection = sanitised_input(
    #    "key number >", type_=int, min_=0, max_=len(publickeys) - 1) # commented out for sketchy copyright
    while True:
        selection = input("integer >")
        try:
            selection = int(selection)
            publickeys[selection]
            break
        except Exception as e:
            print("Please enter a valid number", e)
    return publickeys[selection]


def chunkstring(string, length=180):
    return (string[0+i:length+i] for i in range(0, len(string), length))


def encrypt(message, key):
    blocks = chunkstring(message)
    output = []
    for block in blocks:
        encrypted = str(base64.standard_b64encode(key.encrypt(
            bytes(block, encoding="utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ), encoding="utf-8")
        output.append(encrypted)
    return "|".join(output)


def decrypt(encrypted_message, private_key):
    blocks = encrypted_message.split("|")
    result = ""
    for block in blocks:
        result += str(private_key.decrypt(
            base64.standard_b64decode(bytes(block, "utf-8")),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ), encoding="utf-8")
    return result


def get_private_key_from_path(path: Path):
    with path.open("r") as f:
        privatekey = serialization.load_pem_private_key(
            bytes(f.read(), encoding="utf-8"),
            password=args.priv_pw,
            backend=default_backend()
        )
    return privatekey


args = parser.parse_args()
if not (args.pub or args.github):
    parser.error('No way to get Public Key, add --pub or --github')
if not Path(args.priv).exists():
    parser.error(
        'Private key couldnt be found, please specify Private key path with --priv')

publickey = None
if args.pub:
    publickey = get_publickey_from_file(Path(args.pub))
if args.github:
    publickey = get_github_publickey(args.github)
privatekey = get_private_key_from_path(Path(args.priv))

options = None
options_keys = {}

def my_public(_, privatekey):
    return str(privatekey.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH), encoding="utf-8")

def do_exit(*_):
    exit(0)

def do_help(key, *_):
    if len(key) > 0:
        print(options_keys[key]["help"])
    else:
        for option_dict in options:
            print(f"{str(option_dict['keys']).ljust(40)}{option_dict['help']}")
    return ""

options = [
    {
        "keys": ["s","e", "send", "encrypt"],
        "action": (encrypt, (publickey,)),
        "help":"Encrypt a message using the specified public key"
    },{
        "keys": ["r", "d", "recieve", "decrypt"],
        "action": (decrypt, (privatekey,)),
        "help":"Dencrypt a message using the specified private key"
    },{
        "keys": ["mine", "my_public"],
        "action": (my_public, (privatekey,)),
        "help":"Print out my public key"
    },{
        "keys": ["exit", "quit"],
        "action": (do_exit,),
        "help":"Exit the application"
    },{
        "keys": ["help", "h"],
        "action": (do_help,),
        "help":"Show this help message"
    }
]

for option_dict in options:
    for key in option_dict["keys"]:
        if key not in options_keys.keys():
            options_keys[key] = option_dict
        else:
            raise ValueError(f"Duplicate key '{key}' in options")

def match_options(input_string: str):
    try:
        option, string = input_string.split(" ", maxsplit=1)
    except ValueError:
        option, string = input_string, ""
    option = options_keys.get(option, None)
    if not option:
        return "Option not recognized, try 'help'"
    action = option["action"]
    if len(action) == 1:
        return action[0](string)
    else:
        func, args = action
        return func(string, *args)

while True:
    try:
        a = input("> ")
        print(match_options(a))
    except Exception as e:
        print("exc",e)