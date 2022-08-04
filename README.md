# FenKeysManagement

Simple key management. Generate tokens for any usage.

FenKeysManagement is a simple tool for manage and generate tokens that can be
used in different applications. Like for example a flask API.

## Usage

### Key management

For managing your keyfile you have a command `fenkm` where you can add, see and revoke tokens.

```
usage: fenkm [-h] [genkey ...] [revokekey ...] [listkeys ...]

Simple key management. Generate tokens for any usage.

positional arguments:
  genkey      Generate a new key. Optional argument comment in the format comment=<comment>
  revokekey   Revoke a key. The format should be <key>=<value> where <key> cant be the id or the key directly
  listkeys    List all the key available

options:
  -h, --help  show this help message and exit
```
### Module usage

As an example, here is a snippet of how I use this in some flask applications.
This is not a working flask application, don't copy past without understanding it.

```
import json

from fenkeysmanagement import KeyManager

# ... more imports and flask related code

key_manager = KeyManager()

# .. more flask related code

def check_perms(request):
    data_str = request.data.decode('utf-8')
    try:
        data_json = json.loads(data_str)
        if "auth_key" in data_json.keys():
            key_manager.reload_keys()
            if not key_manager.key_revoked(data_json['auth_key']):
                return True
        return False
    except json.decoder.JSONDecodeError:
        return False

# ... more flask related code

@app.route("/", methods=["POST"])
def home():
    if not check_perms(request):
        # ... code for handle the failed auth verification
    # ... code for handle the real request after correct auth verification

# ... more flask related code

```
