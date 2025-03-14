# 🤑 bunq.sh

**bunq.sh** is a succinct Bash script to interact with the [bunq API](https://doc.bunq.com/).
It provides device registration, and allows fetching balances for checking
and savings accounts.

## 📦 Requirements

- bash
- curl
- jq
- OpenSSL

## 🔧 Configuration

Set these environment variables or use command-line options:
- **BUNQ_CONFIG_HOME**: Defaults to `~/.config/bunq`
- **BUNQ_API_URL**: Defaults to `https://api.bunq.com`
- **BUNQ_API_KEY**: Your API key (required for registration; Pro subscription is required for API access)
- **BUNQ_PRIVKEY** & **BUNQ_PUBKEY**: Paths to your RSA keys (defaults to `$BUNQ_CONFIG_HOME/keys/{pub,priv}key.pem`)
- **BUNQ_DEVICE_NAME**: Defaults to `bunq.sh@HOSTANME`
- **BUNQ_SESSION_TOKEN**: Your active session token (or use **BUNQ_SESSION_TOKEN_FILE**)
- Optional flags: **DEBUG**, **JSON_OUTPUT**, **NO_COLOR**

## 🚀 Usage

```shell
./bunq.sh --help

# Registration flow (requires BUNQ_API_KEY; Pro subscription required)
./bunq.sh register -k YOUR_API_KEY

# Display user info
./bunq.sh -t YOUR_SESSION_TOKEN user-info

# Fetch balances (requires valid session token)
./bunq.sh -t YOUR_SESSION_TOKEN balances

# Get a new session token
./bunq.sh login -k YOUR_API_KEY -I INSTALLATION_TOKEN

# Execute a raw API call
./bunq.sh raw -t SESSION_TOKEN /v1/device-server
```

## 📚 References

- [bunq API Documentation](https://docs.bunq.com)
- **Note:** A bunq Pro subscription is required for API access.

## 📄 License

This project is licensed under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html).
