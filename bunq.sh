#!/usr/bin/env bash

# API docs: https://doc.bunq.com/
# Response codes are described here: https://beta.doc.bunq.com/basics/errors

# Default configuration
BUNQ_API_URL_PROD=https://api.bunq.com
BUNQ_API_URL_SANDBOX=https://public-api.sandbox.bunq.com
BUNQ_API_URL="${BUNQ_API_URL:-${BUNQ_API_URL_PROD}}"

BUNQ_CONFIG_HOME="${XDG_CONFIG_HOME:-${HOME}/.config}/bunq"
BUNQ_PRIVKEY="${BUNQ_PRIVKEY:-${BUNQ_CONFIG_HOME}/keys/privkey.pem}"
BUNQ_PUBKEY="${BUNQ_PUBKEY:-${BUNQ_CONFIG_HOME}/keys/pubkey.pem}"

BUNQ_API_KEY="${BUNQ_API_KEY:-}"
BUNQ_DEVICE_NAME="${BUNQ_DEVICE_NAME:-$(basename "$0")@$(uname -n)}" # bunq.sh@hostname
BUNQ_SESSION_TOKEN="${BUNQ_SESSION_TOKEN:-}"
BUNQ_SESSION_TOKEN_FILE="${BUNQ_SESSION_TOKEN_FILE:-${BUNQ_CONFIG_HOME}/session_token}"
BUNQ_INSTALLATION_TOKEN="${BUNQ_INSTALLATION_TOKEN:-}"
BUNQ_INCLUDE_EXT_ACCOUNTS="${BUNQ_INCLUDE_EXT_ACCOUNTS:-}"

DEBUG=${DEBUG:-}
JSON_OUTPUT=${JSON_OUTPUT:-}
NO_COLOR="${NO_COLOR:-}"
STORE_SESSION_TOKEN=${STORE_SESSION_TOKEN:-}
QUIET=${QUIET:-}

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] <command>

Options:
  -h, --help                      Show this help message and exit
  -d, --debug                     Enable debug output
  -t, --trace                     Enable shell tracing
  -j, --json                      Output raw JSON data
  -k, --api-key KEY               Set API key (BUNQ_API_KEY)
  -t, --token TOKEN               Set your session token (BUNQ_SESSION_TOKEN)
  -I, --installation-token TOKEN  Set the installation token (BUNQ_INSTALLATION_TOKEN)
  -u, --url URL                   Set the BUNQ_API_URL (default: $BUNQ_API_URL_PROD)
  --sandbox                       Target the sandbox API by setting BUNQ_API_URL to $BUNQ_API_URL_SANDBOX
  -S, --store-token FILE          Store session token in BUNQ_SESSION_TOKEN_FILE
  -q, --quiet                     Suppress non-error output
  --no-color                      Disable color output

Commands:
  register              Run the registration flow (step 1 - only required once)
  login                 Login, generate session token (step 2)
  user                  Fetch user information
  balances              Fetch balances for cheking and savings accounts
  raw ENDPOINT          Execute a raw API request
EOF
  return 0
}

echo_debug() {
  [[ -z $DEBUG ]] && return 0

  local magenta="" nc=""

  if [[ -t 2 && -z "$NO_COLOR" ]]
  then
    magenta='\033[1;35m'
    nc='\033[0m'
  fi

  printf "%b\n" "${magenta}DBG${nc} $*" >&2
}

echo_warning() {
  local yellow="" nc=""

  if [[ -t 2 && -z "$NO_COLOR" ]]
  then
    yellow='\033[1;33m'
    nc='\033[0m'
  fi

  printf "%b\n" "${yellow}WRN${nc} $*" >&2
}

echo_error() {
  local red="" nc=""

  if [[ -t 2 && -z "$NO_COLOR" ]]
  then
    red='\033[1;31m'
    nc='\033[0m'
  fi

  printf "%b\n" "${red}ERR${nc} $*" >&2
}

echo_info() {
  [[ -n $QUIET ]] && return 0
  local blue="" nc=""

  if [[ -t 2 && -z "$NO_COLOR" ]]
  then
    blue='\033[1;34m'
    nc='\033[0m'
  fi

  printf "%b\n" "${blue}INF${nc} $*" >&2
}

array_to_json() {
  if [[ $# -eq 0 ]]
  then
    printf '%s\n' "[]"
    return 0
  fi

  printf '%s\n' "$@" | jq -cRn '[inputs]'
}

set_session_token() {
  if [[ -z "$BUNQ_SESSION_TOKEN" && -r "$BUNQ_SESSION_TOKEN_FILE" ]]
  then
    BUNQ_SESSION_TOKEN=$(cat "$BUNQ_SESSION_TOKEN_FILE")
    echo_info "Read session token from $BUNQ_SESSION_TOKEN_FILE"
  fi

  # Check if the session token is still valid
  if [[ -n "$BUNQ_SESSION_TOKEN" ]]
  then
    if user_info &>/dev/null
    then
      echo_debug "Session token is valid."
      return 0
    fi

    echo_warning "Session token is invalid or expired."
    # Remove token token file
    rm -f "$BUNQ_SESSION_TOKEN_FILE"
    unset BUNQ_SESSION_TOKEN
  fi

  if [[ -z "$BUNQ_INSTALLATION_TOKEN" ]]
  then
    echo_error "Missing BUNQ_INSTALLATION_TOKEN. Please use the -I option, or run the register command."
    return 2
  fi

  echo_info "Attempting to create a new session token"
  if ! BUNQ_SESSION_TOKEN=$(create_session "$BUNQ_INSTALLATION_TOKEN")
  then
    echo_error "Failed to retrieve session token"
    return 1
  fi

  echo_info "Session token created successfully"
  if [[ -n $STORE_SESSION_TOKEN ]]
  then
    printf '%s\n' "$BUNQ_SESSION_TOKEN" > "$BUNQ_SESSION_TOKEN_FILE"
    echo_info "Stored session token in $BUNQ_SESSION_TOKEN_FILE"
  fi
  return 0
}

# sign_payload takes a payload string and returns its base64-encoded RSA SHA256 signature.
# https://beta.doc.bunq.com/basics/authentication/signing
sign_payload() {
  generate_keys >&2 || return 1
  local payload="$1"
  printf '%s' "$payload" | openssl dgst -sha256 -sign "$BUNQ_PRIVKEY" | \
    base64 -w 0
}

generate_keys() {
  if [[ -f $BUNQ_PRIVKEY && -f $BUNQ_PUBKEY ]]
  then
    return 0
  fi

  echo_info "Generating RSA key pair"
  mkdir -p "$(dirname "$BUNQ_PRIVKEY")" "$(dirname "$BUNQ_PUBKEY")"

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$BUNQ_PRIVKEY"
  openssl rsa -in "$BUNQ_PRIVKEY" -pubout -out "$BUNQ_PUBKEY"

  echo_info "Generated keys: $BUNQ_PRIVKEY and $BUNQ_PUBKEY"
}

# https://beta.doc.bunq.com/quickstart/opening-a-session#id-1.-post-installation
register_installation() {
  if [[ ! -f $BUNQ_PUBKEY ]]
  then
    echo_error "Public key not found. Run the registration flow to generate keys."
    return 1
  fi

  # Read the public key as-is into JSON.
  local payload
  payload=$(jq -Rs '{ client_public_key: . }' "$BUNQ_PUBKEY")

  local response
  response=$(curl -fsSL \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BUNQ_API_URL}/v1/installation")

  jq -er <<< "$response" '
    .Response[] | select(has("Token")) | .Token.token
  '
}

public_ip() {
  curl -fsSL https://checkip.amazonaws.com/
}

# https://doc.bunq.com/api/1/call/device-server/method/post#/device-server/CREATE_DeviceServer
# https://beta.doc.bunq.com/quickstart/opening-a-session#id-2.-post-device-server
register_device() {
  local installation_token="$1"

  if [[ -z "$BUNQ_API_KEY" ]]
  then
    echo_error "Missing BUNQ_API_KEY (--api-key)"
    return 1
  fi

  local permitted_ips='[]'
  if [[ -n $BUNQ_WILDCARD_API ]]
  then
    local pub_ip
    if ! pub_ip=$(public_ip)
    then
      echo_error "Failed to determine public IP. We won't be able to create a wilcard key."
      return 1
    fi

    permitted_ips=$(array_to_json "$pub_ip" "*")
  fi

  local payload
  payload=$(jq -n \
    --arg description "$BUNQ_DEVICE_NAME" \
    --arg secret "$BUNQ_API_KEY" \
    --argjson permitted_ips "$permitted_ips" \
    '
      {
        description: $description,
        secret: $secret,
      }
      | if ($permitted_ips | length) > 0
        then
          .permitted_ips = $permitted_ips
        else
          .
        end
    '
  )

  local signature
  signature=$(sign_payload "$payload")

  local response
  response=$(curl -fsSL \
    -H "Content-Type: application/json" \
    -H "X-Bunq-Client-Authentication: ${installation_token}" \
    -H "X-Bunq-Client-Signature: ${signature}" \
    -d "$payload" \
    "${BUNQ_API_URL}/v1/device-server")

  jq -er <<< "$response" '
    if .Response[0].DeviceServer.token
    then
      .Response[0].DeviceServer.token
    else
      .Response[0].Id.id
    end
  '
}

# https://beta.doc.bunq.com/quickstart/opening-a-session#id-3.-post-session-server
create_session() {
  local installation_token="${1:-$BUNQ_INSTALLATION_TOKEN}"

  if [[ -z "$BUNQ_API_KEY" ]]
  then
    echo_error "Missing BUNQ_API_KEY (--api-key)"
    return 1
  fi

  local payload
  payload=$(jq -cn --arg secret "$BUNQ_API_KEY" '{ secret: $secret }')

  local signature
  signature=$(sign_payload "$payload")

  local response
  response=$(curl -fsSL \
    -H "Content-Type: application/json" \
    -H "X-Bunq-Client-Authentication: ${installation_token}" \
    -H "X-Bunq-Client-Signature: ${signature}" \
    -d "$payload" \
    "${BUNQ_API_URL}/v1/session-server")

  jq -er <<< "$response" '
    .Response[] | select(has("Token")) | .Token.token
  '
}

login() {
  local installation_token="${1:-$BUNQ_INSTALLATION_TOKEN}"

  if [[ -z "$installation_token" ]]
  then
    echo_error "Missing installation token. Register first, or set BUNQ_INSTALLATION_TOKEN"
    return 1
  fi

  local session_token
  session_token=$(create_session "$installation_token")

  if [[ -z "$session_token" || "$session_token" == "null" ]]
  then
    echo_error "Failed to create session."
    return 2
  fi

  echo_info "Session token: $session_token"
  return 0
}

bunq_api_curl() {
  local endpoint="${1#/}"
  shift

  curl -fsSL \
    -H "Content-Type: application/json" \
    -H "X-Bunq-Client-Authentication: ${BUNQ_SESSION_TOKEN}" \
    -H "X-Bunq-Client-Request-Id: $(uuidgen)" \
    "$@" \
    "${BUNQ_API_URL}/${endpoint}"
}

user_info() {
  bunq_api_curl "/v1/user"
}

user_id() {
  local res

  if ! res=$(user_info)
  then
    echo_error "Failed to fetch user info."
    return 1
  fi

  jq -er <<< "$res" '
    .Response[] | select(.UserPerson != null) | .UserPerson.id
  '
}

fetch_balances() {
  echo_info "Fetching main bank account balances"

  local user_id
  if ! user_id=$(user_id) || [[ -z "$user_id" ]]
  then
    echo_error "Failed to extract user id from user info."
    return 1
  fi

  echo_debug "User ID: $user_id"

  local res
  res=$(bunq_api_curl \
    "/v1/user/${user_id}/monetary-account-bank")

  jq -e <<< "$res"
  # jq -er <<< "$res" '
  #   .Response[]? |
  #   .MonetaryAccountBank? |
  #   "Main Account ID: \(.id) - Balance: \(.balance.value) \(.balance.currency)"
  # '
}

fetch_savings() {
  echo_info "Fetching savings account balances"

  local user_id="$1"
  if [[ -z $user_id ]] && ! user_id=$(user_id) || [[ -z "$user_id" ]]
  then
    echo_error "Failed to extract user id from user info."
    return 1
  fi

  echo_debug "User ID: $user_id"

  local res
  res=$(bunq_api_curl \
    "/v1/user/${user_id}/monetary-account-savings")

  jq -e <<< "$res"
}

fetch_ext_balances() {
  echo_info "Fetching external bank account balances"

  local user_id="$1"
  if [[ -z $user_id ]] && ! user_id=$(user_id) || [[ -z "$user_id" ]]
  then
    echo_error "Failed to extract user id from user info."
    return 1
  fi

  echo_debug "User ID: $user_id"

  local res
  res=$(bunq_api_curl \
    "/v1/user/${user_id}/monetary-account-external")

  # External Accounts have a balance field, but it's *always* 0.00
  # There are 2 fields we can use instead: balance_available and balance_booked
  jq -e <<< "$res" '
    .Response |= map(
      .MonetaryAccountExternal |= (
        .balance = (
          if .open_banking_account.OpenBankingAccount.balance_available != null
          then
            .open_banking_account.OpenBankingAccount.balance_available
          else
            .open_banking_account.OpenBankingAccount.balance_booked
          end
        )
      )
    )
  '
}

fetch_all_balances() {
  local user_id
  if ! user_id=$(user_id) || [[ -z "$user_id" ]]
  then
    echo_error "Failed to extract user id from user info."
    return 1
  fi

  {
    fetch_balances "$user_id"
    fetch_savings "$user_id"
    if [[ -n "$BUNQ_INCLUDE_EXT_ACCOUNTS" ]]
    then
      fetch_ext_balances "$user_id"
    fi
  } | jq -es 'reduce .[] as $item ([]; . + $item.Response)'
}

main() {
  if [[ "$#" -lt 1 ]]
  then
    usage
    return 2
  fi

  local -a args
  while [[ "$#" -gt 0 ]]
  do
    case "$1" in
      -h|--help)
        usage
        return 0
        ;;
      -d|--debug)
        DEBUG=1
        shift
        ;;
      --trace)
        set -x
        shift
        ;;
      -j|--json|--raw)
        JSON_OUTPUT=1
        shift
        ;;
      -k|--key|--api-key|--api-token)
        BUNQ_API_KEY="$2"
        shift 2
        ;;
      -t|--token)
        BUNQ_SESSION_TOKEN="$2"
        shift 2
        ;;
      -I|--installation-token)
        BUNQ_INSTALLATION_TOKEN="$2"
        shift 2
        ;;
      --priv|--privkey)
        BUNQ_PRIVKEY="$2"
        shift 2
        ;;
      --pub|--pubkey)
        BUNQ_PUBKEY="$2"
        shift 2
        ;;
      -e|--ext*)
        BUNQ_INCLUDE_EXT_ACCOUNTS=1
        shift
        ;;
      -u|--url)
        BUNQ_API_URL="$2"
        shift 2
        ;;
      --sandbox)
        BUNQ_API_URL="$BUNQ_API_URL_SANDBOX"
        shift
        ;;
      -S|--store-token|--store-session-token)
        STORE_SESSION_TOKEN=1
        shift
        ;;
      --no-color)
        NO_COLOR=1
        shift
        ;;
      -q|--quiet)
        QUIET=1
        shift
        ;;
      --)
        args+=("$@")
        break
        ;;
      -*)
        echo_error "Unknown argument: $1"
        usage
        return 2
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done

  set -- "${args[@]}"

  local ACTION="${1:-}"
  if [[ -z "$ACTION" ]]
  then
    echo_error "Missing command"
    usage >&2
    return 2
  fi

  # process action/action aliases
  case "$ACTION" in
    register)
      ACTION="register"
      shift
      ;;
    login)
      ACTION="login"
      shift
      ;;
    balance*)
      ACTION="balances"
      shift
      ;;
    user*|acc*)
      ACTION="user-info"
      shift
      ;;
    raw|curl)
      ACTION="raw-curl"
      shift
      ;;
    *)
      echo_error "Unknown command: $1"
      return 2
      ;;
  esac

  local data

  case "$ACTION" in
    register)
      generate_keys

      local installation_token
      if ! installation_token=$(register_installation) || \
         [[ -z "$installation_token" || "$installation_token" == "null" ]]
      then
        echo_error "Failed to register installation!"
        return 2
      fi

      local device_token
      if ! device_token=$(register_device "$installation_token") ||
         [[ -z "$device_token" || "$device_token" == "null" ]]
      then
        echo_error "Failed to register device!"
        echo_info "Installation token: $installation_token"
        return 2
      fi

      local session_token
      if ! session_token=$(create_session "$installation_token") || \
         [[ -z "$session_token" || "$session_token" == "null" ]]
      then
        echo_error "Failed to create session!"
        echo_info "Installation token: $installation_token"
        echo_info "Device token: $device_token"
        return 2
      fi

      if [[ -n "$JSON_OUTPUT" ]]
      then
        jq -en \
          --arg installation_token "$installation_token" \
          --arg device_token "$device_token" \
          --arg session_token "$session_token" \
          '
            {
              installation_token: $installation_token,
              device_token: $device_token,
              session_token: $session_token
            }
          '
        return "$?"
      fi

      echo_info "Installation token: $installation_token"
      echo_info "Device token: $device_token"
      echo_info "Session token: $session_token"
      return 0
      ;;
    login)
      login "$BUNQ_INSTALLATION_TOKEN"
      ;;
    balances)
      set_session_token || return 2

      if ! data=$(fetch_all_balances)
      then
        echo_error "Failed to fetch balances."
        return 1
      fi

      if [[ "$JSON_OUTPUT" ]]
      then
        jq -e <<< "$data"
        return "$?"
      fi

      # TODO Pretty output
      jq -er <<< "$data" '
        .[]
        | to_entries[].value
        | select(.status != "CANCELLED")
        | [.description, .balance.value]
        | @tsv
      '
      ;;
    user-info)
      set_session_token || return 2
      if ! data=$(user_info)
      then
        echo_error "Failed to fetch user info"
        return 1
      fi

      if [[ "$JSON_OUTPUT" ]]
      then
        jq -e <<< "$data"
        return "$?"
      fi

      # TODO Pretty output
      jq -er <<< "$data" '
        .Response[].UserPerson
        | (.alias[] | select(.type == "EMAIL").value) as $email
        | (.alias[] | select(.type == "PHONE_NUMBER").value) as $phone
        | (.address_main | .street + " " + .house_number + ", " + .postal_code + " " + .city) as $address
        | [
            .display_name,
            $email,
            $phone,
            $address
          ]
        | @tsv
      '
      ;;
    raw-curl)
      bunq_api_curl "$@" | {
        if [[ -n $JSON_OUTPUT ]]
        then
          jq -e
        else
          cat
        fi
      }
      ;;
    *)
      echo_error "Unknown command: $ACTION"
      usage >&2
      return 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]
then
  set -euo pipefail

  main "$@"
  exit $?
fi
