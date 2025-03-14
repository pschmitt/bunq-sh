#!/usr/bin/env bash

# https://doc.bunq.com/

# Default configuration
BUNQ_CONFIG_HOME="${XDG_CONFIG_HOME:-${HOME}/.config}/bunq"
BUNQ_API_URL="${BUNQ_API_URL:-https://api.bunq.com}"
BUNQ_API_KEY="${BUNQ_API_KEY:-}"
BUNQ_PRIVKEY="${BUNQ_PRIVKEY:-${BUNQ_CONFIG_HOME}/keys/privkey.pem}"
BUNQ_PUBKEY="${BUNQ_PUBKEY:-${BUNQ_CONFIG_HOME}/keys/pubkey.pem}"
BUNQ_DEVICE_NAME="${BUNQ_DEVICE_NAME:-$(basename "$0")@$(uname -n)}" # bunq.sh@hostname
BUNQ_SESSION_TOKEN="${BUNQ_SESSION_TOKEN:-}"
BUNQ_SESSION_TOKEN_FILE="${BUNQ_SESSION_TOKEN_FILE:-}"
DEBUG=${DEBUG:-}
JSON_OUTPUT=${JSON_OUTPUT:-}
NO_COLOR="${NO_COLOR:-}"
QUIET=${QUIET:-}

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] <command>

Options:
  -h, --help            Show this help message and exit
  -d, --debug           Enable debug output
  -t, --trace           Enable shell tracing
  -j, --json            Output raw JSON data
  -k, --api-key KEY     Set API key (mainly intended for device registration)
  -t, --token TOKEN     Set your session token
  -u, --url URL         Set the BUNQ_API_URL (default: https://api.bunq.com)
  -q, --quiet           Suppress non-error output
  --no-color            Disable color output

Commands:
  register              Run the registration flow
  user                  Fetch user information
  balances              Fetch balances for cheking and savings accounts
EOF
  return 0
}

echo_debug() {
  [[ -z $DEBUG ]] && return 0

  local magenta nc

  if [[ -t 2 && -z "$NO_COLOR" ]]
  then
    magenta='\033[1;35m'
    nc='\033[0m'
  fi

  printf "%b\n" "${magenta}DBG${nc} $*" >&2
}


echo_error() {
  local red nc

  if [[ -t 2 && -z "$NO_COLOR" ]]
  then
    red='\033[1;31m'
    nc='\033[0m'
  fi

  printf "%b\n" "${red}ERR${nc} $*" >&2
}

echo_info() {
  [[ -n $QUIET ]] && return 0
  local blue nc

  if [[ -t 2 && -z "$NO_COLOR" ]]
  then
    blue='\033[1;34m'
    nc='\033[0m'
  fi

  printf "%b\n" "${blue}INF${nc} $*" >&2
}

set_session_token() {
  if [[ -z "$BUNQ_SESSION_TOKEN" ]]
  then
    if [[ -r "$BUNQ_SESSION_TOKEN_FILE" ]]
    then
      BUNQ_SESSION_TOKEN=$(cat "$BUNQ_SESSION_TOKEN_FILE")
      echo_info "Read session token from $BUNQ_SESSION_TOKEN_FILE"
    else
      echo_error "Missing BUNQ_SESSION_TOKEN. Use the -t option, or run the register command."
      return 2
    fi
  fi
}

# sign_payload takes a payload string and returns its base64-encoded RSA SHA256 signature.
sign_payload() {
  local payload="$1"
  openssl dgst -sha256 -sign "$BUNQ_PRIVKEY" <<< "$payload" | \
    base64 -w 0 | tr -d '\n'
}

generate_keys() {
  if [[ -f $BUNQ_PRIVKEY && -f $BUNQ_PUBKEY ]]
  then
    return 0
  fi

  echo_info "Generating RSA key pair..."
  mkdir -p "$(dirname "$BUNQ_PRIVKEY")" "$(dirname "$BUNQ_PUBKEY")"

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$BUNQ_PRIVKEY"
  openssl rsa -in "$BUNQ_PRIVKEY" -pubout -out "$BUNQ_PUBKEY"

  echo_info "Generated keys: $BUNQ_PRIVKEY and $BUNQ_PUBKEY"
}

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

register_device() {
  local installation_token="$1"

  if [[ -z "$BUNQ_API_KEY" ]]
  then
    echo_error "Missing BUNQ_API_KEY (--api-key)"
    return 1
  fi

  local payload
  payload=$(jq -n \
    --arg desc "${BUNQ_DEVICE_NAME}" \
    --arg secret "${BUNQ_API_KEY}" \
    '{ description: $desc, secret: $secret }')

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

create_session() {
  local installation_token="$1"

  if [[ -z "$BUNQ_API_KEY" ]]
  then
    echo_error "Missing BUNQ_API_KEY (--api-key)"
    return 1
  fi

  local payload
  payload=$(jq -n --arg secret "$BUNQ_API_KEY" '{ secret: $secret }')

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
  echo_info "Fetching main bank account balances..."

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
  echo_info "Fetching savings account balances..."

  local user_id
  if ! user_id=$(user_id) || [[ -z "$user_id" ]]
  then
    echo_error "Failed to extract user id from user info."
    return 1
  fi

  echo_debug "User ID: $user_id"

  local res
  res=$(bunq_api_curl \
    "/v1/user/${user_id}/monetary-account-savings")

  jq -e <<< "$res"
  # jq -er <<< "$res" '
  #   .Response[]? |
  #   .MonetaryAccountSavings? |
  #   "Savings Account ID: \(.id) - Balance: \(.balance.value) \(.balance.currency)"
  # '
}

fetch_all_balances() {
  {
    fetch_balances
    fetch_savings
  } | jq -es 'reduce .[] as $item ([]; . + $item.Response)'
}

main() {
  local ACTION

  if [[ "$#" -lt 1 ]]
  then
    usage
    return 2
  fi

  while [[ "$#" -gt 0 ]]
  do
    case "$1" in
      -h|--help)
        usage
        return 0
        ;;
      -d|--debug)
        DEBUG=1
        ;;
      --trace)
        set -x
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
      --priv|--privkey)
        BUNQ_PRIVKEY="$2"
        shift 2
        ;;
      --pub|--pubkey)
        BUNQ_PUBKEY="$2"
        shift 2
        ;;
      -u|--url)
        BUNQ_API_URL="$2"
        shift 2
        ;;
      --no-color)
        NO_COLOR=1
        shift
        ;;
      -q|--quiet)
        QUIET=1
        shift
        ;;
      register)
        ACTION="register"
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
      *)
        echo_error "Unknown argument: $1"
        usage
        return 2
        ;;
    esac
  done

  local data

  case "$ACTION" in
    register)
      generate_keys

      local installation_token
      if ! installation_token=$(register_installation) || \
         [[ -z "$installation_token" || "$installation_token" == "null" ]]
      then
        echo_error "Failed to register installation."
        return 2
      fi

      local device_token
      if ! device_token=$(register_device "$installation_token") ||
         [[ -z "$device_token" || "$device_token" == "null" ]]
      then
        echo_error "Failed to register device."
        return 2
      fi

      local session_token
      if ! session_token=$(create_session "$installation_token") || \
         [[ -z "$session_token" || "$session_token" == "null" ]]
      then
        echo_error "Failed to create session."
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

      echo_info "Your session token is: $session_token"
      return 0
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
    *)
      echo_error "Unknown command: $ACTION"
      usage
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
