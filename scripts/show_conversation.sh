#!/usr/bin/env bash
# Show a conversation's audit trail, or its decrypted transcript for humans.
#
# The ledger records the four-stage chat lifecycle (INPUT_RECEIVED,
# DLP_REDACTION, ROUTING_DECISION, EGRESS_FILTERED), the delivered answer
# (RESPONSE_SENT) and incidents. With the pre-production payload escrow on,
# --markdown decrypts the newest request and, when present, the delivered
# answer, and renders them as a transcript. An injection-refused turn has no
# answer row: the notice is gateway-authored, not model output.
#
#   BASTION_TOKEN=$ADMIN_TOKEN scripts/show_conversation.sh 98ccb1945eed4a97a7424c0b7c7ce814
#   BASTION_TOKEN=$ADMIN_TOKEN scripts/show_conversation.sh --markdown 98ccb...
#   BASTION_TOKEN=$ADMIN_TOKEN scripts/show_conversation.sh --escrow 98ccb...
#   BASTION_TOKEN=$ADMIN_TOKEN scripts/show_conversation.sh --json 98ccb...
#
# Auth: BASTION_TOKEN wins. Otherwise BASTION_USER + BASTION_PASSWORD mint one
# through the Keycloak password grant (dev `bastion-cli` public client). The
# password goes over stdin, never into curl's argv.
#
# Exit codes: 0 success, 1 an audit or escrow request failed, 2 setup error.

set -uo pipefail

BASE_URL="${BASTION_BASE_URL:-http://localhost:8000}"
KEYCLOAK_URL="${BASTION_KEYCLOAK_URL:-http://localhost:8080}"
REALM="${BASTION_REALM:-bastion}"
CLIENT_ID="${BASTION_CLIENT_ID:-bastion-cli}"
PAGE_SIZE="${BASTION_AUDIT_PAGE_SIZE:-200}"

usage() {
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"
}

CONVERSATION=""
SHOW_ESCROW=0
AS_JSON=0
AS_MARKDOWN=0
while (($#)); do
    case "$1" in
        --escrow) SHOW_ESCROW=1 ;;
        --json) AS_JSON=1 ;;
        --markdown) AS_MARKDOWN=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        -*)
            echo "show-conversation: unknown option: $1 (try --help)" >&2
            exit 2
            ;;
        *)
            if [[ -n "$CONVERSATION" ]]; then
                echo "show-conversation: pass exactly one conversation id" >&2
                exit 2
            fi
            CONVERSATION="$1"
            ;;
    esac
    shift
done
if ((AS_JSON && AS_MARKDOWN)); then
    echo "show-conversation: --json and --markdown are mutually exclusive" >&2
    exit 2
fi

command -v curl >/dev/null || {
    echo "show-conversation: curl is not on PATH" >&2
    exit 2
}
command -v jq >/dev/null || {
    echo "show-conversation: jq is not on PATH" >&2
    exit 2
}
if [[ -z "$CONVERSATION" ]]; then
    echo "show-conversation: a conversation id is required" >&2
    usage >&2
    exit 2
fi

TOKEN="${BASTION_TOKEN:-}"
if [[ -z "$TOKEN" ]]; then
    if [[ -z "${BASTION_USER:-}" || -z "${BASTION_PASSWORD:-}" ]]; then
        echo "show-conversation: set BASTION_TOKEN, or BASTION_USER + BASTION_PASSWORD" >&2
        exit 2
    fi
    token_json=$(curl -sS -X POST \
        "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' --data @- <<EOF
grant_type=password&client_id=$CLIENT_ID&username=$BASTION_USER&password=$(printf '%s' "$BASTION_PASSWORD" | jq -sRr @uri)&scope=openid%20profile%20email
EOF
    )
    TOKEN=$(jq -r '.access_token // empty' <<<"$token_json" 2>/dev/null)
    if [[ -z "$TOKEN" ]]; then
        echo "show-conversation: token request failed: $(jq -r '.error_description // .error // "unknown error"' <<<"$token_json" 2>/dev/null)" >&2
        exit 2
    fi
fi
AUTH=(-H "Authorization: Bearer $TOKEN")

# Walk /api/audit newest-first (it is cursor-paginated), then sort by id.
RECORDS='[]'
BEFORE=""
while :; do
    URL="$BASE_URL/api/audit?session_id=$(printf '%s' "$CONVERSATION" | jq -sRr @uri)&limit=$PAGE_SIZE"
    if [[ -n "$BEFORE" ]]; then
        URL+="&before_id=$BEFORE"
    fi
    PAGE=$(curl -sS -f "${AUTH[@]}" "$URL") || {
        echo "show-conversation: audit request failed (check the token and BASTION_BASE_URL)" >&2
        exit 1
    }
    RECORDS=$(jq -c --argjson page "$PAGE" '. + $page.records' <<<"$RECORDS") || {
        echo "show-conversation: unexpected audit response" >&2
        exit 1
    }
    BEFORE=$(jq -r '.next_before_id // empty' <<<"$PAGE")
    [[ -n "$BEFORE" ]] || break
done
RECORDS=$(jq -c 'sort_by(.id)' <<<"$RECORDS")
ACTORS=$(jq -r '[.[].actor_id] | unique | join(", ")' <<<"$RECORDS")

# Decrypt one escrowed input. Prints the payload array, or nothing on failure.
decrypt_input() {
    local id="$1" body code
    body=$(curl -sS -w '\n%{http_code}' -X POST "${AUTH[@]}" "$BASE_URL/api/audit/$id/escrow")
    code="${body##*$'\n'}"
    body="${body%$'\n'*}"
    if [[ "$code" == "200" ]]; then
        jq -c '.payload' <<<"$body"
        return 0
    fi
    echo "show-conversation: audit record $id: HTTP $code $(jq -r '.detail // empty' <<<"$body" 2>/dev/null)" >&2
    return 1
}

# --markdown: the newest escrowed request and delivered answer, as a transcript.
if ((AS_MARKDOWN)); then
    REQUEST_ID=""
    REQUEST=""
    for ID in $(jq -r '[.[] | select(.event_type == "INPUT_RECEIVED") | .id] | reverse | .[]' <<<"$RECORDS"); do
        if REQUEST=$(decrypt_input "$ID"); then
            REQUEST_ID="$ID"
            break
        fi
    done
    ANSWER_ID=""
    ANSWER=""
    for ID in $(jq -r '[.[] | select(.event_type == "RESPONSE_SENT") | .id] | reverse | .[]' <<<"$RECORDS"); do
        if ANSWER=$(decrypt_input "$ID"); then
            ANSWER_ID="$ID"
            break
        fi
    done
    if [[ -z "$REQUEST_ID" && -z "$ANSWER_ID" ]]; then
        echo "show-conversation: no escrowed payload to render (is PAYLOAD_ESCROW_ENABLED on and the row unexpired?)" >&2
        exit 1
    fi

    echo "**Conversation:** \`$CONVERSATION\`"
    echo "**Actor(s):** \`$ACTORS\`"
    if [[ -n "$REQUEST_ID" ]]; then
        echo "**Request source:** audit record $REQUEST_ID ($(jq 'length' <<<"$REQUEST") messages)"
    fi
    if [[ -n "$ANSWER_ID" ]]; then
        echo "**Answer source:** audit record $ANSWER_ID (\`egress_delivered\`)"
    fi
    echo
    COUNT=0
    if [[ -n "$REQUEST_ID" ]]; then
        COUNT=$(jq 'length' <<<"$REQUEST")
        jq -r '
            to_entries[] |
            "### \(.key + 1). \(.value.role)" +
            (if .value.name then " (`\(.value.name)`)" else "" end) +
            "\n\n\(.value.content)\n"
        ' <<<"$REQUEST"
    fi
    if [[ -n "$ANSWER_ID" ]]; then
        echo "### $((COUNT + 1)). assistant"
        echo
        # The payload is a JSON string; -r prints the delivered text verbatim.
        jq -r '.' <<<"$ANSWER"
        echo
    else
        echo "> No delivered answer is escrowed for this conversation (flag off,"
        echo "> expired, or the latest turn was refused before the model)."
        echo
    fi
    exit 0
fi

# Table mode (default) and --json: one row per ledger event.
ENRICHED=$(jq -c '
    [ .[] | . + { detail:
        (if .event_type == "INPUT_RECEIVED" then
            "messages=\(.metadata_json.messages) chars=\(.metadata_json.chars)"
         elif .event_type == "DLP_REDACTION" then
            "redacted=\(.metadata_json.redacted) entities=\(.metadata_json.entities) types=\(.metadata_json.types | join(","))"
         elif .event_type == "ROUTING_DECISION" then
            "route=\(.metadata_json.route) label=\(.metadata_json.label) confidence=\(.metadata_json.confidence)"
         elif .event_type == "EGRESS_FILTERED" then
            "blocked=\(.metadata_json.blocked) model=\(.metadata_json.model) restored=\(.metadata_json.restored_tokens)"
         elif .event_type == "RESPONSE_SENT" then
            "model=\(.metadata_json.model) chars=\(.metadata_json.chars) truncated=\(.metadata_json.truncated)"
         elif .event_type == "ESCROW_ACCESSED" then
            "audit_log_id=\(.metadata_json.audit_log_id) outcome=\(.metadata_json.outcome)"
         elif .event_type == "SECURITY_INCIDENT" then
            "stage=\(.metadata_json.stage) reason=\(.metadata_json.reason)"
         else
            (.metadata_json | tostring)
         end) } ]
' <<<"$RECORDS")

if ((AS_JSON)); then
    jq '.' <<<"$RECORDS"
else
    echo "Conversation: $CONVERSATION"
    echo "Actor(s): $ACTORS"
    echo
    jq -r '.[] | [(.id | tostring), .timestamp, .event_type, .detail] | @tsv' <<<"$ENRICHED" |
        column -t -s $'\t'
fi

if ((SHOW_ESCROW)); then
    IDS=$(jq -r '.[] | select(.event_type == "INPUT_RECEIVED" or .event_type == "RESPONSE_SENT") | .id' <<<"$ENRICHED")
    if [[ -z "$IDS" ]]; then
        echo
        echo "no INPUT_RECEIVED or RESPONSE_SENT rows to decrypt"
        exit 0
    fi
    STATUS=0
    for ID in $IDS; do
        EVENT=$(jq -r --argjson id "$ID" '.[] | select(.id == $id) | .event_type' <<<"$ENRICHED")
        echo
        if PAYLOAD=$(decrypt_input "$ID"); then
            echo "$EVENT payload for audit record $ID:"
            if [[ "$EVENT" == "RESPONSE_SENT" ]]; then
                jq -r '.' <<<"$PAYLOAD"
            else
                jq '.' <<<"$PAYLOAD"
            fi
        else
            STATUS=1
        fi
    done
    exit "$STATUS"
fi
