#!/usr/bin/env bash
#
# API Endpoint False-Positive Verifier v5.0 (Shell Edition)
# ==========================================================
# Parses ffuf JSON output and removes false positives using the same
# v5 logic: Response proof > Path name. Always.
#
# Dependencies: jq, curl, bash 4+
#
# Usage:
#   ./api_verifier.sh -f ffuf_output.json -o clean.json
#   ./api_verifier.sh -f ffuf_output.json --reprobe -t 50 -o clean.json
#   ./api_verifier.sh -f ffuf_output.json --include-fp -o full_audit.json
#
# The script:
#   1. Finds the dominant CL+Words+Lines fingerprint (catch-all detection)
#   2. Marks entries matching the catch-all as FP UNLESS they have proof:
#      - Structured content-type (json/yaml/xml) matching path category
#      - Body content proving real API data (with --reprobe)
#   3. Path names like /actuator/health mean NOTHING if the response
#      is identical to every other path on the server.

set -euo pipefail

VERSION="5.0.0"
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
MAGENTA='\033[95m'
RST='\033[0m'
BOLD='\033[1m'

# ========================= DEFAULTS ========================================
FFUF_FILE=""
URL_LIST=""
OUTPUT_FILE=""
THREADS=30
TIMEOUT=10
INCLUDE_FP=false
REPROBE=false
CL_TOL=10
RATE=0
PROXY=""
COOKIES=""
NO_VERIFY=false
QUIET=false
CUSTOM_HEADERS=()

# ========================= USAGE ===========================================
usage() {
    cat <<EOF
API False-Positive Verifier v${VERSION} (Shell Edition)
Response proof > Path name. Always.

USAGE:
  $0 -f ffuf_output.json [OPTIONS]
  $0 --url-list urls.txt [OPTIONS]

OPTIONS:
  -f, --ffuf-file FILE    ffuf JSON output file
  --url-list FILE         Plain text file with URLs (one per line)
  -o, --output FILE       Output file (.json, default: <input>_clean.json)
  -t, --threads NUM       Reprobe threads (default: 30)
  --timeout SEC           HTTP timeout (default: 10)
  --reprobe               Re-fetch URLs to verify body content
  --include-fp            Include FPs in output (tagged)
  --cl-tol NUM            CL tolerance +/- bytes (default: 10)
  --rate NUM              Max req/sec for reprobe (default: unlimited)
  -H, --header STR        Custom header (repeatable)
  --cookies STR           Cookies string
  --proxy URL             HTTP proxy
  --no-verify             Skip SSL verification
  -q, --quiet             Minimal output
  -h, --help              Show this help
EOF
    exit 0
}

# ========================= LOGGING ==========================================
log() { [[ "$QUIET" == "true" ]] || echo -e "$*" >&2; }
err() { echo -e "${RED}[!] $*${RST}" >&2; }

# ========================= ARGUMENT PARSING =================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --url-list)       URL_LIST="$2"; shift 2 ;;
        -f|--ffuf-file)   FFUF_FILE="$2"; shift 2 ;;
        -o|--output)      OUTPUT_FILE="$2"; shift 2 ;;
        -t|--threads)     THREADS="$2"; shift 2 ;;
        --timeout)        TIMEOUT="$2"; shift 2 ;;
        --reprobe)        REPROBE=true; shift ;;
        --include-fp)     INCLUDE_FP=true; shift ;;
        --cl-tol)         CL_TOL="$2"; shift 2 ;;
        --rate)           RATE="$2"; shift 2 ;;
        -H|--header)      CUSTOM_HEADERS+=("$2"); shift 2 ;;
        --cookies)        COOKIES="$2"; shift 2 ;;
        --proxy)          PROXY="$2"; shift 2 ;;
        --no-verify)      NO_VERIFY=true; shift ;;
        -q|--quiet)       QUIET=true; shift ;;
        -h|--help)        usage ;;
        *)                err "Unknown option: $1"; usage ;;
    esac
done

# ========================= VALIDATION ======================================
if [[ -z "$FFUF_FILE" ]] && [[ -z "$URL_LIST" ]]; then
    err "Missing required option: -f/--ffuf-file or --url-list"
    usage
fi

if [[ -n "$FFUF_FILE" ]] && [[ ! -f "$FFUF_FILE" ]]; then
    err "File not found: $FFUF_FILE"
    exit 1
fi

if [[ -n "$URL_LIST" ]] && [[ ! -f "$URL_LIST" ]]; then
    err "URL list not found: $URL_LIST"
    exit 1
fi

for cmd in jq curl; do
    if ! command -v "$cmd" &>/dev/null; then
        err "Required tool not found: $cmd"
        exit 1
    fi
done

if [[ -z "$OUTPUT_FILE" ]]; then
    if [[ -n "$FFUF_FILE" ]]; then
        OUTPUT_FILE="${FFUF_FILE%.json}_clean.json"
    else
        OUTPUT_FILE="${URL_LIST%.txt}_verified.json"
    fi
fi

# ========================= BANNER ==========================================
if [[ "$QUIET" != "true" ]]; then
    cat <<'BANNER'
   ___    ____  ____   _    __          _ ____
  / _ |  / __ \/  _/  | |  / /__  ____(_) __/_  __
 / __ | / /_/ // /    | | / / _ \/ __/ / /_/ / / /
/_/ |_|/ .___/___/    | |/ /  __/ /  / / __/ /_/ /
      /_/             |___/\___/_/  /_/_/  \__, /
   FP Verifier v5.0 (Shell)              /____/
BANNER
fi

# ========================= PATH CLASSIFICATION ==============================
# Returns what content-type a real endpoint should have
classify_path() {
    local path="${1,,}"  # lowercase
    local cat="generic"

    if [[ "$path" =~ (swagger|swagger-ui|swagger\.json|swagger\.yaml|swagger-resources|swagger-config) ]]; then
        cat="swagger"
    elif [[ "$path" =~ (openapi|openapi\.json|openapi\.yaml|api-docs|api-documentation) ]]; then
        cat="openapi"
    elif [[ "$path" =~ (graphql|graphiql|playground|gql|voyager|altair) ]]; then
        cat="graphql"
    elif [[ "$path" =~ (actuator|actuator/) ]]; then
        cat="actuator"
    elif [[ "$path" =~ (/metrics$|/prometheus|healthz$|readyz$|livez$|health-check|healthcheck|_health$|_status$|_ping$|server-status|server-info|build-info) ]]; then
        cat="metrics"
    elif [[ "$path" =~ (debug|phpinfo|info\.php|__debug__|trace\.axd|elmah\.axd|web\.config|WEB-INF|META-INF|jmx-console) ]]; then
        cat="debug"
    elif [[ "$path" =~ (oauth|\.well-known/openid|\.well-known/jwks|connect/token|auth/token|auth/login|saml|oidc|/token$|/authorize$) ]]; then
        cat="auth"
    elif [[ "$path" =~ (\.env$|\.git$|\.git/|\.htaccess|\.htpasswd|docker-compose|\.aws/credentials|config\.(json|yaml|yml|xml)$|secrets$|security\.txt|robots\.txt|sitemap\.xml) ]]; then
        cat="config_leak"
    elif [[ "$path" =~ (\.wsdl|wsdl$|\.xsd) ]]; then
        cat="wsdl"
    elif [[ "$path" =~ (\.proto$|grpc|twirp) ]]; then
        cat="proto"
    elif [[ "$path" =~ (redoc|rapidoc|scalar) ]]; then
        cat="redoc"
    elif [[ "$path" =~ \.(json|yaml|yml|xml)$ ]]; then
        cat="api_json"
    elif [[ "$path" =~ (metadata$|computeMetadata|ec2-metadata|kubernetes|k8s/) ]]; then
        cat="cloud_meta"
    fi

    echo "$cat"
}

# Check if content-type matches what the category should return
ct_matches_category() {
    local ct="${1,,}"
    local cat="$2"

    case "$cat" in
        swagger|openapi|actuator|auth)
            [[ "$ct" =~ (json|yaml) ]] && return 0 ;;
        graphql)
            [[ "$ct" =~ (json|html) ]] && return 0 ;;
        metrics)
            [[ "$ct" =~ (json|plain|openmetrics) ]] && return 0 ;;
        wsdl)
            [[ "$ct" =~ xml ]] && return 0 ;;
        proto)
            [[ "$ct" =~ (protobuf|grpc) ]] && return 0 ;;
        config_leak)
            [[ "$ct" =~ (plain|json|yaml|xml|octet) ]] && return 0 ;;
        api_json)
            [[ "$ct" =~ (json|yaml|xml) ]] && return 0 ;;
        cloud_meta)
            [[ "$ct" =~ (json|plain) ]] && return 0 ;;
        debug|redoc)
            [[ "$ct" =~ (html|plain) ]] && return 0 ;;
    esac
    return 1
}

# Check if content-type is structured (not HTML)
is_structured_ct() {
    local ct="${1,,}"
    [[ "$ct" =~ (application/json|application/xml|text/xml|application/yaml|text/yaml|application/x-yaml|application/x-protobuf|application/graphql|application/grpc|application/soap|application/vnd\.|application/hal\+json|application/problem\+json|text/csv|application/octet-stream) ]]
}

is_html_ct() {
    local ct="${1,,}"
    [[ "$ct" =~ text/html ]]
}

# ========================= BODY ANALYSIS ====================================
# Analyze response body and return a score (0-100) and type
analyze_body() {
    local body="$1"
    local ct="${2,,}"
    local path="${3,,}"
    local score=0
    local btype="unknown"
    local detail=""

    [[ -z "$body" || ${#body} -lt 2 ]] && { echo "0|unknown|"; return; }

    # OpenAPI/Swagger spec
    local oa_keys
    oa_keys=$(echo "$body" | grep -oiE '"(openapi|swagger|info|paths|components|definitions|basePath|schemes|servers)"' | wc -l)
    if [[ $oa_keys -ge 3 ]]; then
        score=$((50 + oa_keys * 10))
        [[ $score -gt 95 ]] && score=95
        echo "${score}|openapi_spec|OpenAPI spec (${oa_keys} keys)"
        return
    fi

    # GraphQL
    local gql_keys
    gql_keys=$(echo "$body" | grep -oiE '"(__schema|__type|data|query|mutation|subscription|types|queryType)"' | wc -l)
    if [[ $gql_keys -ge 2 ]]; then
        score=$((50 + gql_keys * 15))
        [[ $score -gt 95 ]] && score=95
        echo "${score}|graphql|GraphQL schema"
        return
    fi

    # WSDL/SOAP
    if echo "$body" | grep -qiE '<(wsdl:definitions|definitions|wsdl:types|xsd:schema|soap:Envelope)'; then
        echo "90|wsdl_soap|WSDL/SOAP definition"
        return
    fi

    # Prometheus metrics
    local prom_help prom_metric
    prom_help=$(echo "$body" | grep -cE '^# (HELP|TYPE) ' 2>/dev/null || true)
    prom_metric=$(echo "$body" | head -100 | grep -cE '^\w+(\{[^}]*\})?\s+[0-9]' 2>/dev/null || true)
    if [[ $prom_help -ge 2 ]] || [[ $prom_metric -ge 5 ]]; then
        score=$((50 + prom_metric * 5))
        [[ $score -gt 95 ]] && score=95
        echo "${score}|prometheus|Prometheus metrics (${prom_metric} series)"
        return
    fi

    # .env / config leak
    local env_vars secrets
    env_vars=$(echo "$body" | head -50 | grep -cE '^[A-Z_][A-Z0-9_]*\s*=\s*.+' 2>/dev/null || true)
    secrets=$(echo "$body" | grep -ciE '(password|secret|api_key|apikey|access_token|private_key|aws_secret|db_password|database_url|jwt_secret)\s*[=:]\s*\S+' 2>/dev/null || true)
    if [[ $env_vars -ge 3 ]] || [[ $secrets -ge 1 ]]; then
        score=$((40 + env_vars * 10 + secrets * 20))
        [[ $score -gt 95 ]] && score=95
        echo "${score}|config_leak|Config leak (${env_vars} vars, ${secrets} secrets)"
        return
    fi

    # Actuator JSON
    local act_keys
    act_keys=$(echo "$body" | grep -oiE '"(status|components|details|diskSpace|db|jvm\.memory|system\.cpu|activeProfiles|propertySources|contexts|beans|mappings)"' | wc -l)
    if [[ $act_keys -ge 2 ]]; then
        score=$((50 + act_keys * 10))
        [[ $score -gt 90 ]] && score=90
        echo "${score}|actuator|Actuator data (${act_keys} keys)"
        return
    fi

    # Valid JSON with API keys
    if echo "$body" | head -c 2 | grep -qE '^\s*[\{\[]'; then
        if echo "$body" | jq . &>/dev/null; then
            local api_keys
            api_keys=$(echo "$body" | jq -r 'if type == "object" then keys[] else empty end' 2>/dev/null | grep -ciE '^(data|results|items|records|payload|response|error|errors|message|code|status|count|total|page|per_page|pagination|links|meta|version|id)$' || true)
            if [[ $api_keys -ge 1 ]]; then
                score=$((30 + api_keys * 12))
                [[ $score -gt 85 ]] && score=85
                echo "${score}|api_response|JSON API (${api_keys} keys)"
                return
            fi
            local total_keys
            total_keys=$(echo "$body" | jq -r 'if type == "object" then keys | length elif type == "array" then length else 0 end' 2>/dev/null || echo 0)
            score=$((50 + total_keys * 3))
            [[ $score -gt 80 ]] && score=80
            echo "${score}|json_data|JSON data (${total_keys} keys)"
            return
        fi
    fi

    # Generic HTML
    if echo "$body" | head -c 1024 | grep -qiE '<!DOCTYPE|<html|<head|<body'; then
        echo "5|html_page|Generic HTML page"
        return
    fi

    # Plain text
    echo "15|plain_text|Plain text (${#body} bytes)"
}

# ========================= REPROBE ==========================================
REPROBE_TMPDIR=""

do_reprobe() {
    local url="$1"
    local tmpfile="$2"

    local curl_opts=(-s -S -o "$tmpfile" -w '%{http_code}\t%{content_type}\t%{size_download}' --max-time "$TIMEOUT")

    if [[ "$NO_VERIFY" == "true" ]]; then
        curl_opts+=(-k)
    fi
    if [[ -n "$PROXY" ]]; then
        curl_opts+=(--proxy "$PROXY")
    fi
    if [[ -n "$COOKIES" ]]; then
        curl_opts+=(-b "$COOKIES")
    fi
    for h in "${CUSTOM_HEADERS[@]+"${CUSTOM_HEADERS[@]}"}"; do
        [[ -n "$h" ]] && curl_opts+=(-H "$h")
    done

    curl_opts+=(-H "User-Agent: api-verifier/5.0")

    local result
    result=$(curl "${curl_opts[@]}" "$url" 2>/dev/null) || { echo "0||0"; return; }

    echo "$result"
}

reprobe_all() {
    local entries_json="$1"
    local total
    total=$(echo "$entries_json" | jq length)

    log "[*] Re-probing $total URLs with $THREADS parallel workers..."

    REPROBE_TMPDIR=$(mktemp -d)
    trap 'rm -rf "$REPROBE_TMPDIR"' EXIT

    local idx=0
    local done_count=0
    local pids=()

    # Process in batches
    echo "$entries_json" | jq -c '.[]' | while IFS= read -r entry; do
        local url
        url=$(echo "$entry" | jq -r '.url')
        local tmpfile="${REPROBE_TMPDIR}/body_${idx}"
        local metafile="${REPROBE_TMPDIR}/meta_${idx}"

        (
            local result
            result=$(do_reprobe "$url" "$tmpfile")
            echo "$result" > "$metafile"
        ) &

        pids+=($!)
        idx=$((idx + 1))

        # Throttle to THREADS
        if [[ ${#pids[@]} -ge $THREADS ]]; then
            wait "${pids[0]}" 2>/dev/null || true
            pids=("${pids[@]:1}")
        fi

        if [[ $RATE -gt 0 ]]; then
            sleep "$(awk -v r="$RATE" 'BEGIN{printf "%.3f", 1/r}')"  
        fi
    done

    # Wait for remaining
    wait 2>/dev/null || true

    # Now merge body analysis back into entries
    local result="$entries_json"
    for i in $(seq 0 $((total - 1))); do
        local metafile="${REPROBE_TMPDIR}/meta_${i}"
        local bodyfile="${REPROBE_TMPDIR}/body_${i}"

        if [[ -f "$metafile" && -f "$bodyfile" ]]; then
            local meta
            meta=$(cat "$metafile")
            local resp_ct
            resp_ct=$(echo "$meta" | cut -f2)
            local body
            body=$(head -c 16384 "$bodyfile" 2>/dev/null || true)

            if [[ -n "$body" ]]; then
                local analysis
                analysis=$(analyze_body "$body" "$resp_ct" "")
                local bscore btype bdetail
                bscore=$(echo "$analysis" | cut -d'|' -f1)
                btype=$(echo "$analysis" | cut -d'|' -f2)
                bdetail=$(echo "$analysis" | cut -d'|' -f3-)

                result=$(echo "$result" | jq --argjson idx "$i" \
                    --arg bscore "$bscore" --arg bdetail "$bdetail" --arg btype "$btype" \
                    --arg resp_ct "$resp_ct" \
                    '.[$idx].content_score = ($bscore | tonumber) |
                     .[$idx].content_analysis = $bdetail |
                     .[$idx].content_type = (if .[$idx].content_type == "" then $resp_ct else .[$idx].content_type end)')
            fi
        fi
    done

    echo "$result"
    log "  [reprobe] Done."
}

# ========================= MAIN FP ENGINE ===================================
run_fp_engine() {
    local entries_json="$1"
    local total
    total=$(echo "$entries_json" | jq length)

    log "[*] v5 FP Engine analyzing $total results..."

    # ===== PHASE 1: Find dominant fingerprints =====
    log "  [Phase 1] Response fingerprint analysis:"

    # Get fingerprint frequencies: CL,Words,Lines -> count
    local fp_freq
    fp_freq=$(echo "$entries_json" | jq -r '.[] | "\(.length),\(.words),\(.lines)"' | sort | uniq -c | sort -rn)

    # Parse dominant fingerprints (>= 10% or >= 10 count)
    local dominant_fps=()
    local catchall_total=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local count fp_str
        count=$(echo "$line" | awk '{print $1}')
        fp_str=$(echo "$line" | awk '{print $2}')
        local cl words lines
        cl=$(echo "$fp_str" | cut -d, -f1)
        words=$(echo "$fp_str" | cut -d, -f2)
        lines=$(echo "$fp_str" | cut -d, -f3)

        local pct
        pct=$(awk -v c="$count" -v t="$total" 'BEGIN{printf "%.1f", c*100/t}')

        log "$(printf "    CL=%-6s W=%-5s L=%-5s -> %sx (%s%%)" "$cl" "$words" "$lines" "$count" "$pct")"

        # Check if dominant (>= 10% or >= 10 count)
        if (( count >= 10 )) || awk -v p="$pct" 'BEGIN{exit !(p >= 10.0)}'; then
            dominant_fps+=("$fp_str")
            catchall_total=$((catchall_total + count))
        fi
    done < <(echo "$fp_freq" | head -5)

    if [[ ${#dominant_fps[@]} -eq 0 ]]; then
        log "    No dominant fingerprint -- all responses appear unique"
        # All verified
        echo "$entries_json" | jq '[.[] | . + {is_fp: false, confidence: "HIGH", fp_reason: "unique_fingerprint"}]'
        return
    fi

    local catchall_pct
    catchall_pct=$(awk -v c="$catchall_total" -v t="$total" 'BEGIN{printf "%.1f", c*100/t}')
    log "    Catch-all coverage: ${catchall_pct}% of all results"

    if awk -v p="$catchall_pct" 'BEGIN{exit !(p >= 60.0)}'; then
        log "    ${RED}** FULL CATCH-ALL SERVER ** Path names are meaningless without content-type/body proof${RST}"
    fi

    # ===== PHASE 2: Classify each entry =====
    log ""
    log "  [Phase 2] Classifying entries (response proof > path name)..."

    # Build jq filter for dominant fps
    local jq_dominant_check=""
    for fp in "${dominant_fps[@]}"; do
        local dcl dw dl
        dcl=$(echo "$fp" | cut -d, -f1)
        dw=$(echo "$fp" | cut -d, -f2)
        dl=$(echo "$fp" | cut -d, -f3)
        if [[ -n "$jq_dominant_check" ]]; then
            jq_dominant_check="$jq_dominant_check or "
        fi
        jq_dominant_check="${jq_dominant_check}(((.length - ${dcl}) | fabs) <= ${CL_TOL} and .words == ${dw} and .lines == ${dl})"
    done

    # CL frequency map
    local cl_freq_json
    cl_freq_json=$(echo "$entries_json" | jq '[.[] | .length] | group_by(.) | map({key: (.[0] | tostring), value: length}) | from_entries')

    # Process each entry
    local fp_count=0
    local verified_count=0
    local result="[]"

    echo "$entries_json" | jq -c '.[]' | while IFS= read -r entry; do
        local url fuzz status length words lines ct
        url=$(echo "$entry" | jq -r '.url')
        fuzz=$(echo "$entry" | jq -r '.fuzz_word // .fuzz // ""')
        status=$(echo "$entry" | jq -r '.status')
        length=$(echo "$entry" | jq -r '.length')
        words=$(echo "$entry" | jq -r '.words')
        lines=$(echo "$entry" | jq -r '.lines')
        ct=$(echo "$entry" | jq -r '.content_type // ""')
        local content_score
        content_score=$(echo "$entry" | jq -r '.content_score // 0')

        local path_cat
        path_cat=$(classify_path "${fuzz:-$url}")

        # Check if matches catch-all
        local matches_catchall=false
        for fp in "${dominant_fps[@]}"; do
            local dcl dw dl
            dcl=$(echo "$fp" | cut -d, -f1)
            dw=$(echo "$fp" | cut -d, -f2)
            dl=$(echo "$fp" | cut -d, -f3)
            local cl_diff=$(( length > dcl ? length - dcl : dcl - length ))
            if [[ $cl_diff -le $CL_TOL && $words -eq $dw && $lines -eq $dl ]]; then
                matches_catchall=true
                break
            fi
        done

        local is_fp=false
        local reasons=""

        if [[ "$matches_catchall" == "true" ]]; then
            reasons="matches_catchall(CL=${length},W=${words},L=${lines})"

            # Can we RESCUE with proof?
            if is_structured_ct "$ct" && ct_matches_category "$ct" "$path_cat"; then
                reasons="${reasons}; RESCUED:ct_matches_path(${path_cat}+${ct})"
                is_fp=false
            elif [[ $content_score -ge 50 ]]; then
                reasons="${reasons}; RESCUED:body_verified(score=${content_score})"
                is_fp=false
            elif is_structured_ct "$ct" && ! is_html_ct "$ct"; then
                if [[ $content_score -ge 30 ]]; then
                    reasons="${reasons}; RESCUED:structured_ct+body(score=${content_score})"
                    is_fp=false
                else
                    reasons="${reasons}; FP:structured_ct_but_catchall_body"
                    is_fp=true
                fi
            else
                is_fp=true
                if [[ "$path_cat" != "generic" ]]; then
                    reasons="${reasons}; FP:path_${path_cat}_but_html_catchall"
                else
                    reasons="${reasons}; FP:generic_catchall"
                fi
            fi
        else
            reasons="unique_response(CL=${length},W=${words},L=${lines})"

            # Check if CL is still very common
            local cl_freq
            cl_freq=$(echo "$cl_freq_json" | jq -r --arg cl "$length" '.[$cl] // 0')
            local cl_pct
            cl_pct=$(awk -v c="$cl_freq" -v t="$total" 'BEGIN{printf "%.1f", c*100/t}')

            if awk -v p="$cl_pct" 'BEGIN{exit !(p >= 15.0)}' && is_html_ct "$ct" && [[ $content_score -lt 30 ]]; then
                is_fp=true
                reasons="${reasons}; FP:common_cl(${cl_pct}%)+html"
            elif awk -v p="$cl_pct" 'BEGIN{exit !(p >= 30.0)}' && [[ $content_score -lt 30 ]]; then
                is_fp=true
                reasons="${reasons}; FP:very_common_cl(${cl_pct}%)"
            fi

            # v5.1 FIX: Categorized paths MUST have matching content-type
            # swagger.json returning text/html is NEVER real even with unique CL
            if [[ "$is_fp" == "false" ]] && [[ "$path_cat" != "generic" ]] && [[ "$path_cat" != "debug" ]] && [[ "$path_cat" != "redoc" ]]; then
                if is_html_ct "$ct" && [[ $content_score -lt 40 ]]; then
                    is_fp=true
                    reasons="${reasons}; FP:path_${path_cat}_returns_html_not_structured"
                elif ! is_structured_ct "$ct" && ! is_html_ct "$ct" && [[ $content_score -lt 20 ]]; then
                    is_fp=true
                    reasons="${reasons}; FP:path_${path_cat}_no_structured_ct_no_proof"
                fi
            fi
        fi

        # Auth status rescue
        if [[ "$is_fp" == "true" ]] && [[ "$status" =~ ^(401|403|405)$ ]]; then
            local same_status_count
            same_status_count=$(echo "$entries_json" | jq "[.[] | select(.status == ${status})] | length")
            local status_pct
            status_pct=$(awk -v c="$same_status_count" -v t="$total" 'BEGIN{printf "%.2f", c*100/t}')
            if awk -v p="$status_pct" 'BEGIN{exit !(p < 20.0)}'; then
                is_fp=false
                reasons="${reasons}; RESCUED:auth_status_${status}"
            fi
        fi

        # Confidence scoring
        local confidence="LOW"
        if [[ "$is_fp" == "true" ]]; then
            confidence="FP"
        else
            local score=0
            [[ "$matches_catchall" == "false" ]] && score=$((score + 25))
            is_structured_ct "$ct" 2>/dev/null && score=$((score + 25))
            [[ $content_score -ge 50 ]] && score=$((score + 25))
            [[ "$status" =~ ^(401|403|405)$ ]] && score=$((score + 20))
            local cl_unique_count
            cl_unique_count=$(echo "$cl_freq_json" | jq -r --arg cl "$length" '.[$cl] // 0')
            [[ $cl_unique_count -le 2 ]] && score=$((score + 15))
            if [[ "$path_cat" != "generic" ]] && ct_matches_category "$ct" "$path_cat" 2>/dev/null; then
                score=$((score + 15))
            fi
            if [[ $score -ge 50 ]]; then
                confidence="HIGH"
            elif [[ $score -ge 25 ]]; then
                confidence="MEDIUM"
            fi
        fi

        # Output augmented entry
        echo "$entry" | jq -c \
            --arg is_fp "$is_fp" \
            --arg confidence "$confidence" \
            --arg fp_reason "$reasons" \
            --arg path_category "$path_cat" \
            '. + {
                is_fp: ($is_fp == "true"),
                confidence: $confidence,
                fp_reason: $fp_reason,
                path_category: $path_category
            }'

    done | jq -s '.'
}

# ========================= PRINT TABLE =====================================
print_hit_table() {
    local results_json="$1"
    local verified
    verified=$(echo "$results_json" | jq '[.[] | select(.is_fp == false)]')
    local count
    count=$(echo "$verified" | jq length)

    if [[ $count -eq 0 ]]; then
        log "[*] No verified endpoints found after filtering."
        return
    fi

    log ""
    log "$(printf '=%.0s' {1..120})"
    log " VERIFIED ENDPOINTS ($count hits)"
    log "$(printf '=%.0s' {1..120})"
    printf "%-8s %-10s %-8s %-8s %-10s %-6s %-14s %s\n" \
        "Status" "Length" "Words" "Lines" "Time(ms)" "Conf" "Category" "URL"
    log "$(printf -- '-%.0s' {1..120})"

    echo "$verified" | jq -r 'sort_by(.confidence != "HIGH", (-.content_score // 0)) | .[] |
        "\(.status)\t\(.length)\t\(.words)\t\(.lines)\t\(.duration_ms // .duration_ns / 1000000 // 0 | floor)\t\(.confidence)\t\(.path_category // "generic")\t\(.url)\t\(.content_analysis // "")\t\(.content_type // "")"' | \
    while IFS=$'\t' read -r st len w l dur conf cat url analysis ct; do
        local color="$CYAN"
        case "$st" in
            2[0-9][0-9]) color="$GREEN" ;;
            3[0-9][0-9]) color="$YELLOW" ;;
            401|403)     color="$RED" ;;
            405)         color="$MAGENTA" ;;
        esac

        local evidence=""
        [[ -n "$analysis" ]] && evidence="  [$analysis]"
        [[ -n "$ct" ]] && evidence="${evidence}  (${ct%%;})"

        printf "${color}%-8s${RST} %-10s %-8s %-8s %-10s %-6s %-14s %s%s\n" \
            "$st" "$len" "$w" "$l" "$dur" "$conf" "${cat:0:13}" "$url" "$evidence"
    done
}

# ========================= WRITE OUTPUT =====================================
write_output() {
    local results_json="$1"
    local outfile="$2"

    local out_json
    if [[ "$INCLUDE_FP" == "true" ]]; then
        out_json="$results_json"
    else
        out_json=$(echo "$results_json" | jq '[.[] | select(.is_fp == false)]')
    fi

    local ext="${outfile##*.}"
    case "$ext" in
        json)
            echo "$out_json" | jq '.' > "$outfile"
            ;;
        csv)
            echo "url,path,fuzz,status,length,words,lines,content_type,confidence,path_category,content_score,content_analysis,is_fp,fp_reason" > "$outfile"
            echo "$out_json" | jq -r '.[] |
                [.url, .path, (.fuzz // .fuzz_word // ""), .status, .length, .words, .lines,
                 (.content_type // ""), .confidence, (.path_category // ""), (.content_score // 0),
                 (.content_analysis // ""), .is_fp, (.fp_reason // "")] | @csv' >> "$outfile"
            ;;
        txt)
            echo "$out_json" | jq -r '.[].url' > "$outfile"
            ;;
        *)
            outfile="${outfile}.json"
            echo "$out_json" | jq '.' > "$outfile"
            ;;
    esac

    local verified
    verified=$(echo "$out_json" | jq '[.[] | select(.is_fp == false)] | length')
    log ""
    log "[+] Saved $verified verified hits to $outfile"
}

# ========================= URL LIST PROBER =================================
probe_url_list() {
    local url_file="$1"
    local total=0 done_count=0 err_count=0
    local entries_json="[]"
    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf $tmpdir" EXIT

    local urls=()
    while IFS= read -r line; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" || "$line" == \#* ]] && continue
        urls+=("$line")
    done < "$url_file"
    total=${#urls[@]}
    log "[*] Loaded $total URLs from $url_file"
    [[ $total -eq 0 ]] && { log "[!] No URLs found."; exit 0; }
    log "[*] Probing $total URLs..."

    local curl_opts=("--max-time" "$TIMEOUT" "-s" "-L")
    [[ "$NO_VERIFY" == "true" ]] && curl_opts+=("-k")
    [[ -n "$PROXY" ]] && curl_opts+=("-x" "$PROXY")
    [[ -n "$COOKIES" ]] && curl_opts+=("-b" "$COOKIES")
    for h in "${CUSTOM_HEADERS[@]+"${CUSTOM_HEADERS[@]}"}"; do
        [[ -n "$h" ]] && curl_opts+=("-H" "$h")
    done

    local i=0
    for url in "${urls[@]}"; do
        i=$((i + 1))
        local outfile="$tmpdir/body_$i"
        local resp
        resp=$(curl "${curl_opts[@]}" -o "$outfile" \
            -w '%{http_code}\t%{size_download}\t%{content_type}\t%{time_total}\t%{redirect_url}' \
            "$url" 2>/dev/null) || { err_count=$((err_count+1)); continue; }

        local status length ct time_s redir
        status=$(echo "$resp" | cut -f1)
        length=$(echo "$resp" | cut -f2)
        ct=$(echo "$resp" | cut -f3)
        time_s=$(echo "$resp" | cut -f4)
        redir=$(echo "$resp" | cut -f5)

        [[ "$status" == "404" || "$status" == "410" || "$status" == "501" || "$status" == "000" ]] && continue

        local path host
        path=$(echo "$url" | sed 's|https\?://[^/]*||; s|?.*||')
        [[ -z "$path" ]] && path="/"
        host=$(echo "$url" | sed 's|https\?://||; s|/.*||')

        local body=""
        [[ -f "$outfile" ]] && body=$(head -c 16384 "$outfile" 2>/dev/null)

        local words=0 lines_count=0
        if [[ -n "$body" ]]; then
            words=$(echo "$body" | wc -w | tr -d ' ')
            lines_count=$(echo "$body" | wc -l | tr -d ' ')
        fi

        local duration_ms
        duration_ms=$(awk -v t="$time_s" 'BEGIN{printf "%.1f", t*1000}')

        local content_score=0 content_analysis="" content_tags=""
        if [[ -n "$body" ]]; then
            local ba_result
            ba_result=$(analyze_body "$body" "$ct" "$path")
            content_score=$(echo "$ba_result" | cut -d'|' -f1)
            content_analysis=$(echo "$ba_result" | cut -d'|' -f2)
            content_tags=$(echo "$ba_result" | cut -d'|' -f3)
        fi

        entries_json=$(echo "$entries_json" | jq \
            --arg url "$url" --arg fw "$path" \
            --argjson st "$status" --argjson len "${length:-0}" \
            --argjson w "$words" --argjson l "$lines_count" \
            --arg ct "$ct" --arg redir "${redir:-}" \
            --argjson dur_ms "${duration_ms:-0}" --arg host "$host" \
            --argjson cs "$content_score" --arg ca "$content_analysis" \
            --arg ctags "$content_tags" \
            '. + [{url:$url, fuzz_word:$fw, status:$st, length:$len, words:$w, lines:$l,
                   content_type:$ct, redirect_location:$redir, duration_ns:0,
                   duration_ms:$dur_ms, host:$host, position:0,
                   content_score:$cs, content_analysis:$ca, content_tags:$ctags}]')

        done_count=$((done_count + 1))
        [[ $((done_count % 100)) -eq 0 ]] && log "  [probe] $done_count/$total"

        if [[ "$RATE" != "0" ]] && [[ -n "$RATE" ]]; then
            sleep "$(awk -v r="$RATE" 'BEGIN{printf "%.3f", 1/r}')"
        fi
    done

    rm -rf "$tmpdir"
    trap - EXIT
    log "  [probe] Done. $done_count/$total probed, $err_count errors"
    echo "$entries_json"
}

# ========================= MAIN ============================================
main() {
    if [[ -n "$URL_LIST" ]]; then
        log "[*] URL list mode: $URL_LIST"
        local entries_json
        entries_json=$(probe_url_list "$URL_LIST")
        local total
        total=$(echo "$entries_json" | jq length)
        log "[*] $total valid responses after probing"
        [[ $total -eq 0 ]] && { log "[!] No valid responses."; exit 0; }

        local results_json
        results_json=$(run_fp_engine "$entries_json")
        [[ "$QUIET" != "true" ]] && print_hit_table "$results_json"

        local fp_count verified_count
        fp_count=$(echo "$results_json" | jq '[.[] | select(.is_fp == true)] | length')
        verified_count=$(echo "$results_json" | jq '[.[] | select(.is_fp == false)] | length')
        log ""
        log "  [Result] Total: $total | FPs: $fp_count ($(awk -v c="$fp_count" -v t="$total" 'BEGIN{printf "%.1f", c*100/t}')%) | Verified: $verified_count"
        write_output "$results_json" "$OUTPUT_FILE"

    elif [[ -n "$FFUF_FILE" ]]; then
        log "[*] Parsing ffuf output: $FFUF_FILE"
        local entries_json
        entries_json=$(jq '[.results[] | {
            url: .url,
            fuzz_word: ((.input.FUZZ // (.input | to_entries | .[0].value // "")) | tostring),
            status: (.status // 0), length: (.length // 0),
            words: (.words // 0), lines: (.lines // 0),
            content_type: (."content-type" // .content_type // ""),
            redirect_location: (.redirectlocation // ""),
            duration_ns: (.duration // 0),
            duration_ms: ((.duration // 0) / 1000000),
            host: (.host // ""), position: (.position // 0),
            content_score: 0, content_analysis: "", content_tags: ""
        }]' "$FFUF_FILE")

        local total
        total=$(echo "$entries_json" | jq length)
        log "[*] Loaded $total results from ffuf"
        local cmdline
        cmdline=$(jq -r '.commandline // ""' "$FFUF_FILE" | head -c 120)
        [[ -n "$cmdline" ]] && log "    Command: $cmdline"
        [[ $total -eq 0 ]] && { log "[!] No results found."; exit 0; }

        [[ "$REPROBE" == "true" ]] && entries_json=$(reprobe_all "$entries_json")

        local results_json
        results_json=$(run_fp_engine "$entries_json")
        [[ "$QUIET" != "true" ]] && print_hit_table "$results_json"

        local fp_count verified_count
        fp_count=$(echo "$results_json" | jq '[.[] | select(.is_fp == true)] | length')
        verified_count=$(echo "$results_json" | jq '[.[] | select(.is_fp == false)] | length')
        log ""
        log "  [Result] Total: $total | FPs: $fp_count ($(awk -v c="$fp_count" -v t="$total" 'BEGIN{printf "%.1f", c*100/t}')%) | Verified: $verified_count"
        write_output "$results_json" "$OUTPUT_FILE"
    else
        err "No input provided. Use -f or --url-list"
        usage
    fi
}

main
