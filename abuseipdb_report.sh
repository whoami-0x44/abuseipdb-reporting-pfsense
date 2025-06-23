#!/bin/sh

# Prevent running multiple instances of the script simultaneously
if pgrep -f "$(basename "$0")" | grep -v "$$" > /dev/null; then
    exit 1
fi

# Paths to log files
file_to_monitor="/var/log/filter.log"
seen_file="/tmp/seen_ips.txt"

# TTL for IPs in seconds (24 hours)
ip_ttl=86400

# Create the seen IPs file if it doesn't exist
touch "$seen_file"
chmod 600 "$seen_file"

# Get current Unix timestamp
now() {
    date +%s
}

# Extract IP address from log line (19th field)
extract_blocked_ips() {
    echo "$1" \
      | grep -E 'eth0.*block,in.*tcp.*,[0-9]+,S,' \
      | awk -F, '{ print $19 }' \
      | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
}

# Check if IP was seen recently and clean up old entries
has_seen_ip() {
    current=$(now)
    found=1
    tmpfile=$(mktemp) || exit 1

    while IFS=: read -r ip_addr ts; do
        [ -z "$ip_addr" ] && continue
        age=$((current - ts))
        if [ "$age" -lt "$ip_ttl" ]; then
            echo "$ip_addr:$ts" >> "$tmpfile"
            if [ "$ip_addr" = "$1" ]; then
                found=0
            fi
        fi
    done < "$seen_file"

    mv "$tmpfile" "$seen_file"
    return $found
}

# Add new IP to the seen file
add_seen_ip() {
    ts=$(now)
    echo "$1:$ts" >> "$seen_file"
}

# Check if ABUSEIPDB API KEY is set
if [ -z "${ABUSEIPDB_API_KEY:-}" ]; then
    return
fi

# Report IP to AbuseIPDB
report_to_abuseipdb() {

    curl --tlsv1.3 -sSf -X POST "https://api.abuseipdb.com/api/v2/report" \
         -H "Key: $ABUSEIPDB_API_KEY" \
         -H "Content-Type: application/json" \
         -d "{\"ip\":\"$1\",\"categories\":[14],\"comment\":\"Port scanning\"}" \
    >/dev/null 2>&1
}

# Main loop: read new lines from the log file
tail -n0 -F "$file_to_monitor" | while IFS= read -r line; do
    ip=$(extract_blocked_ips "$line")

    if [ -n "$ip" ]; then
        if has_seen_ip "$ip"; then
            :
        else
            report_to_abuseipdb "$ip"
            add_seen_ip "$ip"
        fi
    fi
done