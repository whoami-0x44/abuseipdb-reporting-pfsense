#!/bin/sh

# Path to the log file
file_to_monitor="/var/log/filter.log"

# How long we remember an IP (in seconds)
ip_ttl=86400

# Store seen IPs here, format "IP:timestamp"
seen_ips=""

# Get current time as UNIX timestamp using Perl (works on FreeBSD)
now() {
    perl -e 'print time'
}

# Extract IP addresses from log lines where incoming TCP connections with SYN flag were blocked on eth0
extract_blocked_ips() {
    echo "$1" \
      | grep -E 'eth0.*block,in.*tcp.*,[0-9]+,S,' \
      | awk -F, '{ print $19 }' \
      | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
}

# Check if we've seen this IP recently and clean out old ones
# Returns 0 if found, 1 if not
has_seen_ip() {
    current=$(now)
    new_list=""
    found=1

    for entry in $seen_ips; do
        [ -z "$entry" ] && continue
        ip_addr=${entry%:*}
        ts=${entry#*:}
        age=$((current - ts))

        # Keep only recent entries
        if [ "$age" -lt "$ip_ttl" ]; then
            new_list="$new_list $ip_addr:$ts"
            [ "$ip_addr" = "$1" ] && found=0
        fi
    done

    seen_ips="$new_list"
    return $found
}

# Add a new IP with the current timestamp
add_seen_ip() {
    ts=$(now)
    if [ -z "$seen_ips" ]; then
        seen_ips="$1:$ts"
    else
        seen_ips="$seen_ips $1:$ts"
    fi
}

# Send the IP report to AbuseIPDB
report_to_abuseipdb() {
    curl --tlsv1.3 -sSf -X POST "https://api.abuseipdb.com/api/v2/report" \
         -H "Key: $ABUSEIPDB_API_KEY" \
         -H "Content-Type: application/json" \
         -d "{\"ip\":\"$1\",\"categories\":[14],\"comment\":\"Port scanning\"}" \
    >/dev/null
}

# Main loop: watch the log and handle new lines as they come in
tail -n0 -F "$file_to_monitor" | while IFS= read -r line; do
    ip=$(extract_blocked_ips "$line")

    # Skip if no IP found on this line
    [ -z "$ip" ] && continue

    # If we've already reported this IP recently, skip it
    if has_seen_ip "$ip"; then
        continue
    fi

    # Otherwise, report it and remember it
    report_to_abuseipdb "$ip"
    add_seen_ip "$ip"
done
