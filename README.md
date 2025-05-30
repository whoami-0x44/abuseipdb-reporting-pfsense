# :shield: Automated AbuseIPDB Reporter for pfSense
This shell script monitors pfSense firewall logs for suspicious IP addresses. It detects TCP packets with the SYN flag that may indicate port scanning attempts and reports them to AbuseIPDB. To avoid duplicate reports, the script tracks each IP address within a 24-hour time window.

---

## :package: Installation

Clone the repository:
```bash 
git clone https://github.com/whoami-0x44/abuseipdb-reporting-pfsense.git

cd abuseipdb-reporting-pfsense
```
By default, the function `extract_blocked_ips` looks for lines containing the `eth0` interface. If your WAN interface has a different name (like enp1s0), simply replace `eth0` in the grep line with the correct interface name for your system.

### Example

If your WAN interface is enp1s0, update this line:
```bash 
grep -E 'eth0.*block,in.*tcp.*,[0-9]+,S,'
```
to:
```bash 
grep -E 'enp1s0.*block,in.*tcp.*,[0-9]+,S,'
```
:wrench: Optional: Customize the report comment by editing the `comment` field in the script.

Make the Script Executable:
```bash 
chmod 700 abuseipdb_report.sh
```

Edit the crontab:
```bash 
vi crontab -e
```

Add to crontab to run the script at system boot:
```bash 
@reboot   ABUSEIPDB_API_KEY="your api key"   /bin/sh   /path/to/abuseipdb_report.sh
```
:pushpin: Replace `your api key` with your actual AbuseIPDB API key.

---

## :gear: Requirements

AbuseIPDB API key: 
- You must set up an AbuseIPDB API key to report suspicious IPs.

---

## :information_source: Why a 24-Hour Reporting Interval?

AbuseIPDB does not accept duplicate reports for the same IP with the same comment within a 24-hour period.
To comply with this, the script tracks each reported IP and avoids re-reporting it within that window.
