import re
import json
import csv
from collections import Counter

# Mənbə faylının adı
log_file = "server_logs.txt"

# 1. Log faylını oxumaq
with open(log_file, "r") as file:
    logs = file.readlines()

# 2. Regex ifadəsi ilə məlumat çıxarmaq
failed_logins = []
log_entries = []

# Regex şablonu
regex = r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) .? (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b) .? \"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)"

for log in logs:
    match = re.search(regex, log)
    if match:
        date, ip, method = match.groups()
        log_entries.append({"date": date, "ip": ip, "method": method})
        if "401" in log or "Failed login attempt" in log:
            failed_logins.append(ip)

# 3. Uğursuz girişlərin statistikasını yaratmaq
failed_counts = Counter(failed_logins)

# 4. 5-dən çox uğursuz giriş cəhdi olan IP-ləri çıxarmaq
threat_ips = {ip: count for ip, count in failed_counts.items() if count > 5}

# 5. Fayllara yazmaq
# Failed logins
with open("failed_logins.json", "w") as file:
    json.dump(failed_counts, file, indent=4)

# Threat IPs
with open("threat_ips.json", "w") as file:
    json.dump(threat_ips, file, indent=4)

# Combined security data
with open("combined_security_data.json", "w") as file:
    json.dump({"failed_logins": failed_counts, "threat_ips": threat_ips}, file, indent=4)

# Log analysis (Text format)
with open("log_analysis.txt", "w") as file:
    file.write("IP Address\tDate\tHTTP Method\n")
    for entry in log_entries:
        file.write(f"{entry['ip']}\t{entry['date']}\t{entry['method']}\n")

# Log analysis (CSV format)
with open("log_analysis.csv", "w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=["ip", "date", "method"])
    writer.writeheader()
    writer.writerows(log_entries)

print("Bütün fayllar uğurla yaradıldı!")

