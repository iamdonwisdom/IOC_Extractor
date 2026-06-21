import re
import csv
from collections import Counter

INPUT_FILE = "sample_report.txt"

with open(INPUT_FILE, "r") as file:
    data = file.read()

# IOC Extraction

ips = list(set(
    re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data)
))

domains = list(set(
    re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', data)
))

urls = list(set(
    re.findall(r'https?://[^\s]+', data)
))

emails = list(set(
    re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', data)
))

md5 = list(set(
    re.findall(r'\b[a-fA-F0-9]{32}\b', data)
))

sha1 = list(set(
    re.findall(r'\b[a-fA-F0-9]{40}\b', data)
))

sha256 = list(set(
    re.findall(r'\b[a-fA-F0-9]{64}\b', data)
))

executables = list(set(
    re.findall(r'\b\w+\.exe\b', data)
))

# Statistics

stats = {
    "IPs": len(ips),
    "Domains": len(domains),
    "URLs": len(urls),
    "Emails": len(emails),
    "MD5": len(md5),
    "SHA1": len(sha1),
    "SHA256": len(sha256),
    "Executables": len(executables)
}

# Severity Scoring

severity = "LOW"

if len(ips) > 0 and len(executables) > 0:
    severity = "HIGH"

elif len(ips) > 0 or len(urls) > 0:
    severity = "MEDIUM"

# Console Output

print("\n========== IOC REPORT ==========")

for key, value in stats.items():
    print(f"{key}: {value}")

print(f"\nThreat Severity: {severity}")

# CSV Export

with open("reports/report.csv", "w", newline="") as csvfile:

    writer = csv.writer(csvfile)

    writer.writerow(["IOC Type", "Value"])

    for item in ips:
        writer.writerow(["IP", item])

    for item in domains:
        writer.writerow(["Domain", item])

    for item in urls:
        writer.writerow(["URL", item])

    for item in emails:
        writer.writerow(["Email", item])

    for item in md5:
        writer.writerow(["MD5", item])

    for item in sha1:
        writer.writerow(["SHA1", item])

    for item in sha256:
        writer.writerow(["SHA256", item])

    for item in executables:
        writer.writerow(["Executable", item])

# HTML Report

html = f"""
<html>
<head>
<title>IOC Report</title>
</head>
<body>

<h1>IOC Extraction Report</h1>

<h2>Threat Severity: {severity}</h2>

<table border="1">
<tr>
<th>IOC Type</th>
<th>Count</th>
</tr>
"""

for key, value in stats.items():
    html += f"<tr><td>{key}</td><td>{value}</td></tr>"

html += """
</table>

</body>
</html>
"""

with open("reports/report.html", "w") as file:
    file.write(html)

print("\nHTML Report Generated")
print("CSV Report Generated")
