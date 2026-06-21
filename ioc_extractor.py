import re
import csv
import glob

# ==========================
# Multi File Processing
# ==========================

files = glob.glob("*.txt")

combined_data = ""

for file in files:
    try:
        with open(file, "r") as f:
            combined_data += f.read() + "\n"
    except:
        pass

data = combined_data

# ==========================
# IOC Extraction
# ==========================

ips = list(set(
    re.findall(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        data
    )
))

domains = list(set(
    re.findall(
        r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        data
    )
))

urls = list(set(
    re.findall(
        r'https?://[^\s]+',
        data
    )
))

emails = list(set(
    re.findall(
        r'[\w\.-]+@[\w\.-]+\.\w+',
        data
    )
))

md5 = list(set(
    re.findall(
        r'\b[a-fA-F0-9]{32}\b',
        data
    )
))

sha1 = list(set(
    re.findall(
        r'\b[a-fA-F0-9]{40}\b',
        data
    )
))

sha256 = list(set(
    re.findall(
        r'\b[a-fA-F0-9]{64}\b',
        data
    )
))

executables = list(set(
    re.findall(
        r'\b\w+\.exe\b',
        data
    )
))

# ==========================
# Statistics
# ==========================

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

# ==========================
# Threat Severity
# ==========================

severity = "LOW"

if len(ips) > 0 and len(executables) > 0:
    severity = "HIGH"

elif len(ips) > 0 or len(urls) > 0:
    severity = "MEDIUM"

# ==========================
# Threat Hunting Summary
# ==========================

summary = f"""
============================
THREAT HUNTING SUMMARY
============================

Files Analyzed: {len(files)}

IP Addresses Found: {len(ips)}
Domains Found: {len(domains)}
URLs Found: {len(urls)}
Emails Found: {len(emails)}
Executables Found: {len(executables)}

Overall Risk Level: {severity}
"""

print(summary)

# ==========================
# CSV Export
# ==========================

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

# ==========================
# HTML Dashboard
# ==========================

html = f"""
<!DOCTYPE html>
<html>
<head>

<title>IOC Dashboard</title>

<style>

body {{
    background:#121212;
    color:white;
    font-family:Arial;
    margin:20px;
}}

.card {{
    background:#1f1f1f;
    padding:15px;
    margin:10px;
    border-radius:10px;
}}

.high {{
    color:red;
}}

.medium {{
    color:orange;
}}

.low {{
    color:lime;
}}

table {{
    width:100%;
    border-collapse:collapse;
}}

th, td {{
    border:1px solid #444;
    padding:10px;
}}

input {{
    width:100%;
    padding:10px;
    margin-bottom:20px;
}}

</style>

<script>

function searchIOC() {{

var input =
document.getElementById("search");

var filter =
input.value.toUpperCase();

var table =
document.getElementById("iocTable");

var tr =
table.getElementsByTagName("tr");

for(var i=0;i<tr.length;i++) {{

var td =
tr[i].getElementsByTagName("td")[1];

if(td) {{

txtValue =
td.textContent ||
td.innerText;

tr[i].style.display =
txtValue.toUpperCase().indexOf(filter) > -1
? ""
: "none";

}}

}}

}}

</script>

</head>

<body>

<h1>IOC Threat Hunting Dashboard</h1>

<div class="card">

<h2>
Threat Severity:
<span class="{severity.lower()}">
{severity}
</span>
</h2>

<p>
Files Analyzed:
{len(files)}
</p>

</div>
"""

for key, value in stats.items():

    html += f"""
    <div class="card">
    <h3>{key}</h3>
    <h1>{value}</h1>
    </div>
    """

html += """

<input
type="text"
id="search"
onkeyup="searchIOC()"
placeholder="Search IOC...">

<table id="iocTable">

<tr>
<th>Type</th>
<th>Indicator</th>
</tr>

"""

for item in ips:
    html += f"<tr><td>IP</td><td>{item}</td></tr>"

for item in domains:
    html += f"<tr><td>Domain</td><td>{item}</td></tr>"

for item in urls:
    html += f"<tr><td>URL</td><td>{item}</td></tr>"

for item in emails:
    html += f"<tr><td>Email</td><td>{item}</td></tr>"

for item in md5:
    html += f"<tr><td>MD5</td><td>{item}</td></tr>"

for item in sha1:
    html += f"<tr><td>SHA1</td><td>{item}</td></tr>"

for item in sha256:
    html += f"<tr><td>SHA256</td><td>{item}</td></tr>"

for item in executables:
    html += f"<tr><td>Executable</td><td>{item}</td></tr>"

html += """

</table>

</body>
</html>

"""

with open("reports/report.html", "w") as f:
    f.write(html)

print("HTML Dashboard Generated")
print("CSV Report Generated")
