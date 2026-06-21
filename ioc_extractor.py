import re

with open("sample_report.txt", "r") as file:
    data = file.read()

ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data)

domains = re.findall(
    r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
    data
)

urls = re.findall(
    r'https?://[^\s]+',
    data
)

emails = re.findall(
    r'[\w\.-]+@[\w\.-]+\.\w+',
    data
)

md5 = re.findall(
    r'\b[a-fA-F0-9]{32}\b',
    data
)

sha1 = re.findall(
    r'\b[a-fA-F0-9]{40}\b',
    data
)

sha256 = re.findall(
    r'\b[a-fA-F0-9]{64}\b',
    data
)

executables = re.findall(
    r'\b\w+\.exe\b',
    data
)

print("\n===== IOC REPORT =====")

print("\nIP Addresses:")
for item in ips:
    print(item)

print("\nDomains:")
for item in domains:
    print(item)

print("\nURLs:")
for item in urls:
    print(item)

print("\nEmails:")
for item in emails:
    print(item)

print("\nMD5 Hashes:")
for item in md5:
    print(item)

print("\nSHA1 Hashes:")
for item in sha1:
    print(item)

print("\nSHA256 Hashes:")
for item in sha256:
    print(item)

print("\nExecutables:")
for item in executables:
    print(item)
