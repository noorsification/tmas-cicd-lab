import json

INPUT_FILE = "scan-results.json"
OUTPUT_FILE = "tmas_overrides.yml"

TARGET_SEVERITIES = {"critical", "high"}


def find_vulnerabilities(obj):
    results = []

    if isinstance(obj, dict):

        if (
            "id" in obj
            and "fix" in obj
            and "severity" in obj
            and "name" in obj
        ):
            results.append(obj)

        for value in obj.values():
            results.extend(find_vulnerabilities(value))

    elif isinstance(obj, list):

        for item in obj:
            results.extend(find_vulnerabilities(item))

    return results


with open(INPUT_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)


vulnerabilities = find_vulnerabilities(data)

selected = []

for vuln in vulnerabilities:

    severity = str(vuln.get("severity", "")).lower()
    fix_state = str(vuln.get("fix", "")).lower()

    if (
        severity in TARGET_SEVERITIES
        and fix_state == "unknown"
    ):
        selected.append(vuln)


# Deduplicate by CVE
unique = {}

for vuln in selected:

    cve = vuln.get("id")

    if cve:
        unique[cve] = vuln


with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

    f.write("vulnerabilities:\n")

    for cve, vuln in sorted(unique.items()):

        severity = vuln.get("severity", "Unknown")
        package = vuln.get("name", "Unknown")
        version = vuln.get("version", "Unknown")

        f.write("  - rule:\n")
        f.write(f"      vulnerability: {cve}\n")
        f.write("      fixState: unknown\n")
        f.write(
            f'    reason: "Automated override for {severity} '
            f'vulnerability with unknown fix state. '
            f'Package: {package}, version: {version}."\n'
        )


print("========================================")
print("TMAS Override Generator")
print("========================================")
print(f"Total vulnerabilities : {len(vulnerabilities)}")
print(f"Selected              : {len(selected)}")
print(f"Unique CVEs           : {len(unique)}")
print("")

if unique:

    print("Override candidates:")

    for cve, vuln in sorted(unique.items()):

        print(
            f"{cve} | "
            f"{vuln.get('severity')} | "
            f"{vuln.get('name')} | "
            f"{vuln.get('version')} | "
            f"fix={vuln.get('fix')}"
        )

else:

    print("No Critical/High vulnerability with fix=unknown.")
