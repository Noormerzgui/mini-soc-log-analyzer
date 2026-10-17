
from datetime import datetime, timedelta
from collections import defaultdict

# ==========================================
# MINI SOC LOG ANALYZER
# Detects suspicious login activity
# ==========================================

LOG_FILE = "login_logs.txt"
REPORT_FILE = "security_report.txt"

TIME_WINDOW = timedelta(minutes=5)
FAILED_LIMIT = 3

print("=" * 45)
print("          MINI SOC LOG ANALYZER")
print("=" * 45)

# Store information about login activity
failed_by_ip = defaultdict(int)
timestamps_by_ip = defaultdict(list)

total_attempts = 0
successful_logins = 0
failed_logins = 0
invalid_lines = 0

# Step 1: Read the security log file
try:
    with open(LOG_FILE, "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            parts = line.split("|")

            if len(parts) != 3:
                invalid_lines += 1
                continue

            try:
                timestamp = datetime.strptime(
                    parts[0].strip(),
                    "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                invalid_lines += 1
                continue

            ip_address = parts[1].strip()
            status = parts[2].strip().upper()

            if status not in ("SUCCESS", "FAILED"):
                invalid_lines += 1
                continue

            total_attempts += 1

            if status == "SUCCESS":
                successful_logins += 1

            elif status == "FAILED":
                failed_logins += 1
                failed_by_ip[ip_address] += 1
                timestamps_by_ip[ip_address].append(timestamp)

except FileNotFoundError:
    print("ERROR: Log file not found:", LOG_FILE)
    print("Make sure the file is in the project folder.")

else:
    # Step 2: Look for repeated failures in 5 minutes
    suspicious_ips = {}

    for ip_address, times in timestamps_by_ip.items():
        times.sort()

        for start in range(len(times)):
            end = start

            while (
                end < len(times)
                and times[end] - times[start] <= TIME_WINDOW
            ):
                end += 1

            attempts_in_window = end - start

            if attempts_in_window >= FAILED_LIMIT:
                suspicious_ips[ip_address] = (
                    times[start],
                    times[end - 1],
                    attempts_in_window
                )
                break

    # Step 3: Display the results
    print("\n--- LOGIN SUMMARY ---")
    print("Total login attempts:", total_attempts)
    print("Successful logins:", successful_logins)
    print("Failed logins:", failed_logins)
    print("Invalid log lines:", invalid_lines)

    print("\n--- FAILED LOGINS BY IP ---")

    if failed_by_ip:
        for ip_address, count in sorted(failed_by_ip.items()):
            print(f"{ip_address}: {count} failed attempts")
    else:
        print("No failed logins found.")

    print("\n--- SECURITY ALERTS ---")

    if suspicious_ips:
        for ip_address, details in sorted(suspicious_ips.items()):
            start_time, end_time, count = details

            print("WARNING: Suspicious activity detected!")
            print("IP address:", ip_address)
            print("Failures in time window:", count)
            print("First failure:", start_time)
            print("Last failure:", end_time)
            print("-" * 30)
    else:
        print("No suspicious 5-minute pattern detected.")

    # Step 4: Save a report
    report = [
        "MINI SOC LOG ANALYZER - SECURITY REPORT",
        "=" * 40,
        f"Total login attempts: {total_attempts}",
        f"Successful logins: {successful_logins}",
        f"Failed logins: {failed_logins}",
        f"Invalid log lines: {invalid_lines}",
        "",
        "FAILED LOGINS BY IP:"
    ]

    for ip_address, count in sorted(failed_by_ip.items()):
        report.append(f"{ip_address}: {count} failed attempts")

    report.extend(["", "SECURITY ALERTS:"])

    if suspicious_ips:
        for ip_address, details in sorted(suspicious_ips.items()):
            start_time, end_time, count = details
            report.append(f"Suspicious IP: {ip_address}")
            report.append(f"Failures in window: {count}")
            report.append(f"Window start: {start_time}")
            report.append(f"Window end: {end_time}")
            report.append("")
    else:
        report.append("No suspicious 5-minute pattern detected.")

    with open(REPORT_FILE, "w") as file:
        file.write("\n".join(report))

    print("\nReport saved to:", REPORT_FILE)
    print("Analysis complete.")
