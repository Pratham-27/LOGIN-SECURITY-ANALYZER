def analyze_log(filename):

    failed_attempts = {}
    failed_users = {}

    successful_logins = 0
    failed_logins = 0
    total_attempts = 0

    try:
        with open(filename, "r") as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                parts = line.split()

                if len(parts) != 5:
                    print("Invalid log format:", line)
                    continue

                date, time, status, username, ip = parts

                total_attempts += 1

                if status == "SUCCESS":
                    successful_logins += 1

                elif status == "FAILED":
                    failed_logins += 1

                    if ip not in failed_attempts:
                        failed_attempts[ip] = {
                            "username": username,
                            "count": 0
                        }

                    failed_attempts[ip]["count"] += 1

                    if username not in failed_users:
                        failed_users[username] = 0

                    failed_users[username] += 1

    except FileNotFoundError:
        return None

    # Calculate Failure Rate and Risk Level

    if total_attempts > 0:

        failure_rate = (failed_logins / total_attempts) * 100

        if failure_rate > 60:
            risk_level = "HIGH"

        elif failure_rate >= 30:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"

    else:

        failure_rate = 0
        risk_level = "LOW"

    # Find Suspicious IPs

    suspicious_ips = {}

    for ip, data in failed_attempts.items():

        if data["count"] >= 5:

            suspicious_ips[ip] = {
                "username": data["username"],
                "count": data["count"]
            }

    # Return all analysis results

    return {
        "total_attempts": total_attempts,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "failure_rate": round(failure_rate, 2),
        "risk_level": risk_level,
        "failed_users": failed_users,
        "failed_attempts": failed_attempts,
        "suspicious_ips": suspicious_ips
    }