import re
import time
import json
import datetime as dt

current_year = dt.datetime.now().year

ssh_log_file = "/home/volkova/mini_soar/fake.log"

json_file = "/home/volkova/mini_soar/cleaned_logs.json"

log_pattern = r"(\S+\s+\S+\s+\S+) (\S+) ([^:]+):\s+(.*)(?:\s+from)?\s+(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)(?:\s+(\S+))?"

get_user_failed_password = r"for\s+(\S+)"

get_user_invalid = r"user\s+(\S+)"

def analyze_ssh_log(line):

    cleaned_logs = []

    match = re.match(log_pattern, line)

    if match:

        timestamp = match.group(1)
        hostname = match.group(2)
        protocol = match.group(3)
        message = match.group(4)
        ip_address = match.group(5)
        port = match.group(6)
        context = match.group(7)
        username = "Desconocido"

        if "failed password" in message.lower():
            user_match = re.search(get_user_failed_password, message)

            if user_match:
                username = user_match.group(1)

            cleaned_logs.append({
            "Timestamp": f"{current_year} {timestamp}", "Hostname": hostname, "Protocol": protocol,
            "Message": message,"Username": username, "IP Address": ip_address, "Port": port,
            "Session context": context
            })

        elif "invalid user" in message.lower():
            user_match = re.search(get_user_invalid, message)

            if user_match:
                username = user_match.group(1)

            cleaned_logs.append({
            "Timestamp": f"{current_year} {timestamp}", "Hostname": hostname, "Protocol": protocol,
            "Message": message,"Username": username, "IP Address": ip_address, "Port": port,
            "Session context": context
            })

    return cleaned_logs


def monitor_logs(file_path):
    try:
        with open(file_path, "r") as file:
            while True:
                line = file.readline()

                if not line:
                    time.sleep(0.5)
                    continue

                resultado = analyze_ssh_log(line)

                if resultado:
                    with open(json_file, "a") as json_l:
                        json_l.write(json.dumps(resultado) + "\n")

    except FileNotFoundError:
        print(f"{file_path}: File not found")

    except KeyboardInterrupt:
        print("Process stopped by user (Ctrl + C)")


if __name__ == "__main__":
    monitor_logs(ssh_log_file)
