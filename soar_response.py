import sqlite3
import json
import datetime as dt
import subprocess

conn = sqlite3.connect("attackers_data.db")

cur = conn.cursor()

mask_time = "%Y %b %d %H:%M:%S"


def check_logs(json_file):

    try:

        with open(json_file, "r") as file:

            for line in file:

                log = json.loads(line)

                ip_log = log["IP Address"]
                try_time = log["Timestamp"]
                state = "monitoring"

                cur.execute("SELECT tries FROM attacks WHERE ip = ?", (ip_log,))

                ip_exist = cur.fetchone()

                if ip_exist:
                    atk_try = ip_exist[0]

                    if atk_try >= 10:
                        subprocess.run(["sudo", "ufw", "deny", "from", ip_log, "to", "any"])

                        cur.execute("UPDATE attacks SET state = 'blocked' WHERE ip = ?", (ip_log,))

                        conn.commit()

                    elif atk_try < 10:
                        get_date = dt.datetime.strptime(try_time, mask_time)

                        formated_date = int(get_date.timestamp())

                        cur.execute("UPDATE attacks SET tries = tries + 1, last_try = ? WHERE ip = ?", (formated_date, ip_log))

                        conn.commit()

                else:
                    get_date = dt.datetime.strptime(try_time, mask_time)

                    formated_date = int(get_date.timestamp())

                    cur.execute("INSERT INTO attacks (ip, first_try, last_try, state, tries) VALUES (?, ?, ?, ?,?)",
                    (ip_log, formated_date, None,  state, 1))

                    conn.commit()

    except FileNotFoundError:
        print(f"File {json_file} not found")


