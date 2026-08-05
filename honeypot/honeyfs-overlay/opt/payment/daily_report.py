#!/usr/bin/env python3
import mysql.connector
import smtplib
from datetime import date

DB = {"host": "10.0.0.5", "user": "root", "password": "Sup3rS3cr3t_Prod!", "database": "payment_db"}

def build_report():
    conn = mysql.connector.connect(**DB)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*), SUM(amount) FROM transactions WHERE DATE(created_at) = CURDATE()")
    count, total = cur.fetchone()
    conn.close()
    return f"[{date.today()}] transactions={count} total={total}"

if __name__ == "__main__":
    print(build_report())
