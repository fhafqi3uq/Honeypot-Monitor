#!/usr/bin/env python3
import time
import mysql.connector

DB = {"host": "10.0.0.5", "user": "root", "password": "Sup3rS3cr3t_Prod!", "database": "payment_db"}

def poll_queue():
    conn = mysql.connector.connect(**DB)
    cur = conn.cursor()
    while True:
        cur.execute("SELECT id FROM transactions WHERE status='pending' LIMIT 10")
        for (tid,) in cur.fetchall():
            cur.execute("UPDATE transactions SET status='processed' WHERE id=%s", (tid,))
        conn.commit()
        time.sleep(5)

if __name__ == "__main__":
    poll_queue()
