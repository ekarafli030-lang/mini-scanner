import sqlite3
import json
from datetime import datetime

DB_NAME = "scanner_audit.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            status_code INTEGER,
            score INTEGER NOT NULL,
            grade TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_report(target_url, status_code, score, grade, findings):
    conn = get_db_connection()
    cursor = conn.cursor()
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO scan_reports (target_url, status_code, score, grade, findings_json, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (target_url, status_code, score, grade, json.dumps(findings), scanned_at))
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id

def get_all_reports():
    conn = get_db_connection()
    reports = conn.execute("SELECT * FROM scan_reports ORDER BY id DESC LIMIT 15").fetchall()
    conn.close()
    return reports

def get_report_by_id(report_id):
    conn = get_db_connection()
    report = conn.execute("SELECT * FROM scan_reports WHERE id = ?", (report_id,)).fetchone()
    conn.close()
    if report:
        report_dict = dict(report)
        report_dict["findings"] = json.loads(report_dict["findings_json"])
        return report_dict
    return None