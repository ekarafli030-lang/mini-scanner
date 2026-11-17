from flask import Flask, render_template, request, redirect, url_for, flash
from db import init_db, save_report, get_all_reports, get_report_by_id
from scanner import run_security_audit

app = Flask(__name__)
app.secret_key = "cyber_audit_secret_key_dev"

# Inisialisasi tabel database saat aplikasi dijalankan
init_db()

@app.route("/")
def index():
    reports = get_all_reports()
    return render_template("index.html", reports=reports)

@app.route("/scan", methods=["POST"])
def scan():
    target_url = request.form.get("target_url", "").strip()
    if not target_url:
        flash("Masukkan URL yang valid terlebih dahulu.", "error")
        return redirect(url_for("index"))

    result = run_security_audit(target_url)

    if not result["success"]:
        flash(result["error"], "error")
        return redirect(url_for("index"))

    report_id = save_report(
        target_url=result["target_url"],
        status_code=result["status_code"],
        score=result["score"],
        grade=result["grade"],
        findings=result["findings"]
    )
    return redirect(url_for("view_report", report_id=report_id))

@app.route("/report/<int:report_id>")
def view_report(report_id):
    report = get_report_by_id(report_id)
    if not report:
        flash("Laporan tidak ditemukan.", "error")
        return redirect(url_for("index"))
    return render_template("report.html", report=report)

if __name__ == "__main__":
    app.run(debug=True, port=5000)