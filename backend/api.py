import os
import json

from flask import Flask, jsonify
from main import run_full_scan
from flask import render_template

app = Flask(__name__)

@app.route("/scan", methods=["GET"])
def scan():
    results = run_full_scan()
    return jsonify(results)

@app.route("/")
def home():
    return "Cloud Security Automation API Running 🚀"

@app.route("/history", methods=["GET"])
def history():
    reports_dir = "reports"
    files = sorted(os.listdir(reports_dir), reverse=True)

    history_data = []

    for file in files:
        if file.endswith(".json"):
            with open(os.path.join(reports_dir, file), "r") as f:
                data = json.load(f)
                history_data.append({
                    "file": file,
                    "timestamp": data["timestamp"],
                    "summary": data["summary"]
                })

    return jsonify(history_data)

@app.route("/report/<filename>", methods=["GET"])
def get_report(filename):
    path = os.path.join("reports", filename)

    if os.path.exists(path):
        with open(path, "r") as f:
            return jsonify(json.load(f))
    else:
        return jsonify({"error": "Report not found"}), 404


@app.route("/ui")
def ui():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
