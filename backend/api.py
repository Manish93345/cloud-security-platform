from flask import Flask, jsonify
from main import run_full_scan

app = Flask(__name__)

@app.route("/scan", methods=["GET"])
def scan():
    results = run_full_scan()
    return jsonify(results)

@app.route("/")
def home():
    return "Cloud Security Automation API Running 🚀"

if __name__ == "__main__":
    app.run(debug=True)
