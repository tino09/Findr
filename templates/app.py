from flask import Flask, request, jsonify, render_template
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# Vulnerability checks
def perform_vulnerability_checks(url):
    results = []

    # Check if the URL is reachable
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            results.append(f"[+] URL reachable: {url}")
        else:
            results.append(f"[-] URL unreachable: HTTP {response.status_code}")
    except Exception as e:
        results.append(f"[-] Error reaching URL: {str(e)}")
        return results

    # Check for SSL/TLS
    if url.startswith("https"):
        results.append("[+] Secure connection (HTTPS) detected")
    else:
        results.append("[-] Insecure connection (HTTP) detected")

    # Check for outdated software (basic headers check)
    try:
        server = response.headers.get('Server', 'Unknown')
        results.append(f"[?] Server header: {server}")
    except Exception as e:
        results.append(f"[-] Unable to retrieve server header: {str(e)}")

    # Check for sensitive data in HTML comments
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        comments = soup.findAll(text=lambda text: isinstance(text, Comment))
        if comments:
            results.append("[-] Found HTML comments that may contain sensitive data")
        else:
            results.append("[+] No sensitive data found in HTML comments")
    except Exception as e:
        results.append(f"[-] Error analyzing HTML: {str(e)}")

    return results

# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/run-assessment", methods=["POST"])
def run_assessment():
    data = request.json
    url = data.get("url")
    if not url:
        return jsonify({"success": False, "error": "No URL provided"})

    try:
        results = perform_vulnerability_checks(url)
        return jsonify({"success": True, "results": "\n".join(results)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == "__main__":
    app.run(debug=True)
