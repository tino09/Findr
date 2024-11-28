from flask import Flask, request, render_template
import requests

app = Flask(__name__)

def check_vulnerabilities(url):
    vulnerabilities = []

    try:
        response = requests.get(url, timeout=10)
        
        # Check for HTTP Strict Transport Security (HSTS)
        if 'Strict-Transport-Security' not in response.headers:
            vulnerabilities.append("HSTS header is missing. This can leave the site vulnerable to man-in-the-middle attacks.")

        # Check for X-Content-Type-Options header
        if 'X-Content-Type-Options' not in response.headers:
            vulnerabilities.append("X-Content-Type-Options header is missing. This can lead to MIME-sniffing attacks.")

        # Check for X-Frame-Options header
        if 'X-Frame-Options' not in response.headers:
            vulnerabilities.append("X-Frame-Options header is missing. This can make the site vulnerable to clickjacking.")

    except requests.exceptions.RequestException as e:
        vulnerabilities.append(f"Error accessing {url}: {str(e)}")

    return vulnerabilities

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    vulnerabilities = check_vulnerabilities(url)
    return render_template('result.html', url=url, vulnerabilities=vulnerabilities)

if __name__ == '__main__':
    app.run(debug=True)
