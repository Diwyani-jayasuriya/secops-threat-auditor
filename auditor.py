from datetime import datetime
import socket
import ssl
from urllib.parse import urlparse
import requests


def check_security_headers(target_url):
   
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    important_headers = {
        "Strict-Transport-Security": "Enforces secure HTTPS connections.",
        "Content-Security-Policy": "Mitigates XSS and data injection attacks.",
        "X-Frame-Options": "Protects against Clickjacking.",
        "X-Content-Type-Options": "Prevents MIME-type sniffing.",
        "Referrer-Policy": "Protects sensitive referrer metadata.",
    }

    results = {
        "headers_found": {},
        "missing_headers": {},
        "score": 100,
        "grade": "A+",
    }

    try:
        response = requests.get(target_url, timeout=7)
        headers = response.headers

        for header, description in important_headers.items():
            if header in headers:
                results["headers_found"][header] = headers[header]
            else:
                results["missing_headers"][header] = description
                results["score"] -= 15

        results["score"] = max(0, results["score"])
        score = results["score"]

        if score >= 90:
            results["grade"] = "A+"
        elif score >= 75:
            results["grade"] = "A"
        elif score >= 60:
            results["grade"] = "B"
        elif score >= 40:
            results["grade"] = "C"
        else:
            results["grade"] = "F"

        return results
    except Exception as e:
        return {"error": f"Connection failed: {str(e)}"}


def check_ssl_certificate(hostname):
  
    if hostname.startswith(("http://", "https://")):
        hostname = urlparse(hostname).netloc

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date_str = cert["notAfter"]
                expire_date = datetime.strptime(
                    expire_date_str, "%b %d %H:%M:%S %Y %Z"
                )
                days_remaining = (expire_date - datetime.utcnow()).days

                return {
                    "expires_on": expire_date.strftime("%Y-%m-%d"),
                    "days_remaining": days_remaining,
                    "is_valid": days_remaining > 0,
                }
    except Exception as e:
        return {"error": f"SSL Handshake failed: {str(e)}"}