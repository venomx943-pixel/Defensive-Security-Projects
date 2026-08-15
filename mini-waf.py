import re
from flask import Flask, request, abort

app = Flask(__name__)

# WAF Rules compiled for performance and clarity
MALICIOUS_SIGNATURES = [
    re.compile(r"<script.*?>.*?</script.*?>", re.IGNORECASE),
    re.compile(r"\bUNION\b.*\bSELECT\b", re.IGNORECASE),
    re.compile(r"\bOR\b\s+1=1", re.IGNORECASE),
    re.compile(r"\.\./\.\./", re.IGNORECASE)
]

def _inspect(payload: str) -> bool:
    """Internal helper to scan strings against known attack signatures."""
    if not payload:
        return False
    return any(pattern.search(payload) for pattern in MALICIOUS_SIGNATURES)

@app.before_request
def waf_inspection_layer():
    """Middleware inspection hook running prior to routing."""
    client_ip = request.remote_addr
    target_uri = request.full_path
    
    # 1. Inspect URI & Query Parameters
    if _inspect(target_uri):
        print(f"[!] WAF BLOCK: Attack pattern in URI from {client_ip} -> {target_uri}")
        abort(403, description="Blocked by Mini-WAF: Malicious request URI.")

    # 2. Inspect Request Body (POST/PUT/PATCH)
    if request.method in {"POST", "PUT", "PATCH"}:
        body = request.get_data(as_text=True)
        if _inspect(body):
            print(f"[!] WAF BLOCK: Payload injection from {client_ip} -> Body length: {len(body)}")
            abort(403, description="Blocked by Mini-WAF: Malicious request payload.")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        user_data = request.form.get("input", "")
        return f"Request processed safely. Data received: {user_data}"
    return "Mini-WAF Protected Application. Server is running securely."

if __name__ == "__main__":
    print("[*] Mini-WAF proxy layer active on port 5000...")
    app.run(host="127.0.0.1", port=5000, debug=False)