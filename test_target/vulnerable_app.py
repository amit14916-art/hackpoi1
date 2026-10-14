from fastapi import FastAPI, Response, Request
from fastapi.responses import PlainTextResponse, HTMLResponse, RedirectResponse

mock_app = FastAPI(title="Mock Test Vulnerable Server")

@mock_app.get("/", response_class=HTMLResponse)
def home(response: Response):
    # Intentionally missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options
    # Intentionally exposing server banners and insecure cookies
    response.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    response.headers["X-Powered-By"] = "Express"
    response.set_cookie(key="session_id", value="abc123secret", secure=False, httponly=False)
    
    html = """<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Testbed Target</title>
    <script src="/static/bundle.js"></script>
    <script src="https://cdn.example.com/untrusted-analytics.js"></script>
</head>
<body>
    <h1>Vulnerable E-Commerce Store</h1>
    <nav>
        <a href="/search?q=books">Search Products</a>
        <a href="/api/products?id=1">Product Details</a>
        <a href="/api/user/profile">User Profile</a>
        <a href="/login?redirect=/dashboard">User Login</a>
    </nav>
    <form action="/search" method="GET">
        <input type="text" name="q" placeholder="Search...">
        <button type="submit">Search</button>
    </form>
</body>
</html>"""
    return html

@mock_app.post("/graphql")
def graphql_endpoint():
    return {
        "data": {
            "__schema": {
                "types": [
                    {"name": "Query"},
                    {"name": "Mutation"},
                    {"name": "User"},
                    {"name": "PaymentCard"},
                    {"name": "SecretAdmin"}
                ]
            }
        }
    }

@mock_app.get("/api/user/profile")
def user_profile(response: Response):
    response.headers["Cache-Control"] = "public, max-age=86400"
    return {"id": 1, "email": "admin@vulnerable-test.com", "role": "superuser"}

@mock_app.get("/.vscode/sftp.json", response_class=PlainTextResponse)
def vscode_sftp():
    return '{\n  "host": "192.168.1.100",\n  "username": "deploy_user",\n  "password": "production_password_xyz",\n  "remotePath": "/var/www/html"\n}'

@mock_app.options("/")
def cors_options(request: Request, response: Response):
    # Vulnerable CORS: Reflects any Origin with credentials enabled
    origin = request.headers.get("origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, TRACE"
    return Response(status_code=204)

@mock_app.api_route("/", methods=["TRACE"])
def trace_method(request: Request):
    # Vulnerable HTTP TRACE method enabled
    headers_text = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
    return PlainTextResponse(f"TRACE / HTTP/1.1\n{headers_text}\n", status_code=200)

@mock_app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # Vulnerable to Reflected XSS: directly reflects input unescaped
    return f"<html><body><h1>Search Results for: {q}</h1><p>No products found.</p></body></html>"

@mock_app.get("/api/products")
def products(id: str = "1"):
    # Vulnerable to SQL Injection: leaks SQLite operational error on quote
    if "'" in id or '"' in id:
        return PlainTextResponse("sqlite3.OperationalError: near \"'\": syntax error in SELECT * FROM products WHERE id = " + id, status_code=500)
    return {"id": id, "name": "Security Pro Tool", "price": 99}

@mock_app.get("/login")
def login(redirect: str = "/"):
    # Vulnerable to Open Redirect
    if redirect.startswith("http"):
        return RedirectResponse(url=redirect, status_code=302)
    return RedirectResponse(url="/", status_code=302)

@mock_app.get("/static/bundle.js", response_class=PlainTextResponse)
def bundle_js():
    # Leaked client-side API credentials
    return """
    // Client Frontend Bundle
    const config = {
        firebaseApiKey: "AIzaSyD-mockGoogleFirebaseKey123456",
        authDomain: "vulnerable-app.firebaseapp.com",
    };
    console.log("App initialized with config", config);
    """

@mock_app.get("/.env", response_class=PlainTextResponse)
def env_leak():
    return "DB_PASSWORD=SuperSecretPass123!\nSECRET_KEY=production_jwt_secret_xyz\nAPP_ENV=production"

@mock_app.get("/.git/HEAD", response_class=PlainTextResponse)
def git_leak():
    return "ref: refs/heads/main\n"

@mock_app.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /api/internal\nDisallow: /backup\n"

@mock_app.get("/.well-known/security-check.txt", response_class=PlainTextResponse)
def security_check_challenge(request: Request):
    return "sec-verify=testtoken123"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(mock_app, host="127.0.0.1", port=9000)
