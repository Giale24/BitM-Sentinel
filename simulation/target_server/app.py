"""
Server Web Target Legittimo (Simulazione Ambiente di Test).

Questo modulo avvia un server HTTP multi-thread sulla porta 5000 (http://localhost:5000)
che emula l'applicazione bancaria / di autenticazione autentica ("Banca Sicura").
Fornisce la pagina di login legittima con form POST verso la dashboard interna,
fungendo da sorgente reale (upstream server) per il proxy malevolo di simulazione.
"""

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

HTML_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <title>Banca Sicura - Accesso Riservato</title>
    <style>
        body { font-family: sans-serif; background: #0f172a; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: #1e293b; padding: 40px; border-radius: 12px; border: 1px solid #334155; width: 320px; }
        h2 { color: #3b82f6; margin-bottom: 20px; }
        input { width: 100%; padding: 10px; margin: 8px 0; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: white; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #3b82f6; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Banca Sicura Login</h2>
        <p style="font-size: 12px; color: #94a3b8;">Portale Ufficiale di Autenticazione</p>
        <form action="http://localhost:5000/dashboard" method="POST">
            <input type="text" name="username" placeholder="Codice Utente" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="text" name="otp" placeholder="Codice OTP (2FA)" required>
            <button type="submit">Accedi al Conto</button>
        </form>
    </div>
</body>
</html>
"""

class LegitimateTargetHandler(BaseHTTPRequestHandler):
    """
    Gestore delle richieste HTTP per il server target legittimo.
    Risponde alle richieste GET con la pagina di autenticazione e alle richieste POST
    confermandone l'avvenuta ricezione sulla dashboard autorizzata.
    """
    def do_GET(self):
        if self.path == "/login" or self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_LOGIN_PAGE.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<h1>Accesso effettuato con successo nella Banca Sicura.</h1>")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Log sintetico
        print(f"[Target Server 5000] {args[0]}")

if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 5000), LegitimateTargetHandler)
    print("=== Target Server Legittimo attivo su http://localhost:5000/login ===")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer arrestato.")
