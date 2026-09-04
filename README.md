# 🛡️ BitM Sentinel (v2.1.1) - Real-Time AI Defense System

> **Progetto tesi:** *Rilevamento e mitigazione in tempo reale di attacchi Browser-in-the-Middle (BitM / CAPEC-701) tramite Large Language Models.*

---

## 📌 Cos'è BitM Sentinel?

**BitM Sentinel** è un sistema di sicurezza proattivo progettato per rilevare e bloccare in tempo reale gli attacchi di tipo **Browser-in-the-Middle (BitM)** e **Adversary-in-the-Middle (AitM)**.

I tradizionali sistemi difensivi di rete (firewall, proxy e filtri DNS) non riescono a bloccare questi attacchi perché sono "ciechi" davanti al traffico cifrato HTTPS e non possono ispezionare il DOM dinamico generato a runtime dal browser.  
**BitM Sentinel risolve questo limite** operando direttamente all'interno del contesto di esecuzione del browser tramite un'architettura cooperativa distribuita a tre livelli.

---

## 🏗️ Architettura e Fasi di Funzionamento

<p align="center">
  <img src="architettura.png" alt="Schermata di Blocco BitM" width="800"/>
</p>

Il sistema opera attraverso **3 livelli sequenziali e complementari**:

### 1️⃣ Livello 1: Sonda Client-Side (Estensione Chrome Manifest V3)
* **Triage Rapido (`triage.js`):** esegue un'analisi euristica istantanea (<5ms) per verificare typosquatting (distanza di Levenshtein), sottodomini ingannevoli (regex Evilginx a due stadi), form con credenziali in GET (CWE-598), iframe invisibili e flussi streaming WebRTC/canvas in contesti sensibili.
* **Ispezione Sincrona (`dom_inspector.js`):** estrae i metadati del DOM (form, action, metodi, script esterni, snippet di testo) e intercetta in modo **rigorosamente sincrono** l'evento `submit` tramite `localPageState`, eliminando qualsiasi race condition prima che le credenziali lascino il browser.
* **Mitigazione Attiva Anti-XSS (`mitigation_overlay.js`):** se il rischio è critico (Score ≥ 75 / BLOCK), disabilita selettivamente solo i campi attivi (`data-bitm-disabled`), inietta la motivazione in modo sicuro tramite `textContent` (prevenendo DOM-XSS da prompt injection) e innalza l'overlay di sicurezza a z-index massimo.
* **Service Worker (`service_worker.js`):** gestisce il timeout a 60 secondi con `AbortController`, aggiorna il badge e libera la memoria RAM eliminando lo stato delle schede chiuse (`chrome.tabs.onRemoved`).

### 2️⃣ Livello 2: Backend Decisionale (Python 3.12 FastAPI)
* **Sicurezza di Rete:** bind rigoroso su loopback `127.0.0.1` e policy CORS ristretta a `chrome-extension://*` e localhost.
* **Caching con Eviction (MD5 Hash):** memorizza l'impronta crittografica del payload DOM, abbattendo la latenza a **~1 ms** sulle visite ripetute, con limite FIFO a 200 record contro memory leak.
* **Validazione Rigida (Pydantic v2):** configurazione centralizzata con `SettingsConfigDict` e tipizzazione formale di `AnalysisRequest` e `AnalysisResponse`.
* **Decisione Fail-Safe (`dom_analyzer.py`):** unisce lo score euristico server e la valutazione semantica dell'IA tramite la formula `final_score = max(heuristic, llm)`, con verifica IP standard (`ipaddress`), controllo porta 5001 decoppiato e deduplicazione delle anomalie.

### 3️⃣ Livello 3: Reasoning Engine (LLM Multi-Provider)
* Valuta la semantica contestuale, la coerenza del brand e le discrepanze di dominio.
* **Supporto Multi-Provider configurabile via `.env`:**
  * **Google Gemini (`gemini-3.5-flash`, `gemini-3.5-flash-lite`, `gemini-3.7-flash`):** inferenza cloud ultra-rapida con Structured Outputs nativi schema-enforced e timeout resiliente a 30s.
  * **DeepSeek-Reasoner (`deepseek-reasoner` / R1 Cloud):** estrazione automatica del JSON con isolamento e rimozione preventiva dei blocchi `<think>`.
  * **Ollama Locale (`Llama 3.2 3B` / `Qwen 2.5`):** esecuzione offline e privata su CPU/GPU per ambienti confidenziali.

---

## 🌐 Supporto Vettori di Attacco: Reverse Proxy & WebRTC Streaming

BitM Sentinel v2.1.1 è in grado di neutralizzare **entrambe le grandi famiglie di attacchi BitM (CAPEC-701)**:

1. **Reverse Proxy HTTP Dinamico (stile Evilginx / Modlishka):**
   * L'attaccante modifica al volo l'attributo `action` della form.
   * *Rilevamento:* BitM Sentinel intercetta il *Form Action Mismatch* (es. form servita su `localhost:5001` che tenta di inviare credenziali a un endpoint terzo malevolo) e congela l'evento `submit` in modo sincrono.

2. **Remote Browser Streaming & WebRTC (stile Cuddlephish / noVNC):**
   * L'attaccante proietta uno streaming video a tutto schermo (`<video playsinline style="width: 100vw">` o `<canvas>`) e usa un keylogger JavaScript via WebSocket per rubare tasti premuti e mouse.
   * *Rilevamento:* BitM Sentinel rileva la presenza di elementi video/canvas a tutto schermo in assenza di form HTML nativi su IP o domini che dichiarano titoli bancari/sensibili, classificando la minaccia con **Score 95 (BLOCK / BITM_STREAMING)**.

---

## 🚀 Guida all'Installazione e Avvio dei Server

### 1. Requisiti di Sistema
* **Python 3.10+**
* **Google Chrome / Brave / Edge**

---

### 2. Installazione e Avvio del Backend FastAPI

1. Apri un terminale e spostati nella cartella `backend`:
   ```bash
   cd backend
   ```
2. Crea e attiva l'ambiente virtuale Python:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Installa le dipendenze:
   ```bash
   pip install -r requirements.txt
   ```
4. Configura il file `.env` (puoi copiare da `.env.example`):
   ```ini
   LLM_PROVIDER=gemini
   LLM_MODEL=gemini-3.5-flash
   GEMINI_API_KEY=inserisci_la_tua_api_key_qui
   HOST=127.0.0.1
   PORT=8000
   ```
5. Avvia il server backend:
   ```bash
   python3 app/main.py
   ```
   *Il server sarà attivo su `http://127.0.0.1:8000` con documentazione OpenAPI interattiva su `http://127.0.0.1:8000/docs`.*

---

### 3. Installazione dell'Estensione nel Browser

1. Apri Google Chrome e digita nella barra degli indirizzi: `chrome://extensions/`
2. Attiva la levetta **"Modalità sviluppatore"** in alto a destra.
3. Clicca su **"Carica estensione non pacchettizzata"** (*Load unpacked*).
4. Seleziona la cartella `BitmProject/extension`.
5. *(Consigliato per test locali)*: Clicca su "Dettagli" dell'estensione e spunta **"Consenti l'accesso agli URL dei file"**.

---

### 4. Scenari di Simulazione e Test

#### A. Portale Bancario Legittimo (Porta 5000)
In un nuovo terminale:
```bash
python3 simulation/target_server/app.py
```
* **Test:** Visita `http://localhost:5000/login` e clicca sull'estensione.
* **Risultato:** `Score: 0/100 (ALLOW)` ➔ Navigazione consentita e badge verde "OK".

#### B. Reverse Proxy Malevolo BitM (Porta 5001)
In un altro terminale:
```bash
python3 simulation/bitm_proxy/app.py
```
* **Test:** Visita `http://localhost:5001/login` e prova a inviare le credenziali.
* **Risultato:** `Score: 95-100/100 (BLOCK)` ➔ Form bloccata in modo sincrono, campi disabilitati e overlay rosso!

#### C. Remote Streaming BitM (Cuddlephish / WebRTC / noVNC)
* **Test:** Visita la sessione streaming su macchina virtuale (es. `http://192.168.122.201/`).
* **Risultato:** `Score: 85-95/100 (BLOCK)` ➔ Rilevato streaming remoto senza form HTML nativi.

#### D. Pagina di Verifica Anomalie Strutturali (test_giallo.html)
* **Test:** Apri il file `simulation/test_giallo.html` nel browser.
* **Risultato:** `Score: 40-55/100 (WARN)` ➔ Rilevate credenziali su HTTP GET (CWE-598) e iframe nascosto: banner arancione non bloccante.

---

### 5. Esecuzione Test Automatizzati

Il progetto include suite di test automatici sia per il backend Python sia per l'estensione:

* **Test Suite Backend (Python):**
  ```bash
  python3 test_full_suite.py
  ```
  *(Verifica 9/9 test unitari: euristiche deterministiche, CWE-598, proxy mismatch, raw IP, parser JSON e cache eviction)*

* **Test Suite Extension (Node.js):**
  ```bash
  node test_suite.js
  ```
  *(Verifica 5/5 test: Levenshtein, regex Evilginx, esenzione YouTube/Twitch e streaming Cuddlephish)*


