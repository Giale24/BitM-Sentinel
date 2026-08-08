# 🛡️ BitM Sentinel - Real-time AI Defense System

Progetto di tesi: **Rilevamento e mitigazione in tempo reale di attacchi Browser-in-the-Middle tramite Large Language Models**.

---

## 📁 Struttura del Progetto

* `extension/`: **Estensione Browser (Chrome Manifest V3)**
  * Triage veloce client-side (`triage.js`)
  * Estrattore DOM e intercettore form (`dom_inspector.js`)
  * Banner di mitigazione e blocco automatico (`mitigation_overlay.js`)
  * Dashboard visiva popup (`popup/`)
* `backend/`: **Engine di Analisi LLM (Python FastAPI)**
  * Supporta sia **LLM Cloud** (Gemini 2.0 Flash, GPT-4o-mini) che **LLM Locali** (Ollama: Qwen2.5-Coder, Llama3.2)
  * Restituisce output JSON Pydantic con punteggio di rischio, motivazione semantica ed azioni di mitigazione.
* `simulation/`: **Ambiente Sandbox di Test**
  * `target_server/app.py`: Server legittimo di test (Porta 5000)
  * `bitm_proxy/app.py`: Proxy BitM simulato stile Evilginx (Porta 5001)

---

## 🚀 Come Eseguire il Progetto

### 1. Installare l'Estensione in Chrome / Brave / Edge
1. Apri il browser e vai a `chrome://extensions/`
2. Attiva la **"Modalità sviluppatore"** in alto a destra.
3. Clicca su **"Carica estensione non impacchettata"** (Load unpacked) e seleziona la cartella `BitmProject/extension`.

---

### 2. Avviare il Backend Python
```bash
cd backend
pip install -r requirements.txt

# Configura la chiave API (opzionale se usi Ollama)
cp .env.example .env

# Avvia il server FastAPI
python3 app/main.py
```
Il server sarà attivo all'indirizzo `http://localhost:8000`.

---

### 3. Eseguire la Simulazione di Test (Pagina Legittima vs Attacco BitM)

Avvia il server legittimo (Porta 5000):
```bash
python3 simulation/target_server/app.py
```

In un altro terminale, avvia il proxy BitM simulato (Porta 5001):
```bash
python3 simulation/bitm_proxy/app.py
```

#### Test di Rilevamento:
* Visita `http://localhost:5000/login` -> **Pagina Legittima** (BitM Sentinel mostrerà lo stato **SICURO**).
* Visita `http://localhost:5001/login` -> **Pagina Proxata BitM** (BitM Sentinel intercetterà la modifica del DOM ed esporrà la **schermata rossa di blocco** di mitigazione in tempo reale).
