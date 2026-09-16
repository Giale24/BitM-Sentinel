// BitM Sentinel - Popup Controller
// Gestisce l'interfaccia grafica del popup dell'estensione Chrome:
// visualizzazione metrica di rischio, latenza, classificazione della minaccia
// e pannello di configurazione per l'endpoint del backend.

document.addEventListener("DOMContentLoaded", async () => {
  // Riferimenti agli elementi DOM per la visualizzazione delle metriche
  const statusBadge = document.getElementById("statusBadge");
  const scoreCircle = document.getElementById("scoreCircle");
  const scoreValue = document.getElementById("scoreValue");
  const statusValue = document.getElementById("statusValue");
  const latencyValue = document.getElementById("latencyValue");
  const attackTypeValue = document.getElementById("attackTypeValue");
  const reasoningText = document.getElementById("reasoningText");

  // Riferimenti ai controlli interattivi e pannello impostazioni
  const btnReanalyze = document.getElementById("btnReanalyze");
  const btnToggleSettings = document.getElementById("btnToggleSettings");
  const settingsPanel = document.getElementById("settingsPanel");
  const backendUrlInput = document.getElementById("backendUrlInput");
  const btnSaveSettings = document.getElementById("btnSaveSettings");

  // Recupero dell'URL del backend salvato nello storage locale per pre-popolare il form di configurazione
  const { backendUrl } = await chrome.storage.local.get(["backendUrl"]);
  if (backendUrl) backendUrlInput.value = backendUrl;

  // Interrogazione dello stato di sicurezza della scheda attiva inviata al service worker
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.runtime.sendMessage({ action: "GET_TAB_STATUS", tabId: tabs[0].id, url: tabs[0].url }, (res) => {
        if (res) updateUI(res);
      });
    }
  });

  // Gestione del pulsante di riesame forzato: invia un messaggio al content script della scheda corrente
  btnReanalyze.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { action: "FORCE_REANALYZE" });
        window.close();
      }
    });
  });

  // Toggle di apertura/chiusura del pannello impostazioni di connessione
  btnToggleSettings.addEventListener("click", () => {
    settingsPanel.classList.toggle("hidden");
  });

  // Salvataggio del nuovo URL dell'endpoint backend nello storage locale
  btnSaveSettings.addEventListener("click", async () => {
    const newUrl = backendUrlInput.value.trim();
    if (newUrl) {
      await chrome.storage.local.set({ backendUrl: newUrl });
      alert("Configurazione backend salvata con successo!");
      settingsPanel.classList.add("hidden");
    }
  });

  /**
   * Aggiorna gli elementi grafici del popup (cerchio del punteggio, badge e messaggi descrittivi)
   * in accordo con la tripartizione del verdetto: "ALLOW" (verde), "WARN" (giallo), "BLOCK" (rosso).
   *
   * @param {Object} data - Risultato dell'analisi restituito dal service worker.
   */
  function updateUI(data) {
    const score = data.riskScore || 0;
    const status = data.status || "ALLOW";

    scoreValue.textContent = score;
    latencyValue.textContent = data.elapsedMs ? `${data.elapsedMs} ms` : "--";
    attackTypeValue.textContent = data.attackType || "Nessuno";
    reasoningText.textContent = data.reasoning || "Pagina analizzata senza anomalie critiche.";

    scoreCircle.className = "score-circle";
    statusBadge.className = "badge";

    // Aggiorna lo stato della pagina in base al punteggio di rischio e allo stato ricevuto
    if (status === "BLOCK" || score >= 75) {
      scoreCircle.classList.add("block");
      statusBadge.classList.add("block");
      statusBadge.textContent = "ATTACCO BLOCK";
      statusValue.textContent = "BLOCCATO";
      statusValue.style.color = "#EF4444";
    } else if (status === "WARN" || score >= 40) {
      scoreCircle.classList.add("warn");
      statusBadge.classList.add("warn");
      statusBadge.textContent = "WARNING";
      statusValue.textContent = "SOSPETTO";
      statusValue.style.color = "#F59E0B";
    } else {
      scoreCircle.classList.add("safe");
      statusBadge.classList.add("safe");
      statusBadge.textContent = "SICURO";
      statusValue.textContent = "SICURO";
      statusValue.style.color = "#10B981";
    }
  }
});
