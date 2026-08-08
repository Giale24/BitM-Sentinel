// BitM Sentinel- Popup Controller

document.addEventListener("DOMContentLoaded", async () => {   // sia assicura che il DOM sia completamente caricato prima di eseguire il codice
  const statusBadge = document.getElementById("statusBadge"); //dichiara le variabili per gli elementi del DOM che verranno aggiornati con i dati ricevuti dal service worker
  const scoreCircle = document.getElementById("scoreCircle");
  const scoreValue = document.getElementById("scoreValue");
  const statusValue = document.getElementById("statusValue");
  const latencyValue = document.getElementById("latencyValue");
  const attackTypeValue = document.getElementById("attackTypeValue");
  const reasoningText = document.getElementById("reasoningText");

  const btnReanalyze = document.getElementById("btnReanalyze");
  const btnToggleSettings = document.getElementById("btnToggleSettings");
  const settingsPanel = document.getElementById("settingsPanel");
  const backendUrlInput = document.getElementById("backendUrlInput");
  const btnSaveSettings = document.getElementById("btnSaveSettings");

  // Invece di hardcodare l'URL del backend, lo recupera dalle impostazioni salvate in chrome.storage.local, permettendo all'utente di configurarlo tramite l'interfaccia popup
  const { backendUrl } = await chrome.storage.local.get(["backendUrl"]);
  if (backendUrl) backendUrlInput.value = backendUrl;

  /* ottiene lo stato della scheda attiva e invia un messaggio al service worker per ottenere l'ultimo stato di analisi della pagina corrente. 
  Una volta ricevuta la risposta, aggiorna l'interfaccia utente con i dati ricevuti.*/
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.runtime.sendMessage({ action: "GET_TAB_STATUS", tabId: tabs[0].id, url: tabs[0].url }, (res) => {
        if (res) updateUI(res);
      });
    }
  });
  // gestione bottoni analizza e impostazioni
  btnReanalyze.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { action: "FORCE_REANALYZE" });
        window.close();
      }
    });
  });

  btnToggleSettings.addEventListener("click", () => {
    settingsPanel.classList.toggle("hidden");
  });

  btnSaveSettings.addEventListener("click", async () => {
    const newUrl = backendUrlInput.value.trim();
    if (newUrl) {
      await chrome.storage.local.set({ backendUrl: newUrl });
      alert("Configurazione backend salvata con successo!");
      settingsPanel.classList.add("hidden");
    }
  });

  // Funzione per aggiornare l'interfaccia utente in base ai dati ricevuti dal service worker
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
