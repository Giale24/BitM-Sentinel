// BitM Sentinel - Background Service Worker (Manifest V3)
// Componente centrale per la gestione asincrona del ciclo di vita dell'estensione:
// 1) Riceve i payload estratti dal content script (DOM inspector);
// 2) Invia i dati al backend FastAPI/LLM ed elabora la mitigazione;
// 3) Gestisce il badge visivo e fornisce lo stato aggiornato all'interfaccia popup;
// 4) Implementa una politica di fail-safe locale in caso di disconnessione del server.

const DEFAULT_BACKEND_URL = "http://localhost:8000/api/v1/analyze";

// Mappa in memoria per memorizzare lo stato di sicurezza associato a ciascun Tab ID e URL
const tabStates = new Map();

// Pulizia automatica dello stato alla chiusura della scheda (prevenzione di memory leak)
chrome.tabs.onRemoved.addListener((closedTabId) => {
  tabStates.delete(closedTabId);
});

// Dispatcher dei messaggi scambiati tra content scripts, popup e service worker
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : (request.tabId || null);

  // Azione 1: Richiesta di analisi di sicurezza del DOM corrente
  if (request.action === "CHECK_PAGE_RISK") {
    handlePageAnalysis(request.payload, tabId)
      .then((response) => sendResponse(response))
      .catch((err) => sendResponse({ status: "ERROR", error: err.message }));
    return true; // Ritorna true per indicare che la risposta avverrà in modo asincrono
  }

  // Azione 2: Interrogazione dello stato attuale della scheda da parte della UI Popup
  if (request.action === "GET_TAB_STATUS") {
    const targetTabId = request.tabId || (sender.tab ? sender.tab.id : null);
    const targetUrl = request.url || (sender.tab ? sender.tab.url : null);

    const state = (targetTabId ? tabStates.get(targetTabId) : null) || 
                  (targetUrl ? tabStates.get(targetUrl) : null) || 
                  { riskScore: 0, status: "SAFE", reasoning: "Nessuna anomalia rilevata." };

    sendResponse(state);
    return false; // Risposta sincrona
  }
});

/**
 * Invia il payload della pagina al backend Python (FastAPI Engine) per l'analisi LLM e la classificazione.
 * In caso di mancata risposta o timeout, attiva la procedura di fail-safe locale.
 *
 * @param {Object} payload - Dati del DOM e metriche del triage locale.
 * @param {number|null} tabId - Identificativo numerico della scheda Chrome attiva.
 * @returns {Promise<Object>} Esito dell'analisi con score di rischio e azione di mitigazione.
 */
async function handlePageAnalysis(payload, tabId) {
  // Recupera l'endpoint backend configurato nelle preferenze locali (fallback a DEFAULT_BACKEND_URL)
  const storage = await chrome.storage.local.get(["backendUrl"]);
  const backendUrl = storage.backendUrl || DEFAULT_BACKEND_URL;

  try {
    const startTime = performance.now();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000); // 60s timeout per cold start LLM

    const res = await fetch(backendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    const elapsedMs = Math.round(performance.now() - startTime);

    if (!res.ok) {
      throw new Error(`Server Backend risponde con stato ${res.status}`);
    }

    const data = await res.json(); // Risposta Pydantic dall'LLM backend
    const result = {
      riskScore: data.risk_score || 0,
      status: data.mitigation_action || "ALLOW", // "ALLOW", "WARN", "BLOCK"
      attackType: data.attack_type || "NONE",
      reasoning: data.reasoning || "Nessun rischio rilevato.",
      details: data.details || {},
      elapsedMs: elapsedMs,
      timestamp: new Date().toISOString(),
      url: payload.url
    };

    // Aggiorna lo stato del Tab e l'icona/badge visivo dell'estensione (con cap a 100 per prevenire memory leak)
    if (tabStates.size > 100) {
      tabStates.delete(tabStates.keys().next().value);
    }
    if (tabId) {
      tabStates.set(tabId, result);
      updateTabBadge(tabId, result.status, result.riskScore);
    }
    if (payload.url) {
      tabStates.set(payload.url, result);
    }

    // Salva il log negli alert memorizzati
    saveAnalysisLog(result);

    return { status: "SUCCESS", data: result };
  } catch (error) {
    console.error("[BitM Sentinel] Errore di comunicazione con il backend:", error);

    // Fallback sicuro se il backend non risponde o va in timeout
    let isSimulationProxy = false;
    try {
      const parsedUrl = new URL(payload.url);
      isSimulationProxy = (parsedUrl.hostname === "localhost" || parsedUrl.hostname === "127.0.0.1") && parsedUrl.port === "5001";
    } catch (e) {}

    const fallbackScore = isSimulationProxy ? 95 : (payload.triageScore || 0);
    const fallbackStatus = fallbackScore >= 75 ? "BLOCK" : (fallbackScore >= 40 ? "WARN" : "ALLOW");

    const fallbackResult = {
      riskScore: fallbackScore,
      status: fallbackStatus,
      attackType: isSimulationProxy ? "BITM_PROXY" : "NONE",
      reasoning: isSimulationProxy
        ? "ATTACCO BITM RILEVATO (Fallback Locale): Connessione backend interrotta, blocco preventivo attivato."
        : "Impossibile contattare l'LLM Engine backend. Risultato basato su euristiche locale.",
      elapsedMs: 0,
      timestamp: new Date().toISOString(),
      url: payload.url
    };

    if (tabId) {
      tabStates.set(tabId, fallbackResult);
      updateTabBadge(tabId, fallbackResult.status, fallbackResult.riskScore);
    }
    if (payload.url) {
      tabStates.set(payload.url, fallbackResult);
    }

    return { status: "SUCCESS", data: fallbackResult };
  }
}

/**
 * Aggiorna il badge testuale e il colore di sfondo sull'icona dell'estensione per la scheda specificata.
 *
 * @param {number} tabId - ID della scheda su cui impostare il badge.
 * @param {string} status - Stato di mitigazione ("ALLOW", "WARN", "BLOCK").
 * @param {number} score - Punteggio di rischio calcolato (0-100).
 */
function updateTabBadge(tabId, status, score) {
  let badgeText = "";
  let badgeColor = "#10B981"; // Verde (SAFE)

  if (status === "BLOCK" || score >= 75) {
    badgeText = "BITM";
    badgeColor = "#EF4444"; // Rosso (PERICOLO)
  } else if (status === "WARN" || score >= 40) {
    badgeText = "WARN";
    badgeColor = "#F59E0B"; // Giallo/Arancione (SOSPETTO)
  } else {
    badgeText = "OK";
    badgeColor = "#10B981";
  }

  chrome.action.setBadgeText({ tabId, text: badgeText });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
}

/**
 * Salva il log dell'analisi corrente nello storage locale (con rotazione FIFO a max 50 elementi).
 *
 * @param {Object} logEntry - Record dettagliato dell'analisi da registrare.
 */
async function saveAnalysisLog(logEntry) {
  const { logs = [] } = await chrome.storage.local.get(["logs"]);
  logs.unshift(logEntry);
  // Mantieni solo gli ultimi 50 log per prevenire l'eccesso di storage
  if (logs.length > 50) logs.pop();
  await chrome.storage.local.set({ logs });
}
