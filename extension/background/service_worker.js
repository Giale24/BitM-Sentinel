// BitM Sentinel - Background Service Worker (Manifest V3)

const DEFAULT_BACKEND_URL = "http://localhost:8000/api/v1/analyze";

// Stato in memoria per ciascun Tab
const tabStates = new Map();

// Eviction automatica alla chiusura delle schede per prevenire memory leak
chrome.tabs.onRemoved.addListener((closedTabId) => {
  tabStates.delete(closedTabId);
});

// Ascolta messaggi inviati dai content scripts (dom_inspector, triage, overlay)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : (request.tabId || null);

  if (request.action === "CHECK_PAGE_RISK") {
    handlePageAnalysis(request.payload, tabId)
      .then((response) => sendResponse(response))
      .catch((err) => sendResponse({ status: "ERROR", error: err.message }));
    return true; // Risposta asincrona
  }

  if (request.action === "GET_TAB_STATUS") {
    const targetTabId = request.tabId || (sender.tab ? sender.tab.id : null);
    const targetUrl = request.url || (sender.tab ? sender.tab.url : null);

    const state = (targetTabId ? tabStates.get(targetTabId) : null) || 
                  (targetUrl ? tabStates.get(targetUrl) : null) || 
                  { riskScore: 0, status: "SAFE", reasoning: "Nessuna anomalia rilevata." };

    sendResponse(state);
    return false;
  }
});

/**
 * Invia il payload della pagina al backend Python (FastAPI Engine) per l'analisi LLM
 */
async function handlePageAnalysis(payload, tabId) {
  // Recupera l'URL del backend dalle impostazioni o usa il default
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
 * Aggiorna il badge colorato e il testo sopra l'icona dell'estensione
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
 * Salva lo storico delle analisi nello storage locale dell'estensione
 */
async function saveAnalysisLog(logEntry) {
  const { logs = [] } = await chrome.storage.local.get(["logs"]);
  logs.unshift(logEntry);
  // Mantieni solo gli ultimi 50 log
  if (logs.length > 50) logs.pop();
  await chrome.storage.local.set({ logs });
}
