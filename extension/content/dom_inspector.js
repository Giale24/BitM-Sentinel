// BitM Sentinel - DOM Inspector & Network Interceptor

// Funzione anonima auto-invocata (IIFE) per evitare collisioni nello scope globale
(function () {
  console.log("[BitM Sentinel] Client inspector inizializzato su:", window.location.href);

  // Stato di rischio locale sincronizzato (consente decisioni immediate e sincrone al submit)
  let localPageState = {
    status: "SAFE",
    riskScore: 0,
    reasoning: "Pagina in attesa di analisi."
  };

  // Esegue un primo triage rapido sincrono all'avvio per valorizzare lo stato locale
  const initialTriage = window.BitMTriage.runFastTriage();
  if (initialTriage.triageScore >= 75) {
    localPageState.status = "BLOCK";
    localPageState.riskScore = initialTriage.triageScore;
    localPageState.reasoning = initialTriage.flags.join(". ");
  }
  
  // Trigger di analisi automatica: attivabile decommentando il blocco sottostante
  /*
  const formsPresent = document.querySelectorAll("form").length > 0;
  const streamPresent = document.querySelectorAll("video, canvas").length > 0;
  const isSuspicious = initialTriage.hasSensitiveInput || initialTriage.triageScore >= 15 || formsPresent || streamPresent;

  if (isSuspicious) {
    console.log("[BitM Sentinel] Rilevata pagina con form o dati sensibili: avvio analisi automatica...");
    inspectAndAnalyzePage(initialTriage);
  }
  */


  // Il popup invia un messaggio al content script per forzare l'analisi della pagina
  chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === "FORCE_REANALYZE") {
      const freshTriage = window.BitMTriage.runFastTriage();
      inspectAndAnalyzePage(freshTriage);
    }
  });

  // Intercetta l'invio delle form sensibili in modo SINCRONO (elimina race condition)
  document.addEventListener("submit", function (e) {
    const form = e.target;
    if (form.querySelector("input[type='password'], input[name*='otp'], input[name*='token']")) {
      console.log("[BitM Sentinel] Intercettato invio di form sensibile. Verifica sincrona...");

      // 1. Controllo SINCRONO dello stato locale accertato dall'analisi
      if (localPageState.status === "BLOCK" || localPageState.riskScore >= 75) {
        e.preventDefault();
        e.stopPropagation();
        console.warn("[BitM Sentinel] SUBMIT BLOCCATO SINCRONAMENTE (Stato accertato: BLOCK)");
        window.BitMMitigation.showBlockOverlay(localPageState.reasoning);
        return false;
      }

      // 2. Paracadute: Triage locale istantaneo sincrono (<1ms) se l'utente invia prima dell'analisi remota
      const immediateTriage = window.BitMTriage.runFastTriage();
      if (immediateTriage.triageScore >= 75) {
        e.preventDefault();
        e.stopPropagation();
        console.warn("[BitM Sentinel] SUBMIT BLOCCATO SINCRONAMENTE (Triage Immediato)");
        localPageState.status = "BLOCK";
        localPageState.riskScore = immediateTriage.triageScore;
        localPageState.reasoning = immediateTriage.flags.join(". ");
        window.BitMMitigation.showBlockOverlay(localPageState.reasoning);
        return false;
      }
    }
  }, true);

  /**
   * Estrae le evidenze strutturali del DOM e le invia al background Service Worker.
   */
  function inspectAndAnalyzePage(triageData) {
    const formsData = [];
    document.querySelectorAll("form").forEach((form, idx) => {  // Scansiona ciascun form HTML per estrarne gli input
      const inputs = [];
      form.querySelectorAll("input, select, textarea").forEach((inp) => {
        inputs.push({
          type: inp.type || inp.tagName.toLowerCase(),
          name: inp.name || inp.id || "",
          placeholder: inp.placeholder || ""
        });
      });

      formsData.push({
        formId: form.id || `form_${idx}`,
        action: form.action || "",
        method: (form.method || "GET").toUpperCase(),
        inputs: inputs
      });
    });

    // Cattura i domini degli script esterni per rilevare keylogger o risorse iniettate da terzi
    const scriptSources = [];
    document.querySelectorAll("script[src]").forEach((scr) => {
      try {
        scriptSources.push(new URL(scr.src, window.location.href).hostname);
      } catch (e) {}
    });

    // Assembla il payload compatto da inviare al backend FastAPI
    const payload = {
      url: window.location.href,
      domain: window.location.hostname,
      title: document.title,
      triageScore: triageData.triageScore,
      triageFlags: triageData.flags,
      hasSensitiveInput: triageData.hasSensitiveInput,
      forms: formsData,
      externalScriptDomains: [...new Set(scriptSources)],
      // Snippet del testo visibile per la verifica semantica da parte dell'LLM (max 1000 char per ridurre token e latenza)
      visibleTextSnippet: (document.body ? document.body.innerText : "").substring(0, 1000).replace(/\s+/g, " ")
    };

    // Inoltra il payload al Service Worker (che gestisce la comunicazione con FastAPI superando CORS e CSP)
    chrome.runtime.sendMessage({ action: "CHECK_PAGE_RISK", payload: payload }, (response) => {
      if (response && response.status === "SUCCESS") {
        const result = response.data;
        console.log(`[BitM Sentinel] Analisi completata in ${result.elapsedMs}ms. Rischio: ${result.riskScore}/100. Azione: ${result.status}`);

        // Aggiorna lo stato sincrono locale per future intercettazioni submit
        localPageState = {
          status: result.status,
          riskScore: result.riskScore,
          reasoning: result.reasoning
        };

        if (result.status === "BLOCK" || result.riskScore >= 75) {
          if (window.BitMMitigation) window.BitMMitigation.showBlockOverlay(result.reasoning);
        } else if (result.status === "WARN" || result.riskScore >= 45) {
          if (window.BitMMitigation) window.BitMMitigation.showWarningBanner(result.reasoning);
        }
      }
    });
  }
})();
