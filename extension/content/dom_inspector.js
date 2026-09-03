// BitM Sentinel - DOM Inspector & Network Interceptor

//funzione anonima auto-invocata per evitare conflitti di variabili globali e creare un contesto isolato per l'analisi del DOM e l'intercettazione delle richieste di rete
(function () {
  console.log("[BitM Sentinel] Client inspector inizializzato su:", window.location.href); //Log di debug

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
   * Costruiamo il pacchetto di prove da inviare al backend per l'analisi del rischio della pagina.
   */
  function inspectAndAnalyzePage(triageData) {
    const formsData = [];
    document.querySelectorAll("form").forEach((form, idx) => { //scansiona tutti i form e raccoglie info
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

    // Cattura gli script esterni caricati nella pagina per l'analisi del rischio, se ci sono keylogger o script sospetti, il backend può rilevarli
    const scriptSources = [];
    document.querySelectorAll("script[src]").forEach((scr) => {
      try {
        scriptSources.push(new URL(scr.src, window.location.href).hostname);
      } catch (e) {}
    });
    //assembla il payload da inviare al backend per l'analisi del rischio della pagina
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
    /* il payload viene inviato al service worker che a sua volta lo invia al backend per l'analisi del rischio della pagina, 
    che risponde con un punteggio di rischio e una raccomandazione di azione (ALLOW, WARN, BLOCK)*/
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
