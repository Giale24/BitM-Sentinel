// BitM Sentinel - DOM Inspector & Network Interceptor

//funzione anonima auto-invocata per evitare conflitti di variabili globali e creare un contesto isolato per l'analisi del DOM e l'intercettazione delle richieste di rete
(function () {
  console.log("[BitM Sentinel] Client inspector inizializzato su:", window.location.href); //Log di debug

  // L'analisi automatica all'avvio è stata disabilitata per risparmiare la quota API (Modalità Manuale)
  // const triageResult = window.BitMTriage.runFastTriage();
  // inspectAndAnalyzePage(triageResult);

  // il popup invia un messaggio al content script per forzare l'analisi della pagina quando l'utente clicca il pulsante "Reanalyze"
  chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === "FORCE_REANALYZE") {
      const freshTriage = window.BitMTriage.runFastTriage();
      inspectAndAnalyzePage(freshTriage);
    }
  });

  // Intercetta l'invio delle form sensibili per applicare la mitigazione preventiva
  document.addEventListener("submit", function (e) {
    const form = e.target;
    if (form.querySelector("input[type='password'], input[name*='otp'], input[name*='token']")) {
      console.log("[BitM Sentinel] Intercettato invio di form sensibile.");
      // Richiede verifica immediata dello stato
      chrome.runtime.sendMessage({ action: "GET_TAB_STATUS" }, (response) => {
        if (response && (response.status === "BLOCK" || response.riskScore >= 75)) {
          e.preventDefault(); //bloccano l'invio dei dati sensibili
          e.stopPropagation();
          window.BitMMitigation.showBlockOverlay(
            response.reasoning || "Attacco Browser-in-the-Middle (BitM) rilevato. Invio credenziali bloccato."
          );
        }
      });
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

        if (result.status === "BLOCK" || result.riskScore >= 75) {
          if (window.BitMMitigation) window.BitMMitigation.showBlockOverlay(result.reasoning);
        } else if (result.status === "WARN" || result.riskScore >= 45) {
          if (window.BitMMitigation) window.BitMMitigation.showWarningBanner(result.reasoning);
        }
      }
    });
  }
})();
