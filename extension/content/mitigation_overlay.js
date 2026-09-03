// BitM Sentinel - Real-time Mitigation & User Defense Overlay

// OVERLAY INLINE: L'interfaccia è generata via JS (e non file esterni) per:
    // 1) Iniettare nativamente nel DOM 2) Evitare che l'attaccante sovrascriva 
    // il nostro CSS nascondendo il blocco 3) Garantire latenza zero sull'interfaccia


//oggetto globale per la gestione della mitigazione e dell'overlay di avviso in caso di rilevamento di gravità rossa (BLOCK) o media (WARN)
window.BitMMitigation = {
  /**
   * Mostra una modale bloccante a schermo intero se viene rilevato un attacco BitM grave
   */
  showBlockOverlay: function (reasoning) { //chiamata quando il risk score è >= 75
    if (document.getElementById("bitm-block-overlay")) return;// controlla se l'overlay è già presente per evitare duplicazioni

    // Disabilita solo gli input attualmente attivi nella pagina, tracciandoli
    document.querySelectorAll("input, button, select, textarea").forEach((el) => {
      if (!el.disabled) {
        el.dataset.bitmDisabled = "true";
        el.disabled = true;
      }
    });
    // div dell'overlay con messaggio di avviso e motivazione dell'analisi semantica LLM
    const overlay = document.createElement("div");
    overlay.id = "bitm-block-overlay";
    overlay.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100vw !important;
      height: 100vh !important;
      background-color: rgba(15, 23, 42, 0.95) !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
      color: #F8FAFC !important;
      backdrop-filter: blur(8px) !important;
    `;

    overlay.innerHTML = `
      <div style="
        background: #1E293B;
        border: 2px solid #EF4444;
        border-radius: 16px;
        padding: 32px;
        max-width: 550px;
        width: 90%;
        box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.3);
        text-align: center;
      ">
        <div style="
          width: 64px;
          height: 64px;
          background: rgba(239, 68, 68, 0.15);
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0 auto 20px auto;
          color: #EF4444;
          font-size: 32px;
          font-weight: bold;
        ">⚠️</div>
        
        <h2 style="margin: 0 0 12px 0; color: #F8FAFC; font-size: 22px;">ATTENZIONE: Attacco BitM Rilevato!</h2>
        
        <p style="color: #94A3B8; font-size: 14px; line-height: 1.6; margin-bottom: 20px;">
          L'engine di intelligenza artificiale <strong>BitM Sentinel</strong> ha bloccato la pagina perché presenta caratteristiche di un attacco <em>Browser-in-the-Middle / Phishing Proxy</em>.
        </p>

        <div style="
          background: #0F172A;
          border-left: 4px solid #EF4444;
          padding: 12px 16px;
          border-radius: 6px;
          text-align: left;
          font-size: 13px;
          color: #CBD5E1;
          margin-bottom: 24px;
        ">
          <strong>Motivazione dell'Analisi Semantica LLM:</strong><br/>
          <div id="bitm-block-reasoning-text" style="margin-top: 6px; white-space: pre-wrap;"></div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: center;">
          <button id="bitm-btn-back" style="
            background: #EF4444;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.2s;
          ">Torna alla Sicurezza</button>
          
          <button id="bitm-btn-bypass" style="
            background: transparent;
            color: #64748B;
            border: 1px solid #475569;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 12px;
            cursor: pointer;
          ">Ignora e Prosegui (Rischioso)</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    // Sanificazione Anti-XSS: popoliamo il testo tramite textContent (non innerHTML)
    const reasoningTextNode = document.getElementById("bitm-block-reasoning-text");
    if (reasoningTextNode) {
      reasoningTextNode.textContent = reasoning || "La pagina sta tentando di intercettare le credenziali tramite un proxy non autorizzato.";
    }

    // Gestione dei bottoni dell'overlay
    document.getElementById("bitm-btn-back").addEventListener("click", () => {
      window.history.back();
    });

    document.getElementById("bitm-btn-bypass").addEventListener("click", () => {
      overlay.remove();
      // Riabilita esclusivamente gli elementi precedentemente disabilitati da BitM
      document.querySelectorAll("[data-bitm-disabled='true']").forEach((el) => {
        el.disabled = false;
        delete el.dataset.bitmDisabled;
      });
    });
  },

  // Mostra un banner di avviso in alto se viene rilevato un attacco di gravità media (WARN)
  showWarningBanner: function (reasoning) {
    if (document.getElementById("bitm-warn-banner")) return;

    const banner = document.createElement("div");
    banner.id = "bitm-warn-banner";
    banner.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100% !important;
      background: #7C2D12 !important;
      color: #FEF08A !important;
      padding: 10px 20px !important;
      z-index: 2147483646 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: space-between !important;
      font-family: system-ui, sans-serif !important;
      font-size: 13px !important;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2) !important;
    `;

    banner.innerHTML = `
      <div>
        <strong>⚡ BitM Sentinel Warning:</strong> <span id="bitm-warn-reasoning-text"></span>
      </div>
      <button id="bitm-warn-close" style="
        background: transparent;
        border: 1px solid #FEF08A;
        color: #FEF08A;
        padding: 4px 10px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 12px;
      ">Chiudi</button>
    `;

    document.body.prepend(banner);

    // Sanificazione Anti-XSS tramite textContent
    const warnTextNode = document.getElementById("bitm-warn-reasoning-text");
    if (warnTextNode) {
      warnTextNode.textContent = reasoning || "Pagina potenzialmente sospetta. Verifica l'URL prima di inserire dati di accesso.";
    }

    document.getElementById("bitm-warn-close").addEventListener("click", () => {
      banner.remove();
    });
  }
};
