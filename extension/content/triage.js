// BitM Sentinel - Fast Client-side Triage (Heuristics Engine)


/*Calcola la distanza di Levenshtein tra due stringhe (per rilevamento typosquatting/domain spoofing)
calcola quanti caratteri si devono modificare per trasformare una stringa nell'altra*/
function levenshteinDistance(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, () => []);
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[a.length][b.length];
}

/**
 * Analizzatore Euristico Locale (Triage veloce < 5ms)
 */
window.BitMTriage = {
  // Lista di brand comunemente bersaglio di attacchi BitM / AitM
  TARGET_BRANDS: ["microsoft", "google", "paypal", "intesa", "postepay", "github", "apple", "amazon"],

  //esegue i test per ottenere un referto rapido 
  runFastTriage: function () {
    const flags = [];
    let score = 0;

    const currentUrl = new URL(window.location.href);
    const hostname = currentUrl.hostname.toLowerCase();

    // 1. Controllo Form Sensibili & Mismatch di Dominio Target
    const forms = document.querySelectorAll("form");
    let hasSensitiveInput = false;

    forms.forEach((form) => {
      const inputs = form.querySelectorAll("input[type='password'], input[type='text'], input[type='number']");
      let containsPassword = false;
      let containsOtp = false;

      inputs.forEach((input) => {
        const name = (input.name || input.id || "").toLowerCase();
        if (input.type === "password" || name.includes("pass") || name.includes("pwd")) {
          containsPassword = true;
          hasSensitiveInput = true;
        }
        if (name.includes("otp") || name.includes("code") || name.includes("token") || name.includes("2fa") || name.includes("mfa")) {
          containsOtp = true;
          hasSensitiveInput = true;
        }
      });
      //allarme se il form sensibile invia dati a un dominio terzo (potenziale attacco BitM)
      if (containsPassword || containsOtp) {
        const actionAttr = form.getAttribute("action");
        if (actionAttr) {
          try {
            const actionUrl = new URL(actionAttr, window.location.href);
            if (actionUrl.origin !== currentUrl.origin || actionUrl.host !== currentUrl.host) {
              score += 55;
              flags.push(`Form sensibile invia credenziali a un host/dominio terzo (${actionUrl.host})`);
            }
          } catch (e) {}
        }
      }
    });

    // 2. Controllo Pattern Subdominio Proxato (stile Evilginx: login.microsoft.com.attacker.com)
    const hostParts = hostname.split(".");
    if (hostParts.length > 3) {
      for (const brand of this.TARGET_BRANDS) {
        if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.net`)) {
          score += 45;
          flags.push(`Nome brand target (${brand}) rilevato in sotto-dominio di un dominio sconosciuto`);
          break;
        }
      }
    }

    // 3. Typosquatting / Dominio Simile
    for (const brand of this.TARGET_BRANDS) {
      const mainDomainPart = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : "";
      if (mainDomainPart && mainDomainPart !== brand && mainDomainPart.length >= 4) {
        const dist = levenshteinDistance(mainDomainPart, brand);
        if (dist === 1 || dist === 2) {
          score += 30;
          flags.push(`Dominio '${mainDomainPart}' altamente simile a brand protetto '${brand}' (Levenshtein: ${dist})`);
        }
      }
    }

    // 4. Controllo Iframe Nascosti o Sovrapposti (Clickjacking / Proxy Injection)
    const iframes = document.querySelectorAll("iframe");
    let hiddenIframeCount = 0;
    iframes.forEach((iframe) => {
      const style = window.getComputedStyle(iframe);
      if (style.opacity === "0" || style.display === "none" || style.visibility === "hidden") {
        hiddenIframeCount++;
      }
    });
    
    if (hiddenIframeCount > 0) {
      score += 15; // Aggiungiamo il malus una sola volta, non per ogni iframe!
      flags.push(`Rilevati ${hiddenIframeCount} iframe invisibili (potenziali tracker o clickjacking)`);
    }

    // 5. Controllo Video/Canvas Streaming BitM (es. Cuddlephish / noVNC / WebRTC)
    const streamElements = document.querySelectorAll("video, canvas");
    let hasStreamingBitM = false;
    streamElements.forEach((el) => {
      const style = window.getComputedStyle(el);
      const isFullScreen = (el.style.width && el.style.width.includes("100")) || 
                           parseInt(style.width) >= window.innerWidth * 0.8;
      if (isFullScreen) {
        hasStreamingBitM = true;
      }
    });

    if (hasStreamingBitM && forms.length === 0) {
      score += 65;
      flags.push("Rilevato flusso video/canvas a tutto schermo senza form nativi (potenziale BitM Streaming/noVNC/WebRTC)");
      hasSensitiveInput = true;
    }

    return {
      triageScore: Math.min(score, 100),
      flags: flags,
      hasSensitiveInput: hasSensitiveInput,
      timestamp: new Date().toISOString()
    };
  }
};
