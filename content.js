(function () {
  "use strict";
  const injectionCode = `
    (function() {
      // 1. Interceptar Canvas
      const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
      const origToBlob = HTMLCanvasElement.prototype.toBlob;
      const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
      let canvasAlerted = false;

      function notifyCanvas(method, w, h) {
        if (!canvasAlerted && w > 16 && h > 16) {
          canvasAlerted = true;
          window.postMessage({
            cyberPi: true,
            type: "canvas-fingerprint",
            details: \`\${method} chamado em canvas \${w}x\${h}\`
          }, "*");
        }
      }

      HTMLCanvasElement.prototype.toDataURL = function(...args) {
        notifyCanvas("toDataURL", this.width, this.height);
        return origToDataURL.apply(this, args);
      };

      HTMLCanvasElement.prototype.toBlob = function(...args) {
        notifyCanvas("toBlob", this.width, this.height);
        return origToBlob.apply(this, args);
      };

      CanvasRenderingContext2D.prototype.getImageData = function(...args) {
        if (this.canvas) notifyCanvas("getImageData", this.canvas.width, this.canvas.height);
        return origGetImageData.apply(this, args);
      };

      // 2. Interceptar eval()
      const origEval = window.eval;
      let evalCount = 0;
      window.eval = function(...args) {
        evalCount++;
        if (evalCount === 20) { // Avisar apenas uma vez quando exceder
          window.postMessage({
            cyberPi: true,
            type: "hijacking-detected",
            threatType: "excessive-eval",
            details: \`Uso excessivo de eval() detectado: mais de 20 chamadas\`
          }, "*");
        }
        return origEval.apply(this, args);
      };

      // 3. Interceptar document.cookie para pegar Supercookies gerados via JS
      try {
        const _proto = Document.prototype;
        const origCookieDesc = Object.getOwnPropertyDescriptor(_proto, 'cookie');
        if (origCookieDesc && origCookieDesc.set && origCookieDesc.configurable) {
          const origSetter = origCookieDesc.set;
          Object.defineProperty(_proto, 'cookie', {
            get: origCookieDesc.get,
            set: function(val) {
              try {
                const parts = String(val).split(";").map(p => p.trim());
                const cookieName = parts[0].split("=")[0].trim();
                let maxAge = 0;
                let isSession = true;
                for (const part of parts) {
                  const lower = part.toLowerCase();
                  if (lower.startsWith("max-age=")) {
                    maxAge = parseInt(lower.split("=")[1]) || 0;
                    isSession = false;
                  } else if (lower.startsWith("expires=")) {
                    const expires = new Date(part.split("=").slice(1).join("="));
                    maxAge = Math.floor((expires.getTime() - Date.now()) / 1000);
                    if (maxAge > 0) isSession = false;
                  }
                }
                // Notificar todo cookie criado via JS para o contador
                window.postMessage({
                  cyberPi: true,
                  type: "js-cookie-set",
                  name: cookieName,
                  domain: window.location.hostname,
                  isSession: isSession,
                  maxAge: maxAge
                }, "*");
                // Sinalizar especificamente supercookies (> 1 ano)
                if (maxAge > 31536000) {
                  window.postMessage({
                    cyberPi: true,
                    type: "supercookie-detected",
                    name: cookieName,
                    domain: window.location.hostname,
                    maxAge: maxAge
                  }, "*");
                }
              } catch (e) {}
              return origSetter.call(this, val);
            },
            configurable: true
          });
        }
      } catch (e) {}
    })();
  `;

  // Injetar o script na página
  try {
    const script = document.createElement("script");
    script.textContent = injectionCode;
    (document.head || document.documentElement).appendChild(script);
    script.remove();
  } catch (e) {
    console.warn("Cyber-PI: Falha ao injetar script", e);
  }

  // Receber mensagens do script injetado
  window.addEventListener("message", (event) => {
    if (event.source !== window || !event.data || !event.data.cyberPi) return;

    try {
      if (event.data.type === "canvas-fingerprint" || event.data.type === "hijacking-detected") {
        browser.runtime.sendMessage({
          type: event.data.type,
          threatType: event.data.threatType,
          details: event.data.details
        });
      } else if (event.data.type === "supercookie-detected") {
        browser.runtime.sendMessage({
          type: "supercookie-detected",
          name: event.data.name,
          domain: event.data.domain,
          maxAge: event.data.maxAge
        });
      } else if (event.data.type === "js-cookie-set") {
        browser.runtime.sendMessage({
          type: "js-cookie-set",
          name: event.data.name,
          domain: event.data.domain,
          isSession: event.data.isSession,
          maxAge: event.data.maxAge
        });
      }
    } catch (e) {}
  });

  let threatSet = new Set();

  function checkElementForHijacking(el) {
    if (el.tagName === "IFRAME") {
      const style = window.getComputedStyle(el);
      const isHidden = style.display === "none" ||
        style.visibility === "hidden" ||
        parseInt(style.width) <= 1 ||
        parseInt(style.height) <= 1 ||
        style.opacity === "0";

      if (isHidden && el.src && !el.src.startsWith("about:") && !threatSet.has(el.src)) {
        threatSet.add(el.src);
        try {
          browser.runtime.sendMessage({
            type: "hijacking-detected",
            threatType: "hidden-iframe",
            details: `Iframe oculto detectado: ${el.src.substring(0, 200)}`
          });
        } catch (e) {}
      }
    } else if (el.tagName === "SCRIPT" && el.src) {
      const src = el.src.toLowerCase();
      if ((src.includes("hook.js") || src.includes("beef") ||
           src.includes("browser_exploitation") || src.includes("evercookie") ||
           src.includes("zombiejs")) && !threatSet.has(el.src)) {
        threatSet.add(el.src);
        try {
          browser.runtime.sendMessage({
            type: "hijacking-detected",
            threatType: "malicious-script",
            details: `Script suspeito detectado: ${el.src.substring(0, 200)}`
          });
        } catch (e) {}
      }
    }
  }

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          checkElementForHijacking(node);
          if (node.querySelectorAll) {
            node.querySelectorAll("iframe, script").forEach(checkElementForHijacking);
          }
        }
      }
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  // Verificar elementos já existentes na inicialização
  function checkExistingHijacking() {
    document.querySelectorAll("iframe, script").forEach(checkElementForHijacking);
  }

  // ============================================================================
  // Monitoramento de Local Storage / Session Storage
  // ============================================================================
  function checkStorage() {
    try {
      if (window.localStorage && window.localStorage.length > 0) {
        const keys = [];
        for (let i = 0; i < Math.min(window.localStorage.length, 50); i++) {
          keys.push(window.localStorage.key(i));
        }
        browser.runtime.sendMessage({ type: "localstorage-detected", keys }).catch(() => {});
      }
      
      if (window.sessionStorage && window.sessionStorage.length > 0) {
        const keys = [];
        for (let i = 0; i < Math.min(window.sessionStorage.length, 50); i++) {
          keys.push(window.sessionStorage.key(i));
        }
        browser.runtime.sendMessage({ type: "sessionstorage-detected", keys }).catch(() => {});
      }
    } catch (e) { /* acesso pode ser bloqueado */ }
  }

  // Executar verificações de storage em intervalos para capturar uso dinâmico (comum em testes manuais da página)
  setInterval(checkStorage, 2000);

  // Executar após carregamento
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      checkExistingHijacking();
      checkStorage();
    });
  } else {
    checkExistingHijacking();
    checkStorage();
  }

})();
