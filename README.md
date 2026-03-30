# Cyber-PI

## Funcionalidades

- **Detecção de domínios de terceiros** em requisições web
- **Monitoramento de cookies** (1ª/3ª parte, sessão/persistente)
- **Detecção de supercookies** (HSTS, ETag tracking, long-lived cookies)
- **Detecção de sincronismo de cookies** (Cookie Sync)
- **Detecção de Canvas Fingerprinting**
- **Monitoramento de localStorage e sessionStorage** (HTML5)
- **Detecção de ameaças de hijacking** (BeEF, XSS hooks, iframes ocultos)
- **Score de privacidade** (0-100) com metodologia baseada nos fatores detectados
- **Bloqueio de rastreadores** (EasyList + listas personalizadas)
- **Relatório de privacidade** por página

## Instalação
1. Abra o Firefox e navegue para `about:debugging`
2. Clique em **"Este Firefox"** (ou "This Firefox")
3. Clique em **"Carregar extensão temporária..."**
4. Selecione o arquivo `manifest.json` deste diretório

## Estrutura
```
Cyber-PI/
├── manifest.json          # Manifesto da extensão
├── background.js          # Script de background (interceptação, bloqueio, score)
├── content.js             # Content script (canvas fingerprint, storage, hijacking)
├── data/
│   └── trackers.js        # Lista de rastreadores conhecidos
├── popup/
│   ├── popup.html         # Interface do popup
│   ├── popup.css          # Estilos
│   └── popup.js           # Lógica da interface
├── icons/
│   └── icon-48.png        # Ícone 48x48
└── requirements.txt       # Dependências Python (dev)
```