"""
AES-GCM Encrypt / Decrypt Web UI
실행: python aes_gcm_ui.py
의존성: pip install flask cryptography
"""

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

app = Flask(__name__)

# ──────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AES-256-GCM Tool</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Oxanium:wght@400;700;800&display=swap');

  :root {
    --bg:       #0a0c10;
    --panel:    #0f1218;
    --border:   #1e2330;
    --accent:   #00e5ff;
    --accent2:  #7b2fff;
    --green:    #00e096;
    --red:      #ff4466;
    --text:     #c9d1e0;
    --muted:    #4a5568;
    --label:    #8892a4;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 40px 16px 60px;
    background-image:
      radial-gradient(ellipse 80% 40% at 50% -10%, rgba(0,229,255,.07) 0%, transparent 70%),
      radial-gradient(ellipse 60% 30% at 80% 110%, rgba(123,47,255,.06) 0%, transparent 70%);
  }

  /* ── Header ── */
  header {
    text-align: center;
    margin-bottom: 40px;
  }
  header h1 {
    font-family: 'Syne', sans-serif;
    font-size: clamp(1.8rem, 4vw, 2.8rem);
    font-weight: 800;
    letter-spacing: -0.02em;
    background: linear-gradient(120deg, var(--accent) 0%, var(--accent2) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  header p {
    margin-top: 8px;
    font-size: .78rem;
    color: var(--muted);
    letter-spacing: .12em;
    text-transform: uppercase;
  }

  /* ── Tab ── */
  .tabs {
    display: flex;
    gap: 4px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 4px;
    margin-bottom: 28px;
    width: 100%;
    max-width: 680px;
  }
  .tab-btn {
    flex: 1;
    padding: 10px 0;
    border: none;
    border-radius: 7px;
    background: transparent;
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
    font-size: .82rem;
    font-weight: 600;
    letter-spacing: .08em;
    cursor: pointer;
    transition: all .2s;
  }
  .tab-btn.active {
    background: linear-gradient(135deg, rgba(0,229,255,.15), rgba(123,47,255,.15));
    color: var(--accent);
    border: 1px solid rgba(0,229,255,.25);
  }
  .tab-btn:hover:not(.active) { color: var(--text); }

  /* ── Card ── */
  .card {
    width: 100%;
    max-width: 680px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 32px;
    display: none;
    flex-direction: column;
    gap: 22px;
    animation: fadeUp .3s ease;
  }
  .card.visible { display: flex; }

  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(10px); }
    to   { opacity: 1; transform: translateY(0);    }
  }

  /* ── Form elements ── */
  .field { display: flex; flex-direction: column; gap: 7px; }
  label {
    font-size: .7rem;
    font-weight: 600;
    letter-spacing: .12em;
    text-transform: uppercase;
    color: var(--label);
  }
  textarea, input[type="text"] {
    background: #070810;
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: .82rem;
    padding: 12px 14px;
    resize: vertical;
    outline: none;
    transition: border-color .2s;
    width: 100%;
  }
  textarea { min-height: 90px; }
  textarea:focus, input[type="text"]:focus {
    border-color: rgba(0,229,255,.4);
    box-shadow: 0 0 0 3px rgba(0,229,255,.07);
  }

  /* ── Button ── */
  .run-btn {
    align-self: flex-end;
    padding: 11px 32px;
    border: none;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: .82rem;
    font-weight: 700;
    letter-spacing: .1em;
    cursor: pointer;
    transition: all .2s;
    position: relative;
    overflow: hidden;
  }
  #encBtn {
    background: linear-gradient(135deg, var(--accent) 0%, #0099bb 100%);
    color: #000;
  }
  #decBtn {
    background: linear-gradient(135deg, var(--accent2) 0%, #5500cc 100%);
    color: #fff;
  }
  .run-btn:hover { filter: brightness(1.15); transform: translateY(-1px); }
  .run-btn:active { transform: translateY(0); filter: brightness(.95); }
  .run-btn:disabled { opacity: .5; cursor: not-allowed; transform: none; }

  /* ── Result box ── */
  .result-box {
    display: none;
    flex-direction: column;
    gap: 14px;
    border-top: 1px solid var(--border);
    padding-top: 22px;
    animation: fadeUp .3s ease;
  }
  .result-box.visible { display: flex; }
  .result-box.error .result-header { color: var(--red); }
  .result-header {
    font-size: .7rem;
    font-weight: 700;
    letter-spacing: .14em;
    text-transform: uppercase;
    color: var(--green);
  }

  .result-row { display: flex; flex-direction: column; gap: 5px; }
  .result-label {
    font-size: .65rem;
    color: var(--label);
    letter-spacing: .1em;
    text-transform: uppercase;
  }
  .result-val {
    background: #070810;
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 10px 60px 10px 14px;
    font-size: .78rem;
    word-break: break-all;
    line-height: 1.6;
    color: var(--text);
    position: relative;
  }
  .copy-btn {
    position: absolute;
    top: 7px; right: 9px;
    background: rgba(255,255,255,.06);
    border: 1px solid var(--border);
    border-radius: 5px;
    color: var(--muted);
    font-size: .65rem;
    padding: 2px 8px;
    cursor: pointer;
    font-family: 'JetBrains Mono', monospace;
    transition: all .15s;
  }
  .copy-btn:hover { color: var(--accent); border-color: rgba(0,229,255,.3); }
  .copy-btn.copied { color: var(--green); }

  /* ── Spinner ── */
  @keyframes spin { to { transform: rotate(360deg); } }
  .spinner {
    display: inline-block;
    width: 14px; height: 14px;
    border: 2px solid rgba(0,0,0,.3);
    border-top-color: #000;
    border-radius: 50%;
    animation: spin .6s linear infinite;
    vertical-align: middle;
    margin-right: 6px;
  }

  /* ── Footer ── */
  footer {
    margin-top: 40px;
    font-size: .68rem;
    color: var(--muted);
    text-align: center;
    letter-spacing: .06em;
  }
</style>
</head>
<body>

<header>
  <h1>AES-256-GCM</h1>
  <p>Authenticated Encryption Tool &nbsp;·&nbsp; Cryptography Hazmat</p>
</header>

<!-- Tabs -->
<div class="tabs">
  <button class="tab-btn active" id="tabEnc" onclick="switchTab('enc')">🔐 &nbsp;ENCRYPT</button>
  <button class="tab-btn"        id="tabDec" onclick="switchTab('dec')">🔓 &nbsp;DECRYPT</button>
</div>

<!-- ENCRYPT card -->
<div class="card visible" id="cardEnc">
  <div class="field">
    <label>Plain Text</label>
    <textarea id="plaintext" placeholder="Please enter text to encrypt..."></textarea>
  </div>
  <button class="run-btn" id="encBtn" onclick="doEncrypt()">ENCRYPT &rarr;</button>

  <div class="result-box" id="encResult">
    <div class="result-header">✓ &nbsp;ENCRYPTION COMPLETE</div>
    <div class="result-row">
      <div class="result-label">KEY &nbsp;(key + nonce, base64)</div>
      <div class="result-val" id="outKey">
        <button class="copy-btn" onclick="copyVal('outKey', this)">copy</button>
        <span id="outKeyText"></span>
      </div>
    </div>
    <div class="result-row">
      <div class="result-label">ENCRYPTED TEXT &nbsp;(base64)</div>
      <div class="result-val" id="outEnc">
        <button class="copy-btn" onclick="copyVal('outEnc', this)">copy</button>
        <span id="outEncText"></span>
      </div>
    </div>
  </div>
</div>

<!-- DECRYPT card -->
<div class="card" id="cardDec">
  <div class="field">
    <label>KEY &nbsp;(base64)</label>
    <input type="text" id="inKey" placeholder="Please enter the KEY..." />
  </div>
  <div class="field">
    <label>ENCRYPTED TEXT &nbsp;(base64)</label>
    <textarea id="inEnc" placeholder="Please enter the ENCRYPTED TEXT..." style="min-height:70px"></textarea>
  </div>
  <button class="run-btn" id="decBtn" onclick="doDecrypt()">DECRYPT &rarr;</button>

  <div class="result-box" id="decResult">
    <div class="result-header" id="decHeader"></div>
    <div class="result-row" id="decRow">
      <div class="result-label">DECRYPTED TEXT</div>
      <div class="result-val" id="outDec">
        <button class="copy-btn" onclick="copyVal('outDec', this)">copy</button>
        <span id="outDecText"></span>
      </div>
    </div>
  </div>
</div>

<footer>
  AES-256 · GCM Mode · 96-bit Nonce · 128-bit Auth Tag &nbsp;|&nbsp; Key never leaves your server
</footer>

<script>
function switchTab(t) {
  document.getElementById('cardEnc').classList.toggle('visible', t === 'enc');
  document.getElementById('cardDec').classList.toggle('visible', t === 'dec');
  document.getElementById('tabEnc').classList.toggle('active', t === 'enc');
  document.getElementById('tabDec').classList.toggle('active', t === 'dec');
}

async function doEncrypt() {
  const text = document.getElementById('plaintext').value.trim();
  if (!text) { alert('Please enter text to encrypt.'); return; }

  const btn = document.getElementById('encBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Processing...';

  const res  = await fetch('/encrypt', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ text })
  });
  const data = await res.json();

  btn.disabled = false;
  btn.innerHTML = 'ENCRYPT &rarr;';

  document.getElementById('outKeyText').textContent = data.key;
  document.getElementById('outEncText').textContent = data.encrypted;
  document.getElementById('encResult').classList.add('visible');
}

async function doDecrypt() {
  const key = document.getElementById('inKey').value.trim();
  const enc = document.getElementById('inEnc').value.trim();
  if (!key || !enc) { alert('Please enter both the KEY and ENCRYPTED TEXT.'); return; }

  const btn = document.getElementById('decBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Processing...';

  const res  = await fetch('/decrypt', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ key, encrypted: enc })
  });
  const data = await res.json();

  btn.disabled = false;
  btn.innerHTML = 'DECRYPT &rarr;';

  const box    = document.getElementById('decResult');
  const header = document.getElementById('decHeader');
  const row    = document.getElementById('decRow');

  box.classList.add('visible');
  if (data.error) {
    box.classList.add('error');
    header.textContent = '✗  ' + data.error;
    row.style.display = 'none';
  } else {
    box.classList.remove('error');
    header.textContent = '✓  DECRYPTION COMPLETE';
    row.style.display  = '';
    document.getElementById('outDecText').textContent = data.plaintext;
  }
}

function copyVal(spanId, btn) {
  const txt = document.getElementById(spanId + 'Text')?.textContent
           || document.getElementById(spanId).innerText.replace('copy','').trim();
  navigator.clipboard.writeText(txt).then(() => {
    btn.textContent = 'copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 1500);
  });
}
</script>
</body>
</html>"""
# ──────────────────────────────────────────────


@app.route("/")
def index():
    return HTML


@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    text = data.get("text", "")

    key   = os.urandom(32)
    nonce = os.urandom(12)

    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, text.encode("utf-8"), None)

    combined_key = base64.b64encode(key + nonce).decode()
    enc_data     = base64.b64encode(ciphertext).decode()

    return jsonify({"key": combined_key, "encrypted": enc_data})


@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json()
    combined_key = data.get("key", "")
    enc_data     = data.get("encrypted", "")

    try:
        raw        = base64.b64decode(combined_key)
        key        = raw[:32]
        nonce      = raw[32:]
        ciphertext = base64.b64decode(enc_data)

        aesgcm    = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return jsonify({"plaintext": plaintext.decode("utf-8")})

    except Exception:
        return jsonify({"Error": "Invalid KEY or ENCRYPTED TEXT."}), 400
