# Secured_Gossip

![GitHub Repo stars](https://img.shields.io/github/stars/sanjanahv/Secured_Gossip?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/sanjanahv/Secured_Gossip)
![GitHub issues](https://img.shields.io/github/issues/sanjanahv/Secured_Gossip)
![GitHub license](https://img.shields.io/github/license/sanjanahv/Secured_Gossip)

An **original, anonymous, client-side encrypted, ephemeral secret-sharing platform** — built from scratch for secure sharing of sensitive text, API keys, and credentials.

---

## 🔒 Overview

Secured_Gossip implements a **zero-knowledge** architecture where the server **never sees plaintext or encryption keys**. All encryption/decryption happens exclusively in the user's browser using the Web Crypto API. The decryption key resides only in the URL fragment (`#key`), which browsers never transmit to servers, ensuring true end-to-end confidentiality.

> 🚀 **Innovation**: Beyond basic zero-knowledge sharing, we add **forward secrecy**, **multi-recipient envelope encryption**, and **time-bound access controls** — features not commonly found together in similar platforms.

---

## 🏗️ Architecture

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#0066cc', 'secondaryColor': '#0099ff', 'tertiaryColor': '#99ccff', 'lineColor': '#333', 'fontSize': '14px'}}}%%
flowchart TD
    subgraph Client[Browser (Client-Side)]
        direction TB
        UI[User Interface<br/>React + Vite] --> Crypto[Cryptography Layer<br/>Web Crypto API]
        Crypto -->|Encrypted Data + Key| Network[Network Layer]
    end

    subgraph Server[Backend Server]
        direction TB
        API[REST API<br/>Node.js + Express] --> Store[In-Memory Store<br/>Map<id, {ciphertext, iv, metadata}>]
        Store -->|Encrypted Data Only| DB[(Ephemeral Storage)]
    end

    Network -->|HTTPS POST| API
    API -->|HTTPS Response| Network
    Network -->|Encrypted Payload| UI

    subgraph Security Features[Security Features]
        direction LR
        ZK[Zero-Knowledge<br/>Server sees only ciphertext]
        FS[Forward Secrecy<br/>Daily-rotating master secret]
        MR[Multi-Recipient<br/>Envelope Encryption]
        PIN[PBKDF2 PIN Protection<br/>300k iterations]
        TA[Time-Bound Access<br/>notBefore/notAfter]
        BR[Burn-After-Read & Revocation]
    end

    Crypto -->|Implements| Security Features
    Store -->|Enforces| Security Features
```

### Component Breakdown

| Layer | Technology | Responsibility |
|-------|------------|----------------|
| **Frontend** | React 18 + Vite | UI, key generation, encryption/decryption, URL fragment handling |
| **Crypto Layer** | Web Crypto API (SubtleCrypto) | AES-256-GCM, HKDF, PBKDF2, envelope encryption |
| **Backend** | Node.js + Express | REST API, rate limiting, PIN verification, ephemeral storage |
| **Storage** | In-Memory Map | Ciphertext + IV + metadata only (plaintext/key never stored) |
| **Security** | Client-Side Only | All cryptographic operations happen in browser |

---

## ⚠️ Threat Model & Limitations

We follow a transparent security model similar to PrivateBin. Understanding what we **do** and **do not** protect against is crucial for informed usage.

### ✅ What We Protect Against
- **Passive Network Eavesdropping**: TLS + client-side encryption
- **Server Compromise**: Server sees only ciphertext; cannot decrypt without client-side key
- **Link Leakage Without PIN**: URL fragment key alone insufficient for decryption (when PIN enabled)
- **Brute-Force PIN Attacks**: Rate limiting + 5-attempt lockout + self-destruct
- **Replay Attacks**: Single-use secrets (burn-after-read) + timestamps
- **Storage Breach**: Stored data remains encrypted; keys never touch disk

### ❌ What We Do NOT Protect Against
- **Malicious Server Code**: A compromised server could serve modified JavaScript to steal keys
- **Client-Side Malware**: Keyloggers, screen scrapers, or compromised browsers
- **Legal Compulsion**: Server administrators may be forced to disclose access logs (IPs, timestamps)
- **URL Fragment Leakage via Referrers**: Though browsers don't send fragments, some plugins or extensions might
- **Quantum Computing Attacks**: AES-256 is quantum-resistant but not post-quantum safe

### 🔐 Our Security Guarantees
- Encryption: AES-256-GCM (NIPS-approved)
- Key Derivation: PBKDF2 (300k iterations) for PIN, HKDF for forward secrecy
- Randomness: cryptographically secure `crypto.getRandomValues()`
- Timing Safety: `crypto.timingSafeEqual()` for all sensitive comparisons
- Ephemerality: Secrets automatically expire or destroy after read

---

## 🏆 Key Innovations (Beyond Typical Zero-Knowledge Pastebins)

| Feature | Description | Benefit |
|---------|-------------|---------|
| **Forward Secrecy** | Daily-rotating master secret + HKDF-derived per-paste DEK | Compromise of one paste doesn't affect others |
| **Multi-Recipient Envelope Encryption** | Single secret encrypted once, then key wrapped per recipient | Efficient secure sharing with multiple parties |
| **Time-Bound Access Windows** | `notBefore`/`notAfter` timestamps in addition to TTL | Precise control over availability windows |
| **Creator-Controlled Revocation** | Delete token allows instant revocation before reading | Active lifecycle management |
| **PIN Attempt Limiting** | 5 incorrect PIN attempts trigger self-destruct | Mitigates offline/online brute force |
| **Burn-After-Read + Status Tracking** | Creator sees when/if secret was viewed | Transparency and auditability |

---

## 🔐 Security Model Summary

- **Encryption**: AES-256-GCM via Web Crypto API, 100% client-side
- **Key Management**: Random 256-bit DEK per paste; travels only in URL fragment `#key`
- **PIN Protection**: PBKDF2 (300,000 iterations) server-side; **not** combined with encryption key
- **Multi-Recipient**: Data Encryption Key (DEK) wrapped per recipient using passphrase-derived KEK
- **Forward Secrecy**: Master secret rotated daily; per-paste DEK = HKDF(master_secret, `secured-gossip-v{version}`, "paste")
- **Storage**: Ciphertext, IV, metadata (expiry, burn flag, view count, timestamps) — **zero plaintext/key**
- **Access Control**: Rate limiting (30 reveals/min/IP), PIN attempt limiting, time windows
- **Integrity**: AES-GCM provides built-in authentication; tampering detected

---

## 📋 Implemented Features

| Feature | Status | Description |
|---------|--------|-------------|
| Client-side AES-256-GCM encryption | ✅ | Via Web Crypto API, no third-party libs |
| Key-in-URL-fragment (never sent to server) | ✅ | Fragment `#key` stays client-side |
| Burn-after-read (one-time secrets) | ✅ | Secret destroyed after first successful decryption |
| Configurable TTL expiration | ✅ | 5 min / 1h / 1d options (customizable) |
| PIN protection with PBKDF2 (300k iterations) | ✅ | Server-side gate, separate from encryption key |
| 5-attempt brute force lockout (self-destruct) | ✅ | After 5 failed PIN attempts, secret is deleted |
| Creator delete/revoke token | ✅ | UUID-based token for instant revocation |
| Creator status tracking | ✅ | `waiting` → `seen` / `expired` / `revoked` / `destroyed` |
| Multi-recipient envelope encryption | ✅ | DEK wrapped per recipient using passphrase |
| Forward secrecy via HKDF-SHA256 key derivation | ✅ | Daily-rotating master secret |
| Time-bound access (notBefore / notAfter windows) | ✅ | Schedule availability beyond simple TTL |
| IP-based rate limiting | ✅ | 30 reveal attempts per minute per IP |

---

## 🛠️ Quickstart (for Judges & Reviewers)

**Requirements**: Node.js v18+, modern browser (Chrome/Firefox/Safari/Edge)

### 1️⃣ Start the Backend
```bash
# Clone repository
git clone https://github.com/sanjanahv/Secured_Gossip.git
cd Secured_Gossip/backend

# Install dependencies
npm install

# Start server
node src/server.js
# → Server running at http://localhost:3001
```

### 2️⃣ Start the Frontend
```bash
# In new terminal
cd ../frontend
npm install

# Start development server
npm run dev
# → App available at http://localhost:5173
```

### 3️⃣ Try It Out
1. Open http://localhost:5173 in your browser
2. Enter a secret (e.g., API key, password, sensitive note)
3. Configure options:
   - **Expiry**: 5 min, 1h, or 1d
   - **Burn-after-read**: Enable for one-time viewing
   - **PIN**: Add 4-32 character PIN for extra protection
   - **Multi-recipient**: Share with multiple people using separate passphrases
   - **Schedule**: Set `notBefore` and `notAfter` timestamps
4. Click **Create Secret**
5. Copy the generated link (contains ID in path, version query param, key in fragment)
6. Open link in **new incognito/private window** to verify decryption works
7. Test burn-after-read by reloading the link (should show "not found")
8. Test PIN protection with wrong/right PINs
9. Test revocation using the delete token shown after creation

---

## 🆚 How We Differ from PrivateBin

While inspired by PrivateBin's zero-knowledge principles, Secured_Gossip introduces **meaningful innovations** rather than replicating features:

| Aspect | PrivateBin | Secured_Gossip |
|--------|------------|----------------|
| **Core Innovation** | Mature, feature-rich pastebin | Forward secrecy + multi-recipient envelope encryption |
| **Multi-Recipient** | Not natively supported | Native envelope encryption (single encrypt, N-wrap) |
| **Forward Secrecy** | Not implemented | Daily-rotating master secret with HKDF |
| **Access Windows** | Simple TTL only | `notBefore` + `notAfter` + TTL |
| **Revocation** | Manual deletion only | Creator-held delete token for instant revocation |
| **PIN/Password** | Client-side derived (combined with key) | Server-side PBKDF2 gate (key unaffected by PIN) |
| **Status Tracking** | Basic view detection | Creator dashboard: waiting/seen/expired/revoked/destroyed |
| **Plausible Deniability** | Explicitly documented | Inherherent; clear threat model documentation |
| **Storage Backend** | Multiple options (filesystem, DB, etc.) | In-Memory Map (demo); designed for Redis swap |
| **UI/UX Features** | Syntax highlighting, file uploads, templates, QR codes | Focused on cryptographic innovation; clean minimal UI |

> 💡 **Philosophy**: Rather than competing on feature count, we advance the **core cryptographic model** of secure sharing while maintaining excellent usability.

---

## 📈 Future Enhancements (Post-Hackathon)

- **Persistent Storage**: Replace in-memory Map with Redis for durability & scaling
- **Deployment**: Docker Compose + Kubernetes manifests for one-click deployment
- **UI Improvements**: 
  - Syntax highlighting (Prism.js / Monaco)
  - Markdown rendering
  - File attachments (client-side encrypted)
  - Copy-to-clipboard with zero-state indicators
  - Dark/light theme toggle
  - QR code sharing for mobile
- **Advanced Access Controls**:
  - Geo/IP-based restrictions
  - Single-use recipient links
  - Social login / SSO integration (optional)
- **Audit & Compliance**:
  - Access logging (encrypted metadata only)
  - GDPR-compliant data deletion
  - SOC 2 / ISO 27001 aligned documentation
- **SDK & Integrations**:
  - npm package for programmatic secret creation
  - Slack / Teams bot for secure sharing
  - CLI tool for DevOps workflows
- **Security Hardening**:
  - Subresource Integrity (SRI) for CDN resources
  - Content Security Policy (CSP) headers
  - Regular third-party security audits

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

> 💬 **Note**: This software is provided as-is for educational and demonstration purposes. While we follow cryptographic best practices, production deployment requires additional hardening, persistent storage, and security review.

---

## 🙏 Acknowledgments

- **PrivateBin** & **ZeroBin** for pioneering the zero-knowledge pastebin concept
- **Web Crypto API** team for enabling strong client-side cryptography in browsers
- **Open Source Cryptography Community** for standards like AES-GCM, HKDF, PBKDF2
- **Hackathon Organizers** for the challenge that inspired this project

---

## 🔗 Links

- **Reference**: [PrivateBin Repository](https://github.com/PrivateBin/PrivateBin)
- **Web Crypto API**: [MDN Documentation](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- **Threat Model Inspiration**: [PrivateBin Security Documentation](https://privatebin.info/)

---

*Secured_Gossip: Where privacy meets practicality. Share with confidence, knowing your secrets stay secret.* 🌐🔒