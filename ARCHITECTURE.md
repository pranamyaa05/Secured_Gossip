# Secured_Gossip Architecture Diagram

## 3D Component Architecture

```mermaid
%%{init: {'theme': 'neutral', 'themeVariables': { 'primaryColor': '#1976d2', 'secondaryColor': '#42a5f5', 'tertiaryColor': '#90caf9', 'background': '#f5f5f5', 'secondaryBackground': '#ffffff', 'tertiaryBackground': '#eeeeee', 'borderRadius': '8px', 'fontSize': '14px'}}}%%
graph 3D
    %% Define 3D positions and styling for components
    subgraph ClientSide[Client Side (Browser)]
        direction TB
        UI[User Interface<br/><b>React 18 + Vite</b>] --> Crypto[Cryptography Engine<br/><b>Web Crypto API (SubtleCrypto)</b>]
        Crypto --> KeyMgr[Key Management<br/><b>Fragment Key • PIN Salt • DEK</b>]
        KeyMgr --> Network[Network Layer<br/><b>HTTPS/Fetch API</b>]
    end

    subgraph Transport[Transport Layer]
        direction TB
        TLS[TLS 1.3 Encryption<br/><b>HTTPS</b>] --> Net[Network Transit]
    end

    subgraph ServerSide[Server Side (Backend)]
        direction TB
        API[REST API Endpoints<br/><b>Node.js + Express</b>] --> Auth[Authentication & Rate Limiting<br/><b>PBKDF2 • IP Tracking</b>]
        Auth --> Store[Secure Storage Engine<br/><b>In-Memory Map • Ephemeral</b>]
        Store --> Meta[Metadata Manager<br/><b>Expiry • Burn Flag • Status</b>]
    end

    %% Security Features Layer (Cross-cutting)
    subgraph Security[Security Features (Client-Side Enforced)]
        direction LR
        ZK[Zero-Knowledge<br/>Server sees only ciphertext] --> FS[Forward Secrecy<br/>Daily-rotating master secret]
        FS --> MR[Multi-Recipient<br/>Envelope Encryption]
        MR --> PB[PBKDF2 PIN Protection<br/>300k iterations]
        PB --> TA[Time-Bound Access<br/>notBefore/notAfter]
        TA --> BR[Burn-After-Read & Revocation]
        BR --> ZK
    end

    %% Data Flow
    UI -->|1. User Input + Options| Crypto
    Crypto -->|2. Generate DEK + Encrypt| KeyMgr
    KeyMgr -->|3. Prepare Payload| Network
    Network -->|4. Encrypted HTTP POST| TLS
    TLS -->|5. Transit Through Network| Net
    Net -->|6. Reach Server Endpoint| API
    API -->|7. Validate & Rate Limit| Auth
    Auth -->|8. Store Ciphertext Only| Store
    Store -->|9. Return ID + Delete Token| Meta
    Meta -->|10. Response to Client| API
    API -->|11. Encrypted HTTP Response| TLS
    TLS -->|12. Transit Back| Net
    Net -->|13. Reach Client| Network
    Network -->|14. Extract Fragment Key| KeyMgr
    KeyMgr -->|15. Decrypt & Display| Crypto
    Crypto -->|16. Render Plaintext| UI

    %% Styling for visual appeal
    classDef client fill:#e3f2fd,stroke:#1976d2,stroke-width:2px;
    classDef server fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
    classDef transport fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;
    classDef security fill:#e8f5e8,stroke:#388e3c,stroke-width:2px;
    classDef dataflow fill:#ffffff,stroke:#424242,stroke-width:1.5px,stroke-dasharray: 2 2;

    class UI,Crypto,KeyMgr,Network client;
    class API,Auth,Store,Meta server;
    class TLS,Net transport;
    class ZK,FS,MR,PB,TA,BR security;
    class {{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}} dataflow;

    %% Tooltips/descriptions (using title syntax)
    click UI "https://react.dev/" "React 18 - Modern UI Library"
    click Crypto "https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API" "Web Crypto API - Native Browser Cryptography"
    click API "https://expressjs.com/" "Express.js - Fast, Unopinionated Web Framework"
    click Store "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map" "JavaScript Map - Ephemeral In-Memory Storage"
    click ZK "https://en.wikipedia.org/wiki/Zero-knowledge_proof" "Zero-Knowledge Principle - Server Never Sees Plaintext"
    click FS "https://en.wikipedia.org/wiki/Forward_secrecy" "Forward Secrecy - Compromise of One Key Doesn't Affect Others"
    click MR "https://en.wikipedia.org/wiki/Envelope_encryption" "Envelope Encryption - Efficient Multi-Recipient Sharing"
    click PB "https://en.wikipedia.org/wiki/PBKDF2" "PBKDF2 - Password-Based Key Derivation Function"
    click TA "https://en.wikipedia.org/wiki/Access_control" "Time-Bound Access - Scheduled Availability Windows"
    click BR "https://en.wikipedia.org/wiki/Burn_after_reading" "Burn-After-Read - Self-Destructing Secrets"
```

## Component Responsibilities

### 🖥️ Client-Side Components
- **User Interface**: React 18 + Vite SPA with intuitive forms for secret creation and viewing
- **Cryptography Engine**: Web Crypto API (SubtleCrypto) performing all AES-256-GCM, HKDF, PBKDF2 operations
- **Key Management**: Handles fragment keys, PIN salts, DEKs, and key derivation processes
- **Network Layer**: HTTPS communication with backend using Fetch API

### 🛠️ Server-Side Components
- **REST API Endpoints**: Express.js routes for secret creation, metadata, revelation, and deletion
- **Authentication & Rate Limiting**: IP-based reveal limiting, PBKDF2 PIN verification, attempt tracking
- **Secure Storage Engine**: Ephemeral in-memory Map storing only ciphertext, IV, and metadata
- **Metadata Manager**: Tracks expiry times, burn-after-read flags, view status, and access windows

### 🔐 Security Features (Implemented Client-Side)
- **Zero-Knowledge**: Server processes only ciphertext; never sees plaintext or encryption keys
- **Forward Secrecy**: Daily-rotating master secret with HKDF-derived per-paste Data Encryption Keys
- **Multi-Recipient Envelope Encryption**: Single DEK encrypted, then wrapped separately per recipient
- **PBKDF2 PIN Protection**: 300,000 iterations server-side PIN verification (separate from encryption key)
- **Time-Bound Access**: notBefore/notAfter timestamps in addition to simple TTL expiration
- **Burn-After-Read & Revocation**: Automatic destruction after view; creator-held delete tokens for instant revocation

## Data Flow Summary

1. **Encryption Path**: User Input → Key Generation → AES-256-GCM Encryption → Payload Preparation → HTTPS POST → Server Storage
2. **Decryption Path**: URL Fragment Parsing → Key Derivation (if needed) → AES-256-GCM Decryption → Plaintext Display
3. **Security Enforcement**: All cryptographic operations, key management, and access decisions happen client-side
4. **Server Role**: Blind storage of ciphertext + metadata; no decryption capability; rate limiting and PIN verification only

## Trust Boundaries

- **Client Trust Boundary**: Browser sandbox (Web Crypto API, localStorage for master secret)
- **Server Trust Boundary**: Node.js process (validates PINs, enforces rate limits, stores blind data)
- **Network Trust Boundary**: TLS 1.3 encrypted channel between client and server
- **Zero Trust Principle**: Server assumes all clients may be malicious; clients assume server may be compromised (but still safe due to client-side encryption)

## Deployment Architecture

For production deployment, the architecture extends to:
```
[Load Balancer] → [Multiple API Instances] → [Redis Cluster] → [Optional: HSM for Master Secrets]
                    ↑
[Static CDN] ← [Frontend Assets]
```

The core security model remains identical regardless of deployment scale—secrets are always encrypted in-browser before touching any network or storage component.