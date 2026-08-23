# Secured_Gossip

An original, anonymous, client-side encrypted, ephemeral secret-sharing platform.

## Overview

Secured_Gossip is being designed and built from scratch as a zero-knowledge platform for sharing sensitive text. The core security principle is that the server never sees plaintext or the encryption key: secrets are encrypted in the browser before they leave the client, and the key travels only in the URL fragment, which is never sent to the server.

## Architecture

- **Frontend** — React + Vite
- **Backend** — Node.js + Express
- **Storage** — ephemeral, Redis/Upstash (planned)
- **Encryption** — AES-256-GCM via the Web Crypto API (planned)

## Project Structure

```
frontend/   React + Vite client application
backend/    Node.js + Express API server
```

## Status

Project initialization only. No security features, storage, or application logic have been implemented yet. See `DECISIONS.md` for the architectural principles guiding this project.