# Architectural & Security Decisions

This document records the architectural and security decisions that guide the Secured_Gossip project. Decisions are made and reviewed by humans; this project is an implementation of those decisions, not a source of them.

## 1. Independently Designed and Implemented from Scratch

Secured_Gossip is an original project. It is not a fork, clone, or derivative of PrivateBin, Bitwarden Send, Password Pusher, or any similar product. Existing products in this space are used only as reference points for understanding the problem domain. No source code, UI, terminology, architecture, or implementation is copied from them.

## 2. Client-Side Encryption Is a Core Security Principle

The server must never receive plaintext or the encryption key. Secrets are encrypted in the client before transmission, and the encryption key remains client-side in the URL fragment, which is never sent to the server. This zero-knowledge property is fundamental to the design.

## 3. Established Cryptographic Primitives Will Be Used

No custom cryptography will be invented. The project will rely exclusively on well-established, widely reviewed cryptographic primitives — specifically AES-256-GCM via the Web Crypto API — and will follow standard, documented usage patterns.

## 4. Humans Make and Review Architectural/Security Decisions

All architectural and security decisions are made and reviewed by humans. This project is an implementation assistant only and does not make design decisions on its own. Any proposed change to the architecture or security model must be explicitly approved before implementation.