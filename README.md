# OAuth 2.0: TLS-Session-Bound Token Exchange

[![IETF Draft](https://img.shields.io/badge/IETF-Draft-blue.svg)](https://datatracker.ietf.org/doc/draft-mw-oauth-tls-bound-token-exchange/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

This repository contains the IETF Internet-Draft for **TLS-Session-Bound Token Exchange**, a mechanism that binds OAuth 2.0 access tokens issued via RFC 8693 (Token Exchange) to a specific mTLS session using TLS Exporter values.

## The Problem: Bearer Token Replay in Agentic AI

OAuth 2.0 Token Exchange (RFC 8693) produces bearer tokens that can be stolen and replayed on any connection. Existing mitigations bind tokens to certificates (RFC 8705) or ephemeral keys (RFC 9449/DPoP), but **not to the TLS session itself**. The abandoned Token Binding work (RFC 8471–8473) addressed session binding but was never adopted for Token Exchange and predates TLS 1.3.

**Agentic AI systems amplify this risk dramatically:**
- Agents autonomously chain hundreds of API calls with token exchanges
- Multi-hop delegation (A→B→C→D) creates bearer tokens at each hop
- Prompt injection attacks can exfiltrate tokens via side channels
- Agent-to-agent traffic is fully automated with no human oversight

## The Solution: TLS Exporter-Based Session Binding

The client presents a **Session-Binding Proof** alongside each bearer token: a signed JWT containing:

1. **Token hash** — SHA-256 of the access token
2. **TLS Exporter value** — cryptographically derived from the mTLS session handshake (RFC 5705 / RFC 8446 §7.5)
3. **Timestamp** — proof creation time
4. **HTTP method and URI** — request binding

The proof is signed with the client's mTLS private key. The resource server verifies the signature, confirms the exporter value matches the current session, and validates all claims.

**Result:** A stolen token is useless on any other TLS session.

## How This Compares

| Property | Bearer | RFC 8705 | DPoP | Token Binding | **This Draft** |
|---|---|---|---|---|---|
| Certificate binding | ❌ | ✅ | ❌ | ❌ | ✅ |
| TLS session binding | ❌ | ❌ | ❌ | ✅ | ✅ |
| Per-request PoP | ❌ | ❌ | ✅ | ❌ | ✅ |
| TLS 1.3 native | N/A | ✅ | ✅ | ⚠️ | ✅ |
| RFC 8693 target | ✅ | Partial | Partial | Never | **✅** |

## Related Work

- **Transitive Attestation** ([draft-mw-wimse-transitive-attestation](https://datatracker.ietf.org/doc/draft-mw-wimse-transitive-attestation/)): Binds identity to a verified host (Proof of Residency). Complementary to this draft's session binding.
- **Actor Chain** ([draft-mw-spice-actor-chain](https://datatracker.ietf.org/doc/draft-mw-spice-actor-chain/)): Provides East-West delegation proof across agent chains.

## Building the Draft

The draft is written in Markdown and uses `mmark` and `xml2rfc` for conversion.

### Prerequisites
- [mmark](https://github.com/mmark-md/mmark)
- [xml2rfc](https://pypi.org/project/xml2rfc/)

### Build Commands
```bash
# Generate TXT, HTML, and XML outputs
make

# Clean build artifacts
make clean
```

## Contributing

This is an active IETF submission. Feedback is welcome via GitHub issues or the [OAuth WG mailing list](https://www.ietf.org/mailman/listinfo/oauth).
