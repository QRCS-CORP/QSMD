# Quantum Secure Messaging Protocol - DUPLEX

## Introduction

[![Build](https://github.com/QRCS-CORP/QSMD/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/QSMD/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/QSMD/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/QSMD/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/qsmd/badge)](https://www.codefactor.io/repository/github/qrcs-corp/qsmd)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/QSMD/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/QSMD/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/QSMD/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/QSMD)](https://github.com/QRCS-CORP/QSMD/releases/tag/2025-06-04)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/QSMD.svg)](https://github.com/QRCS-CORP/QSMD/commits/main)
[![Security Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Target Industry](https://img.shields.io/static/v1?label=Target%20Industry&message=Communications&color=brightgreen)](#)

**QSMP DUPLEX** is a post-quantum secure messaging protocol providing mutual authentication and encrypted tunnel establishment between two peers. Both parties hold long-term asymmetric signing key pairs, and each verifies the other's identity before any secret material is exchanged. Engineered from the ground up to address the cryptographic challenges posed by quantum computing, QSMD avoids the design compromises and legacy constraints of protocols such as TLS, SSH, and PGP. There is no algorithm negotiation, no versioning attack surface, and no backward compatibility with classical-only primitives.

> This repository contains the **DUPLEX** variant of QSMP: a mutual authentication model designed for peer-to-peer and high-security client-server deployments targeting 512-bit security.  
> The **SIMPLEX** (one-way trust, optimised throughput) variant is maintained in a [separate repository](https://github.com/QRCS-CORP/QSMP).

---

## Documentation

| Resource | Description |
|---|---|
| [Help Documentation](https://qrcs-corp.github.io/QSMD/) | Full API and usage reference |
| [Summary Document](https://qrcs-corp.github.io/QSMD/pdf/qsmd_summary.pdf) | Protocol overview and design rationale |
| [Protocol Specification](https://qrcs-corp.github.io/QSMD/pdf/qsmd_specification.pdf) | Complete formal protocol definition |
| [Formal Analysis](https://qrcs-corp.github.io/QSMD/pdf/qsmd_formal.pdf) | Security proofs and formal verification |
| [Implementation Analysis](https://qrcs-corp.github.io/QSMD/pdf/qsmd_analysis.pdf) | Implementation security considerations |
| [Integration Guide](https://qrcs-corp.github.io/QSMD/pdf/qsmd_integration.pdf) | Deployment and integration instructions |

---

## Overview

QSMP DUPLEX establishes a 512-bit secure, bidirectional, authenticated encryption tunnel between a client and server using a **mutual trust model**: both parties hold long-term signing key pairs, and each verifies the other's public verification key — distributed out-of-band prior to connection — before any secret is encapsulated. Two independent shared secrets are derived from two separate KEM exchanges, and session keys are derived from both secrets combined with a rolling transcript hash. The complete handshake completes in **five passes** with no session tickets, no certificate chains, and no runtime cipher negotiation.

The protocol is complete and self-contained. All cryptographic parameters are fixed at compile time for a given configuration, eliminating downgrade attacks and cipher-suite confusion by construction. 

### Key Properties

- **Post-quantum security** — all asymmetric operations use NIST-standardised post-quantum algorithms
- **Mutual authentication** — both client and server hold long-term signing key pairs; each verifies the other's identity before any encapsulation occurs
- **Dual-secret key derivation** — session keys are derived from two independent KEM-encapsulated secrets combined with the transcript hash, providing defence in depth against single-primitive compromise
- **512-bit security** — SHA3-512 transcript hashing, 64-byte session keys, and 64-byte MAC tags throughout
- **Transcript binding** — session keys are derived from a rolling SHA3-512 hash of every exchanged message, cryptographically committing them to the complete handshake history
- **Explicit key confirmation** — both parties independently encrypt the transcript hash and exchange it as the final handshake step; the session is not established unless both transcripts match exactly
- **Forward secrecy** — symmetric ratchet via cSHAKE-512 refreshes session keys on demand without a new asymmetric exchange
- **Optional asymmetric ratchet** — when `QSMD_ASYMMETRIC_RATCHET` is defined, full asymmetric rekeying is available, generating fresh encapsulation keys and deriving new session keys without terminating the connection
- **Anti-replay protection** — per-packet sequence counters and UTC timestamp validation on every received message
- **Minimal attack surface** — no algorithm negotiation, no fallback cipher paths, no protocol versioning surface
- **MISRA-C aligned** — structured for deployment in safety-critical and high-assurance environments

---

## Cryptographic Primitives

QSMD is built exclusively on algorithms from the NIST Post-Quantum Cryptography standardization process and NIST FIPS standards.

### Key Encapsulation (KEM)

| Algorithm | NIST Security Level | Standard |
|---|---|---|
| ML-KEM (Kyber) | 1 / 3 / 5 / 6 | NIST FIPS 203 |
| Classic McEliece | 1 / 3 / 5 / 6 / 7 | NIST PQC Selected |

Each handshake performs two independent KEM exchanges — one from each peer — producing two separate shared secrets. Both secrets are combined with the session transcript hash to derive the final session keys. A fresh ephemeral encapsulation key pair is generated by each party for its respective exchange, and all private keys are destroyed immediately after decapsulation.

### Digital Signatures

| Algorithm | NIST Security Level | Standard |
|---|---|---|
| ML-DSA (Dilithium) | 2 / 3 / 5 | NIST FIPS 204 |
| SLH-DSA (SPHINCS+) | 2 / 3 / 5 / 6 | NIST FIPS 205 |

Both parties sign their ephemeral public encapsulation keys during the handshake. Each party verifies the peer's signature against the pre-distributed public verification key before accepting the encapsulation key. This ensures that neither party can be substituted by an active attacker, even if network traffic is fully controlled.

> For maximum security, the McEliece / SPHINCS+ combination is recommended.  
> For a balance of performance and security, Dilithium / Kyber or Dilithium / McEliece are recommended.

### Supported Algorithm Combinations

| KEM | Signature | Notes |
|---|---|---|
| Kyber-S1 | Dilithium-S1 | |
| Kyber-S3 | Dilithium-S3 | |
| Kyber-S5 | Dilithium-S5 | Recommended balanced configuration |
| Kyber-S6 | Dilithium-S5 | |
| McEliece-S1 | Dilithium-S1 | |
| McEliece-S3 | Dilithium-S3 | |
| McEliece-S5 | Dilithium-S5 | |
| McEliece-S6 | Dilithium-S5 | |
| McEliece-S7 | Dilithium-S5 | |
| McEliece-S1 | SPHINCS+-S1 (f/s) | |
| McEliece-S3 | SPHINCS+-S3 (f/s) | |
| McEliece-S5 | SPHINCS+-S5 (f/s) | Recommended maximum-security configuration |
| McEliece-S6 | SPHINCS+-S5 (f/s) | |
| McEliece-S7 | SPHINCS+-S6 (f/s) | True 512-bit security with SPHINCS+ 512-bit option enabled in QSC |

### Symmetric AEAD Cipher

| Cipher | Construction | Authentication |
|---|---|---|
| **RCS** (Rijndael Cryptographic Stream) | Wide-block Rijndael, 256-bit state, increased rounds, strengthened key schedule | KMAC or QMAC (post-quantum secure) |

RCS operates on a 256-bit wide Rijndael state with a cryptographically strengthened key schedule. Authentication is integrated natively via post-quantum secure KMAC or QMAC, with the serialised packet header included as associated data on every packet.

### Hash and Key Derivation

| Primitive | Algorithm | Purpose |
|---|---|---|
| Hash | SHA3-512 | Transcript hashing, public key binding |
| KDF | cSHAKE-512 | Session key derivation, symmetric ratchet |
| Entropy | ACP | RDRAND + system state, hashed with SHAKE-512 |

---

## Key Exchange Protocol

The QSMP DUPLEX handshake is a five-pass mutually authenticated key exchange. Both parties hold long-term signing key pairs. Each party's public verification key is distributed to the other out-of-band prior to connection.

### Trust Model
```
Key Distribution (out-of-band, both directions)
        │
        │  Client generates signing keypair.  Server generates signing keypair.
        │  Each distributes their public verification key to the other.
        ▼
    Client ──── sends verkey_C ────► Server
    Server ──── sends verkey_S ────► Client
        │
        │  During handshake:
        │  Client verifies Server's signature using verkey_S
        │  Server verifies Client's signature using verkey_C
```

### Exchange Sequence
```
Legend:
  C        = Client
  S        = Server
  H        = SHA3-512
  KEM      = Key Encapsulation Mechanism
  SIG      = ML-DSA or SLH-DSA Signature
  cSHAKE   = Customizable SHAKE-512 KDF
  sch      = Rolling transcript hash
  pk_s     = Server ephemeral public encapsulation key
  pk_c     = Client ephemeral public encapsulation key
  cpta     = Ciphertext from client encapsulation (secret seca)
  cptb     = Ciphertext from server encapsulation (secret secb)
  kid      = Key identifier
  cfg      = Configuration string
  pvka     = Client public verification key
  pvkb     = Server public verification key
  sph      = Serialized packet header (includes UTC timestamp)

Pass 1  C → S :  kid || cfg || Ssk_C(H(kid || cfg || sph))
                 sch₁ = H(cfg || pvka || pvkb)
                 sch₁ = H(sch₁ || H(kid || cfg || sph))

Pass 2  S → C :  Ssk_S(H(pk_s || sph)) || pk_s
                 sch₂ = H(sch₁ || H(pk_s || sph))

Pass 3  C → S :  cpta || pk_c || Ssk_C(H(pk_c || cpta || sph))
                 seca = KEM_Encaps(pk_s)
                 sch₃ = H(sch₂ || H(pk_c || cpta || sph))

Pass 4  S → C :  Ssk_S(H(cptb || sph)) || cptb
                 seca = KEM_Decaps(cpta)
                 secb = KEM_Encaps(pk_c)
                 k1, k2, n1, n2 = cSHAKE(seca || secb || sch₃)
                 sch₄ = H(sch₃ || H(cptb || sph))

Pass 5  C → S :  Ek1(sch₄)    [establish request: client encrypts transcript hash]
        S → C :  Ek2(sch₄)    [establish response: server encrypts transcript hash]
                 Session established only if both decrypted hashes match exactly
```

### Ratchet System

After session establishment, both parties may refresh session keys on demand without terminating the connection.

```
Symmetric Ratchet (always available):
  new_keys = cSHAKE-512(ratchet_token, current_ratchet_key, cfg)
  Both TX and RX cipher instances are reinitialized atomically.

Asymmetric Ratchet (when QSMD_ASYMMETRIC_RATCHET is defined):
  Initiator generates fresh KEM keypair, signs and sends the public key.
  Responder encapsulates a new secret, signs and sends the ciphertext.
  Initiator decapsulates the secret.
  Both parties inject the new secret into the symmetric ratchet.
  Ephemeral keys are securely erased immediately after use.
```

---

## Build Requirements

| Platform | Toolchain |
|---|---|
| Windows | Visual Studio 2022 or newer |
| macOS | Clang via Xcode or Homebrew |
| Linux | GCC or Clang (C23-capable) |
| Dependency | [QSC Library](https://github.com/QRCS-CORP/QSC) |

---

### Windows (MSVC)

The Visual Studio solution contains three projects: **QSMD** (library), **Server**, and **Client**. The QSMD library is expected in a folder parallel to the Server and Client project folders.

> **Critical:** The `Enable Enhanced Instruction Set` property must be set to the **same value** across the QSC library, the QSMD library, and all application projects in both Debug and Release configurations. Mismatched intrinsics settings produce ABI-incompatible struct layouts and are a source of undefined behaviour.

**Build order:**
1. Build the **QSC** library
2. Build the **QSMD** library
3. Build **Server** and **Client**

**Include path configuration:**  
If the library files are not at their default locations, update the include paths in each project under:  
`Configuration Properties → C/C++ → General → Additional Include Directories`

Default paths:
- `$(SolutionDir)QSMD`
- `$(SolutionDir)..\QSC\QSC`

Ensure each application project's **References** property includes the QSMD library, and that the QSMD library references the QSC library.

#### Local Protocol Test (Visual Studio)
```
1. Set QSMD Listener as the startup project and run it.
   On first run the listener generates a signing keypair automatically:

   listener> The private-key was not detected, generating a new private/public keypair...
   listener> The publickey has been saved to C:\Users\stepp\Documents\QSMD\listener_public_key.qpkey
   listener> Distribute the public-key to intended clients.
   listener> Waiting for a connection...
   listener>

2. Right-click QSMD Sender in the Solution Explorer → Debug → Start New Instance.
   Enter the loopback address and the path to the listener's public key when prompted.
   On first run the sender also generates its own signing keypair:

   sender> Enter the destination IPv4 address, ex. 192.168.1.1
   sender> 127.0.0.1
   sender> Enter the path of the listener's public key:
   sender> C:\Users\stepp\Documents\QSMD\listener_public_key.qpkey
   sender> The private-key was not detected, generating a new private/public keypair...
   sender> The publickey has been saved to C:\Users\stepp\Documents\QSMD\sender_public_key.qpkey
   sender> Distribute the public-key to intended clients.
   sender>

   Both parties complete mutual authentication and the five-pass key exchange.
   The encrypted tunnel is established. Messages typed in either console are
   transmitted over the post-quantum secure channel.
```

> Both the listener's and sender's public key files (`.qpkey`) are generated once and persist across restarts. Each operator must distribute their own public key file to the other party out-of-band before the first connection. On subsequent starts, existing key pairs are loaded automatically.

---

### macOS / Linux (Eclipse)

The QSC and QSMD library projects, along with the Server and Client projects, have been tested with the Eclipse IDE on Ubuntu and macOS.

Eclipse project files (`.project`, `.cproject`, `.settings`) are located in platform-specific subdirectories under the `Eclipse` folder. Copy the files from `Eclipse/Ubuntu/<project-name>` or `Eclipse/MacOS/<project-name>` directly into the folder containing each project's source files.

To create a project in Eclipse: select **C/C++ Project → Create an empty project** and use the same name as the source folder. Eclipse will load all settings automatically. Repeat for each project. GCC and Clang project files differ — select the set that matches your platform.

The default Eclipse projects are configured with no enhanced instruction extensions. Add flags as needed for your target hardware.

#### Compiler Flag Reference

**AVX (256-bit FP/SIMD)**
```
-msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2
```
| Flag | Purpose |
|---|---|
| `-msse2` | Baseline x86_64 SSE2 |
| `-mavx` | 256-bit FP/SIMD |
| `-maes` | AES-NI hardware acceleration |
| `-mpclmul` | Carry-less multiply (GHASH) |
| `-mrdrnd` | RDRAND hardware RNG |
| `-mbmi2` | Bit manipulation (PEXT/PDEP) |

**AVX2 (256-bit integer SIMD)**
```
-msse2 -mavx -mavx2 -maes -mpclmul -mrdrnd -mbmi2
```
| Flag | Purpose |
|---|---|
| `-mavx2` | 256-bit integer and FP SIMD |
| *(others as above)* | |

**AVX-512 (512-bit SIMD)**
```
-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -maes -mpclmul -mrdrnd -mbmi2
```
| Flag | Purpose |
|---|---|
| `-mavx512f` | 512-bit Foundation instructions |
| `-mavx512bw` | 512-bit byte/word integer operations |
| `-mvaes` | Vector-AES in 512-bit registers |
| *(others as above)* | |

---

## Cryptographic Dependencies

QSMP DUPLEX depends on the [QSC Cryptographic Library](https://github.com/QRCS-CORP/QSC) for all underlying cryptographic operations, including post-quantum primitives, symmetric ciphers, hash functions, and random number generation.

---

## Related Repositories

| Repository | Description |
|---|---|
| [QSMP SIMPLEX](https://github.com/QRCS-CORP/QSMP) | One-way trust variant optimised for high-performance client-server deployments |
| [QSC Library](https://github.com/QRCS-CORP/QSC) | Underlying cryptographic primitive library |
| [QSTP](https://github.com/QRCS-CORP/QSTP) | Root-anchored tunneling protocol with certificate-based server identity |

---

## License

> **Investment Inquiries:**  
> QRCS is currently seeking a corporate investor for this technology. Parties interested in licensing or investment are invited to contact us at [contact@qrcscorp.ca](mailto:contact@qrcscorp.ca) or visit [https://www.qrcscorp.ca](https://www.qrcscorp.ca) for a full inventory of our products and services.

> **Patent Notice:**  
> One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.

**License and Use Notice (2025–2026)**

This repository contains cryptographic reference implementations, test code, and supporting materials published by Quantum Resistant Cryptographic Solutions Corporation (QRCS) for the purposes of public review, cryptographic analysis, interoperability testing, and evaluation.

All source code and materials in this repository are provided under the **Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025–2026**, unless explicitly stated otherwise.

This license permits non-commercial research, evaluation, and testing use only. It does not permit production deployment, operational use, or incorporation into any commercial product or service without a separate written agreement executed with QRCS.

The public availability of this repository is intentional and is provided to support cryptographic transparency, independent security assessment, and compliance with applicable cryptographic publication and export regulations.

Commercial use, production deployment, supported builds, certified implementations, and integration into products or services require a separate commercial license and support agreement.

For licensing inquiries, supported implementations, or commercial use, contact: [licensing@qrcscorp.ca](mailto:licensing@qrcscorp.ca)

*Quantum Resistant Cryptographic Solutions Corporation, 2026. All rights reserved.*
