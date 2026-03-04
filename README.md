# Quantum Secure Messaging Protocol - SIMPLEX

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

**QSMP SIMPLEX** is a post-quantum secure messaging protocol that integrates key exchange, server authentication, and encrypted tunnel establishment into a single, self-contained specification. Engineered from the ground up to address the cryptographic challenges posed by quantum computing, QSMP avoids the design compromises and legacy constraints of protocols such as TLS, SSH, and PGP. There is no algorithm negotiation, no versioning attack surface, and no backward compatibility with classical-only primitives.

> This repository contains the **SIMPLEX** variant of QSMP: a one-way trust model optimised for high-performance client-server deployments.  
> The **DUPLEX** (mutual authentication, peer-to-peer) variant is maintained in a [separate repository](https://github.com/QRCS-CORP/QSMP-Duplex).

---

## Documentation

| Resource | Description |
|---|---|
| [Help Documentation](https://qrcs-corp.github.io/QSMP/) | Full API and usage reference |
| [Summary Document](https://qrcs-corp.github.io/QSMP/pdf/qsmp_summary.pdf) | Protocol overview and design rationale |
| [Protocol Specification](https://qrcs-corp.github.io/QSMP/pdf/qsmp_specification.pdf) | Complete formal protocol definition |
| [Formal Analysis](https://qrcs-corp.github.io/QSMP/pdf/qsmp_formal.pdf) | Security proofs and formal verification |
| [Implementation Analysis](https://qrcs-corp.github.io/QSMP/pdf/qsmp_analysis.pdf) | Implementation security considerations |
| [Integration Guide](https://qrcs-corp.github.io/QSMP/pdf/qsmp_integration.pdf) | Deployment and integration instructions |

---

## Overview

QSMP SIMPLEX establishes a 256-bit secure, bidirectional, authenticated encryption tunnel between a client and server using a **one-way trust model**: the client authenticates the server using a pre-distributed public verification key, and both parties derive shared session keys from a post-quantum KEM exchange. The complete handshake completes in **two round trips** with no session tickets, no certificate chains, and no runtime cipher negotiation.

The protocol is complete and self-contained. All cryptographic parameters are fixed at compile time for a given configuration, eliminating downgrade attacks and cipher-suite confusion by construction.

### Key Properties

- **Post-quantum security** - all asymmetric operations use NIST-standardised post-quantum algorithms
- **Two-round-trip handshake** - session establishment with minimal latency overhead
- **Transcript binding** - session keys are derived from a rolling SHA3-256 hash of every exchanged message, cryptographically committing them to the complete handshake
- **Explicit key confirmation** - the server's final transcript hash is encrypted and sent to the client; the session is not established unless both parties hold an identical transcript
- **Forward secrecy** - symmetric ratchet via cSHAKE-256 refreshes session keys on demand without a new asymmetric exchange
- **Anti-replay protection** - per-packet sequence counters and UTC timestamp validation on every received message
- **Minimal attack surface** - no algorithm negotiation, no fallback cipher paths, no protocol versioning surface
- **MISRA-C aligned** - structured for deployment in safety-critical and high-assurance environments

---

## Cryptographic Primitives

QSMP is built exclusively on algorithms from the NIST Post-Quantum Cryptography standardization process and NIST FIPS standards.

### Key Encapsulation (KEM)

| Algorithm | NIST Security Level | Standard |
|---|---|---|
| ML-KEM (Kyber) | 1 / 3 / 5 | NIST FIPS 203 |
| Classic McEliece | 1 / 3 / 5 | NIST PQC Selected |

ML-KEM or McEliece is used to encapsulate the session secret. A fresh ephemeral encapsulation key pair is generated by the server for each connection, and the private key is destroyed immediately after decapsulation.

### Digital Signatures

| Algorithm | NIST Security Level | Standard |
|---|---|---|
| ML-DSA (Dilithium) | 2 / 3 / 5 | NIST FIPS 204 |
| SLH-DSA (SPHINCS+) | 2 / 3 / 5 | NIST FIPS 205 |

ML-DSA or SLH-DSA authenticates the server's ephemeral public encapsulation key during the handshake. The client verifies this signature against the server's pre-distributed public verification key before any secret is encapsulated.

### Symmetric AEAD Cipher

| Cipher | Construction | Authentication |
|---|---|---|
| **RCS** (Rijndael Cryptographic Stream) | Wide-block Rijndael, 256-bit state, increased rounds, strengthened key schedule | KMAC or QMAC (post-quantum secure) |

RCS operates on a 256-bit wide Rijndael state with a cryptographically strengthened key schedule. Authentication is integrated natively via post-quantum secure KMAC or QMAC, with the serialised packet header included as associated data on every packet.

### Hash and Key Derivation

| Primitive | Algorithm | Purpose |
|---|---|---|
| Hash | SHA3-256 | Transcript hashing, public key binding |
| KDF | cSHAKE-256 | Session key derivation, symmetric ratchet |
| Entropy | ACP | RDRAND + system state, hashed with SHAKE-512 |

---

## Key Exchange Protocol

The QSMP SIMPLEX handshake is a two-round authenticated key exchange. The server holds a long-term signing key pair; the client holds the server's public verification key, distributed out-of-band prior to connection.

### Trust Model
```
Key Distribution (out-of-band)
        │
        │  Server generates signing keypair.
        │  Public verification key (.qpkey) is
        │  distributed to clients manually.
        ▼
    QSMP Server ──── signs ephemeral pubkey ────► Client
                                                     │
                                          Verifies signature using
                                          pre-distributed verkey
```

### Exchange Sequence
```
Legend:
  C       = Client
  S       = Server
  H       = SHA3-256
  KEM     = Key Encapsulation Mechanism
  SIG     = ML-DSA or SLH-DSA Signature
  cSHAKE  = Customizable SHAKE-256 KDF
  sch     = Rolling transcript hash
  pk_kem  = Ephemeral public encapsulation key
  kid     = Key identifier
  cfg     = Configuration string

Round 1  C → S :  kid || cfg
                  sch₁ = H(cfg || kid || verkey)

Round 2  S → C :  SIG(H(cfg || kid || pk_kem)) || pk_kem
                  sch₂ = H(sch₁ || H(cfg || kid || pk_kem))

Round 3  C → S :  KEM_Encaps(pk_kem) → ciphertext || secret
                  sch₃ = H(sch₂ || ciphertext)
                  session_keys = cSHAKE(secret, sch₃)

Confirm  S → C :  Ek(sch₃)
                  C decrypts and verifies sch₃ matches local transcript
                  Session established only on exact match
```

Session keys are derived from `cSHAKE(shared_secret, transcript_hash)`, binding them cryptographically to both parties' identities and every value exchanged during the handshake. The server encrypts its final transcript hash with the newly established session cipher and sends it as explicit key confirmation — a mismatch terminates the connection immediately before any application data is processed.

### Security Properties

| Property | Mechanism |
|---|---|
| Server authentication | ML-DSA / SLH-DSA signature over transcript hash, verified against pre-distributed verkey |
| Key exchange secrecy | ML-KEM / McEliece — quantum-safe encapsulation of ephemeral secret |
| Transcript binding | Four-step rolling SHA3-256 hash over all exchanged values |
| Explicit key confirmation | Server transmits `Ek(sch₃)`; client verifies before accepting session |
| Message confidentiality | RCS-256 AEAD per packet |
| Message integrity | KMAC/QMAC authentication tag, 256-bit, per packet |
| Anti-replay | Per-packet sequence counter + UTC timestamp window |
| Forward secrecy | cSHAKE-256 symmetric ratchet refreshes session keys without re-handshaking |
| Key erasure | Compiler-resistant secure erase on all key material immediately after use |

---

## Performance and Scalability

The QSMP server is implemented as a multi-threaded platform capable of maintaining a uniquely keyed encrypted tunnel for each connected client simultaneously. Ephemeral encapsulation keys are generated and destroyed within the scope of each exchange, ensuring complete session isolation with no shared key material between connections. The per-client state is compact by design, enabling a single server instance to sustain a large number of concurrent connections without significant memory pressure.

---

## Compilation

QSMP uses the [QSC Cryptographic Library](https://github.com/QRCS-CORP/QSC) — a standalone, portable, MISRA-aligned cryptographic library written in C23. QSC supports platform-optimised builds across Windows, macOS, and Linux, with hardware acceleration for AES-NI, AVX2/AVX-512, and RDRAND where available.

### Prerequisites

| Tool | Requirement |
|---|---|
| CMake | 3.15 or newer |
| Windows | Visual Studio 2022 or newer |
| macOS | Clang via Xcode or Homebrew |
| Linux | GCC or Clang (C23-capable) |
| Dependency | [QSC Library](https://github.com/QRCS-CORP/QSC) |

---

### Windows (MSVC)

The Visual Studio solution contains three projects: **QSMP** (library), **Server**, and **Client**. The QSMP library is expected in a folder parallel to the Server and Client project folders.

> **Critical:** The `Enable Enhanced Instruction Set` property must be set to the **same value** across the QSC library, the QSMP library, and all application projects in both Debug and Release configurations. Mismatched intrinsics settings produce ABI-incompatible struct layouts and are a source of undefined behaviour.

**Build order:**
1. Build the **QSC** library
2. Build the **QSMP** library
3. Build **Server** and **Client**

**Include path configuration:**  
If the library files are not at their default locations, update the include paths in each project under:  
`Configuration Properties → C/C++ → General → Additional Include Directories`

Default paths:
- `$(SolutionDir)QSMP`
- `$(SolutionDir)..\QSC\QSC`

Ensure each application project's **References** property includes the QSMP library, and that the QSMP library references the QSC library.

#### Local Protocol Test (Visual Studio)
```
1. Set QSMP Server as the startup project and run it.
   On first run the server generates a signing keypair automatically:

   server> The private-key was not detected, generating a new private/public keypair...
   server> The publickey has been saved to C:\Users\<username>\Documents\QSMP\server_public_key.qpkey
   server> Distribute the public-key to intended clients.
   server>
   server> Waiting for a connection...

2. Right-click QSMP Client in the Solution Explorer → Debug → Start New Instance.
   Enter the loopback address and the path to the server's public key when prompted:

   client> Enter the destination IPv4 address, ex. 192.168.1.1
   client> 127.0.0.1
   client> Enter the path of the public key:
   client> C:\Users\<username>\Documents\QSMP\server_public_key.qpkey
   client>

   The client authenticates the server, completes the key exchange, and the
   encrypted tunnel is established. Messages typed in either console are
   transmitted over the post-quantum secure channel.
```

> The server's public key file (`server_public_key.qpkey`) is generated once and persists across restarts. Distribute this file to all intended clients out-of-band before they connect. On subsequent server starts, the existing keypair is loaded automatically.

---

### macOS / Linux (Eclipse)

The QSC and QSMP library projects, along with the Server and Client projects, have been tested with the Eclipse IDE on Ubuntu and macOS.

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

QSMP SIMPLEX depends on the [QSC Cryptographic Library](https://github.com/QRCS-CORP/QSC) for all underlying cryptographic operations, including post-quantum primitives, symmetric ciphers, hash functions, and random number generation.

---

## Related Repositories

| Repository | Description |
|---|---|
| [QSMP DUPLEX](https://github.com/QRCS-CORP/QSMD) | Mutual authentication variant for 512-bit secure peer-to-peer and high-security deployments |
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
