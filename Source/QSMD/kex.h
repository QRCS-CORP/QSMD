/* 2021-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSMD_KEX_H
#define QSMD_KEX_H

#include "qsmd.h"

/**
 * \file kex.h
 * \brief QSMD Key Exchange Functions.
 *
 * \details
 * This header file contains the internal key exchange functions for the Quantum Secure Messaging Protocol (QSMD).
 * QSMD supports two key exchange variants:
 * 
 * - **Duplex:** A bidirectional key exchange method that enables mutual authentication and secure session key
 *   establishment. Both parties exchange cryptographic material to derive a shared secret.
 *
 * - **Simplex:** A unidirectional key exchange method where typically the client verifies the server's identity.
 *
 * The file defines internal state structures for both the client and server roles in Duplex and Simplex key exchanges.
 * These structures encapsulate various cryptographic parameters such as key identities, session token hashes,
 * asymmetric keys (for encryption, signing, and verification), shared secrets, and session expiration times.
 *
 * The following internal (non-exportable) functions are declared:
 *
 * - \c qsmd_kex_duplex_server_key_exchange: Executes the server-side Duplex key exchange.
 * - \c qsmd_kex_duplex_client_key_exchange: Executes the client-side Duplex key exchange.
 * - \c qsmd_kex_simplex_server_key_exchange: Executes the server-side Simplex key exchange.
 * - \c qsmd_kex_simplex_client_key_exchange: Executes the client-side Simplex key exchange.
 * - \c qsmd_kex_test: Runs a suite of internal tests to validate the correctness of the key exchange operations.
 *
 * \note These functions and state structures are internal and are not part of the public QSMD API.
 */

 /*!
 * \def QSMD_KEX_TEST_ENABLED
 * \brief Enable to manually test the kex
 */
 //#define QSMD_KEX_TEST_ENABLED

/**
 * \struct qsmd_kex_duplex_client_state
 * \brief Internal state for the Duplex key exchange (client-side).
 *
 * \details
 * This structure holds the state information required by a client participating in a Duplex key exchange.
 * It includes:
 * - \c keyid: A unique key identity string (of size \c QSMD_KEYID_SIZE) that identifies the key exchange session.
 * - \c schash: A session token hash (of size \c QSMD_HASH_SIZE) used to verify session integrity.
 * - \c prikey: The client's asymmetric cipher private key (of size \c QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE).
 * - \c pubkey: The client's asymmetric cipher public key (of size \c QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE).
 * - \c rverkey: The remote party's asymmetric signature verification key (of size \c QSMD_ASYMMETRIC_VERIFY_KEY_SIZE).
 * - \c sigkey: The client's asymmetric signature signing key (of size \c QSMD_ASYMMETRIC_SIGNING_KEY_SIZE).
 * - \c ssec: The derived asymmetric shared secret (of size \c QSMD_SECRET_SIZE) computed during key exchange.
 * - \c verkey: The client's local asymmetric signature verification key (of size \c QSMD_ASYMMETRIC_VERIFY_KEY_SIZE).
 * - \c expiration: A timestamp (in seconds from the epoch) indicating when the key exchange session expires.
 */
typedef struct qsmd_kex_duplex_client_state
{
	uint8_t keyid[QSMD_KEYID_SIZE];							/*!< The key identity string */
	uint8_t schash[QSMD_HASH_SIZE];				/*!< The session token hash */
	uint8_t prikey[QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE];		/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE];		/*!< The asymmetric cipher public key */
	uint8_t rverkey[QSMD_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The remote asymmetric signature verification-key */
	uint8_t sigkey[QSMD_ASYMMETRIC_SIGNING_KEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t ssec[QSMD_SECRET_SIZE];							/*!< The asymmetric shared secret */
	uint8_t verkey[QSMD_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The local asymmetric signature verification-key */
	uint64_t expiration;									/*!< The expiration time, in seconds from epoch */
} qsmd_kex_duplex_client_state;

/**
 * \struct qsmd_kex_duplex_server_state
 * \brief Internal state for the Duplex key exchange (server-side).
 *
 * \details
 * This structure holds the state information required by a server participating in a Duplex key exchange.
 * It contains cryptographic parameters including key identities, session hashes, asymmetric keys, and an expiration
 * timestamp. In addition, it includes a callback function (\c key_query) that is used to retrieve the appropriate
 * public key during the key exchange process.
 */
typedef struct qsmd_kex_duplex_server_state
{
	uint8_t keyid[QSMD_KEYID_SIZE];							/*!< The key identity string */
	uint8_t schash[QSMD_HASH_SIZE];				/*!< The session token hash */
	uint8_t prikey[QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE];		/*!< The asymmetric cipher private key */
	uint8_t pubkey[QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE];		/*!< The asymmetric cipher public key */
	uint8_t rverkey[QSMD_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The remote asymmetric signature verification-key */
	uint8_t sigkey[QSMD_ASYMMETRIC_SIGNING_KEY_SIZE];		/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSMD_ASYMMETRIC_VERIFY_KEY_SIZE];		/*!< The local asymmetric signature verification-key */
	uint64_t expiration;									/*!< The expiration time, in seconds from epoch */
	bool (*key_query)(uint8_t*, const uint8_t*);			/*!< The key query callback */
} qsmd_kex_duplex_server_state;

/**
 * \brief Execute the server-side Duplex key exchange.
 *
 * \details
 * This function processes an incoming Duplex key exchange request on the server side.
 * It uses the server key exchange state (\c qsmd_kex_duplex_server_state) to verify client credentials,
 * exchange the necessary asymmetric keys, and update the QSMD connection state accordingly.
 *
 * \param kss A pointer to the duplex server key exchange state structure.
 * \param cns A pointer to the current QSMD connection state.
 *
 * \return Returns a value of type \c qsmd_errors indicating the outcome of the key exchange process.
 *
 * \note This is an internal non-exportable API.
 */
qsmd_errors qsmd_kex_duplex_server_key_exchange(qsmd_kex_duplex_server_state* kss, qsmd_connection_state* cns);

/**
 * \brief Execute the client-side Duplex key exchange.
 *
 * \details
 * This function initiates and completes the Duplex key exchange from the client side.
 * It processes the server's response, computes the shared secret, and updates the QSMD connection state
 * with the derived cryptographic parameters.
 *
 * \param kcs A pointer to the duplex client key exchange state structure.
 * \param cns A pointer to the current QSMD connection state.
 *
 * \return Returns a value of type \c qsmd_errors representing the result of the key exchange operation.
 *
 * \note This is an internal non-exportable API.
 */
qsmd_errors qsmd_kex_duplex_client_key_exchange(qsmd_kex_duplex_client_state* kcs, qsmd_connection_state* cns);

#if defined(QSMD_KEX_TEST_ENABLED)
/**
 * \brief Run internal tests for the key exchange functions.
 *
 * \details
 * This function executes a suite of internal tests designed to validate the correct operation of the QSMD
 * key exchange mechanisms. The tests include:
 *
 * - Verifying the proper initialization and management of state structures for both Duplex and Simplex modes.
 * - Testing the cryptographic operations involved in key generation, shared secret derivation, and session token hashing.
 * - Ensuring that the key exchange functions correctly update the QSMD connection state.
 *
 * The function returns true if all internal tests pass, confirming the reliability and correctness of the key exchange implementation.
 *
 * \return Returns true if the key exchange tests succeed; otherwise, false.
 *
 * \note This is an internal non-exportable API.
 */
bool qsmd_kex_test(void);
#endif

#endif
