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

#ifndef QSMD_H
#define QSMD_H

#include "qsmdcommon.h"
#include "async.h"
#include "rcs.h"
#include "sha3.h"

/**
* \file qsmp.h
* \brief QSMD support header
* Common defined parameters and functions of the qsmp client and server implementations.
* 
* Note:
* These definitions determine the asymmetric protocol set used by QSMD.
* The individual parameter sets for each cipher and signature scheme,
* can be configured in the QSC libraries common.h file.
* For maximum security, I recommend the McElice/SPHINCS+ set.
* For a balance of performance and security, the Dilithium/Kyber,
* or Dilithium/McEliece sets are recommended.
* 
* Parameter Sets:
* Kyber-S1, Dilithium-S1
* Kyber-S3, Dilithium-S3
* Kyber-S5, Dilithium-S5
* Kyber-S6, Dilithium-S5
* McEliece-S1, Dilithium-S1
* McEliece-S3, Dilithium-S3
* McEliece-S5, Dilithium-S5
* McEliece-S6, Dilithium-S5
* McEliece-S7, Dilithium-S5
* McEliece-S1, Sphincs-S1(f,s)
* McEliece-S3, Sphincs-S3(f,s)
* McEliece-S5, Sphincs-S5(f,s)
* McEliece-S6, Sphincs-S5(f,s)
* McEliece-S7, Sphincs-S6(f,s)
* 
* Recommended:
* Kyber-S5, Dilithium-S5
* Kyber-S6, Dilithium-S5
* McEliece-S5, Dilithium-S5
* McEliece-S5, Sphincs-S5(f,s)
* 
* The parameter sets used by QSMD are selected in the QSC library in the 
* libraries common.h file. Settings are at library defaults, however, a true 512-bit
* security system can be acheived by selecting the McEliece/SPHINCS+ parameter in QSMD
* and setting SPHINCS+ to one of the 512-bit options in the QSC library.
*/

/*!
* \def QSMD_CONFIG_DILITHIUM_KYBER
* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/Kyber.
*/
#define QSMD_CONFIG_DILITHIUM_KYBER

///*!
//* \def QSMD_CONFIG_DILITHIUM_MCELIECE
//* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/McEliece.
//*/
//#define QSMD_CONFIG_DILITHIUM_MCELIECE

///*!
//* \def QSMD_CONFIG_SPHINCS_MCELIECE
//* \brief Sets the asymmetric cryptographic primitive-set to Sphincs+/McEliece.
//*/
//#define QSMD_CONFIG_SPHINCS_MCELIECE

/** \cond DOXYGEN_NO_DOCUMENT */
#if (!defined(QSMD_CONFIG_DILITHIUM_KYBER) && !defined(QSMD_CONFIG_DILITHIUM_MCELIECE) && !defined(QSMD_CONFIG_SPHINCS_MCELIECE))
#	define QSMD_CONFIG_DILITHIUM_KYBER
#endif
/** \endcond DOXYGEN_NO_DOCUMENT */

#include "qsmdcommon.h"
#include "socketbase.h"

#if defined(QSMD_CONFIG_DILITHIUM_KYBER)
#	include "dilithium.h"
#	include "kyber.h"
#elif defined(QSMD_CONFIG_DILITHIUM_MCELIECE)
#	include "dilithium.h"
#	include "mceliece.h"
#elif defined(QSMD_CONFIG_SPHINCS_MCELIECE)
#	include "sphincsplus.h"
#	include "mceliece.h"
#else
#	error Invalid parameter set!
#endif

/*!
* \def QSMD_ASYMMETRIC_RATCHET
* \brief Enable the asymmetric ratchet option
*/
#define QSMD_ASYMMETRIC_RATCHET

/*!
* \def QSMD_CONFIG_SIZE
* \brief The size of the protocol configuration string
*/
#define QSMD_CONFIG_SIZE 48U

/*!
* \def QSMD_HASH_SIZE
* \brief The Duplex 512-bit hash function size
*/
#define QSMD_HASH_SIZE 64U

/*!
* \def QSMD_MACKEY_SIZE
* \brief The Duplex 512-bit mac key size
*/
#define QSMD_MACKEY_SIZE 64U

/*!
* \def QSMD_MACTAG_SIZE
* \brief The Duplex 512-bit mac key size
*/
#define QSMD_MACTAG_SIZE 64U

/*!
* \def QSMD_NONCE_SIZE
* \brief The size of the symmetric cipher nonce
*/
#define QSMD_NONCE_SIZE 32U

/*!
* \def QSMD_SYMMETRIC_KEY_SIZE
* \brief TheDuplex  512-bit symmetric cipher key size
*/
#define QSMD_SYMMETRIC_KEY_SIZE 64U

/*!
* \def QSMD_ASYMMETRIC_SECRET_SIZE
* \brief The Simplex 256-bit symmetric cipher key size
*/
#define QSMD_ASYMMETRIC_SECRET_SIZE 32U

/*!
* \def QSMD_CLIENT_PORT
* \brief The default client port address
*/
#define QSMD_CLIENT_PORT 30118U

/*!
 * \def QSMD_CONNECTIONS_MAX
 * \brief The maximum number of QSMD connections.
 * \details This is a modifiable constant: set to the desired number of maximum connections.
 *
 * \details Modifiable constant: calculated given approx 5k
 * (3480 connection state + 1500 mtu + overhead), per connection on 256GB of DRAM.
 * Can be scaled to a greater number provided the hardware can support it.
 */
#define QSMD_CONNECTIONS_MAX 100U

/*!
* \def QSMD_CONNECTION_MTU
* \brief The QSMD packet buffer size
*/
#define QSMD_CONNECTION_MTU 1500U

/*!
* \def QSMD_ERROR_SEQUENCE
* \brief The packet error sequence number
*/
#define QSMD_ERROR_SEQUENCE 0xFF00000000000000ULL

/*!
* \def QSMD_ERROR_MESSAGE_SIZE
* \brief The packet error message size
*/
#define QSMD_ERROR_MESSAGE_SIZE 1U

/*!
* \def QSMD_FLAG_SIZE
* \brief The packet flag size
*/
#define QSMD_FLAG_SIZE 1U

/*!
* \def QSMD_HEADER_SIZE
* \brief The QSMD packet header size
*/
#define QSMD_HEADER_SIZE 21U

/*!
* \def QSMD_KEYID_SIZE
* \brief The QSMD key identity size
*/
#define QSMD_KEYID_SIZE 16U

/*!
* \def QSMD_MSGLEN_SIZE
* \brief The size of the packet message length
*/
#define QSMD_MSGLEN_SIZE 4U

/*!
* \def QSMD_NETWORK_MTU_SIZE
* \brief The size of the packet MTU length
*/
#define QSMD_NETWORK_MTU_SIZE 1500U

/*!
* \def QSMD_RTOK_SIZE
* \brief The size of the ratchet token
*/
#define QSMD_RTOK_SIZE 32U

/*!
* \def QSMD_SERVER_PORT
* \brief The default server port address
*/
#define QSMD_SERVER_PORT 30119U

/*!
* \def QSMD_PACKET_TIME_THRESHOLD
* \brief The maximum number of seconds a packet is valid
* Note: On interior networks with a shared (NTP) time source, this could be set at 1 second,
* depending on network and device traffic conditions. For exterior networks, this time needs to
* be adjusted to account for clock-time differences, between 30-100 seconds.
*/
#define QSMD_PACKET_TIME_THRESHOLD 60U

/*!
* \def QSMD_POLLING_INTERVAL
* \brief The polling interval in milliseconds (2 minutes)
*/
#define QSMD_POLLING_INTERVAL (120U * 1000U)

/*!
* \def QSMD_PUBKEY_DURATION_DAYS
* \brief The number of days a public key remains valid
*/
#define QSMD_PUBKEY_DURATION_DAYS 365U

/*!
* \def QSMD_PUBKEY_DURATION_SECONDS
* \brief The number of seconds a public key remains valid
*/
#define QSMD_PUBKEY_DURATION_SECONDS (QSMD_PUBKEY_DURATION_DAYS * 24U * 60U * 60U)

/*!
* \def QSMD_PUBKEY_LINE_LENGTH
* \brief The line length of the printed QSMD public key
*/
#define QSMD_PUBKEY_LINE_LENGTH 64U

/*!
* \def QSMD_SECRET_SIZE
* \brief The size of the shared secret for each channel
*/
#define QSMD_SECRET_SIZE 32U

/*!
* \def QSMD_SEQUENCE_SIZE
* \brief The size of the packet sequence number
*/
#define QSMD_SEQUENCE_SIZE 8U

/*!
* \def QSMD_SEQUENCE_TERMINATOR
* \brief The sequence number of a packet that closes a connection
*/
#define QSMD_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
* \def QSMD_SRVID_SIZE
* \brief The QSMD server identity size
*/
#define QSMD_SRVID_SIZE 8U

/*!
* \def QSMD_STOKEN_SIZE
* \brief The session token size
*/
#define QSMD_STOKEN_SIZE 64U

/*!
* \def QSMD_TIMESTAMP_SIZE
* \brief The key expiration timestamp size
*/
#define QSMD_TIMESTAMP_SIZE 8U

/*!
* \def QSMD_TIMESTAMP_STRING_SIZE
* \brief The key expiration timestamp string size
*/
#define QSMD_TIMESTAMP_STRING_SIZE 20U

/*!
* \def QSMD_MESSAGE_MAX
* \brief The maximum message size used during the key exchange (1 GB)
*/
#define QSMD_MESSAGE_MAX 0x10000UL

/** \cond DOXYGEN_NO_DOCUMENT */
extern const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE];
/** \endcond DOXYGEN_NO_DOCUMENT */

#if defined(QSMD_CONFIG_DILITHIUM_KYBER)

	/*!
	 * \def qsmd_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define qsmd_cipher_generate_keypair qsc_kyber_generate_keypair
	/*!
	 * \def qsmd_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmd_cipher_decapsulate qsc_kyber_decapsulate
	/*!
	 * \def qsmd_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmd_cipher_encapsulate qsc_kyber_encapsulate
	/*!
	 * \def qsmd_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define qsmd_signature_generate_keypair qsc_dilithium_generate_keypair
	/*!
	 * \def qsmd_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define qsmd_signature_sign qsc_dilithium_sign
	/*!
	 * \def qsmd_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define qsmd_signature_verify qsc_dilithium_verify

/*!
* \def QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)

/*!
* \def QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMD_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMD_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMD_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

#elif defined(QSMD_CONFIG_DILITHIUM_MCELIECE)
	/*!
	 * \def qsmd_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define qsmd_cipher_generate_keypair qsc_mceliece_generate_keypair
	/*!
	 * \def qsmd_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmd_cipher_decapsulate qsc_mceliece_decapsulate
	/*!
	 * \def qsmd_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmd_cipher_encapsulate qsc_mceliece_encapsulate
	/*!
	 * \def qsmd_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define qsmd_signature_generate_keypair qsc_dilithium_generate_keypair
	/*!
	 * \def qsmd_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define qsmd_signature_sign qsc_dilithium_sign
	/*!
	 * \def qsmd_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define qsmd_signature_verify qsc_dilithium_verify

/*!
* \def QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array
*/
#	define QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMD_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMD_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMD_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

#elif defined(QSMD_CONFIG_SPHINCS_MCELIECE)

	/*!
	 * \def qsmd_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair
	 */
#	define qsmd_cipher_generate_keypair qsc_mceliece_generate_keypair
	/*!
	 * \def qsmd_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmd_cipher_decapsulate qsc_mceliece_decapsulate
	/*!
	 * \def qsmd_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the asymmetric cipher
	 */
#	define qsmd_cipher_encapsulate qsc_mceliece_encapsulate
	/*!
	 * \def qsmd_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair
	 */
#	define qsmd_signature_generate_keypair qsc_sphincsplus_generate_keypair
	/*!
	 * \def qsmd_signature_sign
	 * \brief Sign a message with the asymmetric signature scheme
	 */
#	define qsmd_signature_sign qsc_sphincsplus_sign
	/*!
	 * \def qsmd_signature_verify
	 * \brief Verify a message with the asymmetric signature scheme
	 */
#	define qsmd_signature_verify qsc_sphincsplus_verify

/*!
* \def QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array
*/
#	define QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array
*/
#	define QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array
*/
#	define QSMD_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_VERIFY_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array
*/
#	define QSMD_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)

/*!
* \def QSMD_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array
*/
#	define QSMD_ASYMMETRIC_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)

#else
#	error invalid parameter set!
#endif

/* public key encoding constants */

/*!
* \def QSMD_SIGKEY_ENCODED_SIZE
* \brief The secret signature key size
*/
#define QSMD_SIGKEY_ENCODED_SIZE (QSMD_KEYID_SIZE + QSMD_TIMESTAMP_SIZE + QSMD_CONFIG_SIZE + QSMD_ASYMMETRIC_SIGNING_KEY_SIZE + QSMD_ASYMMETRIC_VERIFY_KEY_SIZE)

/*!
* \def QSMD_PUBKEY_HEADER_SIZE
* \brief The size of the QSMD public key header
*/
#define QSMD_PUBKEY_HEADER_SIZE 40U

/*!
* \def QSMD_PUBKEY_VERSION_SIZE
* \brief The size of the QSMD public key version string
*/
#define QSMD_PUBKEY_VERSION_SIZE 19U

/*!
* \def QSMD_PUBKEY_CONFIG_SIZE
* \brief The size of the QSMD public key configuration prefix
*/
#define QSMD_PUBKEY_CONFIG_SIZE 16

/*!
* \def QSMD_PUBKEY_KEYID_SIZE
* \brief The size of the QSMD public key identifier prefix
*/
#define QSMD_PUBKEY_KEYID_SIZE 10U

/*!
* \def QSMD_PUBKEY_EXPIRATION_SIZE
* \brief The size of the QSMD public key expiration prefix
*/
#define QSMD_PUBKEY_EXPIRATION_SIZE 13U

/*!
* \def QSMD_PUBKEY_FOOTER_SIZE
* \brief The size of the QSMD public key footer
*/
#define QSMD_PUBKEY_FOOTER_SIZE 38U

/*!
* \var QSMD_PUBKEY_HEADER
* \brief The QSMD public key header string
*/
static const char QSMD_PUBKEY_HEADER[QSMD_PUBKEY_HEADER_SIZE] = "------BEGIN QSMD PUBLIC KEY BLOCK------";

/*!
* \var QSMD_PUBKEY_VERSION
* \brief The QSMD public key version string
*/
static const char QSMD_PUBKEY_VERSION[QSMD_PUBKEY_VERSION_SIZE] = "Version: QSMD v1.2";

/*!
* \var QSMD_PUBKEY_CONFIG_PREFIX
* \brief The QSMD public key configuration prefix string
*/
static const char QSMD_PUBKEY_CONFIG_PREFIX[QSMD_PUBKEY_CONFIG_SIZE] = "Configuration: ";

/*!
* \var QSMD_PUBKEY_KEYID_PREFIX
* \brief The QSMD public key keyid prefix string
*/
static const char QSMD_PUBKEY_KEYID_PREFIX[QSMD_PUBKEY_KEYID_SIZE] = "Host ID: ";

/*!
* \var QSMD_PUBKEY_EXPIRATION_PREFIX
* \brief The QSMD public key expiration prefix string
*/
static const char QSMD_PUBKEY_EXPIRATION_PREFIX[QSMD_PUBKEY_EXPIRATION_SIZE] = "Expiration: ";

/*!
* \var QSMD_PUBKEY_FOOTER
* \brief The QSMD public key footer string
*/
static const char QSMD_PUBKEY_FOOTER[QSMD_PUBKEY_FOOTER_SIZE] = "------END QSMD PUBLIC KEY BLOCK------";

/* error code strings */

/*!
* \def QSMD_ERROR_STRING_DEPTH
* \brief The depth of the QSMD error string array
*/
#define QSMD_ERROR_STRING_DEPTH 27U

/*!
* \def QSMD_ERROR_STRING_WIDTH
* \brief The width of each QSMD error string
*/
#define QSMD_ERROR_STRING_WIDTH 128U

/** \cond DOXYGEN_NO_DOCUMENT */
extern const char QSMD_ERROR_STRINGS[QSMD_ERROR_STRING_DEPTH][QSMD_ERROR_STRING_WIDTH];
/** \endcond DOXYGEN_NO_DOCUMENT */

/*!
* \def QSMD_MESSAGE_STRING_DEPTH
* \brief The depth of the QSMD message string array
*/
#define QSMD_MESSAGE_STRING_DEPTH 21U

/*!
* \def QSMD_MESSAGE_STRING_WIDTH
* \brief The width of each QSMD message string
*/
#define QSMD_MESSAGE_STRING_WIDTH 128U

/** \cond DOXYGEN_NO_DOCUMENT 
extern const char QSMD_MESSAGE_STRINGS[QSMD_MESSAGE_STRING_DEPTH][QSMD_MESSAGE_STRING_WIDTH];
/** \endcond DOXYGEN_NO_DOCUMENT */

/*!
* \enum qsmd_configuration
* \brief The asymmetric cryptographic primitive configuration
*/
QSMD_EXPORT_API typedef enum qsmd_configuration
{
	qsmd_configuration_none = 0x00U,				/*!< No configuration was specified */
	qsmd_configuration_sphincs_mceliece = 0x01U,	/*!< The Sphincs+ and McEliece configuration */
	qsmd_configuration_dilithium_kyber = 0x02U,		/*!< The Dilithium and Kyber configuration */
	qsmd_configuration_dilithium_mceliece = 0x03U,	/*!< The Dilithium and Kyber configuration */
	qsmd_configuration_dilithium_ntru = 0x04U,		/*!< The Dilithium and NTRU configuration */
	qsmd_configuration_falcon_kyber = 0x05U,		/*!< The Falcon and Kyber configuration */
	qsmd_configuration_falcon_mceliece = 0x06U,		/*!< The Falcon and McEliece configuration */
	qsmd_configuration_falcon_ntru = 0x07U,			/*!< The Falcon and NTRU configuration */
} qsmd_configuration;

/*!
* \enum qsmd_messages
* \brief The logging message enumeration
*/
QSMD_EXPORT_API typedef enum qsmd_messages
{
	qsmd_messages_none = 0x00U,						/*!< No configuration was specified */
	qsmd_messages_accept_fail = 0x01U,				/*!< The socket accept failed */
	qsmd_messages_listen_fail = 0x02U,				/*!< The listener socket could not connect */
	qsmd_messages_bind_fail = 0x03U,				/*!< The listener socket could not bind to the address */
	qsmd_messages_create_fail = 0x04U,				/*!< The listener socket could not be created */
	qsmd_messages_connect_success = 0x05U,			/*!< The server connected to a host */
	qsmd_messages_receive_fail = 0x06U,				/*!< The socket receive function failed */
	qsmd_messages_allocate_fail = 0x07U,			/*!< The server memory allocation request has failed */
	qsmd_messages_kex_fail = 0x08U,					/*!< The key exchange has experienced a failure */
	qsmd_messages_disconnect = 0x09U,				/*!< The server has disconnected the client */
	qsmd_messages_disconnect_fail = 0x0AU,			/*!< The server has disconnected the client due to an error */
	qsmd_messages_socket_message = 0x0BU,			/*!< The server has had a socket level error */
	qsmd_messages_queue_empty = 0x0CU,				/*!< The server has reached the maximum number of connections */
	qsmd_messages_listener_fail = 0x0DU,			/*!< The server listener socket has failed */
	qsmd_messages_sockalloc_fail = 0x0EU,			/*!< The server has run out of socket connections */
	qsmd_messages_decryption_fail = 0x0FU,			/*!< The message decryption has failed */
	qsmd_messages_connection_fail = 0x10U,			/*!< The connection failed or was interrupted */
	qsmd_messages_invalid_request = 0x11U,			/*!< The function received an invalid request */
	qsmd_messages_asymmetric_ratchet = 0x12U,		/*!< The host received an asymmetric ratchet request */
	qsmd_messages_symmetric_ratchet = 0x13U,		/*!< The host received a symmetric ratchet request */
	qsmd_messages_ratchet_failure = 0x14U,			/*!< The host received an invalid ratchet request */
} qsmd_messages;

/*!
* \enum qsmd_errors
* \brief The QSMD error values
*/
QSMD_EXPORT_API typedef enum qsmd_errors
{
	qsmd_error_none = 0x00U,						/*!< No error was detected */
	qsmd_error_accept_fail = 0x01U,					/*!< The socket accept function returned an error */
	qsmd_error_authentication_failure = 0x02U,		/*!< The symmetric cipher had an authentication failure */
	qsmd_error_channel_down = 0x03U,				/*!< The communications channel has failed */
	qsmd_error_connection_failure = 0x04U,			/*!< The device could not make a connection to the remote host */
	qsmd_error_connect_failure = 0x05U,				/*!< The transmission failed at the KEX connection phase */
	qsmd_error_decapsulation_failure = 0x06U,		/*!< The asymmetric cipher failed to decapsulate the shared secret */
	qsmd_error_decryption_failure = 0x07U,			/*!< The decryption authentication has failed */
	qsmd_error_establish_failure = 0x08U,			/*!< The transmission failed at the KEX establish phase */
	qsmd_error_exchange_failure = 0x09U,			/*!< The transmission failed at the KEX exchange phase */
	qsmd_error_hash_invalid = 0x0AU,				/*!< The public-key hash is invalid */
	qsmd_error_hosts_exceeded = 0x0BU,				/*!< The server has run out of socket connections */
	qsmd_error_invalid_input = 0x0CU,				/*!< The expected input was invalid */
	qsmd_error_invalid_request = 0x0DU,				/*!< The packet flag was unexpected */
	qsmd_error_key_expired = 0x0EU,					/*!< The QSMD public key has expired  */
	qsmd_error_key_unrecognized = 0x0FU,			/*!< The key identity is unrecognized */
	qsmd_error_keychain_fail = 0x10U,				/*!< The ratchet operation has failed */
	qsmd_error_listener_fail = 0x11U,				/*!< The listener function failed to initialize */
	qsmd_error_memory_allocation = 0x12U,			/*!< The server has run out of memory */
	qsmd_error_message_time_invalid = 0x13U,		/*!< The packet has valid time expired */
	qsmd_error_packet_unsequenced = 0x14U,			/*!< The packet was received out of sequence */
	qsmd_error_random_failure = 0x15U,				/*!< The random generator has failed */
	qsmd_error_receive_failure = 0x16U,				/*!< The receiver failed at the network layer */
	qsmd_error_transmit_failure = 0x17U,			/*!< The transmitter failed at the network layer */
	qsmd_error_unknown_protocol = 0x18U,			/*!< The protocol string was not recognized */
	qsmd_error_verify_failure = 0x19U,				/*!< The expected data could not be verified */
	qsmd_messages_system_message = 0x1AU,			/*!< The remote host sent an error or disconnect message */
} qsmd_errors;

/*!
* \enum qsmd_flags
* \brief The QSMD packet flags
*/
QSMD_EXPORT_API typedef enum qsmd_flags
{
	qsmd_flag_none = 0x00U,							/*!< No flag was specified */
	qsmd_flag_connect_request = 0x01U,				/*!< The QSMD key-exchange client connection request flag  */
	qsmd_flag_connect_response = 0x02U,				/*!< The QSMD key-exchange server connection response flag */
	qsmd_flag_connection_terminate = 0x03U,			/*!< The connection is to be terminated */
	qsmd_flag_encrypted_message = 0x04U,			/*!< The message has been encrypted flag */
	qsmd_flag_exstart_request = 0x05U,				/*!< The QSMD key-exchange client exstart request flag */
	qsmd_flag_exstart_response = 0x06U,				/*!< The QSMD key-exchange server exstart response flag */
	qsmd_flag_exchange_request = 0x07U,				/*!< The QSMD key-exchange client exchange request flag */
	qsmd_flag_exchange_response = 0x08U,			/*!< The QSMD key-exchange server exchange response flag */
	qsmd_flag_establish_request = 0x09U,			/*!< The QSMD key-exchange client establish request flag */
	qsmd_flag_establish_response = 0x0AU,			/*!< The QSMD key-exchange server establish response flag */
	qsmd_flag_remote_connected = 0x0BU,				/*!< The remote host is connected flag */
	qsmd_flag_remote_terminated = 0x0CU,			/*!< The remote host has terminated the connection */
	qsmd_flag_session_established = 0x0DU,			/*!< The exchange is in the established state */
	qsmd_flag_session_establish_verify = 0x0EU,		/*!< The exchange is in the established verify state */
	qsmd_flag_unrecognized_protocol = 0x0FU,		/*!< The protocol string is not recognized */
	qsmd_flag_asymmetric_ratchet_request = 0x10U,	/*!< The host has received a asymmetric key ratchet request */
	qsmd_flag_asymmetric_ratchet_response = 0x11U,	/*!< The host has received a asymmetric key ratchet request */
	qsmd_flag_symmetric_ratchet_request = 0x12U,	/*!< The host has received a symmetric key ratchet request */
	qsmd_flag_transfer_request = 0x13U,				/*!< Reserved - The host has received a transfer request */
	qsmd_flag_general_error_condition = 0x14U,				/*!< The connection experienced an error */
} qsmd_flags;

/*!
* \struct qsmd_network_packet
* \brief The QSMD packet structure
*/
QSMD_EXPORT_API typedef struct qsmd_network_packet
{
	uint8_t flag;									/*!< The packet flag */
	uint32_t msglen;								/*!< The packets message length */
	uint64_t sequence;								/*!< The packet sequence number */
	uint64_t utctime;								/*!< The UTC time the packet was created in seconds */
	uint8_t* pmessage;								/*!< A pointer to the packets message buffer */
} qsmd_network_packet;

/*!
* \struct qsmd_client_verification_key
* \brief The QSMD client key structure
*/
QSMD_EXPORT_API typedef struct qsmd_client_verification_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSMD_CONFIG_SIZE];				/*!< The primitive configuration string */
	uint8_t keyid[QSMD_KEYID_SIZE];					/*!< The key identity string */
	uint8_t verkey[QSMD_ASYMMETRIC_VERIFY_KEY_SIZE];/*!< The asymmetric signatures verification-key */
} qsmd_client_verification_key;

/*!
* \struct qsmd_server_signature_key
* \brief The QSMD server key structure
*/
QSMD_EXPORT_API typedef struct qsmd_server_signature_key
{
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint8_t config[QSMD_CONFIG_SIZE];				/*!< The primitive configuration string */
	uint8_t keyid[QSMD_KEYID_SIZE];					/*!< The key identity string */
	uint8_t sigkey[QSMD_ASYMMETRIC_SIGNING_KEY_SIZE];/*!< The asymmetric signature signing-key */
	uint8_t verkey[QSMD_ASYMMETRIC_VERIFY_KEY_SIZE]; /*!< The asymmetric signature verification-key */
} qsmd_server_signature_key;

/*!
* \struct qsmd_connection_state
* \brief The QSMD socket connection state structure
*/
QSMD_EXPORT_API typedef struct qsmd_connection_state
{
	qsc_socket target;								/*!< The target socket structure */
	qsc_rcs_state rxcpr;							/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;							/*!< The transmit channel cipher state */
	uint64_t rxseq;									/*!< The receive channels packet sequence number  */
	uint64_t txseq;									/*!< The transmit channels packet sequence number  */
	uint32_t cid;									/*!< The connections instance count */
	qsmd_flags exflag;								/*!< The KEX position flag */
	bool receiver;									/*!< The instance was initialized in listener mode */
#if defined(QSMD_ASYMMETRIC_RATCHET)
	uint8_t deckey[QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE]; /*!< The decasulation key storage */
	uint8_t enckey[QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE]; /*!< The encasulation key storage */
	uint8_t sigkey[QSMD_ASYMMETRIC_SIGNING_KEY_SIZE]; /*!< The local signing key */
	uint8_t verkey[QSMD_ASYMMETRIC_VERIFY_KEY_SIZE];  /*!< The remote signature verification key */
	qsc_mutex txlock;								/*!< The transmit channel lock */
	uint8_t rtcs[QSMD_ASYMMETRIC_SECRET_SIZE];		/*!< The symmetric ratchet key */
#endif
} qsmd_connection_state;

/*!
* \brief Close the network connection between hosts
*
* \param cns: A pointer to the connection state structure
* \param err: The error message
* \param notify: Notify the remote host connection is closing
*/
QSMD_EXPORT_API void qsmd_connection_close(qsmd_connection_state* cns, qsmd_errors err, bool notify);

/*!
 * \brief Decrypt an error message.
 *
 * \param cns A pointer to the QSMD connection state structure.
 * \param message [const] The serialized error packet.
 * \param merr A pointer to an \c qsmd_errors error value.
 *
 * \return Returns true if the message was decrypted successfully, false on failure.
 */
QSMD_EXPORT_API bool qsmd_decrypt_error_message(qsmd_errors* merr, qsmd_connection_state* cns, const uint8_t* message);

/*!
* \brief Reset the connection state
*
* \param cns: A pointer to the connection state structure
*/
QSMD_EXPORT_API void qsmd_connection_state_dispose(qsmd_connection_state* cns);

/*!
* \brief Return a pointer to a string description of an error code
*
* \param error: The error type
* 
* \return Returns a pointer to an error string or NULL
*/
QSMD_EXPORT_API const char* qsmd_error_to_string(qsmd_errors error);

/*!
* \brief Populate a packet header and set the creation time
*
* \param packetout: A pointer to the output packet structure
* \param flag: The packet flag
* \param sequence: The packet sequence number
* \param msglen: The length of the message array
*/
QSMD_EXPORT_API void qsmd_header_create(qsmd_network_packet* packetout, qsmd_flags flag, uint64_t sequence, uint32_t msglen);

/*!
* \brief Validate a packet header and timestamp
*
* \param cns: A pointer to the connection state structure
* \param packetin: A pointer to the input packet structure
* \param kexflag: The packet flag
* \param pktflag: The packet flag
* \param sequence: The packet sequence number
* \param msglen: The length of the message array
*
* \return: Returns the function error state
*/
QSMD_EXPORT_API qsmd_errors qsmd_header_validate(qsmd_connection_state* cns, const qsmd_network_packet* packetin, qsmd_flags kexflag, qsmd_flags pktflag, uint64_t sequence, uint32_t msglen);

/*!
* \brief Generate a QSMD key-pair; generates the public and private asymmetric signature keys.
*
* \param pubkey: The public key, distributed to clients
* \param prikey: The private key, a secret key known only by the server
* \param keyid: [const] The key identity string
*/
QSMD_EXPORT_API void qsmd_generate_keypair(qsmd_client_verification_key* pubkey, qsmd_server_signature_key* prikey, const uint8_t* keyid);

/*!
* \brief Get the error string description
*
* \param emsg: The message enumeration
* 
* \return Returns a pointer to the message string or NULL
*/
QSMD_EXPORT_API const char* qsmd_get_error_description(qsmd_messages emsg);

/*!
* \brief Log the message, socket error, and string description
*
* \param emsg: The message enumeration
* \param err: The socket exception enumeration
* \param msg: [const] The message string
*/
QSMD_EXPORT_API void qsmd_log_error(qsmd_messages emsg, qsc_socket_exceptions err, const char* msg);

/*!
* \brief Log a message
*
* \param emsg: The message enumeration
*/
QSMD_EXPORT_API void qsmd_log_message(qsmd_messages emsg);

/*!
* \brief Log a system error message
*
* \param err: The system error enumerator
*/
QSMD_EXPORT_API void qsmd_log_system_error(qsmd_errors err);

/*!
* \brief Log a message and description
*
* \param emsg: The message enumeration
* \param msg: [const] The message string
*/
QSMD_EXPORT_API void qsmd_log_write(qsmd_messages emsg, const char* msg);

/*!
* \brief Clear a packet's state
*
* \param packet: A pointer to the packet structure
*/
QSMD_EXPORT_API void qsmd_packet_clear(qsmd_network_packet* packet);

/*!
* \brief Decrypt a message and copy it to the message output
*
* \param cns: A pointer to the connection state structure
* \param message: The message output array
* \param msglen: A pointer receiving the message length
* \param packetin: [const] A pointer to the input packet structure
*
* \return: Returns the function error state
*/
QSMD_EXPORT_API qsmd_errors qsmd_packet_decrypt(qsmd_connection_state* cns, uint8_t* message, size_t* msglen, const qsmd_network_packet* packetin);

/*!
* \brief Encrypt a message and build an output packet
*
* \param cns: A pointer to the connection state structure
* \param packetout: A pointer to the output packet structure
* \param message: [const] The input message array
* \param msglen: The length of the message array
*
* \return: Returns the function error state
*/
QSMD_EXPORT_API qsmd_errors qsmd_packet_encrypt(qsmd_connection_state* cns, qsmd_network_packet* packetout, const uint8_t* message, size_t msglen);

/*!
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
QSMD_EXPORT_API void qsmd_packet_error_message(qsmd_network_packet* packet, qsmd_errors error);

/*!
* \brief Deserialize a byte array to a packet header
*
* \param packet: [const] The header byte array to deserialize
* \param header: A pointer to the packet structure
*/
QSMD_EXPORT_API void qsmd_packet_header_deserialize(const uint8_t* header, qsmd_network_packet* packet);

/*!
* \brief Serialize a packet header to a byte array
*
* \param packet: [const] A pointer to the packet structure to serialize
* \param header: The header byte array
*/
QSMD_EXPORT_API void qsmd_packet_header_serialize(const qsmd_network_packet* packet, uint8_t* header);

/*!
* \brief Sets the local UTC seconds time in the packet header
*
* \param packet: A pointer to a network packet
*/
QSMD_EXPORT_API void qsmd_packet_set_utc_time(qsmd_network_packet* packet);

/*!
* \brief Checks the local UTC seconds time against the packet sent time for validity within the packet time threshold
*
* \param packet: [const] A pointer to a network packet
*
* \return Returns true if the packet was received within the valid-time threhold
*/
QSMD_EXPORT_API bool qsmd_packet_time_valid(const qsmd_network_packet* packet);

/*!
* \brief Serialize a packet to a byte array
*
* \param packet: [const] The header byte array to deserialize
* \param pstream: A pointer to the packet structure
* 
* \return Returns the size of the byte stream
*/
QSMD_EXPORT_API size_t qsmd_packet_to_stream(const qsmd_network_packet* packet, uint8_t* pstream);

/*!
* \brief Compares two public keys for equality
*
* \param a: [const] The first public key
* \param b: [const] The second public key
*
* \return Returns true if the certificates are identical
*/
QSMD_EXPORT_API bool qsmd_public_key_compare(const qsmd_client_verification_key* a, const qsmd_client_verification_key* b);

/*!
* \brief Decode a public key string and populate a client key structure
*
* \param pubk: A pointer to the output client key
* \param enck: [const] The input encoded key
*
* \return: Returns true for success
*/
QSMD_EXPORT_API bool qsmd_public_key_decode(qsmd_client_verification_key* pubk, const char* enck, size_t enclen);

/*!
* \brief Encode a public key structure and copy to a string
*
* \param enck: The output encoded public key string
* \param enclen: The length of the encoding array
* \param pubk: [const] A pointer to the public key structure
*
* \return: Returns the encoded string length
*/
QSMD_EXPORT_API size_t qsmd_public_key_encode(char* enck, size_t enclen, const qsmd_client_verification_key* pubk);

/*!
* \brief Get the key encoding string size
*
* \return Returns the size of the encoded string
*/
QSMD_EXPORT_API size_t qsmd_public_key_encoding_size(void);

/*!
* \brief Decode a secret signature key structure and copy to an array
*
* \param kset: A pointer to the output server key structure
* \param serk: [const] The input encoded secret key string
*/
QSMD_EXPORT_API void qsmd_signature_key_deserialize(qsmd_server_signature_key* kset, const uint8_t* serk);

/*!
* \brief Encode a secret key structure and copy to a string
*
* \param serk: The output encoded public key string
* \param kset: [const] A pointer to the secret server key structure
*/
QSMD_EXPORT_API void qsmd_signature_key_serialize(uint8_t* serk, const qsmd_server_signature_key* kset);

/*!
* \brief Deserialize a byte array to a packet
*
* \param pstream: [const] The header byte array to deserialize
* \param packet: A pointer to the packet structure
* 
* \return Returns true on a valid stream, false otherwise
*/
QSMD_EXPORT_API bool qsmd_stream_to_packet(const uint8_t* pstream, qsmd_network_packet* packet);

#if defined (QSMD_DEBUG_MODE)
/*!
* \brief Test the certificate encoding and decoding functions
*
* \return Returns true if the encoding tests succeed
*/
QSMD_EXPORT_API bool qsmd_certificate_encoding_test(void);
#endif

#endif
