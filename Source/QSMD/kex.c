#include "kex.h"
#include "acp.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "rcs.h"
#include "sha3.h"
#include "socketserver.h"
#include "stringutils.h"
#include "timestamp.h"

#define KEX_CONNECT_REQUEST_MESSAGE_SIZE (QSMD_KEYID_SIZE + QSMD_CONFIG_SIZE + QSMD_HASH_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_CONNECT_REQUEST_PACKET_SIZE (QSMD_HEADER_SIZE + KEX_CONNECT_REQUEST_MESSAGE_SIZE)
#define KEX_CONNECT_RESPONSE_MESSAGE_SIZE (QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + QSMD_HASH_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_CONNECT_RESPONSE_PACKET_SIZE (QSMD_HEADER_SIZE + KEX_CONNECT_RESPONSE_MESSAGE_SIZE)

#define KEX_EXCHANGE_REQUEST_MESSAGE_SIZE (QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + QSMD_HASH_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_EXCHANGE_REQUEST_PACKET_SIZE (QSMD_HEADER_SIZE + KEX_EXCHANGE_REQUEST_MESSAGE_SIZE)
#define KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE (QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMD_HASH_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_EXCHANGE_RESPONSE_PACKET_SIZE (QSMD_HEADER_SIZE + KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE)

#define KEX_ESTABLISH_REQUEST_MESSAGE_SIZE (QSMD_HASH_SIZE + QSMD_MACTAG_SIZE)
#define KEX_ESTABLISH_REQUEST_PACKET_SIZE (QSMD_HEADER_SIZE + KEX_ESTABLISH_REQUEST_MESSAGE_SIZE)
#define KEX_ESTABLISH_RESPONSE_MESSAGE_SIZE (QSMD_HASH_SIZE + QSMD_MACTAG_SIZE)
#define KEX_ESTABLISH_RESPONSE_PACKET_SIZE (QSMD_HEADER_SIZE + KEX_ESTABLISH_RESPONSE_MESSAGE_SIZE)

static void kex_send_network_error(const qsc_socket* sock, qsmd_errors error)
{
	QSMD_ASSERT(sock != NULL);

	if (qsc_socket_is_connected(sock) == true)
	{
		qsmd_network_packet resp = { 0 };
		uint8_t spct[QSMD_HEADER_SIZE + QSMD_ERROR_MESSAGE_SIZE] = { 0U };

		resp.pmessage = spct + QSMD_HEADER_SIZE;
		qsmd_packet_error_message(&resp, error);
		qsmd_packet_header_serialize(&resp, spct);
		qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);
	}
}

static void kex_duplex_client_reset(qsmd_kex_duplex_client_state* kcs)
{
	QSMD_ASSERT(kcs != NULL);

	if (kcs != NULL)
	{
		qsc_memutils_secure_erase(kcs->keyid, QSMD_KEYID_SIZE);
		qsc_memutils_secure_erase(kcs->schash, QSMD_HASH_SIZE);
		qsc_memutils_secure_erase(kcs->prikey, QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE);
		qsc_memutils_secure_erase(kcs->pubkey, QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
		qsc_memutils_secure_erase(kcs->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
		qsc_memutils_secure_erase(kcs->sigkey, QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
		qsc_memutils_secure_erase(kcs->ssec, QSMD_SECRET_SIZE);
		qsc_memutils_secure_erase(kcs->rverkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
		kcs->expiration = 0U;
	}
}

static void kex_duplex_server_reset(qsmd_kex_duplex_server_state* kss)
{
	QSMD_ASSERT(kss != NULL);

	if (kss != NULL)
	{
		qsc_memutils_secure_erase(kss->keyid, QSMD_KEYID_SIZE);
		qsc_memutils_secure_erase(kss->schash, QSMD_HASH_SIZE);
		qsc_memutils_secure_erase(kss->prikey, QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE);
		qsc_memutils_secure_erase(kss->pubkey, QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
		qsc_memutils_secure_erase(kss->sigkey, QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
		qsc_memutils_secure_erase(kss->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
		kss->expiration = 0U;
	}
}

/*
Legend:
<-, ->		-Direction operators
:=, !=, ?=	-Equality operators; assignment, not equals, evaluate
C			-The client host, initiates the exchange
S			-The server host, listens for a connection
G			-The asymmetric cipher key generator function
-Esk		-The asymmetric decapsulation function and secret key
Epk			-The asymmetric encapsulation function and public key
Ssk			-Sign data with the secret signature key
Vpk			-Verify a signature the public verification key
cfg			-The protocol configuration string
cond,		-A conditional statement
cprrx		-A receive channels symmetric cipher instance
cprtx		-A transmit channels symmetric cipher instance
cpt			-The symmetric ciphers cipher-text
cpta		-The asymmetric ciphers cipher-text
-Ek			-The symmetric decryption function and key
Ek			-The symmetric encryption function and key
H			-The hash function (SHA3)
k,mk		-A symmetric cipher or MAC key
KDF			-The key expansion function (SHAKE)
kid			-The public keys unique identity array
Mmk			-The MAC function and key (KMAC)
pk,sk		-Asymmetric public and secret keys
pvk			-Public signature verification key
sch			-A hash of the configuration string and and asymmetric verification-keys
sec			-The shared secret derived from asymmetric encapsulation and decapsulation
sph			-The serialized packet header, including the UTC timestamp
spkh		-The signed hash of the asymmetric public encapsulation-key
*/

/*
Connect Request:
The client stores a hash of the configuration string, and both of the public asymmetric signature verification-keys,
which is used as a session cookie during the exchange.
sch := H(cfg || pvka || pvkb)
The client hashes the key identity string, the configuration string, and the serialized packet header, and signs the hash.
sm := Ssk(H(kid || cfg || sph))
The client sends the kid, the config, and the signed hash to the server.
C{ kid || cfg || sm }->S
*/
static qsmd_errors kex_duplex_client_connect_request(qsmd_kex_duplex_client_state* kcs, qsmd_connection_state* cns, qsmd_network_packet* packetout)
{
	QSMD_ASSERT(kcs != NULL);
	QSMD_ASSERT(packetout != NULL);

	qsc_keccak_state kstate = { 0 };
	qsmd_errors qerr;
	uint64_t tm;

	if (kcs != NULL && packetout != NULL)
	{
		tm = qsc_timestamp_datetime_utc();
		
		if (tm <= kcs->expiration)
		{
			uint8_t phash[QSMD_HASH_SIZE] = { 0U };
			uint8_t shdr[QSMD_HEADER_SIZE] = { 0U };
			size_t mlen;

			/* 1) store the transcript hash of the configuration string, and the public signature keys: sch = H(cfg || pvka || pvkb) */
			qsc_memutils_clear(kcs->schash, QSMD_HASH_SIZE);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, (const uint8_t*)QSMD_CONFIG_STRING, QSMD_CONFIG_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->keyid, QSMD_KEYID_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->rverkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kcs->schash);

			/* copy the key-id and configuration string to the message */
			qsc_memutils_copy(packetout->pmessage, kcs->keyid, QSMD_KEYID_SIZE);
			qsc_memutils_copy(((uint8_t*)packetout->pmessage + QSMD_KEYID_SIZE), QSMD_CONFIG_STRING, QSMD_CONFIG_SIZE);
			/* assemble the connection-request packet */
			qsmd_header_create(packetout, qsmd_flag_connect_request, cns->txseq, KEX_CONNECT_REQUEST_MESSAGE_SIZE);

			/* version 1.3 serialize header, then hash/sign the header and message */
			qsmd_packet_header_serialize(packetout, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMD_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetout->pmessage, QSMD_KEYID_SIZE + QSMD_CONFIG_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

			/* 2) update the transcript hash with the signature hash sch = H(sch || phash) */
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->schash, QSMD_HASH_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, phash, QSMD_HASH_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kcs->schash);

			/* sign the hash and add it to the message */
			mlen = 0U;
			qsmd_signature_sign(packetout->pmessage + QSMD_KEYID_SIZE + QSMD_CONFIG_SIZE, &mlen, phash, QSMD_HASH_SIZE, kcs->sigkey, qsc_acp_generate);

			/* clear the state */
			qsc_memutils_secure_erase(phash, sizeof(phash));
			qsc_memutils_secure_erase(shdr, sizeof(shdr));

			cns->exflag = qsmd_flag_connect_request;
			qerr = qsmd_error_none;
		}
		else
		{
			cns->exflag = qsmd_flag_none;
			qerr = qsmd_error_key_expired;
		}
	}
	else
	{
		cns->exflag = qsmd_flag_none;
		qerr = qsmd_error_invalid_input;
	}

	return qerr;
}

/*
Exchange Request:
The client verifies the flag, sequence number, valid-time timestamp, and message size of the connect response packet.
The client verifies the signature of the hash, then generates its own hash of the public key and serialized packet header, 
and compares it with the one contained in the message. 
If the hash matches, the client uses the public-key to encapsulate a shared secret. 
If the hash does not match, the key exchange is aborted.
cond := Vpk(H(pk || sh)) = (true ?= pk : 0)
cpta, seca := Epk(seca)
The client stores the shared secret (seca), which along with a second shared secret and the session cookie, 
which will be used to generate the session keys.
The client generates an asymmetric encryption key-pair, stores the private key, 
hashes the public encapsulation key, cipher-text, and serialized packet header, 
and then signs the hash using its asymmetric signature key.
pk, sk := G(cfg)
kch := H(pk || cpta || sh)
skch := Ssk(kch)
The client sends a response message containing the signed hash of its encapsulation-key and 
cipher-text and serialized header, and a copy of the cipher-text and encapsulation key.
C{ cpta || pk || skch }-> S
*/
static qsmd_errors kex_duplex_client_exchange_request(qsmd_kex_duplex_client_state* kcs, qsmd_connection_state* cns, const qsmd_network_packet* packetin, qsmd_network_packet* packetout)
{
	QSMD_ASSERT(kcs != NULL);
	QSMD_ASSERT(packetin != NULL);
	QSMD_ASSERT(packetout != NULL);

	uint8_t khash[QSMD_HASH_SIZE] = { 0U };
	size_t mlen;
	size_t slen;
	qsmd_errors qerr;

	if (kcs != NULL && packetin != NULL && packetout != NULL)
	{
		slen = 0U;
		mlen = QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE;

		/* verify the asymmetric signature */
		if (qsmd_signature_verify(khash, &slen, packetin->pmessage, mlen, kcs->rverkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t phash[QSMD_HASH_SIZE] = { 0U };
			uint8_t shdr[QSMD_HEADER_SIZE] = { 0U };
			const uint8_t* pubk = packetin->pmessage + mlen;

			/* version 1.3 hash the public encapsulation key and header */
			qsmd_packet_header_serialize(packetin, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMD_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, pubk, QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

			/* verify the public key hash */
			if (qsc_intutils_verify(phash, khash, QSMD_HASH_SIZE) == 0)
			{
				/* 3) update the transcript hash with the signature hash sch = H(sch || phash) */
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->schash, QSMD_HASH_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, phash, QSMD_HASH_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kcs->schash);

				/* generate, and encapsulate the secret */

				/* store the cipher-text in the message */
				qsmd_cipher_encapsulate(kcs->ssec, packetout->pmessage, pubk, qsc_acp_generate);

				/* generate the asymmetric encryption key-pair */
				qsmd_cipher_generate_keypair(kcs->pubkey, kcs->prikey, qsc_acp_generate);

				/* copy the public key to the message */
				qsc_memutils_copy(packetout->pmessage + QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE, kcs->pubkey, QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
					
				/* assemble the exchange-request packet */
				qsmd_header_create(packetout, qsmd_flag_exchange_request, cns->txseq, KEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

				/* version 1.3 hash the public encapsulation key and packet header */
				qsmd_packet_header_serialize(packetout, shdr);
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMD_HEADER_SIZE);

				/* hash the public encapsulation key and cipher-text */
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetout->pmessage, QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

				/* 4) update the transcript hash with the signature hash sch = H(sch || phash) */
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->schash, QSMD_HASH_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, phash, QSMD_HASH_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kcs->schash);

				/* sign the hash and add it to the message */
				mlen = 0;
				qsmd_signature_sign(packetout->pmessage + QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE, &mlen, phash, QSMD_HASH_SIZE, kcs->sigkey, qsc_acp_generate);

				qerr = qsmd_error_none;
				cns->exflag = qsmd_flag_exchange_request;
			}
			else
			{
				cns->exflag = qsmd_flag_none;
				qerr = qsmd_error_verify_failure;
			}

			/* clear the state */
			qsc_memutils_secure_erase(phash, sizeof(phash));
			qsc_memutils_secure_erase(shdr, sizeof(shdr));
		}
		else
		{
			cns->exflag = qsmd_flag_none;
			qerr = qsmd_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = qsmd_flag_none;
		qerr = qsmd_error_invalid_input;
	}

	return qerr;
}

/*
The client verifies the flag, sequence number, valid-time timestamp, and message size of the exchange response packet.
The client verifies the signature of the hash, then generates its own hash of the cipher-text and packet header, 
and compares it with the one contained in the message. 
If the hash matches, the client decapsulates the shared secret (secb). If the hash comparison fails,
the key exchange is aborted.
cond := Vpk(H(cptb)) = (true ?= cptb : 0)
secb := -Esk(cptb)
The client combines both secrets and the session cookie to create the session keys, 
and two unique nonce, one for each channel of the communications stream.
k1, k2, n1, n2 := KDF(seca, secb, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k2, n2)
cprtx(k1, n1)
The client encrypts the session cookie with the tx cipher, adding the serialized packet header 
to the additional data of the cipher MAC.
cm := Ek(sch, sh)
In the event of an error, the client sends an error message to the server, 
aborting the exchange and terminating the connection on both hosts.
C{ cm }-> S
*/
static qsmd_errors kex_duplex_client_establish_request(qsmd_kex_duplex_client_state* kcs, qsmd_connection_state* cns, const qsmd_network_packet* packetin, qsmd_network_packet* packetout)
{
	QSMD_ASSERT(kcs != NULL);
	QSMD_ASSERT(packetin != NULL);
	QSMD_ASSERT(packetout != NULL);

	qsmd_errors qerr;
	uint8_t khash[QSMD_HASH_SIZE] = { 0U };
	size_t mlen;
	size_t slen;

	if (kcs != NULL && packetin != NULL && packetout != NULL)
	{
		slen = 0U;
		mlen = QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE;

		/* verify the asymmetric signature */
		if (qsmd_signature_verify(khash, &slen, packetin->pmessage + QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE, mlen, kcs->rverkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t phash[QSMD_HASH_SIZE] = { 0U };
			uint8_t secb[QSMD_SECRET_SIZE] = { 0U };
			uint8_t shdr[QSMD_HEADER_SIZE] = { 0U };

			/* version 1.3 hash the public encapsulation key and header */
			qsmd_packet_header_serialize(packetin, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMD_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetin->pmessage, QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

			/* verify the cipher-text hash */
			if (qsc_intutils_verify(phash, khash, QSMD_HASH_SIZE) == 0)
			{
				/* 5) update the transcript hash with the signature hash sch = H(sch || phash) */
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->schash, QSMD_HASH_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, phash, QSMD_HASH_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kcs->schash);

				/* clear the state */
				qsc_memutils_secure_erase(khash, sizeof(khash));
				qsc_memutils_secure_erase(phash, sizeof(phash));

				if (qsmd_cipher_decapsulate(secb, packetin->pmessage, kcs->prikey) == true)
				{
					uint8_t prnd[(QSC_KECCAK_512_RATE * 3U)] = { 0U };

					/* initialize cSHAKE k = H(seca, secb, pkh) */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, kcs->ssec, QSMD_SECRET_SIZE, kcs->schash, QSMD_HASH_SIZE, secb, sizeof(secb));
					qsc_memutils_secure_erase(secb, sizeof(secb));
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 3);

					/* permute the state so we are not storing the current key */
					qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
					/* copy as next key */
					qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMD_SYMMETRIC_KEY_SIZE);

					/* initialize the symmetric cipher, and raise client channel-1 tx */
					qsc_rcs_keyparams kp = { 0 };
					kp.key = prnd;
					kp.keylen = QSMD_SYMMETRIC_KEY_SIZE;
					kp.nonce = prnd + QSMD_SYMMETRIC_KEY_SIZE;
					kp.info = NULL;
					kp.infolen = 0U;
					qsc_rcs_initialize(&cns->txcpr, &kp, true);

					/* initialize the symmetric cipher, and raise client channel-1 rx */
					kp.key = prnd + QSMD_SYMMETRIC_KEY_SIZE + QSMD_NONCE_SIZE;
					kp.keylen = QSMD_SYMMETRIC_KEY_SIZE;
					kp.nonce = prnd + QSMD_SYMMETRIC_KEY_SIZE + QSMD_NONCE_SIZE + QSMD_SYMMETRIC_KEY_SIZE;
					kp.info = NULL;
					kp.infolen = 0U;
					qsc_rcs_initialize(&cns->rxcpr, &kp, false);

					/* clear the keys */
					qsc_memutils_secure_erase((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));
					qsc_memutils_secure_erase(prnd, sizeof(prnd));

					/* assemble the establish-request packet */
					qsmd_header_create(packetout, qsmd_flag_establish_request, cns->txseq, KEX_ESTABLISH_REQUEST_MESSAGE_SIZE);

					/* version 1.3 protocol change: encrypt and add schash to establish request */
					qsmd_packet_header_serialize(packetout, shdr);
					qsc_rcs_set_associated(&cns->txcpr, shdr, QSMD_HEADER_SIZE);
					qsc_rcs_transform(&cns->txcpr, packetout->pmessage, kcs->schash, QSMD_HASH_SIZE);

					/* 6) update the transcript hash with the ciphertext sch = H(sch || cpt) */
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, kcs->schash, QSMD_HASH_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetout->pmessage, packetout->msglen);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kcs->schash);

					qerr = qsmd_error_none;
					cns->exflag = qsmd_flag_establish_request;
				}
				else
				{
					cns->exflag = qsmd_flag_none;
					qerr = qsmd_error_decapsulation_failure;
				}
			}
			else
			{
				cns->exflag = qsmd_flag_none;
				qerr = qsmd_error_verify_failure;
			}
		}
		else
		{
			cns->exflag = qsmd_flag_none;
			qerr = qsmd_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = qsmd_flag_none;
		qerr = qsmd_error_invalid_input;
	}

	return qerr;
}

/*
Establish Verify:
The client verifies the packet flag, sequence number, valid-time timestamp, and message size of the establish response packet.
The client uses the rx cipher instance, adding the serialized establish response packet header to the AD and decrypting the ciphertext.
The session cookie is hashed, and the hash is compared to the decrypted message for equivalence.
If the hahs matches, both sides have confirmed that the encrypted tunnel has been established.
Otherwise the tunnel is in an error state indicated by the message, 
and the tunnel is torn down on both sides. 
The client sets the operational state to session established, and is now ready to process data.
*/
static qsmd_errors kex_duplex_client_establish_verify(qsmd_kex_duplex_client_state* kcs, qsmd_connection_state* cns, const qsmd_network_packet* packetin)
{
	QSMD_ASSERT(kcs != NULL);
	QSMD_ASSERT(packetin != NULL);

	qsmd_errors qerr;

	if (kcs != NULL && packetin != NULL)
	{
		uint8_t phash[QSMD_HASH_SIZE] = { 0U };
		uint8_t shdr[QSMD_HEADER_SIZE] = { 0U };

		/* version 1.3 protocol change: decrypt and verify the server schash */
		qsmd_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, QSMD_HEADER_SIZE);

		if (qsc_rcs_transform(&cns->rxcpr, phash, packetin->pmessage, QSMD_HASH_SIZE) == true)
		{
			uint8_t shash[QSMD_HASH_SIZE] = { 0U };

			qsc_sha3_compute512(shash, kcs->schash, QSMD_HASH_SIZE);

			/* verify the server schash */
			if (qsc_intutils_verify(phash, shash, QSMD_HASH_SIZE) == 0)
			{
				cns->exflag = qsmd_flag_session_established;
				qerr = qsmd_error_none;
			}
			else
			{
				qerr = qsmd_error_verify_failure;
			}

			qsc_memutils_secure_erase(shash, sizeof(shash));
		}
		else
		{
			qerr = qsmd_error_decryption_failure;
		}

		/* clear the state */
		qsc_memutils_secure_erase(phash, sizeof(phash));
		qsc_memutils_secure_erase(shdr, sizeof(shdr));
	}
	else
	{
		qerr = qsmd_error_invalid_input;
	}

	return qerr;
}

/*
The server verifies the packet flag, sequence number, valid-time timestamp, and message size of the connect request packet.
The server responds with either an error message, or a connect response packet.
Any error during the key exchange will generate an error-packet sent to the remote host, 
which will trigger a tear down of the exchange, and the network connection on both sides.
The server first checks the packet header including the valid-time timestamp.
The server then verifies that it has the requested asymmetric signature verification key,
corresponding to the kid sent by the client. The server verifies that it has a compatible protocol configuration. 
The server loads the client's signature verification key, and checks the signature of the message:
mh = Vpk(sm)
If the signature is verified, the server hashes the message kid, config string, and serialized packet header
and compares the signed hash:
m ?= H(kid || cfg || sph)
The server stores a hash of the configuration string, key identity, and both public signature verification-keys, 
to create the public key hash, which is used as a session cookie.
sch := H(cfg || kid || pvka || pvkb)
The server then generates an asymmetric encryption key-pair, stores the private key, 
hashes the public encapsulation key, and then signs the hash of the public encapsulation key and the serialized 
packet header using the asymmetric signature key.
The public signature verification key can itself be signed by a ‘chain of trust' model, 
like X.509, using a signature verification extension to this protocol.
pk,sk := G(cfg)
pkh := H(pk || sph)
spkh := Ssk(pkh)
The server sends a connect response message containing a signed hash of the public asymmetric encapsulation-key, 
and a copy of that key.
S{ spkh || pk }-> C
*/
static qsmd_errors kex_duplex_server_connect_response(qsmd_kex_duplex_server_state* kss, qsmd_connection_state* cns, const qsmd_network_packet* packetin, qsmd_network_packet* packetout)
{
	QSMD_ASSERT(cns != NULL);
	QSMD_ASSERT(kss != NULL);
	QSMD_ASSERT(packetin != NULL);
	QSMD_ASSERT(packetout != NULL);

	qsmd_errors qerr;

	qerr = qsmd_error_none;

	if (cns != NULL && kss != NULL && packetin != NULL && packetout != NULL)
	{
		const uint8_t* pkid = packetin->pmessage;

		/* compare the kid in the message, to stored kids through the interface */
		if (kss->key_query(kss->rverkey, pkid) == true)
		{
			uint64_t tm;

			tm = qsc_timestamp_datetime_utc();

			/* check the keys expiration date */
			if (tm <= kss->expiration)
			{
				char confs[QSMD_CONFIG_SIZE + sizeof(char)] = { 0 };

				/* get a copy of the configuration string */
				qsc_memutils_copy(confs, packetin->pmessage + QSMD_KEYID_SIZE, QSMD_CONFIG_SIZE);

				/* compare the state configuration string to the message configuration string */
				if (qsc_stringutils_compare_strings(confs, QSMD_CONFIG_STRING, QSMD_CONFIG_SIZE) == true)
				{
					uint8_t phash[QSMD_HASH_SIZE] = { 0U };
					size_t mlen;
					size_t slen;

					slen = 0U;
					mlen = QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE;

					/* verify the asymmetric signature */
					if (qsmd_signature_verify(phash, &slen, packetin->pmessage + QSMD_KEYID_SIZE + QSMD_CONFIG_SIZE, mlen, kss->rverkey) == true)
					{
						qsc_keccak_state kstate = { 0 };
						uint8_t shash[QSMD_HASH_SIZE] = { 0U };
						uint8_t shdr[QSMD_HEADER_SIZE] = { 0U };

						/* 1) store a hash of the session token, the configuration string,
							and the public signature key: sch = H(stok || cfg || pvk) */
						qsc_memutils_clear(kss->schash, QSMD_HASH_SIZE);
						qsc_sha3_initialize(&kstate);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, (const uint8_t*)QSMD_CONFIG_STRING, QSMD_CONFIG_SIZE);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->keyid, QSMD_KEYID_SIZE);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->rverkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
						qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kss->schash);

						/* version 1.3 serialize header, then hash/sign the header and message */
						qsmd_packet_header_serialize(packetin, shdr);
						qsc_sha3_initialize(&kstate);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMD_HEADER_SIZE);
						qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetin->pmessage, QSMD_KEYID_SIZE + QSMD_CONFIG_SIZE);
						qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, shash);

						/* verify the message hash */
						if (qsc_intutils_verify(phash, shash, QSMD_HASH_SIZE) == 0)
						{

							/* 2) update the transcript hash with the signature hash sch = H(sch || phash) */
							qsc_sha3_initialize(&kstate);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->schash, QSMD_HASH_SIZE);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, phash, QSMD_HASH_SIZE);
							qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kss->schash);

							/* initialize the packet and asymmetric encryption keys */
							qsc_memutils_clear(kss->pubkey, QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
							qsc_memutils_clear(kss->prikey, QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE);

							/* generate the asymmetric encryption key-pair */
							qsmd_cipher_generate_keypair(kss->pubkey, kss->prikey, qsc_acp_generate);

							/* assemble the connection-response packet */
							qsmd_header_create(packetout, qsmd_flag_connect_response, cns->txseq, KEX_CONNECT_RESPONSE_MESSAGE_SIZE);

							/* version 1.3 hash the public encapsulation key and header */
							qsmd_packet_header_serialize(packetout, shdr);
							qsc_sha3_initialize(&kstate);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMD_HEADER_SIZE);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->pubkey, QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
							qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

							/* 3) update the transcript hash with the signature hash sch = H(sch || phash) */
							qsc_sha3_initialize(&kstate);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->schash, QSMD_HASH_SIZE);
							qsc_sha3_update(&kstate, qsc_keccak_rate_512, phash, QSMD_HASH_SIZE);
							qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kss->schash);

							/* sign the hash and add it to the message */
							mlen = 0U;
							qsmd_signature_sign(packetout->pmessage, &mlen, phash, QSMD_HASH_SIZE, kss->sigkey, qsc_acp_generate);

							/* copy the public key to the message */
							qsc_memutils_copy(((uint8_t*)packetout->pmessage + mlen), kss->pubkey, QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);

							qerr = qsmd_error_none;
							cns->exflag = qsmd_flag_connect_response;
						}
						else
						{
							cns->exflag = qsmd_flag_none;
							qerr = qsmd_error_verify_failure;
						}

						qsc_memutils_secure_erase(shash, sizeof(shash));
						qsc_memutils_secure_erase(shdr, sizeof(shdr));
					}
					else
					{
						cns->exflag = qsmd_flag_none;
						qerr = qsmd_error_authentication_failure;
					}

					qsc_memutils_secure_erase(phash, sizeof(phash));
				}
				else
				{
					cns->exflag = qsmd_flag_none;
					qerr = qsmd_error_unknown_protocol;
				}

				/* clear the state */
				qsc_memutils_secure_erase(confs, sizeof(confs));
			}
			else
			{
				cns->exflag = qsmd_flag_none;
				qerr = qsmd_error_key_expired;
			}
		}
		else
		{
			cns->exflag = qsmd_flag_none;
			qerr = qsmd_error_key_unrecognized;
		}
	}
	else
	{
		cns->exflag = qsmd_flag_none;
		qerr = qsmd_error_invalid_input;
	}

	return qerr;
}

/*
Exchange Response:
The server verifies the packet flag, sequence number, valid-time timestamp, and message size of the exchange request packet.
The server verifies the signature of the hash, then generates its own hash of the public key and cipher-text and serialized header, 
and compares it with the one contained in the message.
If the hash matches, the server uses the private-key to decapsulate the shared secret.
If the hash comparison fails, the key exchange is aborted.
cond := Vpk(H(pk || cpta)) = (true ?= cph : 0)
The server decapsulates the second shared-secret, and stores the secret (seca).
seca := -Esk(cpta)
The server generates a cipher-text and the second shared secret (secb) using the clients public encapsulation key.
cptb, secb := Epk(secb)
The server combines both secrets and the session cookie to create two session keys, and two unique nonce, 
one for each channel of the communications stream.
k1, k2, n1, n2 := Exp(seca || secb || sch)
The receive and transmit channel ciphers are initialized.
cprrx(k1,n1)
cprtx(k2,n2)
The server hashes the cipher-text and serialized packet header, and signs the hash.
cpth := H(cptb || sh)
scph := Ssk(cpth)
The server sends the signed hash of the cipher-text, and the cipher-text to the client.
S{ scph || cptb }-> C
*/
static qsmd_errors kex_duplex_server_exchange_response(qsmd_kex_duplex_server_state* kss, qsmd_connection_state* cns, const qsmd_network_packet* packetin, qsmd_network_packet* packetout)
{
	QSMD_ASSERT(kss != NULL);
	QSMD_ASSERT(packetin != NULL);
	QSMD_ASSERT(packetout != NULL);

	qsmd_errors qerr;

	if (kss != NULL && packetin != NULL && packetout != NULL)
	{
		uint8_t khash[QSMD_HASH_SIZE] = { 0U };
		size_t mlen;
		size_t slen;

		slen = 0;
		mlen = QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE;

		/* verify the asymmetric signature */
		if (qsmd_signature_verify(khash, &slen, packetin->pmessage + QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE, mlen, kss->rverkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t phash[QSMD_HASH_SIZE] = { 0U };
			uint8_t shdr[QSMD_HEADER_SIZE] = { 0U };

			/* version 1.3 hash the public encapsulation key and header */
			qsmd_packet_header_serialize(packetin, shdr);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMD_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetin->pmessage, QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

			/* verify the public key hash */
			if (qsc_intutils_verify(phash, khash, QSMD_HASH_SIZE) == 0)
			{
				/* 4) update the transcript hash with the signature hash sch = H(sch || phash) */
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->schash, QSMD_HASH_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, phash, QSMD_HASH_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kss->schash);

				uint8_t seca[QSMD_SECRET_SIZE] = { 0U };
				uint8_t secb[QSMD_SECRET_SIZE] = { 0U };

				if (qsmd_cipher_decapsulate(seca, packetin->pmessage, kss->prikey) == true)
				{
					uint8_t prnd[(QSC_KECCAK_512_RATE * 3U)] = { 0U };

					/* generate, and encapsulate the secret and store the cipher-text in the message */
					qsmd_cipher_encapsulate(secb, packetout->pmessage, packetin->pmessage + QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE, qsc_acp_generate);

					/* assemble the exstart-request packet */
					qsmd_header_create(packetout, qsmd_flag_exchange_response, cns->txseq, KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);
					
					/* version 1.3 hash the public encapsulation key and header */
					qsmd_packet_header_serialize(packetout, shdr);
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, shdr, QSMD_HEADER_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetout->pmessage, QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, phash);

					/* 5) update the transcript hash with the signature hash sch = H(sch || phash) */
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->schash, QSMD_HASH_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_512, phash, QSMD_HASH_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kss->schash);

					/* sign the hash and add it to the message */
					mlen = 0U;
					qsmd_signature_sign(packetout->pmessage + QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE, &mlen, phash, QSMD_HASH_SIZE, kss->sigkey, qsc_acp_generate);

					/* initialize cSHAKE k = H(seca, secb, pkh) */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, seca, sizeof(seca), kss->schash, QSMD_HASH_SIZE, secb, sizeof(secb));
					/* clear keying material */
					qsc_memutils_secure_erase(seca, sizeof(seca));
					qsc_memutils_secure_erase(secb, sizeof(secb));
					/* generate the key set */
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 3U);
					/* permute the state so we are not storing the current key */
					qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
					/* copy as next key */
					qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMD_SYMMETRIC_KEY_SIZE);

					/* initialize the symmetric cipher, and raise client channel-1 tx */
					qsc_rcs_keyparams kp = { 0 };
					kp.key = prnd;
					kp.keylen = QSMD_SYMMETRIC_KEY_SIZE;
					kp.nonce = prnd + QSMD_SYMMETRIC_KEY_SIZE;
					kp.info = NULL;
					kp.infolen = 0U;
					qsc_rcs_initialize(&cns->rxcpr, &kp, false);

					/* initialize the symmetric cipher, and raise client channel-1 rx */
					kp.key = prnd + QSMD_SYMMETRIC_KEY_SIZE + QSMD_NONCE_SIZE;
					kp.keylen = QSMD_SYMMETRIC_KEY_SIZE;
					kp.nonce = prnd + QSMD_SYMMETRIC_KEY_SIZE + QSMD_NONCE_SIZE + QSMD_SYMMETRIC_KEY_SIZE;
					kp.info = NULL;
					kp.infolen = 0U;
					qsc_rcs_initialize(&cns->txcpr, &kp, true);

					/* clear keying material */
					qsc_memutils_secure_erase(prnd, sizeof(prnd));
					qsc_memutils_secure_erase((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));

					qerr = qsmd_error_none;
					cns->exflag = qsmd_flag_exchange_response;
				}
				else
				{
					cns->exflag = qsmd_flag_none;
					qerr = qsmd_error_decapsulation_failure;
				}
			}
			else
			{
				cns->exflag = qsmd_flag_none;
				qerr = qsmd_error_hash_invalid;
			}

			qsc_memutils_secure_erase(phash, sizeof(phash));
			qsc_memutils_secure_erase(shdr, sizeof(shdr));
		}
		else
		{
			cns->exflag = qsmd_flag_none;
			qerr = qsmd_error_authentication_failure;
		}

		qsc_memutils_secure_erase(khash, sizeof(khash));
	}
	else
	{
		cns->exflag = qsmd_flag_none;
		qerr = qsmd_error_invalid_input;
	}

	return qerr;
}

/*
Establish Response:
The server verifies the packet flag, sequence number, valid-time timestamp, and message size of the establish request packet.
If the flag is set to establish request, the server sends an empty message back to the client 
with the establish response flag set. 
Otherwise the tunnel is in an error state indicated in the message, and the tunnel is torn down on both sides. 
The server sets the operational state to session established, and is now ready to process data.
The server uses the rx cipher to decrypt the message, adding the serialized packet header to the additional data of the cipher MAC. 
The decrypted session cookie is compared to the local session cookie for equivalence. 
If the cookie is verified, the server hashes the session cookie, and encrypts it with the tx cipher,
adding the serialized establish response packet header to the AD of the tx cipher.
hsch = H(sch)
cm := Ek(hsch, sh)
S{ cm }-> C
*/
static qsmd_errors kex_duplex_server_establish_response(qsmd_kex_duplex_server_state* kss, qsmd_connection_state* cns, const qsmd_network_packet* packetin, qsmd_network_packet* packetout)
{
	QSMD_ASSERT(cns != NULL);
	QSMD_ASSERT(packetin != NULL);
	QSMD_ASSERT(packetout != NULL);
	
	qsmd_errors qerr;

	qerr = qsmd_error_invalid_input;

	if (cns != NULL && packetin != NULL && packetout != NULL)
	{
		qsc_keccak_state kstate = { 0 };
		uint8_t phash[QSMD_HASH_SIZE] = { 0U };
		uint8_t shdr[QSMD_HEADER_SIZE] = { 0U };

		/* version 1.3 protocol change: decrypt and verify the schash */
		qsmd_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, QSMD_HEADER_SIZE);

		if (qsc_rcs_transform(&cns->rxcpr, phash, packetin->pmessage, QSMD_HASH_SIZE) == true)
		{
			/* verify the schash */
			if (qsc_intutils_verify(phash, kss->schash, QSMD_HASH_SIZE) == 0)
			{
				/* 6) update the transcript hash with the ciphertext sch = H(sch || cpt) */
				qsc_sha3_initialize(&kstate);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, kss->schash, QSMD_HASH_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_512, packetin->pmessage, packetin->msglen);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_512, kss->schash);

				/* assemble the establish-response packet */
				qsmd_header_create(packetout, qsmd_flag_establish_response, cns->txseq, KEX_ESTABLISH_RESPONSE_MESSAGE_SIZE);

				/* version 1.3 protocol change: hash the schash and send it in the establish response message */
				qsc_memutils_clear(phash, QSMD_HASH_SIZE);
				qsc_sha3_compute512(phash, kss->schash, QSMD_HASH_SIZE);

				qsmd_packet_header_serialize(packetout, shdr);
				qsc_rcs_set_associated(&cns->txcpr, shdr, QSMD_HEADER_SIZE);
				qsc_rcs_transform(&cns->txcpr, packetout->pmessage, phash, QSMD_HASH_SIZE);

				qerr = qsmd_error_none;
				cns->exflag = qsmd_flag_session_established;
			}
			else
			{
				cns->exflag = qsmd_flag_none;
				qerr = qsmd_error_verify_failure;
			}
		}
		else
		{
			cns->exflag = qsmd_flag_none;
			qerr = qsmd_error_decryption_failure;
		}

		/* clear state */
		qsc_memutils_secure_erase(phash, sizeof(phash));
		qsc_memutils_secure_erase(shdr, sizeof(shdr));
	}

	return qerr;
}

qsmd_errors qsmd_kex_duplex_client_key_exchange(qsmd_kex_duplex_client_state* kcs, qsmd_connection_state* cns)
{
	QSMD_ASSERT(kcs != NULL);
	QSMD_ASSERT(cns != NULL);

	qsmd_network_packet reqt = { 0 };
	qsmd_network_packet resp = { 0 };
	uint8_t* brqt;
	uint8_t* brsp;
	const size_t lrqt = KEX_EXCHANGE_REQUEST_PACKET_SIZE;
	const size_t lrsp = (KEX_CONNECT_RESPONSE_PACKET_SIZE > KEX_EXCHANGE_RESPONSE_PACKET_SIZE) ? 
		KEX_CONNECT_RESPONSE_PACKET_SIZE : KEX_EXCHANGE_RESPONSE_PACKET_SIZE;
	size_t rlen;
	size_t slen;
	qsmd_errors qerr;

	if (kcs != NULL && cns != NULL)
	{
		brqt = (uint8_t*)qsc_memutils_malloc(lrqt);

		if (brqt != NULL)
		{
			brsp = (uint8_t*)qsc_memutils_malloc(lrsp);

			if (brsp != NULL)
			{
				/* 1. connect stage */
				qsc_memutils_clear(brqt, lrqt);
				reqt.pmessage = brqt + QSMD_HEADER_SIZE;

				/* create the connection request packet */
				qerr = kex_duplex_client_connect_request(kcs, cns, &reqt);

				if (qerr == qsmd_error_none)
				{
					qsmd_packet_header_serialize(&reqt, brqt);
					/* send the connection request */
					slen = qsc_socket_send(&cns->target, brqt, KEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

					/* check the size sent */
					if (slen == KEX_CONNECT_REQUEST_PACKET_SIZE)
					{
						/* increment the transmit sequence counter */
						cns->txseq += 1U;

						/* allocated memory must be set to zero per MISRA */
						qsc_memutils_clear(brsp, lrsp);
						resp.pmessage = brsp + QSMD_HEADER_SIZE;

						/* blocking receive waits for connect response */
						rlen = qsc_socket_receive(&cns->target, brsp, KEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

						if (rlen == KEX_CONNECT_RESPONSE_PACKET_SIZE)
						{
							/* convert server response to packet */
							qsmd_packet_header_deserialize(brsp, &resp);
							/* validate the packet header including the timestamp */
							qerr = qsmd_header_validate(cns, &resp, qsmd_flag_connect_request, qsmd_flag_connect_response, cns->rxseq, KEX_CONNECT_RESPONSE_MESSAGE_SIZE);
						}
						else
						{
							qerr = qsmd_error_receive_failure;
						}
					}
					else
					{
						qerr = qsmd_error_transmit_failure;
					}
				}

				/* 2. exchange stage */
				if (qerr == qsmd_error_none)
				{
					qsc_memutils_clear(brqt, KEX_CONNECT_REQUEST_PACKET_SIZE);

					/* create the exchange request packet */
					qerr = kex_duplex_client_exchange_request(kcs, cns, &resp, &reqt);

					if (qerr == qsmd_error_none)
					{
						/* serialize the packet header to the buffer */
						qsmd_packet_header_serialize(&reqt, brqt);

						/* send exchange request */
						slen = qsc_socket_send(&cns->target, brqt, KEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

						if (slen == KEX_EXCHANGE_REQUEST_PACKET_SIZE)
						{
							cns->txseq += 1U;
							qsc_memutils_clear(brsp, KEX_CONNECT_RESPONSE_PACKET_SIZE);
							resp.pmessage = brsp + QSMD_HEADER_SIZE;

							/* wait for exchange response */
							rlen = qsc_socket_receive(&cns->target, brsp, KEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

							/* check the received size */
							if (rlen == KEX_EXCHANGE_RESPONSE_PACKET_SIZE)
							{
								/* convert server response to packet */
								qsmd_packet_header_deserialize(brsp, &resp);
								/* validate the header and timestamp */
								qerr = qsmd_header_validate(cns, &resp, qsmd_flag_exchange_request, qsmd_flag_exchange_response, cns->rxseq, KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);
							}
							else
							{
								qerr = qsmd_error_receive_failure;
							}
						}
						else
						{
							qerr = qsmd_error_transmit_failure;
						}
					}
				}

				/* 3. establish stage */
				if (qerr == qsmd_error_none)
				{
					qsc_memutils_clear(brqt, KEX_EXCHANGE_REQUEST_PACKET_SIZE);

					/* create the establish request packet */
					qerr = kex_duplex_client_establish_request(kcs, cns, &resp, &reqt);

					if (qerr == qsmd_error_none)
					{
						qsmd_packet_header_serialize(&reqt, brqt);

						/* send the establish request packet */
						slen = qsc_socket_send(&cns->target, brqt, KEX_ESTABLISH_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

						if (slen == KEX_ESTABLISH_REQUEST_PACKET_SIZE)
						{
							cns->txseq += 1U;
							/* wait for the establish response */
							rlen = qsc_socket_receive(&cns->target, brsp, KEX_ESTABLISH_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

							if (rlen == KEX_ESTABLISH_RESPONSE_PACKET_SIZE)
							{
								qsmd_packet_header_deserialize(brsp, &resp);
								/* validate the header */
								qerr = qsmd_header_validate(cns, &resp, qsmd_flag_establish_request, qsmd_flag_establish_response, cns->rxseq, KEX_ESTABLISH_RESPONSE_MESSAGE_SIZE);

								if (qerr == qsmd_error_none)
								{
									/* verify the exchange  */
									qerr = kex_duplex_client_establish_verify(kcs, cns, &resp);
								}
								else
								{
									qerr = qsmd_error_packet_unsequenced;
								}
							}
							else
							{
								qerr = qsmd_error_receive_failure;
							}
						}
						else
						{
							qerr = qsmd_error_transmit_failure;
						}
					}
				}

				qsc_memutils_secure_erase(brsp, lrsp);
				qsc_memutils_alloc_free(brsp);
			}
			else
			{
				qerr = qsmd_error_memory_allocation;
			}

			qsc_memutils_secure_erase(brqt, lrqt);
			qsc_memutils_alloc_free(brqt);
		}
		else
		{
			qerr = qsmd_error_memory_allocation;
		}

		kex_duplex_client_reset(kcs);

		if (qerr != qsmd_error_none)
		{
			if (cns->target.connection_status == qsc_socket_state_connected)
			{
				kex_send_network_error(&cns->target, qerr);
				qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
			}

			qsmd_connection_state_dispose(cns);
		}
	}
	else
	{
		qerr = qsmd_error_invalid_input;
	}

	return qerr;
}

qsmd_errors qsmd_kex_duplex_server_key_exchange(qsmd_kex_duplex_server_state* kss, qsmd_connection_state* cns)
{
	QSMD_ASSERT(kss != NULL);
	QSMD_ASSERT(cns != NULL);

	qsmd_network_packet reqt = { 0 };
	qsmd_network_packet resp = { 0 };
	uint8_t* brqt;
	uint8_t* brsp;
	const size_t lrqt = KEX_EXCHANGE_REQUEST_PACKET_SIZE;
	const size_t lrsp = (KEX_CONNECT_RESPONSE_PACKET_SIZE > KEX_EXCHANGE_RESPONSE_PACKET_SIZE) ? 
		KEX_CONNECT_RESPONSE_PACKET_SIZE : KEX_EXCHANGE_RESPONSE_PACKET_SIZE;
	size_t rlen;
	size_t slen;
	qsmd_errors qerr;

	if (kss != NULL && cns != NULL)
	{
		brsp = (uint8_t*)qsc_memutils_malloc(lrsp);

		if (brsp != NULL)
		{
			brqt = (uint8_t*)qsc_memutils_malloc(lrqt);

			if (brqt != NULL)
			{
				/* 1. connect stage */
				qsc_memutils_clear(brqt, KEX_CONNECT_REQUEST_PACKET_SIZE);
				reqt.pmessage = brqt + QSMD_HEADER_SIZE;

				/* blocking receive waits for client connect request */
				rlen = qsc_socket_receive(&cns->target, brqt, KEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

				if (rlen == KEX_CONNECT_REQUEST_PACKET_SIZE)
				{
					/* convert server response to packet */
					qsmd_packet_header_deserialize(brqt, &reqt);
					qerr = qsmd_header_validate(cns, &reqt, qsmd_flag_none, qsmd_flag_connect_request, cns->rxseq, KEX_CONNECT_REQUEST_MESSAGE_SIZE);

					if (qerr == qsmd_error_none)
					{
						qsc_memutils_clear(brsp, KEX_CONNECT_RESPONSE_PACKET_SIZE);
						resp.pmessage = brsp + QSMD_HEADER_SIZE;

						/* create the connection request packet */
						qerr = kex_duplex_server_connect_response(kss, cns, &reqt, &resp);

						if (qerr == qsmd_error_none)
						{
							qsmd_packet_header_serialize(&resp, brsp);
							slen = qsc_socket_send(&cns->target, brsp, KEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

							if (slen == KEX_CONNECT_RESPONSE_PACKET_SIZE)
							{
								cns->txseq += 1U;
							}
							else
							{
								qerr = qsmd_error_transmit_failure;
							}
						}
					}
				}
				else
				{
					qerr = qsmd_error_receive_failure;
				}

				/* 2. exchange stage */
				if (qerr == qsmd_error_none)
				{
					qsc_memutils_clear(brqt, KEX_CONNECT_REQUEST_PACKET_SIZE);

					/* wait for the exchange request */
					rlen = qsc_socket_receive(&cns->target, brqt, KEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

					if (rlen == KEX_EXCHANGE_REQUEST_PACKET_SIZE)
					{
						qsmd_packet_header_deserialize(brqt, &reqt);
						qerr = qsmd_header_validate(cns, &reqt, qsmd_flag_connect_response, qsmd_flag_exchange_request, cns->rxseq, KEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

						if (qerr == qsmd_error_none)
						{
							qsc_memutils_clear(brsp, KEX_CONNECT_RESPONSE_PACKET_SIZE);

							/* create the exchange response packet */
							qerr = kex_duplex_server_exchange_response(kss, cns, &reqt, &resp);

							if (qerr == qsmd_error_none)
							{
								qsmd_packet_header_serialize(&resp, brsp);
								slen = qsc_socket_send(&cns->target, brsp, KEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

								if (slen == KEX_EXCHANGE_RESPONSE_PACKET_SIZE)
								{
									cns->txseq += 1U;
								}
								else
								{
									qerr = qsmd_error_transmit_failure;
								}
							}
						}
					}
					else
					{
						qerr = qsmd_error_receive_failure;
					}
				}

				/* 3. establish stage */
				if (qerr == qsmd_error_none)
				{
					qsc_memutils_clear(brqt, KEX_ESTABLISH_REQUEST_PACKET_SIZE);

					/* wait for the establish request */
					rlen = qsc_socket_receive(&cns->target, brqt, KEX_ESTABLISH_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

					if (rlen == KEX_ESTABLISH_REQUEST_PACKET_SIZE)
					{
						qsmd_packet_header_deserialize(brqt, &reqt);
						qerr = qsmd_header_validate(cns, &reqt, qsmd_flag_exchange_response, qsmd_flag_establish_request, cns->rxseq, KEX_ESTABLISH_REQUEST_MESSAGE_SIZE);

						if (qerr == qsmd_error_none)
						{
							qsc_memutils_clear(brsp, KEX_ESTABLISH_RESPONSE_PACKET_SIZE);

							/* create the establish response packet */
							qerr = kex_duplex_server_establish_response(kss, cns, &reqt, &resp);

							if (qerr == qsmd_error_none)
							{
								qsmd_packet_header_serialize(&resp, brsp);
								slen = qsc_socket_send(&cns->target, brsp, KEX_ESTABLISH_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

								if (slen == KEX_ESTABLISH_RESPONSE_PACKET_SIZE)
								{
									cns->txseq += 1U;
								}
								else
								{
									qerr = qsmd_error_transmit_failure;
								}
							}
						}
					}
					else
					{
						qerr = qsmd_error_receive_failure;
					}
				}

				qsc_memutils_secure_erase(brqt, lrqt);
				qsc_memutils_alloc_free(brqt);
			}
			else
			{
				qerr = qsmd_error_memory_allocation;
			}

			qsc_memutils_secure_erase(brsp, lrsp);
			qsc_memutils_alloc_free(brsp);
		}
		else
		{
			qerr = qsmd_error_memory_allocation;
		}

		kex_duplex_server_reset(kss);

		if (qerr != qsmd_error_none)
		{
			if (cns->target.connection_status == qsc_socket_state_connected)
			{
				kex_send_network_error(&cns->target, qerr);
				qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
			}

			qsmd_connection_state_dispose(cns);
		}
	}
	else
	{
		qerr = qsmd_error_invalid_input;
	}

	return qerr;
}

#if defined(QSMD_KEX_TEST_ENABLED)
bool qsmd_kex_test(void)
{
	qsmd_kex_duplex_client_state dkcs = { 0 };
	qsmd_kex_duplex_server_state dkss = { 0 };
	qsmd_connection_state cnc = { 0 };
	qsmd_connection_state cns = { 0 };
	qsmd_network_packet pckclt = { 0 };
	qsmd_network_packet pcksrv = { 0 };
	uint8_t mclt[QSMD_HEADER_SIZE + QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + QSMD_HASH_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE] = { 0U };
	uint8_t msrv[QSMD_HEADER_SIZE + QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + QSMD_HASH_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE] = { 0U };
	qsmd_errors qerr;
	bool res;

	pckclt.pmessage = mclt;
	pcksrv.pmessage = msrv;
	qsmd_signature_generate_keypair(dkcs.verkey, dkcs.sigkey, qsc_acp_generate);
	qsmd_signature_generate_keypair(dkss.verkey, dkss.sigkey, qsc_acp_generate);
	qsc_memutils_copy(dkcs.rverkey, dkss.verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_copy(dkss.rverkey, dkcs.verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);

	dkcs.expiration = qsc_timestamp_datetime_utc() + QSMD_PUBKEY_DURATION_SECONDS;
	dkss.expiration = dkcs.expiration;

	res = false;
	qerr = kex_duplex_client_connect_request(&dkcs, &cnc, &pckclt);

	if (qerr == qsmd_error_none)
	{
		qerr = kex_duplex_server_connect_response(&dkss, &cns, &pckclt, &pcksrv);

		if (qerr == qsmd_error_none)
		{
			qerr = kex_duplex_client_exchange_request(&dkcs, &cnc, &pcksrv, &pckclt);

			if (qerr == qsmd_error_none)
			{
				qerr = kex_duplex_server_exchange_response(&dkss, &cns, &pckclt, &pcksrv);

				if (qerr == qsmd_error_none)
				{
					qerr = kex_duplex_client_establish_request(&dkcs, &cnc, &pcksrv, &pckclt);

					if (qerr == qsmd_error_none)
					{
						qerr = kex_duplex_server_establish_response(&dkss, &cns, &pckclt, &pcksrv);

						if (qerr == qsmd_error_none)
						{
							qerr = kex_duplex_client_establish_verify(&dkcs, &cnc, &pcksrv);

							if (qerr == qsmd_error_none)
							{
								res = true;
							}
						}
					}
				}
			}
		}
	}

	return res;
}
#endif
