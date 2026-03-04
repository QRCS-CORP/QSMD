#include "client.h"
#include "kex.h"
#include "logger.h"
#include "acp.h"
#include "async.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "socketserver.h"
#include "timestamp.h"

/** \cond */
typedef struct client_receiver_state
{
	qsmd_connection_state* pcns;
	void (*callback)(qsmd_connection_state*, const uint8_t*, size_t);
} client_receiver_state;

typedef struct listener_receiver_state
{
	qsmd_connection_state* pcns;
	void (*callback)(qsmd_connection_state*, const uint8_t*, size_t);
} listener_receiver_state;

typedef struct listener_receive_loop_args
{
	listener_receiver_state* prcv;
} listener_receive_loop_args;
/** \endcond */

#if defined(QSMD_ASYMMETRIC_RATCHET)
/** \cond */
#define QSMD_ASYMMETRIC_RATCHET_REQUEST_MESSAGE_SIZE (QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE + QSMD_MACTAG_SIZE)
#define QSMD_ASYMMETRIC_RATCHET_REQUEST_PACKET_SIZE (QSMD_HEADER_SIZE + QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE + QSMD_MACTAG_SIZE)
#define QSMD_ASYMMETRIC_RATCHET_RESPONSE_MESSAGE_SIZE (QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE + QSMD_MACTAG_SIZE)
#define QSMD_ASYMMETRIC_RATCHET_RESPONSE_PACKET_SIZE (QSMD_HEADER_SIZE + QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE + QSMD_MACTAG_SIZE)

/** \endcond */
#endif

/* Private Functions */

/** \cond */
static void client_duplex_state_initialize(qsmd_kex_duplex_client_state* kcs, qsmd_connection_state* cns, const qsmd_server_signature_key* kset, const qsmd_client_verification_key* rverkey)
{
	qsc_memutils_copy(kcs->verkey, kset->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_copy(kcs->sigkey, kset->sigkey, QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kcs->keyid, rverkey->keyid, QSMD_KEYID_SIZE);
	qsc_memutils_copy(kcs->rverkey, rverkey->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_memutils_clear(cns->rtcs, QSMD_SYMMETRIC_KEY_SIZE);
	kcs->expiration = rverkey->expiration;
	cns->target.instance = qsc_acp_uint32();
	qsc_rcs_dispose(&cns->rxcpr);
	qsc_rcs_dispose(&cns->txcpr);
	cns->exflag = qsmd_flag_none;
	cns->cid = 0U;
	cns->rxseq = 0U;
	cns->txseq = 0U;
	cns->receiver = false;
}

static void listener_duplex_state_initialize(qsmd_kex_duplex_server_state* kss, listener_receiver_state* rcv, 
	const qsmd_server_signature_key* kset, 
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	qsc_memutils_copy(kss->keyid, kset->keyid, QSMD_KEYID_SIZE);
	qsc_memutils_copy(kss->sigkey, kset->sigkey, QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kss->verkey, kset->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
	kss->key_query = key_query;
	kss->expiration = kset->expiration;
	qsc_memutils_clear((uint8_t*)&rcv->pcns->rxcpr, sizeof(qsc_rcs_state));
	qsc_memutils_clear((uint8_t*)&rcv->pcns->txcpr, sizeof(qsc_rcs_state));
	qsc_memutils_clear(&rcv->pcns->rtcs, QSMD_SYMMETRIC_KEY_SIZE);
	rcv->pcns->exflag = qsmd_flag_none;
	rcv->pcns->cid = 0U;
	rcv->pcns->rxseq = 0U;
	rcv->pcns->txseq = 0U;
	rcv->pcns->receiver = true;
}

static void symmetric_ratchet(qsmd_connection_state* cns, const uint8_t* secret, size_t seclen)
{
	qsc_keccak_state kstate = { 0 };
	qsc_rcs_keyparams kp = { 0 };
	uint8_t prnd[(QSC_KECCAK_512_RATE * 3)] = { 0U };

	/* re-key the ciphers using the token, ratchet key, and configuration name */
	qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, secret, seclen, (const uint8_t*)QSMD_CONFIG_STRING, QSMD_CONFIG_SIZE, cns->rtcs, QSMD_SYMMETRIC_KEY_SIZE);
	/* re-key the ciphers using the symmetric ratchet key */
	qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 3);

	qsc_async_mutex_lock(cns->txlock);

	if (cns->receiver == true)
	{
		/* initialize for decryption, and raise client channel rx */
		kp.key = prnd;
		kp.keylen = QSMD_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMD_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->rxcpr, &kp, false);

		/* initialize for encryption, and raise client channel tx */
		kp.key = prnd + QSMD_SYMMETRIC_KEY_SIZE + QSMD_NONCE_SIZE;
		kp.keylen = QSMD_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMD_SYMMETRIC_KEY_SIZE + QSMD_NONCE_SIZE + QSMD_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->txcpr, &kp, true);
	}
	else
	{
		/* initialize for encryption, and raise tx */
		kp.key = prnd;
		kp.keylen = QSMD_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMD_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->txcpr, &kp, true);

		/* initialize decryption, and raise rx */
		kp.key = prnd + QSMD_SYMMETRIC_KEY_SIZE + QSMD_NONCE_SIZE;
		kp.keylen = QSMD_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSMD_SYMMETRIC_KEY_SIZE + QSMD_NONCE_SIZE + QSMD_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qsc_rcs_initialize(&cns->rxcpr, &kp, false);
	}

	qsc_async_mutex_unlock(cns->txlock);

	/* permute key state and store next key */
	qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
	qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSMD_SYMMETRIC_KEY_SIZE);
	/* erase the key array */
	qsc_memutils_secure_erase(prnd, sizeof(prnd));
	qsc_memutils_secure_erase((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));
}

static bool symmetric_ratchet_response(qsmd_connection_state* cns, const qsmd_network_packet* packetin)
{
	uint8_t rkey[QSMD_RTOK_SIZE] = { 0U };
	uint8_t shdr[QSMD_HEADER_SIZE] = { 0U };
	size_t mlen;
	bool res;

	res = false;

	if (packetin->sequence == cns->rxseq + 1U)
	{
		/* serialize the header and add it to the ciphers associated data */
		qsmd_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, QSMD_HEADER_SIZE);
		mlen = packetin->msglen - (size_t)QSMD_MACTAG_SIZE;

		/* authenticate then decrypt the data */
		if (qsc_rcs_transform(&cns->rxcpr, rkey, packetin->pmessage, mlen) == true)
		{
			cns->rxseq += 1U;
			/* inject into key state */
			symmetric_ratchet(cns, rkey, sizeof(rkey));
			res = true;
		}
	}

	qsc_memutils_secure_erase(rkey, sizeof(rkey));
	qsc_memutils_secure_erase(shdr, sizeof(shdr));

	return res;
}

#if defined(QSMD_ASYMMETRIC_RATCHET)
static bool asymmetric_ratchet_response(qsmd_connection_state* cns, const qsmd_network_packet* packetin)
{
	size_t mlen;
	bool res;

	res = false;

	if (packetin->sequence == cns->rxseq + 1U && packetin->msglen == QSMD_ASYMMETRIC_RATCHET_REQUEST_MESSAGE_SIZE)
	{
		uint8_t imsg[QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE] = { 0U };
		uint8_t shdr[QSMD_HEADER_SIZE] = { 0U };

		/* serialize the header and add it to the ciphers associated data */
		qsmd_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, QSMD_HEADER_SIZE);
		mlen = packetin->msglen - (size_t)QSMD_MACTAG_SIZE;

		/* authenticate then decrypt the data */
		if (qsc_rcs_transform(&cns->rxcpr, imsg, packetin->pmessage, mlen) == true)
		{
			uint8_t rhash[QSMD_HASH_SIZE] = { 0U };
			const uint8_t* rpub = imsg + QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE;

			/* verify the signature */
			if (qsmd_signature_verify(rhash, &mlen, imsg, QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE, cns->verkey) == true)
			{
				uint8_t lhash[QSMD_HASH_SIZE] = { 0U };

				/* hash the public key */
				qsc_sha3_compute512(lhash, rpub, QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);

				/* compare the signed hash with the local hash */
				if (qsc_intutils_verify(rhash, lhash, QSMD_HASH_SIZE) == 0)
				{
					qsmd_network_packet pkt = { 0 };
					uint8_t omsg[QSMD_ASYMMETRIC_RATCHET_RESPONSE_PACKET_SIZE] = { 0U };
					uint8_t mtmp[QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE + QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE] = { 0 };					
					uint8_t khash[QSMD_HASH_SIZE] = { 0U };
					uint8_t ssec[QSMD_ASYMMETRIC_SECRET_SIZE] = { 0U };
					size_t slen;

					cns->rxseq += 1U;
					mlen = QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE;

					/* encapsulate a secret with the public key */
					qsmd_cipher_encapsulate(ssec, mtmp + mlen, rpub, qsc_acp_generate);

					/* compute a hash of the cipher-text */
					qsc_sha3_compute512(khash, mtmp + mlen, QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE);

					/* sign the hash */
					mlen = 0U;
					qsmd_signature_sign(mtmp, &mlen, khash, sizeof(khash), cns->sigkey, qsc_acp_generate);

					qsc_async_mutex_lock(cns->txlock);
					/* create the outbound packet */
					cns->txseq += 1U;
					pkt.flag = qsmd_flag_asymmetric_ratchet_response;
					pkt.msglen = QSMD_ASYMMETRIC_RATCHET_RESPONSE_MESSAGE_SIZE;
					pkt.sequence = cns->txseq;
					mlen += QSMD_HEADER_SIZE + QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE;

					/* serialize the header */
					qsmd_packet_header_serialize(&pkt, omsg);
					/* add the header to the ciphers associated data */
					qsc_rcs_set_associated(&cns->txcpr, omsg, QSMD_HEADER_SIZE);
					/* encrypt the message */
					qsc_rcs_transform(&cns->txcpr, omsg + QSMD_HEADER_SIZE, mtmp, sizeof(mtmp));
					mlen += QSMD_MACTAG_SIZE;

					qsc_async_mutex_unlock(cns->txlock);

					/* send the encrypted message */
					slen = qsc_socket_send(&cns->target, omsg, mlen, qsc_socket_send_flag_none);
					
					if (slen == mlen)
					{
						/* pass the secret to the symmetric ratchet */
						symmetric_ratchet(cns, ssec, sizeof(ssec));
						res = true;
					}

					qsc_memutils_secure_erase(omsg, sizeof(omsg));
					qsc_memutils_secure_erase(mtmp, sizeof(mtmp));
					qsc_memutils_secure_erase(khash, sizeof(khash));
					qsc_memutils_secure_erase(ssec, sizeof(ssec));
				}

				qsc_memutils_secure_erase(lhash, sizeof(lhash));
			}

			qsc_memutils_secure_erase(rhash, sizeof(rhash));
		}

		qsc_memutils_secure_erase(imsg, sizeof(imsg));
		qsc_memutils_secure_erase(shdr, sizeof(shdr));
	}

	return res;
}

static bool asymmetric_ratchet_finalize(qsmd_connection_state* cns, const qsmd_network_packet* packetin)
{
	uint8_t imsg[QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE + QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE] = { 0 };
	uint8_t rhash[QSMD_HASH_SIZE] = { 0 };
	uint8_t shdr[QSMD_HEADER_SIZE] = { 0 };
	uint8_t ssec[QSMD_ASYMMETRIC_SECRET_SIZE] = { 0 };
	size_t mlen;
	size_t mpos;
	bool res;

	res = false;
	mlen = 0U;
	mpos = QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE;

	if (packetin->sequence == cns->rxseq + 1U && packetin->msglen == QSMD_ASYMMETRIC_RATCHET_RESPONSE_MESSAGE_SIZE)
	{
		/* serialize the header and add it to the ciphers associated data */
		qsmd_packet_header_serialize(packetin, shdr);
		qsc_rcs_set_associated(&cns->rxcpr, shdr, QSMD_HEADER_SIZE);
		mlen = packetin->msglen - (size_t)QSMD_MACTAG_SIZE;

		/* authenticate then decrypt the data */
		if (qsc_rcs_transform(&cns->rxcpr, imsg, packetin->pmessage, mlen) == true)
		{
			/* verify the signature using the senders public key */
			if (qsmd_signature_verify(rhash, &mlen, imsg, mpos, cns->verkey) == true)
			{
				uint8_t lhash[QSMD_HASH_SIZE] = { 0U };

				/* compute a hash of cipher-text */
				qsc_sha3_compute512(lhash, imsg + mpos, QSMD_ASYMMETRIC_CIPHER_TEXT_SIZE);

				/* verify the embedded hash against a hash of the cipher-text */
				if (qsc_intutils_verify(rhash, lhash, QSMD_HASH_SIZE) == 0)
				{
					/* decapsulate the secret */
					res = qsmd_cipher_decapsulate(ssec, imsg + mpos, cns->deckey);

					if (res == true)
					{
						cns->rxseq += 1U;

						/* pass the secret to the symmetric ratchet */
						symmetric_ratchet(cns, ssec, sizeof(ssec));
					}

					qsc_memutils_secure_erase(ssec, sizeof(ssec));
					qsc_memutils_secure_erase(cns->enckey, QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
					qsc_memutils_secure_erase(cns->deckey, QSMD_ASYMMETRIC_DECAPSULATION_KEY_SIZE);
				}

				qsc_memutils_secure_erase(lhash, sizeof(lhash));
			}
		}
	}

	qsc_memutils_secure_erase(imsg, sizeof(imsg));
	qsc_memutils_secure_erase(rhash, sizeof(rhash));
	qsc_memutils_secure_erase(shdr, sizeof(shdr));
	qsc_memutils_secure_erase(ssec, sizeof(ssec));

	return res;
}
#endif

static void client_connection_dispose(client_receiver_state* prcv)
{
	/* send a close notification to the server */
	if (qsc_socket_is_connected(&prcv->pcns->target) == true)
	{
		qsmd_connection_close(prcv->pcns, qsmd_error_none, true);
	}

	/* dispose of resources */
	qsmd_connection_state_dispose(prcv->pcns);
}

static void client_receive_loop(void* prcv)
{
	QSMD_ASSERT(prcv != NULL);

	qsmd_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	client_receiver_state* pprcv;
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qsmd_errors qerr;

	pprcv = (client_receiver_state*)prcv;
	qsc_memutils_copy(cadd, (const char*)pprcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(QSMD_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (pprcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0U;
			slen = 0U;
			qsc_memutils_clear(rbuf, QSMD_HEADER_SIZE);

			plen = qsc_socket_peek(&pprcv->pcns->target, rbuf, QSMD_HEADER_SIZE);

			if (plen == QSMD_HEADER_SIZE)
			{
				qsmd_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0U && pkt.msglen <= QSMD_MESSAGE_MAX)
				{
					uint8_t* rtmp;

					plen = pkt.msglen + QSMD_HEADER_SIZE;
					rtmp = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rtmp != NULL)
					{
						rbuf = rtmp;
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&pprcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0U)
						{
							qsmd_packet_header_deserialize(rbuf, &pkt);
							pkt.pmessage = rbuf + QSMD_HEADER_SIZE;

							if (pkt.flag == qsmd_flag_encrypted_message)
							{
								uint8_t* rmsg;

								slen = pkt.msglen;
								slen -= QSMD_MACTAG_SIZE;
								rmsg = (uint8_t*)qsc_memutils_malloc(slen);

								if (rmsg != NULL)
								{
									qsc_memutils_clear(rmsg, slen);
									qerr = qsmd_packet_decrypt(pprcv->pcns, rmsg, &mlen, &pkt);

									if (qerr == qsmd_error_none)
									{
										pprcv->callback(pprcv->pcns, rmsg, mlen);
									}
									else
									{
										/* close the connection on authentication failure */
										qsmd_log_write(qsmd_messages_decryption_fail, cadd);
										break;
									}

									qsc_memutils_secure_erase(rmsg, slen);
									qsc_memutils_alloc_free(rmsg);
								}
								else
								{
									/* close the connection on memory allocation failure */
									qsmd_log_write(qsmd_messages_allocate_fail, cadd);
									break;
								}
							}
							else if (pkt.flag == qsmd_flag_general_error_condition)
							{
								/* anti-dos: break on error message is conditional
								   on succesful authentication/decryption */
								if (qsmd_decrypt_error_message(&qerr, pprcv->pcns, rbuf) == true)
								{
									qsmd_log_system_error(qerr);
									break;
								}
							}
							else if (pkt.flag == qsmd_flag_symmetric_ratchet_request)
							{
								if (symmetric_ratchet_response(pprcv->pcns, &pkt) == false)
								{
									qsmd_log_write(qsmd_messages_symmetric_ratchet, (const char*)pprcv->pcns->target.address);
									break;
								}
							}
#if defined(QSMD_ASYMMETRIC_RATCHET)
							else if (pkt.flag == qsmd_flag_asymmetric_ratchet_request)
							{
								if (asymmetric_ratchet_response(pprcv->pcns, &pkt) == false)
								{
									qsmd_log_write(qsmd_messages_asymmetric_ratchet, (const char*)pprcv->pcns->target.address);
									break;
								}
							}
							else if (pkt.flag == qsmd_flag_asymmetric_ratchet_response)
							{
								if (asymmetric_ratchet_finalize(pprcv->pcns, &pkt) == false)
								{
									qsmd_log_write(qsmd_messages_asymmetric_ratchet, (const char*)pprcv->pcns->target.address);
									break;
								}
							}
#endif
							else
							{
								qsc_socket_exceptions err = qsc_socket_get_last_error();

								if (err != qsc_socket_exception_success)
								{
									qsmd_log_error(qsmd_messages_receive_fail, err, cadd);

									/* fatal socket errors */
									if (err == qsc_socket_exception_circuit_reset ||
										err == qsc_socket_exception_circuit_terminated ||
										err == qsc_socket_exception_circuit_timeout ||
										err == qsc_socket_exception_dropped_connection ||
										err == qsc_socket_exception_network_failure ||
										err == qsc_socket_exception_shut_down)
									{
										qsmd_log_write(qsmd_messages_connection_fail, cadd);
										break;
									}
								}
							}
						}
						else
						{
							qsmd_log_write(qsmd_messages_receive_fail, cadd);
							break;
						}
					}
				}
				else
				{
					/* close the connection on memory allocation failure */
					qsmd_log_write(qsmd_messages_allocate_fail, cadd);
					break;
				}
			}
			else
			{
				qsmd_log_write(qsmd_messages_receive_fail, cadd);
				break;
			}
			
			qsc_memutils_secure_erase(rbuf, plen);
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		qsmd_log_write(qsmd_messages_allocate_fail, cadd);
	}
}

static void listener_receive_loop(listener_receiver_state* prcv)
{
	QSMD_ASSERT(prcv != NULL);

	qsmd_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qsmd_errors qerr;

	qsc_memutils_copy(cadd, (const char*)prcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(QSMD_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0U;
			slen = 0U;
			qsc_memutils_clear(rbuf, QSMD_HEADER_SIZE);

			plen = qsc_socket_peek(&prcv->pcns->target, rbuf, QSMD_HEADER_SIZE);

			if (plen == QSMD_HEADER_SIZE)
			{
				qsmd_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0U && pkt.msglen <= QSMD_MESSAGE_MAX)
				{
					uint8_t* rtmp;

					plen = pkt.msglen + QSMD_HEADER_SIZE;
					rtmp = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rtmp != NULL)
					{
						rbuf = rtmp;
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0U)
						{
							qsmd_packet_header_deserialize(rbuf, &pkt);
							pkt.pmessage = rbuf + QSMD_HEADER_SIZE;

							if (pkt.flag == qsmd_flag_encrypted_message)
							{
								uint8_t* rmsg;

								slen = pkt.msglen;
								slen -= QSMD_MACTAG_SIZE;
								rmsg = (uint8_t*)qsc_memutils_malloc(slen);

								if (rmsg != NULL)
								{
									qsc_memutils_clear(rmsg, slen);
									qerr = qsmd_packet_decrypt(prcv->pcns, rmsg, &mlen, &pkt);

									if (qerr == qsmd_error_none)
									{
										prcv->callback(prcv->pcns, rmsg, mlen);
									}
									else
									{
										/* close the connection on authentication failure */
										qsmd_log_write(qsmd_messages_decryption_fail, cadd);
										break;
									}

									qsc_memutils_secure_erase(rmsg, slen);
									qsc_memutils_alloc_free(rmsg);
								}
								else
								{
									/* close the connection on memory allocation failure */
									qsmd_log_write(qsmd_messages_allocate_fail, cadd);
									break;
								}
							}
							else if (pkt.flag == qsmd_flag_connection_terminate)
							{
								qsmd_log_write(qsmd_messages_disconnect, cadd);
								break;
							}
							else if (pkt.flag == qsmd_flag_symmetric_ratchet_request)
							{
								if (symmetric_ratchet_response(prcv->pcns, &pkt) == false)
								{
									qsmd_log_write(qsmd_messages_ratchet_failure, (const char*)prcv->pcns->target.address);
									break;
								}
							}
#if defined(QSMD_ASYMMETRIC_RATCHET)
							else if (pkt.flag == qsmd_flag_asymmetric_ratchet_request)
							{
								if (asymmetric_ratchet_response(prcv->pcns, &pkt) == false)
								{
									qsmd_log_write(qsmd_messages_ratchet_failure, (const char*)prcv->pcns->target.address);
									break;
								}
							}
							else if (pkt.flag == qsmd_flag_asymmetric_ratchet_response)
							{
								if (asymmetric_ratchet_finalize(prcv->pcns, &pkt) == false)
								{
									qsmd_log_write(qsmd_messages_ratchet_failure, (const char*)prcv->pcns->target.address);
									break;
								}
							}
#endif
							else
							{
								qsc_socket_exceptions err = qsc_socket_get_last_error();

								if (err != qsc_socket_exception_success)
								{
									qsmd_log_error(qsmd_messages_receive_fail, err, cadd);

									/* fatal socket errors */
									if (err == qsc_socket_exception_circuit_reset ||
										err == qsc_socket_exception_circuit_terminated ||
										err == qsc_socket_exception_circuit_timeout ||
										err == qsc_socket_exception_dropped_connection ||
										err == qsc_socket_exception_network_failure ||
										err == qsc_socket_exception_shut_down)
									{
										qsmd_log_write(qsmd_messages_connection_fail, cadd);
										break;
									}
								}
							}
						}
						else
						{
							qsmd_log_write(qsmd_messages_receive_fail, cadd);
							break;
						}

						qsc_memutils_secure_erase(rbuf, plen);
					}
				}
				else
				{
					/* close the connection on memory allocation failure */
					qsmd_log_write(qsmd_messages_allocate_fail, cadd);
					break;
				}
			}
			else
			{
				qsmd_log_write(qsmd_messages_receive_fail, cadd);
				break;
			}
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		qsmd_log_write(qsmd_messages_allocate_fail, cadd);
	}
}

static void listener_receive_loop_wrapper(void* state)
{
	listener_receive_loop_args* args = (listener_receive_loop_args*)state;

	if (args != NULL)
	{
		listener_receive_loop(args->prcv);
	}
}

static qsmd_errors listener_duplex_start(const qsmd_server_signature_key* kset, 
	listener_receiver_state* prcv, 
	void (*send_func)(qsmd_connection_state*),
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	QSMD_ASSERT(kset != NULL);
	QSMD_ASSERT(prcv != NULL);
	QSMD_ASSERT(send_func != NULL);

	listener_receive_loop_args largs = { 0 };
	qsmd_kex_duplex_server_state* pkss;
	qsc_thread trcv;
	qsmd_errors qerr;

	qerr = qsmd_error_invalid_input;
	pkss = (qsmd_kex_duplex_server_state*)qsc_memutils_malloc(sizeof(qsmd_kex_duplex_server_state));

	if (pkss != NULL)
	{
		qsc_memutils_clear((uint8_t*)pkss, sizeof(qsmd_kex_duplex_server_state));

		/* initialize the kex */
		listener_duplex_state_initialize(pkss, prcv, kset, key_query);
		qerr = qsmd_kex_duplex_server_key_exchange(pkss, prcv->pcns);

#if defined(QSMD_ASYMMETRIC_RATCHET)
		/* store the local signing key and the remote verify key for asymmetyric ratchet option */
		qsc_memutils_copy(prcv->pcns->sigkey, kset->sigkey, QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
		qsc_memutils_copy(prcv->pcns->verkey, pkss->rverkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
#endif

		qsc_memutils_secure_erase((uint8_t*)pkss, sizeof(qsmd_kex_duplex_server_state));
		qsc_memutils_alloc_free(pkss);
		pkss = NULL;

		if (qerr == qsmd_error_none)
		{
#if defined(QSMD_ASYMMETRIC_RATCHET)
			prcv->pcns->txlock = qsc_async_mutex_create();
#endif
			/* initialize the receiver loop on a new thread */
			largs.prcv = prcv;
			trcv = qsc_async_thread_create(&listener_receive_loop_wrapper, &largs);

			/* start the send loop on the *main* thread */
			send_func(prcv->pcns);

			/* terminate the receiver thread */
			(void)qsc_async_thread_terminate(trcv);

#if defined(QSMD_ASYMMETRIC_RATCHET)
			qsc_memutils_secure_erase(prcv->pcns->sigkey, QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
			qsc_memutils_secure_erase(prcv->pcns->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_async_mutex_destroy(prcv->pcns->txlock);
#endif
		}
	}

	qsmd_logger_dispose();
	
	return qerr;
}
/** \endcond */

/* Public Functions */

/* The Signal ratchet system:
* Signal forwards a set of public cipher keys from the server to client.
* The client uses a public key to encrypt a shared secret and forward the cipher-text to the server.
* The server decrypts the cipher-text, and both client and server use the secret to re-key a symmetric cipher,
* used to encrypt/decrypt text and files.
* This system is very 'top heavy'. 
* It requires the client and server to cache large asymmetric public/private keys,
* changes the key frequently (per message), and large transfers of asymmetric key chains.
* When a server connects to multiple clients, it must track which key-set belongs to which client,
* cache multiple keys while waiting for cipher-text response, scan cached keys for time-outs,
* and generate and send large sets of keys to clients.
* 
* To make this a more efficient model, asymmetric keys should only be cached for as long as they are needed;
* they are created, transmitted, deployed, and the memory released. 
* The symmetric cipher keys can still be replaced, either periodically or with every message, 
* and a periodic injection of entropy with an asymmetric exchange, that can be triggered by the application,
* ex. exceeding a bandwidth count, or per session or even per message, triggers exchange and injection.
* Previous keys can still be protected by running keccak permute on a persistant key state, and using that to
* re-key the symmetric ciphers (possibly with a salt sent over the encrypted channel).
* This will still require key tracking when dealing with server/client, but keys are removed as soon as they are used,
* in a variable collection (item|tag: find/add/remove).
* In a p2p configuration, clients can each sign their piece of the exchange, public key and cipher-text, 
* and no need to track keys as calls are receive-waiting and can be executed in one function.
*/

#if defined(QSMD_ASYMMETRIC_RATCHET)
bool qsmd_duplex_send_asymmetric_ratchet_request(qsmd_connection_state* cns)
{
	QSMD_ASSERT(cns != NULL);

	bool res;
	
	res = false;

	if (cns != NULL)
	{
		qsmd_network_packet pkt = { 0 };
		uint8_t khash[QSMD_HASH_SIZE] = { 0U };
		uint8_t pmsg[QSMD_ASYMMETRIC_SIGNATURE_SIZE + QSMD_HASH_SIZE + QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE] = { 0U };
		uint8_t spct[QSMD_ASYMMETRIC_RATCHET_REQUEST_PACKET_SIZE] = { 0U };
		size_t mlen;
		size_t smlen;
		size_t slen;

		qsc_async_mutex_lock(cns->txlock);

		cns->txseq += 1U;
		pkt.pmessage = spct + QSMD_HEADER_SIZE;
		pkt.flag = qsmd_flag_asymmetric_ratchet_request;
		pkt.msglen = QSMD_ASYMMETRIC_RATCHET_REQUEST_MESSAGE_SIZE;
		pkt.sequence = cns->txseq;

		qsmd_packet_header_serialize(&pkt, spct);
		mlen = QSMD_HEADER_SIZE;

		/* generate the asymmetric cipher keypair */
		qsmd_cipher_generate_keypair(cns->enckey, cns->deckey, qsc_acp_generate);

		/* hash the public key */
		qsc_sha3_compute512(khash, cns->enckey, QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);

		/* sign the hash */
		smlen = 0U;
		qsmd_signature_sign(pmsg, &smlen, khash, sizeof(khash), cns->sigkey, qsc_acp_generate);
		mlen += smlen;

		/* copy the key to the message */
		qsc_memutils_copy(pmsg + smlen, cns->enckey, QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE);
		mlen += QSMD_ASYMMETRIC_ENCAPSULATION_KEY_SIZE;

		/* encrypt the message */
		qsc_rcs_set_associated(&cns->txcpr, spct, QSMD_HEADER_SIZE);
		qsc_rcs_transform(&cns->txcpr, pkt.pmessage, pmsg, sizeof(pmsg));
		mlen += QSMD_MACTAG_SIZE;

		qsc_async_mutex_unlock(cns->txlock);

		/* send the ratchet request */
		slen = qsc_socket_send(&cns->target, spct, mlen, qsc_socket_send_flag_none);

		if (slen == mlen)
		{
			res = true;
		}

		qsc_memutils_secure_erase(khash, sizeof(khash));
		qsc_memutils_secure_erase(pmsg, sizeof(pmsg));
		qsc_memutils_secure_erase(spct, sizeof(spct));
	}

	return res;
}
#endif

bool qsmd_duplex_send_symmetric_ratchet_request(qsmd_connection_state* cns)
{
	QSMD_ASSERT(cns != NULL);

	size_t plen;
	size_t slen;
	bool res;
	
	res = false;

	if (cns != NULL)
	{
		qsmd_network_packet pkt = { 0 };
		uint8_t pmsg[QSMD_RTOK_SIZE + QSMD_MACTAG_SIZE] = { 0U };
		uint8_t rkey[QSMD_RTOK_SIZE] = { 0U };

		/* generate the token key */
		if (qsc_acp_generate(rkey, sizeof(rkey)) == true)
		{
			uint8_t shdr[QSMD_HEADER_SIZE] = { 0U };
			uint8_t spct[QSMD_HEADER_SIZE + QSMD_RTOK_SIZE + QSMD_MACTAG_SIZE] = { 0U };

			cns->txseq += 1U;
			pkt.pmessage = pmsg;
			pkt.flag = qsmd_flag_symmetric_ratchet_request;
			pkt.msglen = QSMD_RTOK_SIZE + QSMD_MACTAG_SIZE;
			pkt.sequence = cns->txseq;

			/* serialize the header and add it to the ciphers associated data */
			qsmd_packet_header_serialize(&pkt, shdr);
			qsc_rcs_set_associated(&cns->txcpr, shdr, QSMD_HEADER_SIZE);
			/* encrypt the message */
			qsc_rcs_transform(&cns->txcpr, pkt.pmessage, rkey, sizeof(rkey));

			/* convert the packet to bytes */
			plen = qsmd_packet_to_stream(&pkt, spct);

			/* send the ratchet request */
			slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);

			if (slen == plen)
			{
				symmetric_ratchet(cns, rkey, sizeof(rkey));
				res = true;
			}

			qsc_memutils_secure_erase(shdr, sizeof(shdr));
			qsc_memutils_secure_erase(spct, sizeof(spct));
		}

		qsc_memutils_secure_erase(pmsg, sizeof(pmsg));
		qsc_memutils_secure_erase(rkey, sizeof(rkey));
	}

	return res;
}

qsmd_errors qsmd_client_duplex_connect_ipv4(const qsmd_server_signature_key* kset, 
	const qsmd_client_verification_key* rverkey, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port,
	void (*send_func)(qsmd_connection_state*), 
	void (*receive_callback)(qsmd_connection_state*, const uint8_t*, size_t))
{
	QSMD_ASSERT(kset != NULL);
	QSMD_ASSERT(rverkey != NULL);
	QSMD_ASSERT(send_func != NULL);
	QSMD_ASSERT(send_func != NULL);
	QSMD_ASSERT(receive_callback != NULL);

	qsmd_kex_duplex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_thread trcv;
	qsc_socket_exceptions serr;
	qsmd_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qsmd_logger_initialize(NULL);

	if (kset != NULL && rverkey != NULL && address != NULL && send_func != NULL && receive_callback != NULL)
	{
		kcs = (qsmd_kex_duplex_client_state*)qsc_memutils_malloc(sizeof(qsmd_kex_duplex_client_state));

		if (kcs != NULL)
		{
			prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

			if (prcv != NULL)
			{
				qsc_memutils_clear(kcs, sizeof(qsmd_kex_duplex_client_state));
				qsc_memutils_clear(prcv, sizeof(client_receiver_state));

				prcv->pcns = (qsmd_connection_state*)qsc_memutils_malloc(sizeof(qsmd_connection_state));

				if (prcv->pcns != NULL)
				{
					prcv->callback = receive_callback;
					qsc_socket_client_initialize(&prcv->pcns->target);

					serr = qsc_socket_client_connect_ipv4(&prcv->pcns->target, address, port);

					if (serr == qsc_socket_exception_success)
					{
						/* initialize the client */
						client_duplex_state_initialize(kcs, prcv->pcns, kset, rverkey);
						/* perform the simplex key exchange */
						qerr = qsmd_kex_duplex_client_key_exchange(kcs, prcv->pcns);
						/* clear the kex state */
						qsc_memutils_secure_erase(kcs, sizeof(qsmd_kex_duplex_client_state));
						qsc_memutils_alloc_free(kcs);
						kcs = NULL;

						if (qerr == qsmd_error_none)
						{
#if defined(QSMD_ASYMMETRIC_RATCHET)
							/* store the local signing key and the remote verify key for asymmetyric ratchet option */
							qsc_memutils_copy(prcv->pcns->sigkey, kset->sigkey, QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
							qsc_memutils_copy(prcv->pcns->verkey, rverkey->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
							prcv->pcns->txlock = qsc_async_mutex_create();
#endif
							/* start the receive loop on a new thread */
							trcv = qsc_async_thread_create(&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);

							/* terminate the receiver thread */
							(void)qsc_async_thread_terminate(trcv);

							/* disconnect the socket */
							qsmd_connection_close(prcv->pcns, qsmd_error_none, true);
							/* dispose of the state */
							client_connection_dispose(prcv);

#if defined(QSMD_ASYMMETRIC_RATCHET)
							qsc_async_mutex_destroy(prcv->pcns->txlock);
							qsc_memutils_secure_erase(prcv->pcns->sigkey, QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
							qsc_memutils_secure_erase(prcv->pcns->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
#endif
						}
						else
						{
							client_connection_dispose(prcv);
							qsmd_log_write(qsmd_messages_kex_fail, (const char*)prcv->pcns->target.address);
							qerr = qsmd_error_exchange_failure;
						}
					}
					else
					{
						/* dispose of the state */
						client_connection_dispose(prcv);
						qsmd_log_write(qsmd_messages_kex_fail, (const char*)prcv->pcns->target.address);
						qerr = qsmd_error_connection_failure;
					}

					qsc_memutils_alloc_free(prcv->pcns);
					prcv->pcns = NULL;
				}
				else
				{
					qsmd_log_message(qsmd_messages_allocate_fail);
					qerr = qsmd_error_memory_allocation;
				}

				qsc_memutils_alloc_free(prcv);
				prcv = NULL;
			}
			else
			{
				qsmd_log_message(qsmd_messages_allocate_fail);
				qerr = qsmd_error_memory_allocation;
			}

			if (kcs != NULL)
			{
				qsc_memutils_alloc_free(kcs);
				kcs = NULL;
			}
		}
		else
		{
			qsmd_log_message(qsmd_messages_allocate_fail);
			qerr = qsmd_error_memory_allocation;
		}
	}
	else
	{
		qsmd_log_message(qsmd_messages_invalid_request);
		qerr = qsmd_error_invalid_input;
	}

	qsmd_logger_dispose();

	return qerr;
}

qsmd_errors qsmd_client_duplex_connect_ipv6(const qsmd_server_signature_key* kset, 
	const qsmd_client_verification_key* rverkey,
	const qsc_ipinfo_ipv6_address* address, uint16_t port,
	void (*send_func)(qsmd_connection_state*),
	void (*receive_callback)(qsmd_connection_state*, const uint8_t*, size_t))
{
	QSMD_ASSERT(kset != NULL);
	QSMD_ASSERT(rverkey != NULL);
	QSMD_ASSERT(send_func != NULL);
	QSMD_ASSERT(send_func != NULL);
	QSMD_ASSERT(receive_callback != NULL);

	qsmd_kex_duplex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_thread trcv;
	qsc_socket_exceptions serr;
	qsmd_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qsmd_logger_initialize(NULL);

	if (kset != NULL && rverkey != NULL && address != NULL && send_func != NULL && receive_callback != NULL)
	{
		kcs = (qsmd_kex_duplex_client_state*)qsc_memutils_malloc(sizeof(qsmd_kex_duplex_client_state));

		if (kcs != NULL)
		{
			prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

			if (prcv != NULL)
			{
				qsc_memutils_clear(kcs, sizeof(qsmd_kex_duplex_client_state));
				qsc_memutils_clear(prcv, sizeof(client_receiver_state));

				prcv->pcns = (qsmd_connection_state*)qsc_memutils_malloc(sizeof(qsmd_connection_state));

				if (prcv->pcns != NULL)
				{
					prcv->callback = receive_callback;
					qsc_socket_client_initialize(&prcv->pcns->target);

					serr = qsc_socket_client_connect_ipv6(&prcv->pcns->target, address, port);

					if (serr == qsc_socket_exception_success)
					{
						/* initialize the client */
						client_duplex_state_initialize(kcs, prcv->pcns, kset, rverkey);
						/* perform the simplex key exchange */
						qerr = qsmd_kex_duplex_client_key_exchange(kcs, prcv->pcns);
						/* clear the kex state */
						qsc_memutils_secure_erase(kcs, sizeof(qsmd_kex_duplex_client_state));
						qsc_memutils_alloc_free(kcs);
						kcs = NULL;

						if (qerr == qsmd_error_none)
						{
#if defined(QSMD_ASYMMETRIC_RATCHET)
							/* store the local signing key and the remote verify key for asymmetyric ratchet option */
							qsc_memutils_copy(prcv->pcns->sigkey, kset->sigkey, QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
							qsc_memutils_copy(prcv->pcns->verkey, rverkey->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
							prcv->pcns->txlock = qsc_async_mutex_create();
#endif
							/* start the receive loop on a new thread */
							trcv = qsc_async_thread_create(&client_receive_loop, prcv);

							/* start the send loop on the main thread */
							send_func(prcv->pcns);

							/* terminate the receiver thread */
							(void)qsc_async_thread_terminate(trcv);

							/* disconnect the socket */
							qsmd_connection_close(prcv->pcns, qsmd_error_none, true);
							/* dispose of the state */
							client_connection_dispose(prcv);

#if defined(QSMD_ASYMMETRIC_RATCHET)
							qsc_async_mutex_destroy(prcv->pcns->txlock);
							qsc_memutils_secure_erase(prcv->pcns->sigkey, QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
							qsc_memutils_secure_erase(prcv->pcns->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
#endif
						}
						else
						{
							qsmd_log_write(qsmd_messages_kex_fail, (const char*)prcv->pcns->target.address);
							qerr = qsmd_error_exchange_failure;
						}
					}
					else
					{
						/* dispose of the state */
						client_connection_dispose(prcv);

						qsmd_log_write(qsmd_messages_kex_fail, (const char*)prcv->pcns->target.address);
						qerr = qsmd_error_connection_failure;
					}

					qsc_memutils_alloc_free(prcv->pcns);
					prcv->pcns = NULL;
				}
				else
				{
					qsmd_log_message(qsmd_messages_allocate_fail);
					qerr = qsmd_error_memory_allocation;
				}

				qsc_memutils_alloc_free(prcv);
				prcv = NULL;
			}
			else
			{
				qsmd_log_message(qsmd_messages_allocate_fail);
				qerr = qsmd_error_memory_allocation;
			}

			if (kcs != NULL)
			{
				qsc_memutils_alloc_free(kcs);
				kcs = NULL;
			}
		}
		else
		{
			qsmd_log_message(qsmd_messages_allocate_fail);
			qerr = qsmd_error_memory_allocation;
		}
	}
	else
	{
		qsmd_log_message(qsmd_messages_invalid_request);
		qerr = qsmd_error_invalid_input;
	}

	qsmd_logger_dispose();

	return qerr;
}

qsmd_errors qsmd_client_duplex_listen_ipv4(const qsmd_server_signature_key* kset, 
	void (*send_func)(qsmd_connection_state*), 
	void (*receive_callback)(qsmd_connection_state*, const uint8_t*, size_t), 
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	QSMD_ASSERT(kset != NULL);
	QSMD_ASSERT(send_func != NULL);
	QSMD_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmd_errors qerr;

	qsmd_logger_initialize(NULL);
	prcv = NULL;

	if (kset != NULL && send_func != NULL && receive_callback != NULL)
	{
		prcv = (listener_receiver_state*)qsc_memutils_malloc(sizeof(listener_receiver_state));

		if (prcv != NULL)
		{
			prcv->pcns = (qsmd_connection_state*)qsc_memutils_malloc(sizeof(qsmd_connection_state));

			if (prcv->pcns != NULL)
			{
				prcv->callback = receive_callback;
				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsmd_connection_state));

				addt = qsc_ipinfo_ipv4_address_any();
				qsc_socket_server_initialize(&prcv->pcns->target);
				qsc_socket_server_initialize(&srvs);

				serr = qsc_socket_server_listen_ipv4(&srvs, &prcv->pcns->target, &addt, QSMD_CLIENT_PORT);

				if (serr == qsc_socket_exception_success)
				{
					qerr = listener_duplex_start(kset, prcv, send_func, key_query);
				}
				else
				{
					qsmd_log_message(qsmd_messages_connection_fail);
					qerr = qsmd_error_connection_failure;
				}

				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsmd_connection_state));
				qsc_memutils_alloc_free(prcv->pcns);
				prcv->pcns = NULL;
			}
			else
			{
				qsmd_log_message(qsmd_messages_allocate_fail);
				qerr = qsmd_error_memory_allocation;
			}

			qsc_memutils_clear((uint8_t*)prcv, sizeof(listener_receiver_state));
			qsc_memutils_alloc_free(prcv);
			prcv = NULL;
		}
		else
		{
			qsmd_log_message(qsmd_messages_allocate_fail);
			qerr = qsmd_error_memory_allocation;
		}
	}
	else
	{
		qsmd_log_message(qsmd_messages_invalid_request);
		qerr = qsmd_error_invalid_input;
	}

	qsmd_logger_dispose();

	return qerr;
}

qsmd_errors qsmd_client_duplex_listen_ipv6(const qsmd_server_signature_key* kset, 
	void (*send_func)(qsmd_connection_state*),
	void (*receive_callback)(qsmd_connection_state*, const uint8_t*, size_t),
	bool (*key_query)(uint8_t* rvkey, const uint8_t* pkid))
{
	QSMD_ASSERT(kset != NULL);
	QSMD_ASSERT(send_func != NULL);
	QSMD_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	listener_receiver_state* prcv;
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	qsmd_errors qerr;

	qsmd_logger_initialize(NULL);
	prcv = NULL;

	if (kset != NULL && send_func != NULL && receive_callback != NULL)
	{
		prcv = (listener_receiver_state*)qsc_memutils_malloc(sizeof(listener_receiver_state));

		if (prcv != NULL)
		{
			prcv->pcns = (qsmd_connection_state*)qsc_memutils_malloc(sizeof(qsmd_connection_state));

			if (prcv->pcns != NULL)
			{
				prcv->callback = receive_callback;
				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsmd_connection_state));

				addt = qsc_ipinfo_ipv6_address_any();
				qsc_socket_server_initialize(&prcv->pcns->target);
				qsc_socket_server_initialize(&srvs);

				serr = qsc_socket_server_listen_ipv6(&srvs, &prcv->pcns->target, &addt, QSMD_CLIENT_PORT);

				if (serr == qsc_socket_exception_success)
				{
					qerr = listener_duplex_start(kset, prcv, send_func, key_query);
				}
				else
				{
					qsmd_log_message(qsmd_messages_connection_fail);
					qerr = qsmd_error_connection_failure;
				}

				qsc_memutils_clear((uint8_t*)prcv->pcns, sizeof(qsmd_connection_state));
				qsc_memutils_alloc_free(prcv->pcns);
				prcv->pcns = NULL;
			}
			else
			{
				qsmd_log_message(qsmd_messages_allocate_fail);
				qerr = qsmd_error_memory_allocation;
			}

			qsc_memutils_clear((uint8_t*)prcv, sizeof(listener_receiver_state));
			qsc_memutils_alloc_free(prcv);
			prcv = NULL;
		}
		else
		{
			qsmd_log_message(qsmd_messages_allocate_fail);
			qerr = qsmd_error_memory_allocation;
		}
	}
	else
	{
		qsmd_log_message(qsmd_messages_invalid_request);
		qerr = qsmd_error_invalid_input;
	}

	qsmd_logger_dispose();

	return qerr;
}
