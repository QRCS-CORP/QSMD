#include "qsmd.h"
#include "logger.h"
#include "async.h"
#include "acp.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

#if defined(QSMD_CONFIG_DILITHIUM_KYBER)
#	if defined(QSC_DILITHIUM_S1P44) && defined(QSC_KYBER_S1K2P512)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "dilithium-s1_kyber-s1_sha3_rcs256";
#	elif defined(QSC_DILITHIUM_S3P65) && defined(QSC_KYBER_S3K3P768)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "dilithium-s3_kyber-s3_sha3_rcs256";
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_KYBER_S5K4P1024)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "dilithium-s5_kyber-s5_sha3_rcs256";
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_KYBER_S6K5P1280)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "dilithium-s5_kyber-s6_sha3_rcs256";
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMD_CONFIG_DILITHIUM_MCELIECE)
#	if defined(QSC_DILITHIUM_S1P44) && defined(QSC_MCELIECE_S1N3488T64)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "dilithium-s1_mceliece-s1_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S3P65) && defined(QSC_MCELIECE_S3N4608T96)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "dilithium-s3_mceliece-s3_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_MCELIECE_S5N6688T128)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "dilithium-s5_mceliece-s5_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_MCELIECE_S6N6960T119)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "dilithium-s5_mceliece-s6_sha3_rcs";
#	elif defined(QSC_DILITHIUM_S5P87) && defined(QSC_MCELIECE_S7N8192T128)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "dilithium-s5_mceliece-s7_sha3_rcs";
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSMD_CONFIG_SPHINCS_MCELIECE)
#	if defined(QSC_SPHINCSPLUS_S1S128SHAKERS) && defined(QSC_MCELIECE_S1N3488T64)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "sphincs+-s1s_mceliece-s1_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS) && defined(QSC_MCELIECE_S3N4608T96)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "sphincs+-s3s_mceliece-s3_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS) && defined(QSC_MCELIECE_S5N6688T128)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "sphincs+-s5s_mceliece-s5_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS) && defined(QSC_MCELIECE_S6N6960T119)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "sphincs+-s5s_mceliece-s6_sha3_rcs";
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS) && defined(QSC_MCELIECE_S7N8192T128)
const char QSMD_CONFIG_STRING[QSMD_CONFIG_SIZE] = "sphincs+-s5s_mceliece-s7_sha3_rcs";
#	else
#		error Invalid parameter set!
#	endif
#endif

const char QSMD_ERROR_STRINGS[QSMD_ERROR_STRING_DEPTH][QSMD_ERROR_STRING_WIDTH] =
{
	"No error was detected",
	"The socket accept function returned an error",
	"The symmetric cipher had an authentication failure",
	"The communications channel has failed",
	"The device could not make a connection to the remote host",
	"The transmission failed at the KEX connection phase",
	"The asymmetric cipher failed to decapsulate the shared secret",
	"The decryption authentication has failed",
	"The transmission failed at the KEX establish phase",
	"The transmission failed at the KEX exchange phase",
	"The public - key hash is invalid",
	"The server has run out of socket connections",
	"The expected input was invalid",
	"The packet flag was unexpected",
	"The QSMD public key has expired ",
	"The key identity is unrecognized",
	"The ratchet operation has failed",
	"The listener function failed to initialize",
	"The server has run out of memory",
	"The packet has valid time expired",
	"The packet was received out of sequence",
	"The random generator has failed",
	"The receiver failed at the network layer",
	"The transmitter failed at the network layer",
	"The protocol string was not recognized",
	"The expected data could not be verified",
	"The remote host sent an error or disconnect message",
};

const char QSMD_MESSAGE_STRINGS[QSMD_MESSAGE_STRING_DEPTH][QSMD_MESSAGE_STRING_WIDTH] =
{
	"The operation completed succesfully.",
	"The socket server accept function failed.",
	"The listener socket listener could not connect.",
	"The listener socket could not bind to the address.",
	"The listener socket could not be created.",
	"The server is connected to remote host: ",
	"The socket receive function failed.",
	"The server had a memory allocation failure.",
	"The key exchange has experienced a failure.",
	"The server has disconnected from the remote host: ",
	"The server has disconnected the client due to an error",
	"The server has had a socket level error: ",
	"The server has reached the maximum number of connections",
	"The server listener socket has failed.",
	"The server has run out of socket connections",
	"The message decryption has failed",
	"The connection failed or was interrupted",
	"The function received an invalid request",
	"The host received an asymmetric ratchet request",
	"The host received a symmetric ratchet request",
	"The host received an invalid ratchet request "
};

void qsmd_connection_close(qsmd_connection_state* cns, qsmd_errors err, bool notify)
{
	QSMD_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		if (qsc_socket_is_connected(&cns->target) == true)
		{
			if (notify == true)
			{
				qsmd_network_packet resp = { 0U };

#if defined(QSMD_ASYMMETRIC_RATCHET)
				qsc_async_mutex_lock(cns->txlock);
#endif
				/* build a disconnect message */
				cns->txseq += 1U;
				resp.flag = qsmd_flag_general_error_condition;
				resp.sequence = cns->txseq;
				resp.msglen = QSMD_MACTAG_SIZE + 1U;

				qsmd_packet_set_utc_time(&resp);

				/* tunnel gets encrypted message */
				if (cns->exflag == qsmd_flag_session_established)
				{
					uint8_t spct[QSMD_HEADER_SIZE + QSMD_MACTAG_SIZE + 1U] = { 0U };
					uint8_t pmsg[1U] = { 0U };

					resp.pmessage = spct + QSMD_HEADER_SIZE;
					qsmd_packet_header_serialize(&resp, spct);
					/* the error is the message */
					pmsg[0U] = (uint8_t)err;

					/* add the header to aad */
					qsc_rcs_set_associated(&cns->txcpr, spct, QSMD_HEADER_SIZE);
					/* encrypt the message */
					qsc_rcs_transform(&cns->txcpr, resp.pmessage, pmsg, sizeof(pmsg));
					/* send the message */
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
				else
				{
					/* pre-established phase */
					uint8_t spct[QSMD_HEADER_SIZE + 1U] = { 0U };

					qsmd_packet_header_serialize(&resp, spct);
					spct[QSMD_HEADER_SIZE] = (uint8_t)err;
					/* send the message */
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
#if defined(QSMD_ASYMMETRIC_RATCHET)
				qsc_async_mutex_unlock(cns->txlock);
#endif
			}

			/* close the socket */
			qsc_socket_close_socket(&cns->target);
		}
	}
}

void qsmd_connection_state_dispose(qsmd_connection_state* cns)
{
	QSMD_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		qsc_rcs_dispose(&cns->rxcpr);
		qsc_rcs_dispose(&cns->txcpr);
		qsc_memutils_secure_erase((uint8_t*)&cns->target, sizeof(qsc_socket));
#if defined(QSMD_ASYMMETRIC_RATCHET)
		qsc_memutils_secure_erase(&cns->rtcs, QSMD_ASYMMETRIC_SECRET_SIZE);
#endif
		cns->rxseq = 0U;
		cns->txseq = 0U;
		cns->cid = 0U;
		cns->exflag = qsmd_flag_none;
		cns->receiver = false;
	}
}

bool qsmd_decrypt_error_message(qsmd_errors* merr, qsmd_connection_state* cns, const uint8_t* message)
{
	QSMD_ASSERT(merr != NULL);
	QSMD_ASSERT(cns != NULL);
	QSMD_ASSERT(message != NULL);

	qsmd_network_packet pkt = { 0U };
	uint8_t dmsg[1U] = { 0U };
	const uint8_t* emsg;
	size_t mlen;
	qsmd_errors err;
	bool res;

	mlen = 0U;
	res = false;
	err = qsmd_error_invalid_input;

	if (merr != NULL && cns != NULL && message != NULL)
	{
		if (cns->exflag == qsmd_flag_session_established)
		{
			qsmd_packet_header_deserialize(message, &pkt);
			emsg = message + QSMD_HEADER_SIZE;

			if (pkt.sequence == cns->rxseq + 1U)
			{
				/* anti-replay; verify the packet time */
				if (qsmd_packet_time_valid(&pkt) == true)
				{
					if (pkt.msglen > QSMD_MACTAG_SIZE)
					{
						qsc_rcs_set_associated(&cns->rxcpr, message, QSMD_HEADER_SIZE);
						mlen = pkt.msglen - QSMD_MACTAG_SIZE;

						if (mlen == 1U)
						{
							/* authenticate then decrypt the data */
							if (qsc_rcs_transform(&cns->rxcpr, dmsg, emsg, mlen) == true)
							{
								cns->rxseq += 1;
								err = (qsmd_errors)dmsg[0U];
								res = true;
							}
						}
					}
				}
			}
		}
	}

	*merr = err;

	return res;
}

const char* qsmd_error_to_string(qsmd_errors error)
{
	const char* dsc;

	dsc = NULL;

	if ((size_t)error < QSMD_ERROR_STRING_DEPTH && error >= 0)
	{
		dsc = QSMD_ERROR_STRINGS[(size_t)error];
	}

	return dsc;
}

void qsmd_header_create(qsmd_network_packet* packetout, qsmd_flags flag, uint64_t sequence, uint32_t msglen)
{
	QSMD_ASSERT(packetout != NULL);

	if (packetout != NULL)
	{
		packetout->flag = flag;
		packetout->sequence = sequence;
		packetout->msglen = msglen;
		/* set the packet creation time */
		qsmd_packet_set_utc_time(packetout);
	}
}

qsmd_errors qsmd_header_validate(qsmd_connection_state* cns, const qsmd_network_packet* packetin, qsmd_flags kexflag, qsmd_flags pktflag, uint64_t sequence, uint32_t msglen)
{
	QSMD_ASSERT(cns != NULL);
	QSMD_ASSERT(packetin != NULL);

	qsmd_errors merr;

	merr = qsmd_error_invalid_input;

	if (cns != NULL && packetin != NULL)
	{
		if (packetin->flag == qsmd_flag_general_error_condition)
		{
			if (packetin->pmessage != NULL)
			{
				merr = (qsmd_errors)packetin->pmessage[0U];
			}
			else
			{
				merr = qsmd_error_invalid_request;
			}
		}
		else
		{
			if (qsmd_packet_time_valid(packetin) == true)
			{
				if (packetin->msglen == msglen)
				{
					if (packetin->sequence == sequence)
					{
						if (packetin->flag == pktflag)
						{
							if (cns->exflag == kexflag)
							{
								cns->rxseq += 1U;
								merr = qsmd_error_none;
							}
							else
							{
								merr = qsmd_error_invalid_request;
							}
						}
						else
						{
							merr = qsmd_error_invalid_request;
						}
					}
					else
					{
						merr = qsmd_error_packet_unsequenced;
					}
				}
				else
				{
					merr = qsmd_error_receive_failure;
				}
			}
			else
			{
				merr = qsmd_error_message_time_invalid;
			}
		}
	}

	return merr;
}

void qsmd_generate_keypair(qsmd_client_verification_key* pubkey, qsmd_server_signature_key* prikey, const uint8_t* keyid)
{
	QSMD_ASSERT(prikey != NULL);
	QSMD_ASSERT(pubkey != NULL);
	QSMD_ASSERT(keyid != NULL);

	if (prikey != NULL && pubkey != NULL && keyid != NULL)
	{
		/* add the timestamp plus duration to the key */
		prikey->expiration = qsc_timestamp_datetime_utc() + QSMD_PUBKEY_DURATION_SECONDS;

		/* set the configuration string and key-identity strings */
		qsc_memutils_copy(prikey->config, QSMD_CONFIG_STRING, QSMD_CONFIG_SIZE);
		qsc_memutils_copy(prikey->keyid, keyid, QSMD_KEYID_SIZE);

		/* generate the signature key-pair */
		qsmd_signature_generate_keypair(prikey->verkey, prikey->sigkey, qsc_acp_generate);

		/* copy the key expiration, config, key-id, and the signatures verification key, to the public key structure */
		pubkey->expiration = prikey->expiration;
		qsc_memutils_copy(pubkey->config, prikey->config, QSMD_CONFIG_SIZE);
		qsc_memutils_copy(pubkey->keyid, prikey->keyid, QSMD_KEYID_SIZE);
		qsc_memutils_copy(pubkey->verkey, prikey->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
	}
}

const char* qsmd_get_error_description(qsmd_messages emsg)
{
	const char* dsc;

	dsc = NULL;

	if ((size_t)emsg < QSMD_MESSAGE_STRING_DEPTH && emsg >= 0U)
	{
		dsc = QSMD_MESSAGE_STRINGS[(size_t)emsg];
	}

	return dsc;
}

void qsmd_log_error(qsmd_messages emsg, qsc_socket_exceptions err, const char* msg)
{
	QSMD_ASSERT(msg != NULL);

	char mtmp[QSMD_ERROR_STRING_WIDTH * 2] = { 0 };
	const char* perr;
	const char* phdr;
	const char* pmsg;

	pmsg = qsmd_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
			qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
			qsmd_logger_write(mtmp);
		}
		else
		{
			qsmd_logger_write(pmsg);
		}
	}

	phdr = qsmd_get_error_description(qsmd_messages_socket_message);
	perr = qsc_socket_error_to_string(err);

	if (pmsg != NULL && perr != NULL)
	{
		qsc_stringutils_clear_string(mtmp);
		qsc_stringutils_copy_string(mtmp, sizeof(mtmp), phdr);
		qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), perr);
		qsmd_logger_write(mtmp);
	}
}

void qsmd_log_message(qsmd_messages emsg)
{
	const char* msg = qsmd_get_error_description(emsg);

	if (msg != NULL)
	{
		qsmd_logger_write(msg);
	}
}

void qsmd_log_system_error(qsmd_errors err)
{
	char mtmp[QSMD_ERROR_STRING_WIDTH * 2U] = { 0 };
	const char* perr;
	const char* pmsg;

	pmsg = qsmd_error_to_string(qsmd_messages_system_message);
	perr = qsmd_error_to_string(err);

	qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
	qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), ": ");
	qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), perr);

	qsmd_logger_write(mtmp);
}

void qsmd_log_write(qsmd_messages emsg, const char* msg)
{
	QSMD_ASSERT(msg != NULL);

	const char* pmsg = qsmd_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			char mtmp[QSMD_ERROR_STRING_WIDTH + 1U] = { 0 };

			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);

			if ((qsc_stringutils_string_size(msg) + qsc_stringutils_string_size(mtmp)) < sizeof(mtmp))
			{
				qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
				qsmd_logger_write(mtmp);
			}
		}
		else
		{
			qsmd_logger_write(pmsg);
		}
	}
}

void qsmd_packet_clear(qsmd_network_packet* packet)
{
	QSMD_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		if (packet->msglen != 0U)
		{
			qsc_memutils_secure_erase(packet->pmessage, packet->msglen);
		}

		packet->flag = (uint8_t)qsmd_flag_none;
		packet->msglen = 0U;
		packet->sequence = 0U;
		packet->utctime = 0U;
	}
}

qsmd_errors qsmd_packet_decrypt(qsmd_connection_state* cns, uint8_t* message, size_t* msglen, const qsmd_network_packet* packetin)
{
	QSMD_ASSERT(cns != NULL);
	QSMD_ASSERT(packetin != NULL);
	QSMD_ASSERT(message != NULL);
	QSMD_ASSERT(msglen != NULL);

	uint8_t hdr[QSMD_HEADER_SIZE] = { 0U };
	qsmd_errors qerr;

	qerr = qsmd_error_invalid_input;
	*msglen = 0U;

	if (cns != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		if (packetin->sequence == cns->rxseq + 1U)
		{
			if (cns->exflag == qsmd_flag_session_established)
			{
				if (qsmd_packet_time_valid(packetin) == true)
				{
					if (packetin->msglen > QSMD_MACTAG_SIZE)
					{
						/* serialize the header and add it to the ciphers associated data */
						qsmd_packet_header_serialize(packetin, hdr);

						qsc_rcs_set_associated(&cns->rxcpr, hdr, QSMD_HEADER_SIZE);
						*msglen = (size_t)packetin->msglen - QSMD_MACTAG_SIZE;

						/* authenticate then decrypt the data */
						if (qsc_rcs_transform(&cns->rxcpr, message, packetin->pmessage, *msglen) == true)
						{
							cns->rxseq += 1U;
							qerr = qsmd_error_none;
						}
						else
						{
							*msglen = 0U;
							qerr = qsmd_error_authentication_failure;
						}
					}
					else
					{
						*msglen = 0U;
						qerr = qsmd_error_receive_failure;
					}
				}
				else
				{
					qerr = qsmd_error_message_time_invalid;
				}
			}
			else
			{
				qerr = qsmd_error_channel_down;
			}
		}
		else
		{
			qerr = qsmd_error_packet_unsequenced;
		}
	}

	return qerr;
}

qsmd_errors qsmd_packet_encrypt(qsmd_connection_state* cns, qsmd_network_packet* packetout, const uint8_t* message, size_t msglen)
{
	QSMD_ASSERT(cns != NULL);
	QSMD_ASSERT(message != NULL);
	QSMD_ASSERT(packetout != NULL);

	qsmd_errors qerr;

	qerr = qsmd_error_invalid_input;

	if (cns != NULL && message != NULL && packetout != NULL)
	{
		if (cns->exflag == qsmd_flag_session_established && msglen != 0)
		{
			uint8_t hdr[QSMD_HEADER_SIZE] = { 0U };

#if defined(QSMD_ASYMMETRIC_RATCHET)
			qsc_async_mutex_lock(cns->txlock);
#endif
			/* assemble the encryption packet */
			cns->txseq += 1U;
			qsmd_header_create(packetout, qsmd_flag_encrypted_message, cns->txseq, (uint32_t)msglen + QSMD_MACTAG_SIZE);

			/* serialize the header and add it to the ciphers associated data */
			qsmd_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&cns->txcpr, hdr, QSMD_HEADER_SIZE);
			/* encrypt the message */
			(void)qsc_rcs_transform(&cns->txcpr, packetout->pmessage, message, msglen);
#if defined(QSMD_ASYMMETRIC_RATCHET)
			qsc_async_mutex_unlock(cns->txlock);
#endif
			qerr = qsmd_error_none;
		}
		else
		{
			qerr = qsmd_error_channel_down;
		}
	}

	return qerr;
}

void qsmd_packet_error_message(qsmd_network_packet* packet, qsmd_errors error)
{
	QSMD_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = qsmd_flag_general_error_condition;
		packet->msglen = QSMD_ERROR_MESSAGE_SIZE;
		packet->sequence = QSMD_ERROR_SEQUENCE;
		packet->pmessage[0U] = (uint8_t)error;
		qsmd_packet_set_utc_time(packet);
	}
}

void qsmd_packet_header_deserialize(const uint8_t* header, qsmd_network_packet* packet)
{
	QSMD_ASSERT(header != NULL);
	QSMD_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		packet->flag = header[0U];
		pos = QSMD_FLAG_SIZE;
		packet->msglen = qsc_intutils_le8to32(header + pos);
		pos += QSMD_MSGLEN_SIZE;
		packet->sequence = qsc_intutils_le8to64(header + pos);
		pos += QSMD_SEQUENCE_SIZE;
		packet->utctime = qsc_intutils_le8to64(header + pos);
	}
}

void qsmd_packet_header_serialize(const qsmd_network_packet* packet, uint8_t* header)
{
	QSMD_ASSERT(header != NULL);
	QSMD_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		header[0U] = packet->flag;
		pos = QSMD_FLAG_SIZE;
		qsc_intutils_le32to8(header + pos, packet->msglen);
		pos += QSMD_MSGLEN_SIZE;
		qsc_intutils_le64to8(header + pos, packet->sequence);
		pos += QSMD_SEQUENCE_SIZE;
		qsc_intutils_le64to8(header + pos, packet->utctime);
	}
}

void qsmd_packet_set_utc_time(qsmd_network_packet* packet)
{
	QSMD_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->utctime = qsc_timestamp_datetime_utc();
	}
}

bool qsmd_packet_time_valid(const qsmd_network_packet* packet)
{
	QSMD_ASSERT(packet != NULL);

	uint64_t ltime;
	bool res;

	res = false;

	if (packet != NULL)
	{
		ltime = qsc_timestamp_datetime_utc();

		/* two-way variance to account for differences in system clocks */
		if (ltime > 0U && ltime < UINT64_MAX &&
			UINT64_MAX - packet->utctime >= QSMD_PACKET_TIME_THRESHOLD &&
			packet->utctime >= QSMD_PACKET_TIME_THRESHOLD)
		{
			res = (ltime >= packet->utctime - QSMD_PACKET_TIME_THRESHOLD && ltime <= packet->utctime + QSMD_PACKET_TIME_THRESHOLD);
		}
	}

	return res;
}

bool qsmd_public_key_compare(const qsmd_client_verification_key* a, const qsmd_client_verification_key* b)
{
	QSMD_ASSERT(a != NULL);
	QSMD_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (a->expiration == b->expiration)
		{
			if (qsc_memutils_are_equal(a->config, b->config, QSMD_CONFIG_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->keyid, b->keyid, QSMD_KEYID_SIZE) == true)
				{
					res = qsc_memutils_are_equal(a->verkey, b->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
				}
			}
		}
	}

	return res;
}

bool qsmd_public_key_decode(qsmd_client_verification_key* pubk, const char* enck, size_t enclen)
{
	QSMD_ASSERT(pubk != NULL);
	QSMD_ASSERT(enck != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char* pvk;
	size_t elen;
	size_t spos;
	size_t slen;
	bool res;

	res = false;

	if (pubk != NULL && enck != NULL)
	{
		spos = sizeof(QSMD_PUBKEY_HEADER) - 1U;
		++spos;

		slen = sizeof(QSMD_PUBKEY_VERSION) - 1U;
		spos += slen;
		++spos;

		spos += sizeof(QSMD_PUBKEY_CONFIG_PREFIX) - 1U;
		slen = sizeof(QSMD_CONFIG_STRING) - 1U;

		qsc_memutils_copy(pubk->config, enck + spos, slen);
		spos += slen;
		++spos;

		spos += sizeof(QSMD_PUBKEY_KEYID_PREFIX) - 1U;
		qsc_intutils_hex_to_bin(enck + spos, pubk->keyid, QSMD_KEYID_SIZE);
		spos += (QSMD_KEYID_SIZE * 2U);
		++spos;

		spos += sizeof(QSMD_PUBKEY_EXPIRATION_PREFIX) - 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(dtm, enck + spos, slen);
		spos += QSC_TIMESTAMP_STRING_SIZE;
		pubk->expiration = qsc_timestamp_datetime_to_seconds(dtm);

		elen = qsc_encoding_base64_encoded_size(QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
		pvk = qsc_memutils_malloc(elen);

		if (pvk != NULL)
		{
			qsc_memutils_secure_erase(pvk, elen);
			elen = qsc_stringutils_remove_line_breaks(pvk, elen, enck + spos, enclen - spos);
			res = qsc_encoding_base64_decode(pubk->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE, pvk, elen);
			qsc_memutils_alloc_free(pvk);
		}
	}

	return res;
}

size_t qsmd_public_key_encode(char* enck, size_t enclen, const qsmd_client_verification_key* pubk)
{
	QSMD_ASSERT(enck != NULL);
	QSMD_ASSERT(pubk != NULL);

	char dtm[QSMD_TIMESTAMP_STRING_SIZE] = { 0 };
	char hexid[(QSMD_KEYID_SIZE * 2U)] = { 0 };
	char* prvs;
	size_t elen;
	size_t slen;
	size_t spos;

	spos = 0U;

	if (enck != NULL && pubk != NULL)
	{
		slen = sizeof(QSMD_PUBKEY_HEADER) - 1U;
		qsc_memutils_copy(enck, QSMD_PUBKEY_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMD_PUBKEY_VERSION) - 1U;
		qsc_memutils_copy(enck + spos, QSMD_PUBKEY_VERSION, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMD_PUBKEY_CONFIG_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSMD_PUBKEY_CONFIG_PREFIX, slen);
		spos += slen;
		slen = sizeof(QSMD_CONFIG_STRING) - 1U;
		qsc_memutils_copy(enck + spos, QSMD_CONFIG_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMD_PUBKEY_KEYID_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSMD_PUBKEY_KEYID_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(pubk->keyid, hexid, QSMD_KEYID_SIZE);
		slen = sizeof(hexid);
		qsc_memutils_copy(enck + spos, hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSMD_PUBKEY_EXPIRATION_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSMD_PUBKEY_EXPIRATION_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(pubk->expiration, dtm);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(enck + spos, dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = QSMD_ASYMMETRIC_VERIFY_KEY_SIZE;
		elen = qsc_encoding_base64_encoded_size(slen);
		prvs = qsc_memutils_malloc(elen);

		if (prvs != NULL)
		{
			qsc_memutils_clear(prvs, elen);
			qsc_encoding_base64_encode(prvs, elen, pubk->verkey, slen);
			spos += qsc_stringutils_add_line_breaks(enck + spos, enclen - spos, QSMD_PUBKEY_LINE_LENGTH, prvs, elen);
			qsc_memutils_alloc_free(prvs);
			enck[spos] = '\n';
		}

		enck[spos] = '\n';
		++spos;
		slen = sizeof(QSMD_PUBKEY_FOOTER) - 1U;
		qsc_memutils_copy((enck + spos), QSMD_PUBKEY_FOOTER, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;
	}

	return spos;
}

size_t qsmd_public_key_encoding_size(void)
{
	size_t elen;
	size_t klen;

	elen = sizeof(QSMD_PUBKEY_HEADER) - 1U;
	++elen;
	elen += sizeof(QSMD_PUBKEY_VERSION) - 1U;
	++elen;
	elen += sizeof(QSMD_PUBKEY_CONFIG_PREFIX) - 1U;
	elen += sizeof(QSMD_CONFIG_STRING) - 1U;
	++elen;
	elen += sizeof(QSMD_PUBKEY_KEYID_PREFIX) - 1U;
	elen += (QSMD_KEYID_SIZE * 2);
	++elen;
	elen += sizeof(QSMD_PUBKEY_EXPIRATION_PREFIX) - 1U;
	elen += QSC_TIMESTAMP_STRING_SIZE - 1U;
	++elen;
	klen = qsc_encoding_base64_encoded_size(QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
	elen += klen + (klen / QSMD_PUBKEY_LINE_LENGTH) + 1U;
	++elen;
	elen += sizeof(QSMD_PUBKEY_FOOTER) - 1U;
	++elen;

	return elen;
}

void qsmd_signature_key_deserialize(qsmd_server_signature_key* kset, const uint8_t* serk)
{
	QSMD_ASSERT(kset != NULL);
	QSMD_ASSERT(serk != NULL);

	size_t pos;

	if (kset != NULL && serk != NULL)
	{
		qsc_memutils_copy(kset->config, serk, QSMD_CONFIG_SIZE);
		pos = QSMD_CONFIG_SIZE;
		kset->expiration = qsc_intutils_le8to64((serk + pos));
		pos += QSMD_TIMESTAMP_SIZE;
		qsc_memutils_copy(kset->keyid, (serk + pos), QSMD_KEYID_SIZE);
		pos += QSMD_KEYID_SIZE;
		qsc_memutils_copy(kset->sigkey, (serk + pos), QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
		pos += QSMD_ASYMMETRIC_SIGNING_KEY_SIZE;
		qsc_memutils_copy(kset->verkey, (serk + pos), QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
	}
}

void qsmd_signature_key_serialize(uint8_t* serk, const qsmd_server_signature_key* kset)
{
	QSMD_ASSERT(serk != NULL);
	QSMD_ASSERT(kset != NULL);

	size_t pos;

	if (serk != NULL && kset != NULL)
	{
		qsc_memutils_copy(serk, kset->config, QSMD_CONFIG_SIZE);
		pos = QSMD_CONFIG_SIZE;
		qsc_intutils_le64to8((serk + pos), kset->expiration);
		pos += QSMD_TIMESTAMP_SIZE;
		qsc_memutils_copy((serk + pos), kset->keyid, QSMD_KEYID_SIZE);
		pos += QSMD_KEYID_SIZE;
		qsc_memutils_copy((serk + pos), kset->sigkey, QSMD_ASYMMETRIC_SIGNING_KEY_SIZE);
		pos += QSMD_ASYMMETRIC_SIGNING_KEY_SIZE;
		qsc_memutils_copy((serk + pos), kset->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
	}
}

size_t qsmd_packet_to_stream(const qsmd_network_packet* packet, uint8_t* pstream)
{
	QSMD_ASSERT(packet != NULL);
	QSMD_ASSERT(pstream != NULL);

	size_t pos;
	size_t res;

	res = 0U;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0U] = packet->flag;
		pos = QSMD_FLAG_SIZE;
		qsc_intutils_le32to8(pstream + pos, packet->msglen);
		pos += QSMD_MSGLEN_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->sequence);
		pos += QSMD_SEQUENCE_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->utctime);
		pos += QSMD_TIMESTAMP_SIZE;
		qsc_memutils_copy(pstream + pos, packet->pmessage, packet->msglen);
		res = (size_t)QSMD_HEADER_SIZE + packet->msglen;
	}

	return res;
}

bool qsmd_stream_to_packet(const uint8_t* pstream, qsmd_network_packet* packet)
{
	QSMD_ASSERT(packet != NULL);
	QSMD_ASSERT(pstream != NULL);

	size_t pos;
	bool res;

	res = false;

	if (packet != NULL && pstream != NULL)
	{
		packet->flag = pstream[0U];
		pos = QSMD_FLAG_SIZE;
		packet->msglen = qsc_intutils_le8to32(pstream + pos);
		pos += QSMD_MSGLEN_SIZE;
		packet->sequence = qsc_intutils_le8to64(pstream + pos);
		pos += QSMD_SEQUENCE_SIZE;
		packet->utctime = qsc_intutils_le8to64(pstream + pos);
		pos += QSMD_TIMESTAMP_SIZE;
		qsc_memutils_copy(packet->pmessage, pstream + pos, packet->msglen);

		res = (packet->flag <= (uint8_t)qsmd_flag_general_error_condition && 
			packet->msglen <= QSMD_MESSAGE_MAX);
	}

	return res;
}

#if defined (QSMD_DEBUG_MODE)
bool qsmd_certificate_encoding_test(void)
{
	qsmd_client_verification_key pcpy = { 0 };
	qsmd_client_verification_key pkey = { 0 };
	qsmd_server_signature_key skey = { 0 };
	uint8_t keyid[QSMD_KEYID_SIZE] = { 0U };
	char* enck;
	size_t elen;
	bool res;

	res = false;
	qsc_acp_generate(keyid, sizeof(keyid));
	qsmd_generate_keypair(&pkey, &skey, keyid);

	elen = qsmd_public_key_encoding_size();
	enck = qsc_memutils_malloc(elen);

	if (enck != NULL)
	{
		qsc_memutils_clear(enck, elen);

		qsmd_public_key_encode(enck, elen, &pkey);
		qsmd_public_key_decode(&pcpy, enck, elen);

		res = qsmd_public_key_compare(&pkey, &pcpy);
		qsc_memutils_alloc_free(enck);
	}

	return res;
}
#endif
