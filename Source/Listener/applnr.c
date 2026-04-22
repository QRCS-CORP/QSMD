/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "applnr.h"
#include "qsmd.h"
#include "client.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "ipinfo.h"
#include "netutils.h"
#include "stringutils.h"

static void listener_print_prompt(void)
{
	qsc_consoleutils_print_safe("listener> ");
}

static void listener_print_error(qsmd_errors error)
{
	const char* msg;

	msg = qsmd_error_to_string(error);

	if (msg != NULL)
	{
		listener_print_prompt();
		qsc_consoleutils_print_line(msg);
	}
}

static void listener_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
		{
			listener_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_line("");
			listener_print_prompt();
		}
	}
}

static void listener_print_string(const char* message, size_t msglen)
{
	if (message != NULL && msglen != 0U)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void listener_print_banner(void)
{
	qsc_consoleutils_print_line("QSMD: Listener Example Project");
	qsc_consoleutils_print_line("Quantum Secure Messaging Duplex Protocol Listener.");
	qsc_consoleutils_print_line("Type 'qsmd asymmetric ratchet' to perform an asymmetric key ratchet operation.");
	qsc_consoleutils_print_line("Type 'qsmd symmetric ratchet' to perform a symmetric key ratchet operation.");
	qsc_consoleutils_print_line("Type 'qsmd quit' to close the connection.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.4.0.0d (A4)");
	qsc_consoleutils_print_line("Date:      March 03, 2026");
	qsc_consoleutils_print_line("Contact:   contact@qrcscorp.ca");
	qsc_consoleutils_print_line("");
}

static bool listener_get_storage_path(char* fpath, size_t pathlen)
{
	bool res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, fpath);
#else
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
#endif

	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, QSMD_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static bool listener_prikey_exists(char fpath[QSC_SYSTEM_MAX_PATH], size_t pathlen)
{
	bool res;

	res = listener_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSMD_PRIKEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static bool listener_senderkey_exists(char fpath[QSC_SYSTEM_MAX_PATH], size_t pathlen)
{
	bool res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, fpath);
#else
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
#endif
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, QSMD_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSMD_SENDER_PUBKEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static bool listener_key_query(uint8_t* rvkey, const uint8_t* pkid)
{
	qsmd_client_verification_key ckey = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char* spub;
	size_t elen;
	bool res;

	(void)pkid;
	res = false;

	/* Note: This is where you would check a set of public key files,
	   using a list of key-ids and corresponding filenames,
	   comparing them to the pkid to match the correct key,
	   and returning the correct key or false if not found. */

	if (listener_senderkey_exists(fpath, sizeof(fpath)) == true)
	{
		elen = qsmd_public_key_encoding_size();
		spub = qsc_memutils_malloc(elen);

		if (spub != NULL)
		{
			qsc_memutils_clear(spub, elen);
			qsc_fileutils_copy_file_to_stream(fpath, spub, elen);
			res = qsmd_public_key_decode(&ckey, spub, elen);
			qsc_memutils_alloc_free(spub);

			if (res == true)
			{
				qsc_memutils_copy(rvkey, ckey.verkey, sizeof(ckey.verkey));
			}
		}
	}
	
	return res;
}

static bool listener_key_dialogue(qsmd_server_signature_key* prik, qsmd_client_verification_key* pubk, uint8_t keyid[QSMD_KEYID_SIZE])
{
	char* spub;
	uint8_t spri[QSMD_SIGNATURE_KEY_SERIALIZED_SIZE] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t elen;
	bool res;

	res = listener_prikey_exists(fpath, sizeof(fpath));

	if (res == true)
	{
		res = qsc_fileutils_copy_file_to_stream(fpath, (char*)spri, sizeof(spri));

		if (res == true)
		{
			qsmd_signature_key_deserialize(prik, spri);
			qsc_memutils_copy(keyid, prik->keyid, QSMD_KEYID_SIZE);
			qsc_memutils_copy(pubk->config, prik->config, QSMD_CONFIG_SIZE);
			qsc_memutils_copy(pubk->keyid, prik->keyid, QSMD_KEYID_SIZE);
			qsc_memutils_copy(pubk->verkey, prik->verkey, QSMD_ASYMMETRIC_VERIFY_KEY_SIZE);
			pubk->expiration = prik->expiration;
			listener_print_message("The private-key has been loaded.");
		}
		else
		{
			listener_print_message("Could not load the key-pair, aborting startup.");
		}
	}
	else
	{
		res = listener_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_folderutils_append_delimiter(fpath);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMD_PUBKEY_NAME);

			listener_print_message("The private-key was not detected, generating a new private/public keypair...");

			res = qsc_acp_generate(keyid, QSMD_KEYID_SIZE);

			if (res == true)
			{
				qsmd_generate_keypair(pubk, prik, keyid);

				elen = qsmd_public_key_encoding_size();
				spub = qsc_memutils_malloc(elen);

				if (spub != NULL)
				{
					qsc_memutils_clear(spub, elen);
					qsmd_public_key_encode(spub, elen, pubk);
					res = qsc_fileutils_copy_stream_to_file(fpath, spub, elen);

					if (res == true)
					{
						qsc_consoleutils_print_safe("listener> The publickey has been saved to ");
						qsc_consoleutils_print_line(fpath);
						listener_print_message("Distribute the public-key to intended clients.");
						listener_print_prompt();

						qsc_stringutils_clear_string(fpath);
						qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
						qsc_folderutils_append_delimiter(fpath);
						qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMD_PRIKEY_NAME);
						qsmd_signature_key_serialize(spri, prik);
						qsc_fileutils_copy_stream_to_file(fpath, (char*)spri, sizeof(spri));
					}
					else
					{
						listener_print_message("Could not load the key-pair, aborting startup.");
					}

					qsc_memutils_alloc_free(spub);
				}
				else
				{
					listener_print_message("Could not encode the public key, aborting startup.");
				}
			}
			else
			{
				listener_print_message("Could not create the key-pair, aborting startup.");
			}
		}
	}

	return res;
}

static void listener_receive_callback(qsmd_connection_state* cns, const uint8_t* pmsg, size_t msglen)
{
	char* cmsg;

	(void)cns;
	cmsg = qsc_memutils_malloc(msglen + sizeof(char));

	if (cmsg != NULL)
	{
		qsc_memutils_clear(cmsg, msglen + sizeof(char));
		qsc_memutils_copy(cmsg, pmsg, msglen);
		qsc_consoleutils_print_safe("RECD: ");
		listener_print_string(cmsg, msglen);
		listener_print_prompt();
		qsc_memutils_alloc_free(cmsg);
	}
}

static void listener_send_loop(qsmd_connection_state* cns)
{
	qsmd_network_packet pkt = { 0 };
	uint8_t msgstr[QSMD_CONNECTION_MTU] = { 0U };
	/* Note: the buffer can be sized to the expected message maximum */
	uint8_t pmsg[QSMD_CONNECTION_MTU] = { 0U };
	char sin[QSMD_CONNECTION_MTU + 1U] = { 0 };
	size_t mlen;
	size_t slen;

	(void)slen;
	mlen = 0U;
	pkt.pmessage = pmsg;

	listener_print_prompt();

	/* start the sender loop */
	while (true)
	{
		if (qsc_consoleutils_line_contains(sin, "qsmd quit"))
		{
			break;
		}
#if defined(QSMD_ASYMMETRIC_RATCHET)
		else if (qsc_consoleutils_line_contains(sin, "qsmd asymmetric ratchet"))
		{
			qsmd_duplex_send_asymmetric_ratchet_request(cns);
			qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
		}
#endif
		else if (qsc_consoleutils_line_contains(sin, "qsmd symmetric ratchet"))
		{
			qsmd_duplex_send_symmetric_ratchet_request(cns);
			qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
		}
		else
		{
			if (mlen > 0U)
			{
				/* convert the packet to bytes */
				qsmd_packet_encrypt(cns, &pkt, (const uint8_t*)sin, mlen);
				qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
				mlen = qsmd_packet_to_stream(&pkt, msgstr);
				slen = qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}
		}

		slen = qsc_consoleutils_get_line(sin, sizeof(sin));
		mlen = (slen > 0U) ? slen - 1U : 0U;

		if (slen > 0U)
		{
			listener_print_prompt();
		}
	}

	qsmd_connection_close(cns, qsmd_error_none, true);
}

int main(void)
{
	qsmd_server_signature_key prik = { 0 };
	qsmd_client_verification_key pubk = { 0 };
	uint8_t kid[QSMD_KEYID_SIZE] = { 0U };
	qsmd_errors qerr;

	listener_print_banner();

	if (listener_key_dialogue(&prik, &pubk, kid) == true)
	{
		qsc_consoleutils_print_line("Waiting for a connection...");
		qerr = qsmd_client_duplex_listen_ipv4(&prik, &listener_send_loop, &listener_receive_callback, &listener_key_query);

		if (qerr != qsmd_error_none)
		{
			listener_print_error(qerr);
			qsc_consoleutils_print_line("The network key-exchange failed, the application will exit.");
		}
	}
	else
	{
		qsc_consoleutils_print_line("The signature key-pair could not be created, the application will exit.");
	}

	qsc_consoleutils_print_line("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}
