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

#include "appsdr.h"
#include "client.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"

static void sender_print_prompt(void)
{
	qsc_consoleutils_print_safe("sender> ");
}

static void sender_print_error(qsmd_errors error)
{
	const char* msg;

	msg = qsmd_error_to_string(error);

	if (msg != NULL)
	{
		sender_print_prompt();
		qsc_consoleutils_print_line(msg);
	}
}

static void sender_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
		{
			sender_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			sender_print_prompt();
		}
	}
}

static void sender_print_string(const char* message, size_t msglen)
{
	if (message != NULL && msglen != 0)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void sender_print_banner(void)
{
	qsc_consoleutils_print_line("QSMD: Sender Example Project");
	qsc_consoleutils_print_line("Quantum Secure Messaging Duplex Protocol Sender.");
	qsc_consoleutils_print_line("Enter the IP address and the server public key to connect.");
	qsc_consoleutils_print_line("Type 'qsmd asymmetric ratchet' to perform an asymmetric key ratchet operation.");
	qsc_consoleutils_print_line("Type 'qsmd symmetric ratchet' to perform a symmetric key ratchet operation.");
	qsc_consoleutils_print_line("Type 'qsmd quit' to close the connection.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.4.0.0d (A4)");
	qsc_consoleutils_print_line("Date:      March 03, 2026");
	qsc_consoleutils_print_line("Contact:   contact@qrcscorp.ca");
	qsc_consoleutils_print_line("");
}

static bool sender_get_storage_path(char fpath[QSC_SYSTEM_MAX_PATH], size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, QSMD_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static bool sender_prikey_exists(char fpath[QSC_SYSTEM_MAX_PATH], size_t pathlen)
{
	bool res;

	res = sender_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSMD_PRIKEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static bool sender_ipv4_dialogue(qsc_ipinfo_ipv4_address* address, qsmd_server_signature_key* sigk, qsmd_client_verification_key* verk)
{
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	uint8_t spri[QSMD_SIGKEY_ENCODED_SIZE] = { 0 };
	char sadd[QSC_IPINFO_IPV4_STRNLEN] = { 0 };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char* spub;
	size_t elen;
	size_t slen;
	bool res;

	res = false;

	/* get the ip address from the user */
	sender_print_message("Enter the destination IPv4 address, ex. 192.168.1.1");
	sender_print_message("");
	slen = qsc_consoleutils_get_formatted_line(sadd, sizeof(sadd));

	if (slen >= QSC_IPINFO_IPV4_MINLEN)
	{
		addv4t = qsc_ipinfo_ipv4_address_from_string(sadd);
		res = (qsc_ipinfo_ipv4_address_is_valid(&addv4t) == true && 
			qsc_ipinfo_ipv4_address_is_zeroed(&addv4t) == false);

		if (res == true)
		{
			qsc_memutils_copy(address->ipv4, addv4t.ipv4, sizeof(addv4t.ipv4));
		}
		else
		{
			sender_print_message("The address format is invalid.");
		}
	}
	else
	{
		sender_print_message("The address format is invalid.");
	}

	/* get the path to the targets public key */
	if (res == true)
	{
		sender_print_message("Enter the path of the listener's public key:");
		sender_print_message("");
		slen = qsc_consoleutils_get_line(fpath, sizeof(fpath)) - 1U;
		res = false;

		if (slen > 0U)
		{
			if (qsc_fileutils_exists(fpath) == true && 
				qsc_stringutils_string_contains(fpath, QSMD_PUBKEY_EXTENSION) == true)
			{
				elen = qsmd_public_key_encoding_size();
				spub = qsc_memutils_malloc(elen);

				if (spub != NULL)
				{
					qsc_memutils_clear(spub, elen);
					qsc_fileutils_copy_file_to_stream(fpath, spub, elen);
					res = qsmd_public_key_decode(verk, spub, elen);
					qsc_memutils_alloc_free(spub);

					if (res == false)
					{
						sender_print_message("The public key is invalid.");
					}
				}
				else
				{
					sender_print_message("The public could not be allocated.");
				}
			}
			else
			{
				sender_print_message("The path is invalid or inaccessable.");
			}
		}
	}

	/* get the clients private key from storage */
	if (res == true)
	{
		res = sender_prikey_exists(fpath, sizeof(fpath));

		if (res == true)
		{
			res = qsc_fileutils_copy_file_to_stream(fpath, (char*)spri, sizeof(spri));

			if (res == true)
			{
				qsmd_signature_key_deserialize(sigk, spri);
				sender_print_message("The private-key has been loaded.");
			}
			else
			{
				sender_print_message("Could not load the key-pair, aborting startup.");
			}
		}
		else
		{
			res = sender_get_storage_path(dir, sizeof(dir));

			if (res == true)
			{
				uint8_t keyid[QSMD_KEYID_SIZE] = { 0U };

				qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
				qsc_folderutils_append_delimiter(fpath);
				qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMD_PUBKEY_NAME);

				sender_print_message("The private-key was not detected, generating a new private/public keypair...");
				res = qsc_acp_generate(keyid, QSMD_KEYID_SIZE);

				if (res == true)
				{
					qsmd_client_verification_key pubk = { 0 };

					qsmd_generate_keypair(&pubk, sigk, keyid);

					elen = qsmd_public_key_encoding_size();
					spub = qsc_memutils_malloc(elen);

					if (spub != NULL)
					{
						qsc_memutils_clear(spub, elen);
						qsmd_public_key_encode(spub, elen, &pubk);
						/* store the encoded public key */
						res = qsc_fileutils_copy_stream_to_file(fpath, spub, elen);
						qsc_memutils_alloc_free(spub);

						if (res == true)
						{
							qsc_consoleutils_print_safe("sender> The publickey has been saved to ");
							qsc_consoleutils_print_line(fpath);
							sender_print_message("Distribute the public-key to intended clients.");
							sender_print_prompt();

							/* store the private key */
							qsc_stringutils_clear_string(fpath);
							qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
							qsc_folderutils_append_delimiter(fpath);
							qsc_stringutils_concat_strings(fpath, sizeof(fpath), QSMD_PRIKEY_NAME);
							qsmd_signature_key_serialize(spri, sigk);
							res = qsc_fileutils_copy_stream_to_file(fpath, (char*)spri, sizeof(spri));
						}
						else
						{
							sender_print_message("Could not load the key-pair, aborting startup.");
						}
					}
					else
					{
						sender_print_message("Public key could not be allocated.");
					}
				}
				else
				{
					sender_print_message("Could not create the key-pair, aborting startup.");
				}
			}
		}
	}

	return res;
}

static void sender_receive_callback(qsmd_connection_state* cns, const uint8_t* pmsg, size_t msglen)
{
	char* cmsg;

	(void)cns;
	cmsg = qsc_memutils_malloc(msglen + sizeof(char));

	if (cmsg != NULL)
	{
		qsc_memutils_clear(cmsg, msglen + sizeof(char));
		qsc_memutils_copy(cmsg, pmsg, msglen);
		qsc_consoleutils_print_safe("RECD: ");
		sender_print_string(cmsg, msglen);
		sender_print_prompt();
		qsc_memutils_alloc_free(cmsg);
	}
}

static void sender_send_loop(qsmd_connection_state* cns)
{
	qsmd_network_packet pkt = { 0 };
	/* Note: the buffer can be sized to the expected message maximum */
	uint8_t pmsg[QSMD_CONNECTION_MTU] = { 0U };
	uint8_t msgstr[QSMD_CONNECTION_MTU] = { 0U };
	char sin[QSMD_CONNECTION_MTU + 1U] = { 0 };
	size_t mlen;
	size_t slen;

	mlen = 0U;
	pkt.pmessage = pmsg;

	sender_print_prompt();

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
				qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}
		}

		slen = qsc_consoleutils_get_line(sin, sizeof(sin));
		mlen = (slen > 0U) ? slen - 1U : 0U;

		if (slen > 0U)
		{
			sender_print_prompt();
		}
	}

	qsmd_connection_close(cns, qsmd_error_none, true);
}

int main(void)
{
	qsmd_server_signature_key sigk = { 0 };
	qsmd_client_verification_key verk = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t ectr;
	bool res;

	res = false;
	ectr = 0U;
	sender_print_banner();

	while (ectr < 3U)
	{
		res = sender_ipv4_dialogue(&addv4t, &sigk, &verk);

		if (res == true)
		{
			break;
		}
		else
		{
			sender_print_prompt();
		}

		++ectr;
	}

	if (res == true)
	{
		qsmd_errors qerr;

		qerr = qsmd_client_duplex_connect_ipv4(&sigk, &verk, &addv4t, QSMD_CLIENT_PORT, &sender_send_loop, &sender_receive_callback);

		if (qerr != qsmd_error_none)
		{
			sender_print_error(qerr);
		}
	}
	else
	{
		qsc_consoleutils_print_line("Invalid input, exiting the application.");
	}
	
	qsc_consoleutils_print_line("The application has exited. Press any key to close..");
	qsc_consoleutils_get_wait();

	return 0;
}
