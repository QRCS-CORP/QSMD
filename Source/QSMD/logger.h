/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
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

#ifndef QSMD_LOGGER_H
#define QSMD_LOGGER_H

#include "qsmdcommon.h"

 /**
  * \file logger.h
  * \brief QSMD logging functions.
  *
  * \details
  * This header defines the internal logging functions for the Quantum Secure Tunneling Protocol (QSMD).
  * These functions provide a basic logging subsystem to record operational events, errors, and diagnostic
  * messages during QSMD execution. The logging system is designed for debugging and monitoring purposes and
  * includes functionality to initialize the log, write messages, read and print the log, reset (clear) the log,
  * and retrieve the current log file size.
  *
  * The logging subsystem uses several defined constants:
  *
  * - \c QSMD_LOGGING_MESSAGE_MAX: Defines the maximum allowed length (in characters) for a single log message.
  * - \c QSMD_LOGGER_PATH: The default directory path where the QSMD log file is stored.
  * - \c QSMD_LOGGER_FILE: The default log filename.
  * - \c QSMD_LOGGER_HEAD: The header string written to the log file at initialization, which typically includes
  *   version information.
  *
  * The logger also includes a built-in manual test (\c qsmd_logger_test()) that exercises all of the logging
  * functions to ensure proper operation.
  *
  * \note These functions and constants are internal and non-exportable.
  */

  /*!
   * \def QSMD_LOGGING_MESSAGE_MAX
   * \brief Maximum length of a log message.
   *
   * This macro defines the maximum number of characters allowed for a single log message.
   */
#define QSMD_LOGGING_MESSAGE_MAX 256U

   /*!
	* \var QSMD_LOGGER_PATH
	* \brief Default directory path for QSMD log files.
	*
	* This static constant defines the default directory where the QSMD log file is stored.
	*/
static const char QSMD_LOGGER_PATH[] = "QSMD";

/*!
 * \var QSMD_LOGGER_FILE
 * \brief Default log file name.
 *
 * This static constant defines the default filename for the QSMD log file.
 */
static const char QSMD_LOGGER_FILE[] = "qsmp.log";

/*!
 * \var QSMD_LOGGER_HEAD
 * \brief Log file header string.
 *
 * This static constant defines the header string that is written to the log file upon initialization.
 * It typically includes the QSMD version information.
 */
static const char QSMD_LOGGER_HEAD[] = "QSMD Version 1.1a";

/**
 * \brief Dispose of the logger.
 *
 * \details
 * Flushes any pending state, destroys the mutex created during initialisation,
 * and resets all internal logger state. This function must be called once when
 * the logging subsystem is no longer required, typically at application shutdown.
 * Calling any other logger function after dispose results in undefined behaviour.
 */
void qsmd_logger_dispose(void);

/*!
 * \brief Test if the log file exists.
 *
 * \details
 * This function checks whether the QSMD log file exists in the configured logging directory.
 *
 * \return Returns true if the log file exists, otherwise false.
 */
bool qsmd_logger_exists(void);

/*!
 * \brief Initialize the logger.
 *
 * \details
 * This function initializes the QSMD logging subsystem. It sets the log file path to the provided
 * value and creates the log file if it does not already exist, writing the default header (\c QSMD_LOGGER_HEAD)
 * to the file.
 *
 * \param path: [const] A pointer to a null-terminated string specifying the log file path.
 */
void qsmd_logger_initialize(const char* path);

/*!
 * \brief Print the log file.
 *
 * \details
 * This function outputs the contents of the QSMD log file to the standard output or a designated debug console.
 * It is useful for real-time debugging and monitoring of log messages.
 */
void qsmd_logger_print(void);

/*!
 * \brief Read the log file into a buffer.
 *
 * \details
 * This function reads the contents of the QSMD log file into the provided output array.
 * The caller must ensure that the output buffer is large enough to hold the log contents.
 *
 * \param output: [const] A pointer to the buffer where the log contents will be stored.
 * \param otplen: The size of the output buffer in bytes.
 */
void qsmd_logger_read(char* output, size_t otplen);

/*!
 * \brief Reset the logger.
 *
 * \details
 * This function erases all contents of the QSMD log file, effectively resetting the log.
 * This is useful for clearing old log data before starting a new session or for troubleshooting.
 */
void qsmd_logger_reset(void);

/*!
 * \brief Get the size of the log file.
 *
 * \details
 * This function returns the current size (in bytes) of the QSMD log file.
 *
 * \return Returns the size of the log file in bytes.
 */
size_t qsmd_logger_size(void);

/*!
 * \brief Write a message to the log file.
 *
 * \details
 * This function appends the provided log message to the QSMD log file. The message should be a null-terminated
 * string and must not exceed \c QSMD_LOGGING_MESSAGE_MAX characters.
 *
 * \param message: [const] A pointer to the log message string.
 *
 * \return Returns true if the message was successfully written to the log file; otherwise, false.
 */
bool qsmd_logger_write(const char* message);

#endif
