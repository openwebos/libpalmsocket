/* @@@LICENSE
*
*      Copyright (c) 2009-2013 LG Electronics, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

/*
 * PalmTestSuite.h
 *
 */


#include <cxxtest/TestSuite.h>


#ifndef PALMTESTSUITE_H_
#define PALMTESTSUITE_H_


/**
 * Contains the Cxx tests
 */
class PalmTestSuite : public CxxTest::TestSuite {
public:
	PalmTestSuite();

	/**
	 * Established a plaintext connection between client and server; transmit 10000000 (ten Million) bytes of data
	 * from cient to server using PmSockWatch for writable/readable notifications; validate received data
	 * content and quantity (e.g., using pattern-based or CRC-based validation)
	 */
	void testBasicHalfDuplexPlainToServer();

	/**
	 * Established a plaintext connection between client and server; transmit 10000000 (ten Million) bytes of data
	 * from server to client using PmSockWatch for writable/readable notifications; validate received data
	 * content and quantity (e.g., using pattern-baed or CRC-based validation)
	 */
	void testBasicHalfDuplexPlainToClient();

	/**
	 * Establish plaintext connection using hostname for server address between client and server, exchange a reasonable
	 * amount of data (10000000 - ten Million bytes) in each direction) in full-duplex mode using PmSockWatch for
	 * readable/writeable notifications; validate received data: amount and content
	 * (e.g., using pattern or CRC-based validation)
	 */
	void testBasicFullDuplexPlainHostnameBased();

	/**
	 * Establish plaintext connection using IP for server address between client and server, exchange a reasonable
	 * amount of data (10000000 - ten Million bytes) in each direction) in full-duplex mode using PmSockWatch for
	 * readable/writeable notifications; validate received data: amount and content
	 * (e.g., using pattern or CRC-based validation)
	 */
	void testBasicFullDuplexPlainIPAddressBased();

	/**
	 * Establish plaintext connection using hostname for server address between client and server, exchange a reasonable
	 * amount of data (10000000 - ten Million bytes) in each direction) in full-duplex mode using PmSockWatch for
	 * readable/writeable notifications;
	 * DIFFERENCE from previous test: on client side there will be only one PmSockWatch watching for G_IO_IN and
	 * G_IO_OUT, too. validate received data: amount and content (e.g., using pattern or CRC-based validation)
	 */
	void testBasicFullDuplexPlainSingleWatch();

	/**
	 * Establish SSL connection between client and server, exchange a reasonable amount of data (10000000 -
	 * ten Million bytes) in each direction) in full-duplex mode using PmSockWatch for readable/writeable notifications;
	 * validate received data: amount and content (e.g., using pattern or CRC-based validation)
	 * Validate connectivity with SSLv3
	 */
	void testBasicFullDuplexSSLv3();

	/**
	 * Establish SSL connection between client and server, exchange a reasonable amount of data (10000000 -
	 * ten Million bytes) in each direction) in full-duplex mode using PmSockWatch for readable/writeable notifications;
	 * validate received data: amount and content (e.g., using pattern or CRC-based validation)
	 * Validate connectivity with TLSv1
	 */
	void testBasicFullDuplexTLSv1();

	/**
	 * basic_validate_deferred_ssl_input_eof
	 * Establish SSL/TLS connection between client and server. Client configures a PmSockWatch instance to
	 * notify for incoming data from server. When notified of readability by PmSockWatch, Clients reads all
	 * incoming data, always requesting 4000 bytes, and validates whatever is returned (content and quantity),
	 * which may be less than 4000 bytes; client should get a total of 10001 (ten Thousand and one) bytes
	 * of data; the final byte read should be read with G_IO_STATUS_NORMAL and subsequent reads should report
	 * G_IO_STATUS_AGAIN until G_IO_STATUS_EOF is finally reported. When Client gets G_IO_STATUS_EOF from
	 * g_io_channel_read_chars, Client initiates bi-directional SSL shutdown and waits for it to complete.
	 * Server sends 10000 (ten Thousand) bytes of data to client. Server sleeps for 5 seconds. Server sends
	 * 1 (one) bytes of data to client and _immediately_  initiates bi-directional SSL shutdown and waits
	 * for it to complete.
	 */
	void testDeferredSSL();

	/**
	 * Established a secure	connection between client and server; transmit 10000000 (ten Million)
	 * bytes of data from cient to server using PmSockWatch for writable/readable notifications;
	 * validate received data content and quantity (e.g., using pattern-based or CRC-based validation)
	 * Report overall throughput in Bytes per second and bits per second
	 */
	void testBasicHalfDuplexSSLToServer();

	/**
	 * Established a secure connection between client and server; transmit 10000000 (ten Million)
	 * bytes of data from server to client using PmSockWatch for writable/readable notifications;
	 * validate received data content and quantity (e.g., using pattern-baed or CRC-based validation)
	 * Report overall throughput in Bytes per second and bits per second
	 */
	void testBasicHalfDuplesSSLToClient();

	/**
	 * Validates PmSockX509CheckCertHostNameMatch(); this function is exported from libpalmsocket via
	 * palmsockx509utils.h.  The comment block for this function in palmsockx509utils.h lists a set of cases
	 * that are not supposed to pass and another set that are supposed to pass.
	 */
	void testBasicCertnameHostnameMatch();

	/**
	 * 1. Append an alias to /etc/hosts on device that maps libpalmsocket.libpalmsocket.com to the
	 * localhost address.
	 * 2. Generate a valid, self-signed certificate with the hostname libpalmsocket.libpalmsocket.com
	 * in the certificate's single Common Name (CN) fied (but not in subjAltName fields)
	 * 3. Establish a secure connection between client and server, using kPmSockCertVerifyOpt_checkHostname,
	 * connecting to the hostname libpalmsocket.libpalmsocket.com and using the server certificate with
	 * libpalmsocket.libpalmsocket.com in the Common Name field.
	 * 4. Exchange 1000 bytes of data between client and server in both directions using
	 * PmSockWatch for writable/readable notifications;
	 * 5. Validate received data content and quantity (e.g., using pattern-based or CRC-based validation)
	 */
	void testCertVerifyHostnameByCommonName();

	/**
	 * 1. Generate a valid, self-signed certificate with the 127.10.10.10 in the certificate's single Common
	 * Name (CN) field (but not in subjAltName fields)
	 * 2. Attempt to establish a secure connection between client and server, using
	 * kPmSockCertVerifyOpt_checkHostname, connecting explicitly to the address 127.0.0.1 and using
	 * the server certificate with 127.10.10.10  in the Common Name field.
	 * 3. Validate via completion callback that connection attempt failed with error code
	 * PSL_ERR_SSL_HOSTNAME_MISMATCH
	 */
	void testCertVerifyHostNameByCommonNameNeg();

	/**
	 * 1. Generate a valid, self-signed certificate with the 127.0.0.1 in the certificate's single Common
	 * Name (CN) field (but not in subjAltName fields)
	 * 2. Establish a secure connection between client and server, using kPmSockCertVerifyOpt_checkHostname,
	 * connecting explicitly to the address 127.0.0.1 and using the server certificate with 127.0.0.1
	 * in the Common Name field.
	 * 3. Exchange 1000 bytes of data between client and server in both directions using
	 * PmSockWatch for writable/readable notifications;
	 * 4. Validate received data content and quantity (e.g., using pattern-based or CRC-based
	 * validation)
	 */
	void testCertVerifyAddressByCommonName();

	/**
	 * 1. Generate a valid, self-signed certificate with the 127.10.10.10 in the certificate's single Common
	 * Name (CN) field (but not in subjAltName fields)
	 * 2. Attempt to establish a secure connection between client and server, using
	 * kPmSockCertVerifyOpt_checkHostname, connecting explicitly to the address 127.0.0.1 and using the
	 * server certificate with 127.10.10.10  in the Common Name field.
	 * 3. Validate via completion callback that connection attempt failed with error code
	 * PSL_ERR_SSL_HOSTNAME_MISMATCH
	 */
	void testCertVerifyAddressByCommonNameNeg();

	/**
	 * 1. Append an alias to /etc/hosts on device that maps libpalmsocket.libpalmsocket.com to the localhost
	 * address.
	 * 2. Generate a valid, self-signed certificate with the hostname libpalmsocket.libpalmsocket.com in
	 * the certificate's single subjAltName/dnsName field (but not in Common Name field(s))
	 * 3. Establish a secure connection between client and server, using kPmSockCertVerifyOpt_checkHostname,
	 * connecting to the hostname libpalmsocket.libpalmsocket.com and using the server certificate with
	 * libpalmsocket.libpalmsocket.com in the subjAltName/dnsName field.
	 * 4. Exchange 1000 bytes of data between client and server in both directions using PmSockWatch for
	 * writable/readable notifications;
	 * 5. Validate received data content and quantity (e.g., using pattern-based or CRC-based validation)
	 */
	void testCertVerifyHostnameBySubjaltName();

	/**
	 * 1. Append an alias to /etc/hosts on device that maps notlibpalmsocket.libpalmsocket.com to the
	 * localhost address.
	 * 2. Generate a valid, self-signed certificate with the hostname libpalmsocket.libpalmsocket.com in
	 * the certificate's single subjAltName/dnsName field (but not in Common Name field(s)); same
	 * as in cert_verify_hostname_by_subjalt_name.
	 * 3. Attempt to establish a secure connection between client and server, using
	 * kPmSockCertVerifyOpt_checkHostname, connecting to the hostname
	 * notlibpalmsocket.libpalmsocket.com and using the server certificate with libpalmsocket.libpalmsocket.com in the
	 * subjAltName/dnsName field.
	 * 4. Validate via completion callback that connection attempt failed with error code
	 * PSL_ERR_SSL_HOSTNAME_MISMATCH;
	 */
	void testCertVerifyHostnameBySubjaltNameNeg();


	/**
	 * 1. Generate a valid, self-signed certificate with the 127.0.0.1 in the certificate's single
	 * subjAltName/ipAddress field (but not in Common Name field(s));
	 * 2. Establish a secure connection between client and server, using kPmSockCertVerifyOpt_checkHostname,
	 * connecting explicitly to the address 127.0.0.1 and using the server certificate with 127.0.0.1 in
	 * the subjAltName/ipAddress field.
	 * 3. Exchange 1000 bytes of data between client and server in both directions using
	 * PmSockWatch for writable/readable notifications;
	 * 4. Validate received data content and quantity (e.g., using pattern-based or CRC-based validation)
	 */
	void testCertVerifyAddressBySubjaltName();

	/**
	 * 1. Generate a valid, self-signed certificate with the 127.10.10.10 in the certificate's single
	 * subjAltName/ipAddress field (but not in Common Name field(s));
	 * 2. Attempt to establish a secure connection between client and server, using
	 * kPmSockCertVerifyOpt_checkHostname, connecting explicitly to the address 127.0.0.1 and using the
	 * server certificate with 127.10.10.10  in the subjAltName/ipAddress field.
	 * 3. Validate via completion callback that connection attempt failed with error code
	 * PSL_ERR_SSL_HOSTNAME_MISMATCH
	 */
	void testCertVerifyAddressBySubjaltNameNeg();

	/**
	 * 1. Generate a self-signed certificate with a validity date range that starts and ends in the past:
	 * start: January 1, 2000; end: January 1, 2001
	 * 2. Establish a secure connection between client and server, using
	 * kPmSockCertVerifyOpt_fallbackToInstalledLeaf, connecting to localhost and using the server certificate
	 * with the validity date range that starts and ends in the past.
	 * 3. Exchange 1000 bytes of data between client and server in both directions using PmSockWatch for
	 * writable/readable notifications;
	 * 4. Validate received data content and quantity (e.g., using pattern-based or CRC-based validation)*
	 */
	void testCertVerifyInstalledLeafFallback();

	/**
	 * 1. Generate a self-signed certificate with a validity date range that starts and ends in the past:
	 * start: January 1, 2000; end: January 1, 2001; same cert as in cert_verify_installed_leaf_fallback.
	 * 2. Attempt to establish a secure connection between client and server,   using not
	 * kPmSockCertVerifyOpt_fallbackToInstalledLeaf, connecting to localhost and using the server
	 * certificate with the validity date range that starts and ends in the past.
	 * 3. Validate via completion callback that connection attempt failed with error code
	 * PSL_ERR_SSL_CERT_VERIFY and via PmSockGetPeerCertVerifyError() that opensslx509_v_err is
	 * X509_V_ERR_CERT_HAS_EXPIRED.
	 */
	void testCertVerifyInstalledLeafFallbackNeg();
};


#endif /* PALMTESTSUITE_H_ */
