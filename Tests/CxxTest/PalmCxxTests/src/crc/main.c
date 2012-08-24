/* @@@LICENSE
*
*      Copyright (c) 2009-2011 Hewlett-Packard Development Company, L.P.
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

/**********************************************************************
 *
 * Filename:    main.c
 * 
 * Description: A simple test program for the CRC implementations.
 *
 * Notes:       To test a different CRC standard, modify crc.h.
 *
 * 
 * Copyright (c) 2000 by Michael Barr.  This software is placed into
 * the public domain and may be used for any purpose.  However, this
 * notice must not be changed or removed and no warranty is either
 * expressed or implied by its publication or distribution.
 **********************************************************************/

#include <stdio.h>
#include <string.h>

#include "crc.h"


//void main2(void) {
//	unsigned char  test[] = "123456789";
//
//
//	/*
//	 * Print the check value for the selected CRC algorithm.
//	 */
//	printf("The check value for the %s standard is 0x%X\n", CRC_NAME, CHECK_VALUE);
//
//	/*
//	 * Compute the CRC of the test message, slowly.
//	 */
//	printf("The crcSlow() of \"123456789\" is 0x%X\n", crcSlow(test, strlen(test)));
//
//	/*
//	 * Compute the CRC of the test message, more efficiently.
//	 */
//	crcInit();
//	printf("The crcFast() of \"123456789\" is 0x%X\n", crcFast(test, strlen(test)));
//
//}   /* main() */
