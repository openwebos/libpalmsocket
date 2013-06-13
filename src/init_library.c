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

/**
 *******************************************************************************
 * @file init_library.c
 * 
 * @brief  process-atomic library constructor and destructor
 *         functions for libpalmsocket.
 * 
 *******************************************************************************
 */
#include "psl_build_config.h"

#include<pthread.h>
#include<unistd.h>
#include<stdlib.h>
#include<syslog.h>

#include"palmsocket.h"


#include "psl_log.h"


/** ========================================================================
 * =========================================================================
 */
void __attribute__ ((constructor))  psl_library_init(void)
{
    /**
     * @note Init logging before other modules, since they may use
     *       logging
     */
    psl_log_init();

    PSL_LOG_INFO("%s", __func__);
}


/** ========================================================================
 * =========================================================================
 */
void __attribute__ ((destructor)) psl_library_free(void) {
    PSL_LOG_INFO("%s", __func__);


    /**
     * @note Uninit logging after other modules, since they may use
     *       logging.
     */
    psl_log_uninit();
}
