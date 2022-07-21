/*
 * Copyright (C) 2020 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#pragma once

typedef struct _TDNF_PLUGIN_HANDLE_
{
    PTDNF pTdnf;
    uint32_t nError; /* last error set by this plugin */
    uint32_t nMetalinkerError; /* metalinker specific error. */
    
    char* pszMetaLinkFile; /* string for the metalink file path. */
    char* pszBaseUrlFile; /* string for the metalink file path. */
    uint32_t nNeedDownload; /* metalink file is valid, a download is needed. */

}TDNF_PLUGIN_HANDLE, *PTDNF_PLUGIN_HANDLE;
