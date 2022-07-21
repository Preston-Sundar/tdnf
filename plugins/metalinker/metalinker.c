/*
 * Copyright (C) 2020-2021 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"

uint32_t
TDNFMetalinkerXMLCheckVersion(
    )
{
    uint32_t dwError = 0;
    const char *pszVersion = NULL;

    pszVersion = LIBXML_VERSION_STRING;
    if (!pszVersion)
    {
        dwError = ERROR_TDNF_META_VERSION_FAILED;
        BAIL_ON_TDNF_ERROR(dwError);
    }

error:
    return dwError;
}


uint32_t
TDNFMetalinkerCheckFile(
    PTDNF_PLUGIN_HANDLE pHandle,
    PTDNF_EVENT_CONTEXT pContext
    )
{
    uint32_t dwError = 0;

    // DEBUG
    // pr_info("\t %s() \n", __FUNCTION__);
    // pr_info("\t %s \n", pContext->pData->pcszStr);
    dwError = TDNFJoinPath(&pHandle->pszMetaLinkFile,
                           pContext->pData->pcszStr,
                           TDNF_REPO_METALINK_FILE_NAME,
                           NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    // If the metalink file is valid, the plugin requests a download be made.
    if (access(pHandle->pszMetaLinkFile, F_OK))
    {
        if (errno != ENOENT)
        {
            dwError = errno;
            BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
        }
        pHandle->nNeedDownload = 1;
    }

    TDNFDebugDumpPluginHandle(pHandle);

error:
    return dwError;
}

void TDNFDebugDumpPluginHandle(PTDNF_PLUGIN_HANDLE p)
{
    printf("pTdnf: %p\n", p->pTdnf);
    printf("nError: %d\n", p->nError);
    printf("nMetalinkerError: %d\n", p->nMetalinkerError);
    printf("pszMetaLinkFile: %s\n", p->pszMetaLinkFile);
    printf("nNeedDownload: %d\n", p->nNeedDownload);
}