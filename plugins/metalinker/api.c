/*
 * Copyright (C) 2022 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#include "includes.h"
#include "config.h"

TDNF_PLUGIN_INTERFACE _interface = {0};

const char *
TDNFPluginGetVersion(
    )
{
    return PLUGIN_VERSION;
}

const char *
TDNFPluginGetName(
    )
{
    return PLUGIN_NAME;
}

uint32_t
TDNFPluginLoadInterface(
    PTDNF_PLUGIN_INTERFACE pInterface
    )
{
    uint32_t dwError = 0;

    if (!pInterface)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    //printf("[METALINKER]: %s.\n", __FUNCTION__);
    pInterface->pFnInitialize = TDNFMetalinkerCheckInitialize;
    pInterface->pFnEventsNeeded = TDNFMetalinkerCheckEventsNeeded;
    pInterface->pFnGetErrorString = TDNFMetalinkerCheckGetErrorString;
    pInterface->pFnEvent = TDNFMetalinkerCheckEvent;
    pInterface->pFnCloseHandle = TDNFMetalinkerCheckClose;

error:
    return dwError;
}

uint32_t
TDNFMetalinkerCheckInitialize(
    const char *pszConfig,
    PTDNF_PLUGIN_HANDLE *ppHandle
    )
{
    UNUSED(pszConfig);
    uint32_t dwError = 0;
    PTDNF_PLUGIN_HANDLE pHandle = NULL;

    /* plugin does not expect config */
    if (!ppHandle)
    {
        dwError = 1;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFMetalinkerXMLCheckVersion();
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateMemory(sizeof(*pHandle), 1, (void **)&pHandle);
    BAIL_ON_TDNF_ERROR(dwError);

    *ppHandle = pHandle;

cleanup:
    return dwError;

error:
    FreePluginHandle(pHandle);
    goto cleanup;
}


uint32_t
TDNFMetalinkerCheckEventsNeeded(
    const PTDNF_PLUGIN_HANDLE pHandle,
    TDNF_PLUGIN_EVENT_TYPE *pnEvents
    )
{
    uint32_t dwError = 0;
    if (!pHandle || !pnEvents)
    {
        dwError = 1;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    // NOTE: may require adding new event types to the plugin interface. 
    *pnEvents = TDNF_PLUGIN_EVENT_TYPE_REPO | TDNF_PLUGIN_EVENT_TYPE_REPO_MD;

cleanup:
    return dwError;

error:
    goto cleanup;

}


uint32_t
TDNFMetalinkerCheckGetErrorString(
    PTDNF_PLUGIN_HANDLE pHandle,
    uint32_t nErrorCode,
    char **ppszError
    )
{
    uint32_t dwError = 0;
    char *pszError = NULL;
    char *pszErrorPre = NULL;
    // const char *pszMetalinkerError = NULL;
    TDNF_ERROR_DESC arErrorDesc[] = METALINKER_ERROR_TABLE;

    if (!pHandle || !ppszError)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (nErrorCode > ERROR_TDNF_META_BASE_START && nErrorCode < ERROR_TDNF_LIBXML_START)
    {
        for(size_t i = 0; i < ARRAY_SIZE(arErrorDesc); ++i)
        {
            if (nErrorCode == (uint32_t)arErrorDesc[i].nCode)
            {
                pszErrorPre = arErrorDesc[i].pszDesc;
                break;
            }
        }
        BAIL_ON_TDNF_ERROR(dwError);
    }

    // NOTE: Handle libxml errors here. 
    // if (pHandle->nGPGError)
    // {
    //     pszGPGError = gpgme_strerror(pHandle->nGPGError);
    // }

    if (pszErrorPre)
    {
        dwError = TDNFAllocateStringPrintf(
                      &pszError, "%s: %s\n",
                      METALINKER_PLUGIN_ERROR, pszErrorPre);
    }
    BAIL_ON_TDNF_ERROR(dwError);

    *ppszError = pszError;

cleanup:
    return dwError;

error:
    TDNF_SAFE_FREE_MEMORY(pszError);
    goto cleanup;
}


/*
 * pContext->nEvent has the following
 * 1. event type such as TDNF_PLUGIN_EVENT_TYPE_REPO
 * 2. event state such as TDNF_PLUGIN_EVENT_STATE_READCONFIG
 * 3. event phase such as TDNF_PLUGIN_EVENT_PHASE_START
 * pContext->pTdnf is the handle to libtdnf
*/
uint32_t
TDNFMetalinkerCheckEvent(
    PTDNF_PLUGIN_HANDLE pHandle,
    PTDNF_EVENT_CONTEXT pContext
    )
{
    uint32_t dwError = 0;
    TDNF_PLUGIN_EVENT_TYPE nEventType = TDNF_PLUGIN_EVENT_TYPE_NONE;
    TDNF_PLUGIN_EVENT_STATE nEventState = TDNF_PLUGIN_EVENT_STATE_NONE;
    TDNF_PLUGIN_EVENT_PHASE nEventPhase = TDNF_PLUGIN_EVENT_PHASE_NONE;

    if (!pHandle || !pContext)
    {
        dwError = 1;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    nEventType = PLUGIN_EVENT_TYPE(pContext->nEvent);
    nEventState = PLUGIN_EVENT_STATE(pContext->nEvent);
    nEventPhase = PLUGIN_EVENT_PHASE(pContext->nEvent);

    if (nEventType == TDNF_PLUGIN_EVENT_TYPE_INIT)
    {
        printf("[METALINKER]: EVENT_INIT.\n");
        dwError = TDNFEventContextGetItemPtr(
                      pContext,
                      TDNF_EVENT_ITEM_TDNF_HANDLE,
                      (const void **)&pHandle->pTdnf);
        BAIL_ON_TDNF_ERROR(dwError);
    }
    else if (nEventType == TDNF_PLUGIN_EVENT_TYPE_REPO)
    {
        pr_info("[METALINKER]: EVENT_REPO __UNHANDLED__\n");
    }
    else if (nEventType == TDNF_PLUGIN_EVENT_TYPE_REPO_MD)
    {
        if (nEventState == TDNF_PLUGIN_EVENT_STATE_DOWNLOAD &&
            nEventPhase == TDNF_PLUGIN_EVENT_PHASE_INIT)
        {
            pr_info("[METALINKER]: EVENT_REPO_MD, DOWNLOAD, START\n");
            dwError = TDNFMetalinkerCheckFile(pHandle, pContext);
            BAIL_ON_TDNF_ERROR(dwError);
        }
        else if (nEventState == TDNF_PLUGIN_EVENT_STATE_DOWNLOAD &&
            nEventPhase == TDNF_PLUGIN_EVENT_PHASE_START)
        {
            pr_info("[METALINKER]: EVENT_REPO_MD, DOWNLOAD, START\n");
            dwError = TDNFMetalinkerMDDownload(pHandle, pContext);
            BAIL_ON_TDNF_ERROR(dwError);
        }
        else if (nEventState == TDNF_PLUGIN_EVENT_STATE_REFRESH &&
            nEventPhase == TDNF_PLUGIN_EVENT_PHASE_START)
        {
            pr_info("[METALINKER]: EVENT_REPO_MD, REFRESH, START\n");
            dwError = TDNFMetalinkerRefreshSolvCookie(pHandle, pContext);
            BAIL_ON_TDNF_ERROR(dwError);
        }
    }
    else
    {
        pr_err("Unexpected event %d in %s plugin\n",
                pContext->nEvent, PLUGIN_NAME);
        goto cleanup;
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}


uint32_t
TDNFMetalinkerCheckClose(
    PTDNF_PLUGIN_HANDLE pHandle
    )
{
    uint32_t dwError = 0;

    if (!pHandle)
    {
        dwError = 1;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    FreePluginHandle(pHandle);

error:
    return dwError;
}


void
FreePluginHandle(
    PTDNF_PLUGIN_HANDLE pHandle
    )
{
    if (pHandle)
    {
        //TDNFFreeRepoGPGCheckData(pHandle->pData);
        TDNFFreeMemory(pHandle);
    }
}