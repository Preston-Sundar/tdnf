/*
 * Copyright (C) 2022 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#ifndef __PLUGINS_METALINKER_PROTOTYPES_H__
#define __PLUGINS_METALINKER_PROTOTYPES_H__

uint32_t
TDNFMetalinkerCheckInitialize(
    const char *pszConfig,
    PTDNF_PLUGIN_HANDLE *ppHandle
    );

uint32_t
TDNFMetalinkerCheckInitialize(
    const char *pszConfig,
    PTDNF_PLUGIN_HANDLE *ppHandle
    );

uint32_t
TDNFMetalinkerCheckEventsNeeded(
    const PTDNF_PLUGIN_HANDLE pHandle,
    TDNF_PLUGIN_EVENT_TYPE *pnEvents
    );

uint32_t
TDNFMetalinkerCheckGetErrorString(
    PTDNF_PLUGIN_HANDLE pHandle,
    uint32_t nErrorCode,
    char **ppszError
    );

uint32_t
TDNFMetalinkerCheckEvent(
    PTDNF_PLUGIN_HANDLE pHandle,
    PTDNF_EVENT_CONTEXT pContext
    );

uint32_t
TDNFMetalinkerCheckClose(
    PTDNF_PLUGIN_HANDLE pHandle
    );

uint32_t
TDNFMetalinkerXMLCheckVersion(
    );

void
FreePluginHandle(
    PTDNF_PLUGIN_HANDLE pHandle
    );

uint32_t
TDNFMetalinkerCheckFile(
    PTDNF_PLUGIN_HANDLE pHandle,
    PTDNF_EVENT_CONTEXT pContext
    );

uint32_t
TDNFMetalinkerRefreshSolvCookie(
    PTDNF_PLUGIN_HANDLE pHandle,
    PTDNF_EVENT_CONTEXT pContext
    );

uint32_t
TDNFMetalinkerMDDownload(
    PTDNF_PLUGIN_HANDLE pHandle,
    PTDNF_EVENT_CONTEXT pContext
    );


uint32_t
TDNFParseAndGetURLFromMetalink(
    PTDNF pTdnf,
    const char *pszRepo,
    const char *pszFile,
    TDNF_ML_CTX *ml_ctx
    );

uint32_t
TDNFMetalinkParseFile(
    TDNF_ML_CTX *ml_ctx,
    int fd,
    const char *filename
    );

void
TDNFMetalinkFree(
    TDNF_ML_CTX *ml_ctx
    );

uint32_t
TDNFXmlParseData(
    TDNF_ML_CTX *ml_ctx,
    xmlNode *node,
    const char *filename
    );

uint32_t
TDNFParseFileTag(
    TDNF_ML_CTX *ml_ctx,
    xmlNode *node,
    const char *filename
    );

uint32_t
TDNFParseHashTag(
    TDNF_ML_CTX *ml_ctx,
    xmlNode *node
    );


uint32_t
TDNFParseUrlTag(
    TDNF_ML_CTX *ml_ctx,
    xmlNode *node
    );

uint32_t
TDNFStoreBaseURLFromMetalink(
    PTDNF pTdnf,
    const char *pszRepo,
    const char *pszRepoMDURL
    );

TDNFDownloadUsingMetalinkResources(
    PTDNF pTdnf,
    const char *pszRepo,
    const char *pszFile,
    const char *pszProgressData,
    char **ppszRepoMDUrl,
    TDNF_ML_CTX *ml_ctx
    );

uint32_t
TDNFCheckRepoMDFileHashFromMetalink(
    char *pszFile,
    TDNF_ML_CTX *ml_ctx
    );

// list.c
void
TDNFSortListOnPreference(
    TDNF_ML_LIST** headUrl
    );

uint32_t
TDNFAppendList(
    TDNF_ML_LIST** head_ref,
    void *new_data
    );

void
TDNFDeleteList(
    TDNF_ML_LIST** head_ref,
    TDNF_ML_FREE_FUNC free_func
    );


void TDNFDebugDumpPluginHandle(PTDNF_PLUGIN_HANDLE p);

#endif /* __PLUGINS_METALINKER_PROTOTYPES_H__ */