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


void TDNFDebugDumpPluginHandle(PTDNF_PLUGIN_HANDLE p);

#endif /* __PLUGINS_METALINKER_PROTOTYPES_H__ */