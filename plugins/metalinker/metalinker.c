/*
 * Copyright (C) 2020-2021 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */


#include "includes.h"

typedef struct _hash_op {
    char *hash_type;
    unsigned int length;
} hash_op;

static hash_op hash_ops[TDNF_HASH_SENTINEL] =
    {
       [TDNF_HASH_MD5]    = {"md5", MD5_DIGEST_LENGTH},
       [TDNF_HASH_SHA1]   = {"sha1", SHA_DIGEST_LENGTH},
       [TDNF_HASH_SHA256] = {"sha256", SHA256_DIGEST_LENGTH},
       [TDNF_HASH_SHA512] = {"sha512", SHA512_DIGEST_LENGTH},
    };

typedef struct _hash_type {
    char *hash_name;
    unsigned int hash_value;
}hash_type;

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

static void
TDNFMetalinkHashFree(
    TDNF_ML_HASH_INFO *ml_hash_info
    )
{
    if (!ml_hash_info)
    {
        return;
    }

    TDNF_SAFE_FREE_MEMORY(ml_hash_info->type);
    TDNF_SAFE_FREE_MEMORY(ml_hash_info->value);
    TDNF_SAFE_FREE_MEMORY(ml_hash_info);
}

static void
TDNFMetalinkUrlFree(
    TDNF_ML_URL_INFO *ml_url_info
    )
{
    if (!ml_url_info)
    {
        return;
    }

    TDNF_SAFE_FREE_MEMORY(ml_url_info->protocol);
    TDNF_SAFE_FREE_MEMORY(ml_url_info->type);
    TDNF_SAFE_FREE_MEMORY(ml_url_info->location);
    TDNF_SAFE_FREE_MEMORY(ml_url_info->url);
    TDNF_SAFE_FREE_MEMORY(ml_url_info);
}

void
TDNFMetalinkFree(
    TDNF_ML_CTX *ml_ctx
    )
{
    if (!ml_ctx)
        return;

    TDNF_SAFE_FREE_MEMORY(ml_ctx->filename);
    TDNFDeleteList(&ml_ctx->hashes, (TDNF_ML_FREE_FUNC)TDNFMetalinkHashFree);
    TDNFDeleteList(&ml_ctx->urls, (TDNF_ML_FREE_FUNC)TDNFMetalinkUrlFree);
    TDNF_SAFE_FREE_MEMORY(ml_ctx);
}

uint32_t
TDNFMetalinkerCheckFile(
    PTDNF_PLUGIN_HANDLE pHandle,
    PTDNF_EVENT_CONTEXT pContext
    )
{
    uint32_t dwError = 0;
    char* pszRepoDataDir = NULL;
    char* pszMetaLink = NULL;
    char* pszRepoMetaLinkURL = NULL;

    dwError = TDNFEventContextGetItemString(
                    pContext,
                    TDNF_EVENT_ITEM_REPO_DATADIR,
                    (const char **)&pszRepoDataDir);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFEventContextGetItemString(
                    pContext,
                    TDNF_EVENT_ITEM_REPO_PLUGIN_URL,
                    (const char **)&pszRepoMetaLinkURL);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFJoinPath(&pHandle->pszMetaLinkFile,
                           pszRepoDataDir,
                           TDNF_REPO_METALINK_FILE_NAME,
                           NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    // Create the repodata directory if it is missing.
    dwError = TDNFUtilsMakeDir(pszRepoDataDir);
    if(dwError == ERROR_TDNF_ALREADY_EXISTS)
    {
        dwError = 0;
    }
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFJoinPath(&pHandle->pszBaseUrlFile,
                           pszRepoDataDir,
                           TDNF_REPO_BASEURL_FILE_NAME,
                           NULL);
    BAIL_ON_TDNF_ERROR(dwError);

    /* get the status flags struct ptr used for metadata download. */
    dwError = TDNFEventContextGetItemPtr(
                    pContext,
                    TDNF_EVENT_ITEM_REPO_MD_STATUS_FLAGS,
                    (const void **)&pHandle->pStatusFlags);
    BAIL_ON_TDNF_ERROR(dwError);

    /* set status flag to indicate that plugin handles repomd.xml download */
    pHandle->pStatusFlags->nPluginHandlesDownload = 1;

    /* set status flag to indicate that plugin handles refresh */
    pHandle->pStatusFlags->nPluginHandlesRefresh = 1;

    /* if metalink file is not present, set flag to download */
    if (access(pHandle->pszMetaLinkFile, F_OK) || access(pHandle->pszBaseUrlFile, F_OK))
    {
        if (errno != ENOENT)
        {
            dwError = errno;
            BAIL_ON_TDNF_SYSTEM_ERROR(dwError);
        }
        pHandle->pStatusFlags->nNeedDownload = 1;
    }

    /* set the metalinker server repo link */
    // TODO: need to have this inside the plugin. Ideally, this is acquired 
    // through the init stage of the plugin (might need an event from config read).
    dwError = TDNFEventContextGetItemString(
                    pContext,
                    TDNF_EVENT_ITEM_REPO_PLUGIN_URL,
                    (const char **)&pszMetaLink);
    BAIL_ON_TDNF_ERROR(dwError);
    // TODO: dealloc in plugin exit or error. 
    dwError = TDNFAllocateString(pszMetaLink,
                                 &(pHandle->pszRepoMetalinkURL));
    BAIL_ON_TDNF_ERROR(dwError);

    // DEBUG
    TDNFDebugDumpPluginHandle(pHandle);


error:
    return dwError;
}

uint32_t
TDNFMetalinkerRefreshSolvCookie(
    PTDNF_PLUGIN_HANDLE pHandle,
    PTDNF_EVENT_CONTEXT pContext)
{
    uint32_t dwError = 0;

    if (!access(pHandle->pszMetaLinkFile, F_OK))
    {
        dwError = SolvCalculateCookieForFile(
            pHandle->pszMetaLinkFile, 
            (unsigned char*) pContext->pData->pPtr
        );
        BAIL_ON_TDNF_ERROR(dwError);
    }

error:
    return dwError;
}


uint32_t
TDNFCheckRepoMDFileHashFromMetalink(
    char *pszFile,
    TDNF_ML_CTX *ml_ctx
    )
{
    uint32_t dwError = 0;
    TDNF_ML_HASH_LIST *hashList = NULL;
    TDNF_ML_HASH_INFO *hashInfo = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    int hash_Type = -1;
    TDNF_ML_HASH_INFO *currHashInfo = NULL;

    if(IsNullOrEmptyString(pszFile) ||
       !ml_ctx)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for(hashList = ml_ctx->hashes; hashList; hashList = hashList->next)
    {
        int currHashType = TDNF_HASH_SENTINEL;
        currHashInfo = hashList->data;

        if(currHashInfo == NULL)
        {
            dwError = ERROR_TDNF_INVALID_REPO_FILE;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        dwError = TDNFGetResourceType(currHashInfo->type, &currHashType);
        BAIL_ON_TDNF_ERROR(dwError);

        if ((hash_Type > currHashType)||
           (!TDNFCheckHexDigest(currHashInfo->value, hash_ops[currHashType].length)))
        {
            continue;
        }
        hash_Type = currHashType;
        hashInfo = currHashInfo;
    }

    dwError = TDNFChecksumFromHexDigest(hashInfo->value, digest);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFCheckHash(pszFile, digest, hash_Type);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFMetalinkerMDDownload(
    PTDNF_PLUGIN_HANDLE pHandle,
    PTDNF_EVENT_CONTEXT pContext)
{
    uint32_t dwError = 0;
    PTDNF_REPO_DATA pRepoData = NULL;
    char *pszRepoId = NULL;
    char *pszRepoMDUrl = NULL;
    char *pszRepoMDFile = NULL;
    char *pszTmpRepoMDFile = NULL;
    char *pszTmpBaseUrlFile = NULL;
    char *pszTmpRepoDataDir = NULL;
    char *pszTmpRepoMetalinkFile = NULL;
    unsigned char pszTmpCookie[SOLV_COOKIE_LEN] = {0};
    PTDNF_PLUGIN_MD_FLAGS pStatusFlags = pHandle->pStatusFlags;
    // int nNewRepoMDFile = 0;
    // int nReplaceRepoMD = 0;
    // int nReplacebaseURL = 0;
    TDNF_ML_CTX *ml_ctx = NULL;

    //TODO: Get needed vars from plugin handle. pRepoData
    dwError = TDNFEventContextGetItemPtr(
                  pContext,
                  TDNF_EVENT_ITEM_REPO_DATA,
                  (const void **)&pRepoData);
    BAIL_ON_TDNF_ERROR(dwError);
    //TODO: Get needed vars from plugin handle. pszTmpRepoDataDir
    dwError = TDNFEventContextGetItemString(
                  pContext,
                  TDNF_EVENT_ITEM_REPO_MD_TMP_DATA_DIR,
                  (const char **)&pszTmpRepoDataDir);
    BAIL_ON_TDNF_ERROR(dwError);
    //TODO: Get needed vars from plugin handle. pszRepoId
    dwError = TDNFEventContextGetItemString(
                  pContext,
                  TDNF_EVENT_ITEM_REPO_ID,
                  (const char **)&pszRepoId);
    BAIL_ON_TDNF_ERROR(dwError);
    //TODO: Get needed vars from plugin handle. pszTmpRepoMDFile
    dwError = TDNFEventContextGetItemString(
                  pContext,
                  TDNF_EVENT_ITEM_REPO_MD_TMP_FILE,
                  (const char **)&pszTmpRepoMDFile);
    BAIL_ON_TDNF_ERROR(dwError);
    // //TODO: Get needed vars from plugin handle. pszRepoMDUrl
    dwError = TDNFEventContextGetItemPtr(
                  pContext,
                  TDNF_EVENT_ITEM_REPO_MD_URL,
                  (const void **)&pszRepoMDUrl);
    BAIL_ON_TDNF_ERROR(dwError);
    //TODO: Get needed vars from plugin handle. pszRepoMDFile
    dwError = TDNFEventContextGetItemString(
                  pContext,
                  TDNF_EVENT_ITEM_REPO_MD_FILE,
                  (const char **)&pszRepoMDFile);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFJoinPath(&pszTmpRepoMetalinkFile,
                            pszTmpRepoDataDir,
                            TDNF_REPO_METALINK_FILE_NAME,
                            NULL);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = TDNFJoinPath(&pszTmpBaseUrlFile,
                            pszTmpRepoDataDir,
                            TDNF_REPO_BASEURL_FILE_NAME,
                            NULL);
    BAIL_ON_TDNF_ERROR(dwError);
    dwError = TDNFDownloadFile(pHandle->pTdnf, pszRepoId, pHandle->pszRepoMetalinkURL,
                                pszTmpRepoMetalinkFile, pszRepoId);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateMemory(1, sizeof(TDNF_ML_CTX),
                                    (void **)&ml_ctx);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFParseAndGetURLFromMetalink(pHandle->pTdnf,
                pszRepoId, pszTmpRepoMetalinkFile, ml_ctx);
    BAIL_ON_TDNF_ERROR(dwError);

    pStatusFlags->nReplaceRepoMD = 1;
    if (pHandle->pszCookie[0])
    {
        dwError = SolvCalculateCookieForFile(pszTmpRepoMetalinkFile, pszTmpCookie);
        BAIL_ON_TDNF_ERROR(dwError);

        if (!memcmp (pHandle->pszCookie, pszTmpCookie, sizeof(pszTmpCookie)))
        {
            pStatusFlags->nReplaceRepoMD = 0;
        }
    }

    if (pStatusFlags->nReplaceRepoMD)
    {
        dwError = TDNFDownloadUsingMetalinkResources(
                    pHandle->pTdnf,
                    pszRepoId,
                    pszTmpRepoMDFile,
                    pszRepoId,
                    &pszRepoMDUrl,
                    ml_ctx);
        BAIL_ON_TDNF_ERROR(dwError);

        //check if the repomd file downloaded using metalink have the same checksum
        //as mentioned in the metalink file.
        dwError = TDNFCheckRepoMDFileHashFromMetalink(pszTmpRepoMDFile , ml_ctx);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = TDNFRepoSetBaseUrl(pHandle->pTdnf, pRepoData, pszTmpBaseUrlFile);
        BAIL_ON_TDNF_ERROR(dwError);
        pStatusFlags->nReplacebaseURL = 1;
        pStatusFlags->nNewRepoMDFile = 1;


        if (!access(pszRepoMDFile, F_OK))
        {
            // TODO: figure out why SOLV_COOKIE_LEN instead of 
            // sizeof(pHandle->pszCookie) causes gcc warnings.
            memset(pHandle->pszCookie, 0, sizeof(pHandle->pszCookie));
            memset(pszTmpCookie, 0, SOLV_COOKIE_LEN);
            dwError = SolvCalculateCookieForFile(pszRepoMDFile, *pHandle->pszCookie);
            BAIL_ON_TDNF_ERROR(dwError);
            dwError = SolvCalculateCookieForFile(pszTmpRepoMDFile, pszTmpCookie);
            BAIL_ON_TDNF_ERROR(dwError);
            if (!memcmp (pHandle->pszCookie, pszTmpCookie, sizeof(pszTmpCookie)))
            {
                pStatusFlags->nReplaceRepoMD = 0;
            }
        }
    }

    if (!pStatusFlags->nReplacebaseURL && !access(pHandle->pszBaseUrlFile, F_OK))
    {
        /* if metalink url is present, then, we will need to
           set the base url to the url which is used to download the repomd */
        dwError = TDNFRepoSetBaseUrl(pHandle->pTdnf, pRepoData, pHandle->pszBaseUrlFile);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (pStatusFlags->nReplacebaseURL)
    {
        dwError = TDNFReplaceFile(pszTmpRepoMetalinkFile, pHandle->pszMetaLinkFile);
        BAIL_ON_TDNF_ERROR(dwError);
        dwError = TDNFReplaceFile(pszTmpBaseUrlFile, pHandle->pszBaseUrlFile);
        BAIL_ON_TDNF_ERROR(dwError);
    }

cleanup:
    if (ml_ctx)
    {
        TDNFMetalinkFree(ml_ctx);
        ml_ctx = NULL;
    }
    return dwError;
error:
    pr_err("Error(%u) : %s\n", dwError, __FUNCTION__);
    goto cleanup;
}

uint32_t
TDNFParseAndGetURLFromMetalink(
    PTDNF pTdnf,
    const char *pszRepo,
    const char *pszFile,
    TDNF_ML_CTX *ml_ctx
    )
{
    int fd = -1;
    uint32_t dwError = 0;

    if (!pTdnf ||
       !pTdnf->pArgs ||
       IsNullOrEmptyString(pszRepo) ||
       IsNullOrEmptyString(pszFile) ||
       !ml_ctx)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    fd = open(pszFile, O_RDONLY);
    if (fd < 0)
    {
        dwError = errno;
        BAIL_ON_TDNF_SYSTEM_ERROR_UNCOND(dwError);
    }

    dwError = TDNFMetalinkParseFile(ml_ctx, fd, TDNF_REPO_METADATA_FILE_NAME);
    if (dwError)
    {
        pr_err("Unable to parse metalink, ERROR: code=%d\n", dwError);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    //sort the URL's in List based on preference.
    TDNFSortListOnPreference(&ml_ctx->urls);

cleanup:
    if (fd >= 0)
    {
        close(fd);
    }
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFParseFileTag(
    TDNF_ML_CTX *ml_ctx,
    xmlNode *node,
    const char *filename
    )
{
    uint32_t dwError = 0;
    xmlChar* xmlPropValue = NULL;
    const char *name = NULL;

    if(!ml_ctx || !node || IsNullOrEmptyString(filename))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    xmlPropValue = xmlGetProp(node, ATTR_NAME);
    if (!xmlPropValue)
    {
        pr_err("%s: Missing attribute \"name\" of file element", __func__);
        dwError = ERROR_TDNF_ML_PARSER_MISSING_FILE_ATTR;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    name = (const char*)xmlPropValue;
    if (strcmp(name, filename))
    {
        pr_err("%s: Invalid filename from metalink file:%s", __func__, name);
        dwError = ERROR_TDNF_ML_PARSER_INVALID_FILE_NAME;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateString(name, &(ml_ctx->filename));
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    if(xmlPropValue)
    {
        xmlFree(xmlPropValue);
        xmlPropValue = NULL;
    }
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFParseHashTag(
    TDNF_ML_CTX *ml_ctx,
    xmlNode *node
    )
{
    uint32_t dwError = 0;
    xmlChar* xmlPropValue = NULL;
    xmlChar* xmlContValue = NULL;
    const char *type = NULL;
    const char *value = NULL;
    TDNF_ML_HASH_INFO *ml_hash_info = NULL;

    if(!ml_ctx || !node)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    //Get Hash Properties.
    xmlPropValue = xmlGetProp(node, ATTR_TYPE);
    if (!xmlPropValue)
    {
        dwError = ERROR_TDNF_ML_PARSER_MISSING_HASH_ATTR;
        pr_err("XML Parser Error:HASH element doesn't have attribute \"type\"");
        BAIL_ON_TDNF_ERROR(dwError);
    }

    type = (const char*)xmlPropValue;
    dwError = TDNFAllocateMemory(1, sizeof(TDNF_ML_HASH_INFO),
                                 (void**)&ml_hash_info);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFAllocateString(type, &(ml_hash_info->type));
    BAIL_ON_TDNF_ERROR(dwError);

    //Get Hash Content.
    xmlContValue = xmlNodeGetContent(node);
    if(!xmlContValue)
    {
        dwError = ERROR_TDNF_ML_PARSER_MISSING_HASH_CONTENT;
        pr_err("XML Parser Error:HASH value is not present in HASH element", value);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    value = (const char*)xmlContValue;
    dwError = TDNFAllocateString(value, &(ml_hash_info->value));
    BAIL_ON_TDNF_ERROR(dwError);

    //Append hash info in ml_ctx hash list.
    dwError = TDNFAppendList(&(ml_ctx->hashes), ml_hash_info);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    if(xmlPropValue)
    {
        xmlFree(xmlPropValue);
        xmlPropValue = NULL;
    }

    if(xmlContValue)
    {
        xmlFree(xmlContValue);
        xmlContValue = NULL;
    }
    return dwError;

error:
    if(ml_hash_info)
    {
        TDNFMetalinkHashFree(ml_hash_info);
        ml_hash_info = NULL;
    }
    goto cleanup;
}

uint32_t
TDNFParseUrlTag(
    TDNF_ML_CTX *ml_ctx,
    xmlNode *node
    )
{
    uint32_t dwError = 0;
    xmlChar* xmlPropValue = NULL;
    xmlChar* xmlContValue = NULL;
    const char *value = NULL;
    int prefValue = 0;
    TDNF_ML_URL_INFO *ml_url_info = NULL;

    if(!ml_ctx || !node)
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFAllocateMemory(1, sizeof(TDNF_ML_URL_INFO),
                                 (void**)&ml_url_info);
    BAIL_ON_TDNF_ERROR(dwError);

    if ((xmlPropValue = xmlGetProp(node, ATTR_PROTOCOL)))
    {
        value = (const char*)xmlPropValue;
        dwError = TDNFAllocateString(value, &(ml_url_info->protocol));
        BAIL_ON_TDNF_ERROR(dwError);
        xmlFree(xmlPropValue);
        xmlPropValue = NULL;
        value = NULL;
    }
    if ((xmlPropValue = xmlGetProp(node, ATTR_TYPE)))
    {
        value = (const char*)xmlPropValue;
        dwError = TDNFAllocateString(value, &(ml_url_info->type));
        BAIL_ON_TDNF_ERROR(dwError);
        xmlFree(xmlPropValue);
        xmlPropValue = NULL;
        value = NULL;
    }
    if ((xmlPropValue = xmlGetProp(node, ATTR_LOCATION)))
    {
        value = (const char*)xmlPropValue;
        dwError = TDNFAllocateString(value, &(ml_url_info->location));
        BAIL_ON_TDNF_ERROR(dwError);
        xmlFree(xmlPropValue);
        xmlPropValue = NULL;
        value = NULL;
    }
    if ((xmlPropValue = xmlGetProp(node, ATTR_PREFERENCE)))
    {
        value = (const char*)xmlPropValue;
        if(sscanf(value, "%d", &prefValue) != 1)
        {
            dwError = ERROR_TDNF_INVALID_PARAMETER;
            pr_err("XML Parser Warning: Preference is invalid value: %s\n", value);
            BAIL_ON_TDNF_ERROR(dwError);
        }
        xmlFree(xmlPropValue);
        xmlPropValue = NULL;

        if (prefValue < 0 || prefValue > 100)
        {
            dwError = ERROR_TDNF_ML_PARSER_MISSING_URL_ATTR;
            pr_err("XML Parser Warning: Bad value (\"%s\") of \"preference\""
                   "attribute in url element (should be in range 0-100)", value);
            BAIL_ON_TDNF_ERROR(dwError);
        }
        else
        {
            ml_url_info->preference = prefValue;
        }
        value = NULL;
    }

    //Get URL Content.
    xmlContValue = xmlNodeGetContent(node);
    if(!xmlContValue)
    {
        dwError = ERROR_TDNF_ML_PARSER_MISSING_URL_CONTENT;
        pr_err("URL is no present in URL element", value);
        BAIL_ON_TDNF_ERROR(dwError);
    }

    value = (const char*)xmlContValue;
    dwError = TDNFAllocateString(value, &(ml_url_info->url));
    BAIL_ON_TDNF_ERROR(dwError);

    //Append url info in ml_ctx url list.
    dwError = TDNFAppendList(&(ml_ctx->urls), ml_url_info);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    if(xmlPropValue)
    {
        xmlFree(xmlPropValue);
        xmlPropValue = NULL;
    }

    if(xmlContValue)
    {
        xmlFree(xmlContValue);
        xmlContValue = NULL;
    }
    return dwError;

error:
    if(ml_url_info)
    {
        TDNFMetalinkUrlFree(ml_url_info);
        ml_url_info = NULL;
    }
    goto cleanup;
}


uint32_t
TDNFXmlParseData(
    TDNF_ML_CTX *ml_ctx,
    xmlNode *node,
    const char *filename
    )
{
    uint32_t dwError = 0;
    xmlChar* xmlContValue = NULL;
    char *size = NULL;

    if(!ml_ctx || !node || IsNullOrEmptyString(filename))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    //Looping through all the nodes from root and parse all children nodes.
    while(node)
    {
        if(node->type == XML_ELEMENT_NODE)
        {
            if(!strcmp((const char*)node->name, TAG_NAME_FILE))
            {
                dwError = TDNFParseFileTag(ml_ctx, node, filename);
                BAIL_ON_TDNF_ERROR(dwError);
            }
            else if(!strcmp((const char*)node->name, TAG_NAME_SIZE))
            {
                //Get File Size.
                xmlContValue = xmlNodeGetContent(node);
                if(!xmlContValue)
                {
                    dwError = ERROR_TDNF_ML_PARSER_MISSING_FILE_SIZE;
                    pr_err("XML Parser Error:File size is missing: %s", size);
                    BAIL_ON_TDNF_ERROR(dwError);
                }
                size = (char*)xmlContValue;
                if(sscanf(size, "%ld", &(ml_ctx->size)) != 1)
                {
                    dwError = ERROR_TDNF_INVALID_PARAMETER;
                    pr_err("XML Parser Warning: size is invalid value: %s\n", size);
                    BAIL_ON_TDNF_ERROR(dwError);
                }
            }
            else if(!strcmp((const char*)node->name, TAG_NAME_HASH))
            {
                dwError = TDNFParseHashTag(ml_ctx, node);
                BAIL_ON_TDNF_ERROR(dwError);
            }
            else if(!strcmp((const char*)node->name, TAG_NAME_URL))
            {
                dwError = TDNFParseUrlTag(ml_ctx, node);
                BAIL_ON_TDNF_ERROR(dwError);
            }
        }
        TDNFXmlParseData(ml_ctx, node->children, filename);
        node = node->next;
    }

cleanup:
    if(xmlContValue)
    {
        xmlFree(xmlContValue);
        xmlContValue = NULL;
    }
    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFMetalinkParseFile(
    TDNF_ML_CTX *ml_ctx,
    int fd,
    const char *filename
    )
{
    uint32_t dwError = 0;
    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;

    if(!ml_ctx || (fd <= 0) || IsNullOrEmptyString(filename))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    //Read The File and get the doc object.
    doc = xmlReadFd(fd, NULL, NULL, 0);

    if (doc == NULL)
    {
        pr_err("%s: Error while reading xml from fd:%d \n", __func__, fd);
        dwError = ERROR_TDNF_ML_PARSER_INVALID_DOC_OBJECT;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    //Get the root element from parsed xml tree.
    root_element = xmlDocGetRootElement(doc);

    if (root_element == NULL)
    {
        pr_err("%s: Error to fetch root element of xml tree\n", __func__);
        dwError = ERROR_TDNF_ML_PARSER_INVALID_ROOT_ELEMENT;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    // Parsing
    dwError = TDNFXmlParseData(ml_ctx, root_element, filename);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    if(doc != NULL)
    {
        xmlFreeDoc(doc);
        doc = NULL;
    }
    xmlCleanupParser();

    return dwError;
error:
    goto cleanup;
}

uint32_t
TDNFStoreBaseURLFromMetalink(
    PTDNF pTdnf,
    const char *pszRepo,
    const char *pszRepoMDURL
    )
{
    uint32_t dwError = 0;
    char *pszBaseUrlFile = NULL;
    PTDNF_REPO_DATA pRepo = NULL;

    if (!pTdnf ||
        !pTdnf->pConf ||
        IsNullOrEmptyString(pszRepo) ||
        IsNullOrEmptyString(pszRepoMDURL))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    if (!pTdnf->pRepos)
    {
        dwError = ERROR_TDNF_NO_REPOS;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    for (pRepo = pTdnf->pRepos; pRepo; pRepo = pRepo->pNext)
    {
        if(!strcmp(pszRepo, pRepo->pszId))
        {
            break;
        }
    }

    if (!pRepo)
    {
        dwError = ERROR_TDNF_NO_REPOS;
        BAIL_ON_TDNF_ERROR(dwError);
    }

    dwError = TDNFGetCachePath(pTdnf, pRepo,
                               "tmp", TDNF_REPO_BASEURL_FILE_NAME,
                               &pszBaseUrlFile);
    BAIL_ON_TDNF_ERROR(dwError);

    dwError = TDNFCreateAndWriteToFile(pszBaseUrlFile, pszRepoMDURL);
    BAIL_ON_TDNF_ERROR(dwError);

cleanup:
    TDNF_SAFE_FREE_MEMORY(pszBaseUrlFile);
    return dwError;
error:
    goto cleanup;
}


uint32_t
TDNFDownloadUsingMetalinkResources(
    PTDNF pTdnf,
    const char *pszRepo,
    const char *pszFile,
    const char *pszProgressData,
    char **ppszRepoMDUrl,
    TDNF_ML_CTX *ml_ctx
    )
{
    uint32_t dwError = 0;
    TDNF_ML_URL_LIST *urlList = NULL;
    TDNF_ML_URL_INFO *urlInfo = NULL;
    char *pszRepoMDUrl = NULL;
    char buf[BUFSIZ] = {0};

    if (!pTdnf ||
        !pTdnf->pArgs ||
        IsNullOrEmptyString(pszFile) ||
        IsNullOrEmptyString(pszRepo))
    {
        dwError = ERROR_TDNF_INVALID_PARAMETER;
        BAIL_ON_TDNF_ERROR(dwError);
    }
    urlList = ml_ctx->urls;

    while(urlList)
    {
        urlInfo = urlList->data;
        if (urlInfo == NULL)
        {
            dwError = ERROR_TDNF_INVALID_REPO_FILE;
            BAIL_ON_TDNF_ERROR(dwError);
        }

        dwError = TDNFStringEndsWith(urlInfo->url, TDNF_REPO_METADATA_FILE_PATH);
        if (dwError)
        {
            dwError = ERROR_TDNF_INVALID_REPO_FILE;
            BAIL_ON_TDNF_ERROR(dwError);
        }
        dwError = TDNFDownloadFile(pTdnf, pszRepo, urlInfo->url, pszFile,
		                   pszProgressData);
        if (dwError)
        {
            urlList = urlList->next;
            if (urlList)
            {
                continue;
            }
            BAIL_ON_TDNF_ERROR(dwError);
        }
        strncpy(buf, urlInfo->url, BUFSIZ-1);
        buf[BUFSIZ-1] = '\0'; // force terminate
        dwError = TDNFTrimSuffix(buf, TDNF_REPO_METADATA_FILE_PATH);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = TDNFStoreBaseURLFromMetalink(pTdnf, pszRepo, buf);
        BAIL_ON_TDNF_ERROR(dwError);

        dwError = TDNFJoinPath(&pszRepoMDUrl,
                               buf,
                               TDNF_REPO_METADATA_FILE_PATH,
                               NULL);
        BAIL_ON_TDNF_ERROR(dwError);
        *ppszRepoMDUrl = pszRepoMDUrl;
        break;
    }

cleanup:
    return dwError;
error:
    TDNF_SAFE_FREE_MEMORY(pszRepoMDUrl);
    *ppszRepoMDUrl = NULL;
    goto cleanup;
}


void TDNFDebugDumpPluginHandle(PTDNF_PLUGIN_HANDLE p)
{
    printf("** DUMP **\n");
    printf("\tpTdnf: %p\n", p->pTdnf);
    printf("\tnError: %d\n", p->nError);
    printf("\tnMetalinkerError: %d\n", p->nMetalinkerError);
    printf("\tpszMetaLinkFile: %s\n", p->pszMetaLinkFile);
    printf("\tpszBaseUrlFile: %s\n", p->pszBaseUrlFile);
    printf("\tnNeedDownload: %d\n", p->nNeedDownload);
    printf("\tpszCookie: %s\n", *(p->pszCookie));
    printf("\tpszRepoMetalinkURL: %s\n\n", p->pszRepoMetalinkURL);
}