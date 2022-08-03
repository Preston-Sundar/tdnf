/*
 * Copyright (C) 2022 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License. The terms
 * of the License are located in the COPYING file of this distribution.
 */

#ifndef __PLUGINS_METALINKER_DEFINES_H__
#define __PLUGINS_METALINKER_DEFINES_H__

#define TDNF_REPO_METALINK_FILE_NAME      "metalink"

#define ERROR_TDNF_META_BASE_START        3000

#define ERROR_TDNF_META_ERROR                        ERROR_TDNF_META_BASE_START + 2
#define ERROR_TDNF_META_VERSION_FAILED               ERROR_TDNF_META_BASE_START + 3
#define ERROR_TDNF_META_VERIFY_RESULT                ERROR_TDNF_META_BASE_START + 4
#define ERROR_TDNF_META_SIGNATURE_CHECK              ERROR_TDNF_META_BASE_START + 5
#define ERROR_TDNF_ML_PARSER_INVALID_DOC_OBJECT      ERROR_TDNF_META_BASE_START + 6
#define ERROR_TDNF_ML_PARSER_INVALID_ROOT_ELEMENT    ERROR_TDNF_META_BASE_START + 7
#define ERROR_TDNF_ML_PARSER_MISSING_FILE_ATTR       ERROR_TDNF_META_BASE_START + 8
#define ERROR_TDNF_ML_PARSER_INVALID_FILE_NAME       ERROR_TDNF_META_BASE_START + 9
#define ERROR_TDNF_ML_PARSER_MISSING_FILE_SIZE       ERROR_TDNF_META_BASE_START + 10
#define ERROR_TDNF_ML_PARSER_MISSING_HASH_ATTR       ERROR_TDNF_META_BASE_START + 11
#define ERROR_TDNF_ML_PARSER_MISSING_HASH_CONTENT    ERROR_TDNF_META_BASE_START + 12
#define ERROR_TDNF_ML_PARSER_MISSING_URL_ATTR        ERROR_TDNF_META_BASE_START + 13
#define ERROR_TDNF_ML_PARSER_MISSING_URL_CONTENT     ERROR_TDNF_META_BASE_START + 14

// NOTE: Need to provide libxml specific errors here eventually.
#define ERROR_TDNF_LIBXML_START           3400


// #define TDNF_REPO_CONFIG_REPO_GPGCHECK_KEY "repo_gpgcheck"
// #define TDNF_REPO_METADATA_SIG_EXT         ".asc"

#define METALINKER_PLUGIN_ERROR "metalinker plugin error"
#define METALINKER_ERROR_TABLE \
{ \
    {ERROR_TDNF_META_ERROR,           "ERROR_TDNF_META_ERROR",           "unknown error"}, \
    {ERROR_TDNF_META_VERSION_FAILED,  "ERROR_TDNF_META_VERSION_FAILED",  "version failed"} \
};
#endif /* __PLUGINS_METALINKER_DEFINES_H__ */


