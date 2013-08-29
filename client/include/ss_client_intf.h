/*
 * secure storage
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
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
 */

#ifndef __SS_MANAGER__
#include "ss_manager.h"
#endif

/*
 * Declare new function
 *
 *  @name: SsClientDataStore
 *  @parameter
 *     - filepath: [in]
 *     - flag: [in]
 *  @return type: int
 *     - 1: success
 *     - <1: error
 */
int SsClientDataStoreFromFile(const char* filepath, ssm_flag flag, const char* group_id);
int SsClientDataStoreFromBuffer(char* writebuffer, size_t bufLen, const char* filename, ssm_flag flag, const char* group_id);

/*
 * Declare new function
 *
 *  @name: SsClientDataRead
 *  @parameter
 *     - filepath: [in]
 *     - pRetBuf: [out]
 *     - bufLen: [in]
 *     - readLen: [out]
 *  @return type: int
 *     - 1: success
 *     - <1: error
 */
int SsClientDataRead(const char* filepath, char* pRetBuf, size_t bufLen, size_t *readLen, ssm_flag flag, const char* group_id);

/*
 * Declare new function
 *
 *  @name: SsClientGetInfo
 *  @parameter
 *     - filepath: [in]
 *     - sfi: [out]
 *  @return type: int
 *     - 1: success
 *     - <1: error
 */
int SsClientGetInfo(const char* filepath, ssm_file_info_t* sfi, ssm_flag flag, const char* group_id);

int SsClientDeleteFile(const char* pFilePath, ssm_flag flag, const char* group_id);

int SsClientEncrypt(const char* pAppId, int idLen, const char* pBuffer, int bufLen, char** ppEncryptedBuffer, int* pEncryptedBufLen);

int SsClientDecrypt(const char* pAppId, int idLen, const char* pBuffer, int bufLen, char** ppDecryptedBuffer, int* pDecryptedBufLen);

int SsClientEncryptPreloadedApplication(const char* pBuffer, int bufLen, char** ppEncryptedBuffer, int* pEncryptedBufLen);
int SsClientDecryptPreloadedApplication(const char* pBuffer, int bufLen, char** ppDecryptedBuffer, int* pEncryptedBufLen);
