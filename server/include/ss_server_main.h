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

#include "ss_manager.h"

/*
 * Declare new function
 *
 *   @name: SsServerDataStore
 *   @parameter
 *     - sender_pid
 *     - filepath
 *   @return type: int
 */
#ifndef SMACK_GROUP_ID
int SsServerDataStoreFromFile(int sender_pid, const char* filepath, ssm_flag flag, const char* cookie, const char* group_id);
int SsServerDataStoreFromBuffer(int sender_pid, char* writebuffer, size_t bufLen, const char* filename, ssm_flag flag, const char* cookie, const char* group_id);
#else
int SsServerDataStoreFromFile(int sender_pid, const char* filepath, ssm_flag flag, int sockfd, const char* group_id);
int SsServerDataStoreFromBuffer(int sender_pid, char* writebuffer, size_t bufLen, const char* filename, ssm_flag flag, int sockfd, const char* group_id);
#endif

/*
 * Declare new function
 *
 *   @name: SsServerDataRead
 *   @parameter
 *     - sender_pid
 *     - filepath
 *     - pRetBuf
 *     - count
 *     - redLen
 *   @return type: int
 */
#ifndef SMACK_GROUP_ID
int SsServerDataRead(int sender_pid, const char* filepath, char* pRetBuf, unsigned int count, unsigned int* readLen, ssm_flag flag, const char* cookie, const char* group_id);
#else
int SsServerDataRead(int sender_pid, const char* filepath, char* pRetBuf, unsigned int count, unsigned int* readLen, ssm_flag flag, int sockfd, const char* group_id);
#endif
/*
 * Declare new function
 *
 *   @name: SsServerGetInfo
 *   @parameter
 *     - sender_pid
 *     - filepath
 *     - file_info
 *   @return type: int
 */

#ifndef SMACK_GROUP_ID
int SsServerGetInfo(int sender_pid, const char* filepath, char* file_info, ssm_flag flag, const char* cookie, const char* group_id);
int SsServerDeleteFile(int sender_pid, const char* filepath, ssm_flag flag, const char* cookie, const char* group_id);
#else
int SsServerGetInfo(int sender_pid, const char* filepath, char* file_info, ssm_flag flag, int sockfd, const char* group_id);
int SsServerDeleteFile(int sender_pid, const char* filepath, ssm_flag flag, int sockfd, const char* group_id);
#endif


