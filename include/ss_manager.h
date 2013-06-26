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
#define __SS_MANAGER__

/**
 * @{
 */

/**
 * @defgroup	SECURE_STORAGE secure storage
 * @ingroup		SecurityFW
 * @{
 */

#define SSM_STORAGE_DEFAULT_PATH	"/opt/share/secure-storage/"

#define DEPRECATED	__attribute__((deprecated))

/**
 * \name Enumeration
 */
typedef enum {
	SSM_FLAG_NONE = 0x00,
	SSM_FLAG_DATA,				// normal data for user (ex> picture, video, memo, etc.)
	SSM_FLAG_SECRET_PRESERVE,	// for preserved operation
	SSM_FLAG_SECRET_OPERATION,	// for oma drm , wifi addr, divx and bt addr
	SSM_FLAG_WIDGET, // for wiget encryption/decryption
	SSM_FLAG_WEB_APP,
	SSM_FLAG_PRELOADED_WEB_APP,
	SSM_FLAG_MAX
} ssm_flag;

/**
 * \name Type definition
 */
typedef struct {
	unsigned int	originSize;
	unsigned int	storedSize;
	char			reserved[8];
}ssm_file_info_t;

/**
 * \name Error codes
 */
#define		SS_PARAM_ERROR					0x00000002	// 2
#define 	SS_FILE_TYPE_ERROR 				0x00000003	// 3
#define		SS_FILE_OPEN_ERROR				0x00000004	// 4
#define 	SS_FILE_READ_ERROR				0x00000005	// 5
//
#define		SS_FILE_WRITE_ERROR				0x00000006	// 6
#define		SS_MEMORY_ERROR					0x00000007	// 7
#define		SS_SOCKET_ERROR					0x00000008	// 8
#define		SS_ENCRYPTION_ERROR				0x00000009	// 9
#define		SS_DECRYPTION_ERROR				0x0000000a	// 10
//
#define		SS_SIZE_ERROR					0x0000000b	// 11
#define		SS_SECURE_STORAGE_ERROR			0x0000000c	// 12
#define		SS_PERMISSION_DENIED			0x0000000d	// 13
#define		SS_TZ_ERROR						0x0000000e	// 14

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name Functions
 */
/**
 * \par Description:
 * Store encrypted file to secure-storage.
 *
 * \par Purpose:
 * Encrypt file in order not to expose the contents of that file. The encrypted file is stored in specific directory and that file only be read by secure-storage server daemon.
 *
 * \par Typical use case:
 * When user wants to store some file securely, he(or she) can use this API.
 *
 * \par Method of function operation:
 * First, encrypt the given file. Then make new file path which will be stored in secure storage. Then store new encrypted file and remove older one.
 *
 * \par Important Notes:
 * - After encryption, original file will be deleted.\n
 *
 * \param[in] pFilePath Absolute file path of original file
 * \param[in] flag Type of stored data (data or secret)
 * \param[in] group_id Sharing group id(string). (NULL if not used)
 *
 * \return Return Type (integer) \n
 * - 0       - Success \n
 * - <0      - Fail \n
 *
 * \par Related functions:
 * None
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * \post None
 * \see None
 * \remark None
 * 
 * \par Sample code:
 * \code
 * #include <ss_manager.h>
 * 
 * ...
 * 
 * int ret = -1;
 * char* infilepath = "/opt/test/test.txt";
 * ssm_flag flag = SSM_FLAG_DATA;
 *
 * ret = ssm_write_file(infilepath, flag, NULL);
 *
 * return ret; // in case of success, return 0. Or fail, return corresponding error code.
 * 
 * ...
 * \endcode
 *
 */
/*================================================================================================*/
int ssm_write_file(const char* pFilePath, ssm_flag flag, const char* group_id);

/**
 * \par Description:
 * Store encrypted file to secure-storage (Original data is in memory buffer).
 *
 * \par Purpose:
 * Encrypt buffer in order not to expose the contents of that buffer. The encrypted file is stored in specific directory and that file only be read by secure-storage server daemon.
 *
 * \par Typical use case:
 * When user wants to store some buffer contents securely, he(or she) can use this API.
 *
 * \par Method of function operation:
 * First, encrypt the given buffer contents. Then make new file path which will be stored in secure storage. Then store new encrypted file.
 *
 * \par Important Notes:
 * None
 *
 * \param[in] pWriteBuffer Data buffer to be stored in secure storage
 * \param[in] bufLen Data size of buffer
 * \param[in] pFileName File name be used when stored. Only file name, not a path
 * \param[in] flag Type of stored data (data or secret)
 * \param[in] group_id Sharing group id(string). (NULL if not used)
 *
 * \return Return Type (integer) \n
 * - 0       - Success \n
 * - <0      - Fail \n
 *
 * \par Related functions:
 * None
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * \post None
 * \see None
 * \remark None
 *
 * \par Sample code:
 * \code
 * #include <ss_manager.h>
 * 
 * ...
 * 
 * int ret = -1;
 * char buf[27] = "abcdefghijklmnopqrstuvwxyz";
 * int buflen = strlen(buf);
 * char* filename = write_buf.txt;
 * ssm_flag flag = SSM_FLAG_SECRET_OPERATION;
 *
 * ret = ssm_write_buffer(buf, buflen, filename, flag, NULL);
 *
 * return ret; // in case of success, return 0. Or fail, return corresponding error code.
 * 
 * ...
 * \endcode
 *
 */
/*================================================================================================*/
int ssm_write_buffer(char* pWriteBuffer, size_t bufLen, const char* pFileName, ssm_flag flag, const char* group_id);

/**
 * \par Description:
 * Decrypt encrypted file into memory buffer.
 *
 * \par Purpose:
 * Read encrypted file which be stored in secure storage. Decrypted contents are only existed in the form of memory buffer, not file.
 *
 * \par Typical use case:
 * When user wants to know the contents which be stored in secure storage, he(or she) can use this API.
 *
 * \par Method of function operation:
 * First, read the file which be in secure storage. Then decrypt that file and store to memory buffer. Then return that buffer.
 *
 * \par Important Notes:
 * - flag must be same with the one of stored data.\n
 * - pFilePath can be either absolute path or file name.\n
 * - pRetBuf is JUST pointer. User allocates memory buffer and passes a pointer.\n
 * - not uses sting function, but uses memory function (not strcpy, strlen, ... use memcpy, memset, ...).\n
 *
 * \param[in] pFilePath File name or path to be read in secure storage
 * \param[in] bufLen Length of data to be read
 * \param[in] flag Type of stored data (data or secret)
 * \param[out] readLen Length of data that this function read
 * \param[out] pRetBuf Buffer for decrypted data
 * \param[in] group_id Sharing group id(string). (NULL if not used)
 *
 * \return Return Type (integer) \n
 * - 0       - Success \n
 * - <0      - Fail \n
 *
 * \par Related functions:
 * ssm_get_info() - use in order to know file size
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * \post None
 * \see None
 * \remark None
 *
 * \par Sample code:
 * \code
 * #include <ss_manager.h>
 * 
 * ...
 * 
 * int ret = -1;
 * char *filepath = "/opt/test/input.txt";
 * int buflen = 128;
 * ssm_flag flag = SSM_FLAG_DATA;
 * char* retbuf = NULL;
 * int readlen = 0;
 * ssm_file_info_t sfi;
 *
 * ssm_getinfo(filepath, &sfi, SSM_FLAG_DATA);
 * retbuf = (char*)malloc(sizeof(char) * (sfi.originSize + 1));
 * memset(retbuf, 0x00, (sfi.originSize + 1));
 *
 * ret = ssm_read(filepath, retbuf, sfi.originSize, &readlen, SSM_FLAG_DATA, NULL);
 * free(retbuf);
 * 
 * return ret; // in case of success, return 0. Or fail, return corresponding error code.
 * 
 * ...
 * \endcode
 *
 */
/*================================================================================================*/
int ssm_read(const char* pFilePath, char* pRetBuf, size_t bufLen, size_t *readLen, ssm_flag flag, const char* group_id);

/**
 * \par Description:
 * Get information of data which will be read.
 *
 * \par Purpose:
 * Use in order to know file statistic information of encrypted file, original file size and encrypted file size.
 *
 * \par Typical use case:
 * When using ssm_read API, user should know the size of original size of encrypted file. In that case, he(or she) can use this API.
 *
 * \par Method of function operation:
 * When encrypting some file, information regarding size of file are saved with encrypted file. In this API, returns that information.
 *
 * \par Important Notes:
 * None
 *
 * \param[in] pFilePath File name or path of file
 * \param[in] flag Type of stored data (data or secret)
 * \param[out] sfi Structure of file information
 * \param[in] group_id Sharing group id(string). (NULL if not used)
 *
 * \return Return Type (integer) \n
 * - 0       - Success \n
 * - <0      - Fail \n
 *
 * \par Related functions:
 * ssm_read()
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * \post None
 * \see None
 * \remark None
 *
 * \par Sample code:
 * \code
 * #include <ss_manager.h>
 * 
 * ...
 * 
 * int ret = -1;
 * char *filepath = "/opt/secure-storage/test/input.txt";
 * ssm_flag flag = SSM_FLAG_DATA;
 * ssm_file_info_t sfi;
 *
 * ret = ssm_getinfo(filepath, &sfi, flag, NULL);
 * 
 * printf(" ** original size: [%d]\n", sfi.originSize);
 * printf(" ** stored size:   [%d]\n", sfi.storedSize);
 * printf(" ** reserved:      [%s]\n", sfi.reserved);
 *
 * return ret; // in case of success, return 0. Or fail, return corresponding error code.
 * 
 * ...
 * \endcode
 *
 */
/*================================================================================================*/
int ssm_getinfo(const char* pFilePath, ssm_file_info_t* sfi, ssm_flag flag, const char* group_id);

/**
 * \par Description:
 * Delete encrypted file in Secure-storage.
 *
 * \par Purpose:
 * The Secure-storage is the special place, which only ss-server daemon can access. Therefore, in order to delete file, process requests to ss-server.
 *
 * \par Typical use case:
 * When user wants to delete specific file, he(or she) can use this API.
 *
 * \par Method of function operation:
 * All files in secure-storage have unique name. Process will request to delete some file, then ss-server deletes that.
 *
 * \par Important Notes:
 * None
 *
 * \param[in] pFilePath File path
 * \param[in] flag Type of stored data (data or secret)
 * \param[in] group_id Sharing group id(string). (NULL if not used)
 *
 * \return Return Type (integer) \n
 * - 0       - Success \n
 * - <0      - Fail \n
 *
 * \par Related functions:
 * None
 *
 * \par Known issues/bugs:
 * None
 *
 * \pre None
 * \post None
 * \see None
 * \remark None
 *
 * \par Sample code:
 * \code
 * #include <ss_manager.h>
 * 
 * ...
 * 
 * int ret = -1;
 * char *infilepath = "res_write_buf.txt";
 * ssm_flag flag = SSM_FLAG_SECRET_OPERATION;
 *
 * ret = ssm_delete_file(infilepath, flag, NULL);
 *
 * return ret; // in case of success, return 0. Or fail, return corresponding error code.
 *
 * ...
 * \endcode
 *
 */
/*================================================================================================*/
int ssm_delete_file(const char* pFilePath, ssm_flag flag, const char* group_id);

//for wrt installer
/*================================================================================================*/
int ssm_encrypt(const char* pAppId, int idLen, const char* pBuffer, int bufLen, char** ppEncryptedBuffer, int* pEncryptedBufLen);
int ssm_decrypt(const char* pAppId, int idLen, const char* pBuffer, int bufLen, char** ppDecryptedBuffer, int* pDecryptedBufLen);

int ssm_encrypt_preloaded_application(const char* pBuffer, int bufLen, char** ppEncryptedBuffer, int* pEncryptedBufLen);
int ssm_decrypt_preloaded_application(const char* pBuffer, int bufLen, char** ppDecryptedBuffer, int* pDecryptedBufLen); 


#ifdef __cplusplus
}
#endif

/**
 * @}
 */

/**
 * @}
 */

#endif
