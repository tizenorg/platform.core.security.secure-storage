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

/* encrypted file format
 * 
 * total file size  = metadata (8 bytes) + realdata (...)
 * -----------------------------------------------------------
 * | metadata | realdata                                      |
 * -----------------------------------------------------------
 * 0           16                                              EOF
 * metadata -> ssm_file_info_t
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <openssl/hmac.h> 

#include <openssl/aes.h>
#include <openssl/sha.h>

#include "secure_storage.h"
#include "ss_server_main.h"
#include "ss_server_ipc.h"

#ifdef SMACK_GROUP_ID
#include <security-server/security-server.h>
#endif

#ifdef USE_KEY_FILE
#define CONF_FILE_PATH	"/usr/share/secure-storage/config"
#endif // USE_KEY_FILE

#define ENCRYPT_SIZE	1024

/* skey : need to help from hardware */
char skey[16+1] = "thisisasecretkey";

/***************************************************************************
 * Internal functions
 **************************************************************************/

char* get_preserved_dir()
{
	FILE* fp_conf = NULL;
	char buf[128];
	char* retbuf = NULL;
	char seps[] = " :\n\r\t";
	char* token = NULL;

	retbuf = (char*)malloc(sizeof(char) * 128);
	if(retbuf == NULL)
	{
	    SLOGE("malloc return NULL\n");
	    return NULL;
	}
	memset(buf, 0x00, 128);
	memset(retbuf, 0x00, 128);

	if(!(fp_conf = fopen(CONF_FILE_PATH, "r")))
	{
		SLOGE("Configuration file is not exist\n");
		free(retbuf);
		return NULL;
	}
	
	while(fgets(buf, 128, fp_conf))
	{
		token = strtok(buf, seps);
		if(!strncmp(token, "PRESERVE_DIR", 12))	// preserve directory?
		{
			token = strtok(NULL, seps);	// real path
			break;
		}

		token = NULL;
	}
	fclose(fp_conf);

	if(token)
		strncpy(retbuf, token, 127);
	else {
	    free(retbuf);
	    return NULL;
	}

	return retbuf;
}

int IsSmackEnabled()
{
	FILE *file = NULL;
	if((file = fopen("/smack/load2", "r")))
	{
		fclose(file);
		return 1;
	}
	return 0;
}

/* get key from hardware( ex. OMAP e-fuse random key ) */
void GetKey(char* key, unsigned char* iv)
{
#ifdef USE_KEY_FILE
	FILE* fp_key = NULL;
	char buf[33];
	char* key_path = NULL;

	memset(buf, 0x00, 33);

	key_path = get_key_file_path();
	if(key_path == NULL)
	{
		SLOGE("Configuration file is not exist\n");
		memcpy(buf, skey, 16);
	}
	else
	{
		if(!(fp_key = fopen(key_path, "r")))
		{
			SLOGE("Secret key file opening error\n");
			memcpy(buf, skey, 16);
		}
		else
		{
			if(!fgets(buf, 33, fp_key))
			{
				SLOGE("Secret key file reading error\n");
				memcpy(buf, skey, 16);	// if fail to get key, set to default value.
			}
		}
	}

	if(key)
		strncpy(key, buf, 16);
	if(iv)
		strncpy(iv, buf+16, 16);

	if(key_path)
		free(key_path);
	if(fp_key)
		fclose(fp_key);
	
#else
	if(key)
		memcpy(key, skey, 16);
	if(iv)
		memcpy(iv, 0x00, 16);
#endif // USE_KEY_FILE
}

unsigned short GetHashCode(const unsigned char* pString)
{
	unsigned short hash = 5381;
	int len = SHA_DIGEST_LENGTH;
	int i;

	for(i = 0; i < len; i++)
	{
		hash = ((hash << 5) + hash) + (unsigned short)pString[i]; // hash * 33 + ch
	}
	
	return hash;
}

int IsDirExist(const char* dirpath)
{
	DIR* dp = NULL;
	
	if((dp = opendir(dirpath)) == NULL) // dir is not exist
	{
		SECURE_SLOGE("directory [%s] is not exist.\n", dirpath);
		return 0; // return value '0' represents dir is not exist
	}
	else
	{
		closedir(dp);
		return 1;
	}

	return -1;
}

int check_privilege_by_sockfd(int sockfd, const char* object, const char* access_rights)
{
    int ret = 0;
#ifdef SMACK_GROUP_ID
	if(!IsSmackEnabled())
		return 0;

	ret = security_server_check_privilege_by_sockfd(sockfd, object, access_rights);
	SECURE_SLOGD("object : %s, access_rights : %s, ret : %d", object, access_rights, ret);
#endif
	return ret;
}

/* convert normal file path to secure storage file path  */
int ConvertFileName(int sender_pid, char* dest, const char* src, ssm_flag flag, const char* group_id)
{
	char s[33+1];
	const char* dir = group_id;
	char* preserved_dir = NULL;
	int is_dir_exist = -1;

	if(!dest || !src)
	{
		SLOGE("Parameter error in ConvertFileName()...\n");
		return SS_FILE_OPEN_ERROR;	// file related error
	}

	// get top-dir path
	if(flag == SSM_FLAG_SECRET_PRESERVE)
	{
		preserved_dir = get_preserved_dir();
		if(preserved_dir == NULL)	// fail to get preserved directory
		{
			SLOGE("fail to get preserved dir\n");
			return SS_FILE_OPEN_ERROR;
		}

		strncpy(dest, preserved_dir, strlen(preserved_dir));  //dest <= /csa
		free(preserved_dir);
	}
	else 	// SSM_FLAG_SECRET_DATA || SSM_FLAG_SECRET_OPERATION || SSM_FLAG_PRELOADED_WEB_APP
	{
		if(CreateStorageDir(SS_STORAGE_DEFAULT_PATH) < 0)
		{
			return SS_FILE_OPEN_ERROR;
		}
		// TBD
		strncpy(dest, SS_STORAGE_DEFAULT_PATH, strlen(SS_STORAGE_DEFAULT_PATH) + 1);
	}

	strncat(dest, dir, (strlen(dir))); 	// add top-dir + dir(label)
	strncat(dest, "/", 1);

	if(CreateStorageDir(dest) < 0)
	{
		return SS_FILE_OPEN_ERROR;
	}

	strncat(dest, "_", 1); 	// /top-dir/label/_

	GetPathHash(src, s);
	strncat(dest, s, strlen(s)); 	// /top-dir/label/_hash
	strncat(dest, SS_FILE_POSTFIX, strlen(SS_FILE_POSTFIX)); 	// /top-dir/label/_hash.e

	SECURE_SLOGD("final dest : %s", dest);

	return 1;
}

int GetProcessExecPath(int pid, char* buffer)
{
	char tmp_cmd[32] = {0,};
	FILE *fp_proc = NULL;
	snprintf(tmp_cmd, 32, "/proc/%d/cmdline", pid);

	if(!(fp_proc = fopen(tmp_cmd, "r")))
	{
		SECURE_SLOGE("file open error: [%s]", tmp_cmd);
		return SS_FILE_OPEN_ERROR;
	}

	fgets((char*)buffer, 256, fp_proc);
	fclose(fp_proc);

	return 0;
}

#ifdef SMACK_GROUP_ID
int GetProcessSmackLabel(int sockfd, char* proc_smack_label)
{
	char* smack_label = security_server_get_smacklabel_sockfd(sockfd);
	if(smack_label)
	{
		strncpy(proc_smack_label, smack_label, strlen(smack_label));
		free(smack_label);
	}
	else
	{
		SLOGE("failed to get smack label");
		return -1; // SS_SECURITY_SERVER_ERROR?
	}
	SECURE_SLOGD("defined smack label : %s", proc_smack_label);
	return 0;
}
#endif

int GetPathHash(const char *src, char *output)
{
	unsigned short h_code = 0;
	unsigned char path_hash[SHA_DIGEST_LENGTH + 1];

	SHA1((unsigned char*)src, (size_t)strlen(src), path_hash);
	h_code = GetHashCode(path_hash);
	memset(output, 0x00, 34);
	snprintf(output, 34, "%u", h_code);

	SECURE_SLOGD("hashing src : %s to output : %s", src, output);

	return 0;
}


int CreateStorageDir(const char* path)
{
	int is_dir_exist = IsDirExist(path);

	if (is_dir_exist == 0) // path directory is not exist
	{
		SECURE_SLOGI("directory [%s] is making now.\n", path);
		if(mkdir(path, 0700) < 0)	// fail to make directory
		{
			SLOGE("[%s] cannot be made\n", SS_STORAGE_DEFAULT_PATH);
			return -SS_FILE_OPEN_ERROR;
		}
	}

	return 0;
}

/*
 * if group_id is given, use group_id
 *
 * if NULL group_id is given
 * smack enable :  use process smack label
 * smack disable :  use process exec path
 *
 */
int GetProcessStorageDir(int sockfd, int sender_pid, const char* group_id, char* output)
{
	char *object = group_id;
	char proc_smack_label[MAX_GROUP_ID_LEN+1] = {0,};
	char hash_buf[10] = {0, };
	int is_shared = strncmp(group_id, "NOTUSED", 7) ? 1 : 0;

#ifdef SMACK_GROUP_ID
	if(IsSmackEnabled())
	{
		if(!is_shared) 	// don't share, use process smack label
		{
			if(GetProcessSmackLabel(sockfd, proc_smack_label) != 0)
			{
				return -SS_SECURE_STORAGE_ERROR;
			}
			object = proc_smack_label;
		}
	}
	else{
#endif
		char exe_path[256] = {0,};
		int h_code2 = 0;

		if(!is_shared)	// don't share
		{
			if(GetProcessExecPath(sender_pid, exe_path) != 0)
			{
				return -SS_SECURE_STORAGE_ERROR;
			}
			h_code2 = GetHashCode(exe_path);
			snprintf(hash_buf, 10, "%u", h_code2);
			object = hash_buf;
		}
#ifdef SMACK_GROUP_ID
	}
#endif
	strncpy(output, object, strlen(object));
	return 0;
}

void SetMetaData(ssm_file_info_convert_t* sfic, unsigned int orig_size, unsigned int stored_size, int flag)
{
	sfic->fInfoStruct.originSize = (unsigned int)orig_size;
	sfic->fInfoStruct.storedSize = (unsigned int)stored_size;
	sfic->fInfoStruct.reserved[0] = flag & 0x000000ff;
}

/* aes crypto function wrapper - p_text : plain text, c_text : cipher text, aes_key : from GetKey, mode : ENCRYPT/DECRYPT, size : data size */
unsigned char* AES_Crypto(unsigned char* p_text, unsigned char* c_text, char* aes_key, unsigned char* iv, int mode,  unsigned long size)
{
	AES_KEY e_key, d_key;
	
	AES_set_encrypt_key((unsigned char*)aes_key, 128, &e_key);
	AES_set_decrypt_key((unsigned char*)aes_key, 128, &d_key);
	
	if(mode == 1)
	{
		AES_cbc_encrypt(p_text, c_text, size, &e_key, iv, AES_ENCRYPT);
		return c_text;
	}
	else
	{
		AES_cbc_encrypt(c_text, p_text, size, &d_key, iv, AES_DECRYPT);
		return p_text;
	}
}


/***************************************************************************
 * Function Definition
 **************************************************************************/
#ifndef SMACK_GROUP_ID
int SsServerDataStoreFromFile(int sender_pid, const char* data_filepath, ssm_flag flag, const char* cookie, const char* group_id)
#else
int SsServerDataStoreFromFile(int sender_pid, const char* data_filepath, ssm_flag flag, int sockfd, const char* group_id)
#endif
{
	char key[16] = {0, };
	unsigned char iv[16] = {0, };
	const char* in_filepath = data_filepath;
	char out_filepath[MAX_FILENAME_LEN] = {0, };
	FILE* fd_in = NULL;
	FILE* fd_out = NULL;
	struct stat file_info;
	ssm_file_info_convert_t sfic;

	unsigned char p_text[ENCRYPT_SIZE]= {0, };
	unsigned char e_text[ENCRYPT_SIZE]= {0, };

	size_t read = 0, rest = 0;
	int res = -1;

	//0. privilege check and get directory name
	char dir[MAX_GROUP_ID_LEN] = {0,};
#ifdef SMACK_GROUP_ID
	if(GetProcessStorageDir(sockfd, sender_pid, group_id, dir) < 0)
#else 
	if(GetProcessStorageDir(-1, sender_pid, group_id, dir) < 0)
#endif
	{
		SLOGE("Failed to get storage dir\n");
		return SS_SECURE_STORAGE_ERROR;
	}

#ifdef SMACK_GROUP_ID
	if(flag != SSM_FLAG_PRELOADED_WEB_APP)
	{
		if(check_privilege_by_sockfd(sockfd, dir, "w") < 0)
		{
			SLOGE("Permission denied\n");
			return SS_PERMISSION_DENIED;
		}
	}
#endif

	// 1. create out file name
	ConvertFileName(sender_pid, out_filepath, in_filepath, flag, dir);

	// 2. file open 
	if(!(fd_in = fopen(in_filepath, "rb")))
	{
		SLOGE("File open error:(in_filepath) %s\n", in_filepath);
		return SS_FILE_OPEN_ERROR;	// file related error
	}
	
	if(!(fd_out = fopen(out_filepath, "wb")))
	{
		SLOGE("File open error:(out_filepath) %s\n", out_filepath);
		fclose(fd_in);
		return SS_FILE_OPEN_ERROR;	// file related error
	}
	if(chmod(out_filepath, 0600) < 0)
	{
	    int err_tmp = errno;
	    SLOGE("chmod error: %s\n", strerror(err_tmp));
	    fclose(fd_in);
	    fclose(fd_out);
	    return SS_FILE_OPEN_ERROR;  // file related error
	}

	// 3. write metadata
	if(!stat(in_filepath, &file_info))
	{
		SetMetaData(&sfic, file_info.st_size, (file_info.st_size/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE, flag);
	}
	else
	{
		SLOGE("the function stat() fail.\n");
		fclose(fd_in);
		fclose(fd_out);
		return SS_FILE_READ_ERROR;
	}

	fwrite(sfic.fInfoArray, 1, sizeof(ssm_file_info_t), fd_out);
	
	// 4. encrypt real data 
	read = fread(p_text, 1, ENCRYPT_SIZE, fd_in);
	GetKey(key, iv);

	while(read == ENCRYPT_SIZE)
	{
		AES_Crypto(p_text, e_text, key, iv, 1, ENCRYPT_SIZE);
		
		fwrite(e_text, 1, ENCRYPT_SIZE, fd_out);

		memset(e_text, 0x00, ENCRYPT_SIZE);
		memset(p_text, 0x00, ENCRYPT_SIZE);
		read = fread( p_text, 1, ENCRYPT_SIZE, fd_in );
	}

	rest = AES_BLOCK_SIZE - (read % AES_BLOCK_SIZE);
	AES_Crypto(p_text, e_text, key, iv, 1, read+rest);
	fwrite(e_text, 1, read + rest, fd_out);

	if((res = fflush(fd_out)) != 0) {
		SLOGE("fail to execute fflush().\n");
		fclose(fd_in);
		fclose(fd_out);
		return SS_FILE_WRITE_ERROR;
	}
	else {
		SLOGI("success to execute fflush().\n");
		if((res = fsync(fd_out->_fileno)) == -1) {
			SLOGE("fail to execute fsync().\n");
			fclose(fd_in);
			fclose(fd_out);
			return SS_FILE_WRITE_ERROR;
		}
		else
			SLOGI("success to execute fsync(). read=[%d], rest=[%d]\n", read, rest);
	}

	fclose(fd_in);
	fclose(fd_out);
	
	return 1;
}

#ifndef SMACK_GROUP_ID
int SsServerDataStoreFromBuffer(int sender_pid, char* writebuffer, size_t bufLen, const char* filename, ssm_flag flag, const char* cookie, const char* group_id)
#else
int SsServerDataStoreFromBuffer(int sender_pid, char* writebuffer, size_t bufLen, const char* filename, ssm_flag flag, int sockfd, const char* group_id)
#endif
{
	char key[16] = {0, };
	unsigned char iv[16] = {0, };
	char out_filepath[MAX_FILENAME_LEN+1] = {0,};
	char *buffer = NULL;
	unsigned int writeLen = 0, loop, rest, count;
	FILE *fd_out = NULL;
	ssm_file_info_convert_t sfic;
	unsigned char p_text[ENCRYPT_SIZE] = {0, };
	unsigned char e_text[ENCRYPT_SIZE] = {0, };
	int res = -1;

	//0. get directory name and privilege check
	char dir[MAX_GROUP_ID_LEN] = {0,};
#ifdef SMACK_GROUP_ID
	if(GetProcessStorageDir(sockfd, sender_pid, group_id, dir) < 0)
#else
	if(GetProcessStorageDir(-1, sender_pid, group_id, dir) < 0)
#endif
	{
		SLOGE("Failed to get storage dir\n");
		return SS_SECURE_STORAGE_ERROR;
	}

#ifdef SMACK_GROUP_ID
	if(flag != SSM_FLAG_PRELOADED_WEB_APP)
	{
		if(check_privilege_by_sockfd(sockfd, dir, "w") < 0)
		{
			SLOGE("Permission denied\n");
			return SS_PERMISSION_DENIED;
		}
	}
#endif

	// create file path from filename
	ConvertFileName(sender_pid, out_filepath, filename, flag, dir);

	writeLen = (unsigned int)(bufLen / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
	buffer = (char*)malloc(writeLen + 1);
	if(!buffer)
	{
		SLOGE("Memory Allocation Fail in SsServerDataStoreFromBuffer()..\n");
		return SS_MEMORY_ERROR;
	}
	memset(buffer, 0x00, writeLen);
	memcpy(buffer, writebuffer, bufLen);

	// open a file with write mode
	if(!(fd_out = fopen(out_filepath, "wb")))
	{
		SECURE_SLOGE("File open error:(out_filepath) %s\n", out_filepath);
		free(buffer);
		return SS_FILE_OPEN_ERROR;	// file related error
	}
	if(chmod(out_filepath, 0600) < 0)
	{
	    int err_tmp = errno;
	    SLOGE("chmod error: %s\n", strerror(err_tmp));
	    free(buffer);
	    fclose(fd_out);
	    return SS_FILE_OPEN_ERROR;  // file related error
	}
	
	// write metadata
	SetMetaData(&sfic, bufLen, writeLen, flag);

	fwrite(sfic.fInfoArray, 1, sizeof(ssm_file_info_t), fd_out);
	
	// encrypt buffer 
	loop = writeLen / ENCRYPT_SIZE;
	rest = writeLen % ENCRYPT_SIZE;
	GetKey(key, iv);
	
	for(count = 0; count < loop; count++)
	{
		memcpy(p_text, buffer+count*ENCRYPT_SIZE, ENCRYPT_SIZE);
		AES_Crypto( p_text, e_text, key, iv, 1, ENCRYPT_SIZE);	
		fwrite(e_text, 1, ENCRYPT_SIZE, fd_out);
		memset(e_text, 0x00, ENCRYPT_SIZE);
		memset(p_text, 0x00, ENCRYPT_SIZE);
	}
		
	memcpy(p_text, buffer + loop*ENCRYPT_SIZE, rest);
	AES_Crypto(p_text, e_text, key, iv, 1, rest);
	fwrite(e_text, 1, rest, fd_out);
	
	if((res = fflush(fd_out)) != 0) {
		SLOGE("fail to execute fflush().\n");
		fclose(fd_out);
		free(buffer);
		return SS_FILE_WRITE_ERROR;
	}
	else {
		SLOGI("success to execute fflush().\n");
		if((res = fsync(fd_out->_fileno)) == -1) {
			SLOGE("fail to execute fsync().\n");
			fclose(fd_out);
			free(buffer);
			return SS_FILE_WRITE_ERROR;
		}
		else
			SLOGI("success to execute fsync(). loop=[%d], rest=[%d]\n", loop, rest);
	}

	fclose(fd_out);
	free(buffer);

	return 1;
}

#ifndef SMACK_GROUP_ID
int SsServerDataRead(int sender_pid, const char* data_filepath, char* pRetBuf, unsigned int count, unsigned int* readLen, ssm_flag flag, const char* cookie, const char* group_id)
#else
int SsServerDataRead(int sender_pid, const char* data_filepath, char* pRetBuf, unsigned int count, unsigned int* readLen, ssm_flag flag, int sockfd, const char* group_id)
#endif
{
	unsigned int offset = count * MAX_RECV_DATA_LEN;
	char key[16] = {0, };
	static unsigned char iv[16] = {0, };
	unsigned char temp_iv[16] = {0, };
	char in_filepath[MAX_FILENAME_LEN] = {0, };
	FILE* fd_in = NULL;
	char *out_data = pRetBuf;
	unsigned char p_text[ENCRYPT_SIZE]= {0, };
	unsigned char e_text[ENCRYPT_SIZE]= {0, };
	size_t read = 0;
	
	*readLen = 0;

	//0. get directory name and privilege check
	char dir[MAX_GROUP_ID_LEN] = {0,};
#ifdef SMACK_GROUP_ID
	if(GetProcessStorageDir(sockfd, sender_pid, group_id, dir) < 0)
#else
	if(GetProcessStorageDir(-1, sender_pid, group_id, dir) < 0)
#endif
	{
		SLOGE("Failed to get storage dir\n");
		return SS_SECURE_STORAGE_ERROR;
	}

#ifdef SMACK_GROUP_ID
	if(flag != SSM_FLAG_PRELOADED_WEB_APP)
	{
		if(check_privilege_by_sockfd(sockfd, dir, "r") < 0)
		{
			SLOGE("Permission denied\n");
			return SS_PERMISSION_DENIED;
		}
	}
#endif

	// 1. create in file name : convert file name in order to access secure storage
	if(flag == SSM_FLAG_WIDGET)
		strncpy(in_filepath, data_filepath, MAX_FILENAME_LEN - 1);
	else
		ConvertFileName(sender_pid, in_filepath, data_filepath, flag, dir);

	// 2. open file
	if(!(fd_in = fopen(in_filepath, "rb")))
	{
		SECURE_SLOGE("File open error:(in_filepath) %s\n", in_filepath);
		return SS_FILE_OPEN_ERROR;	// file related error
	}
	
	// 3. skip to offset
	if(fseek(fd_in, (long)offset + sizeof(ssm_file_info_t), SEEK_SET) < 0)
	{
	    int err_tmp = errno;
	    SECURE_SLOGE("Fseek error: %s in %s\n", strerror(err_tmp), in_filepath);
	    fclose(fd_in);
	    return SS_FILE_OPEN_ERROR;  // file related error
	}
	
	// 4. decrypt data
	GetKey(key, temp_iv);
	if(count == 0)
		memcpy(iv, temp_iv, 16);
	
	read = fread(e_text, 1, ENCRYPT_SIZE, fd_in);
	
	while((read == ENCRYPT_SIZE))
	{
		AES_Crypto(p_text, e_text, key, iv, 0, ENCRYPT_SIZE) ;
		
		memcpy(out_data, p_text, ENCRYPT_SIZE);
		out_data += ENCRYPT_SIZE;
		*readLen += ENCRYPT_SIZE;

		if(*readLen == MAX_RECV_DATA_LEN)
			goto Last;
		
		memset(p_text, 0x00, ENCRYPT_SIZE);
		memset(e_text, 0x00, ENCRYPT_SIZE);

		read = fread(e_text, 1, ENCRYPT_SIZE, fd_in);
	}

	AES_Crypto(p_text, e_text, key, iv, 0, read) ;

	memcpy(out_data, p_text, read);
	out_data += read;
	*readLen += read;
Last:
	*out_data = '\0';

	fclose(fd_in);

	return 1;
}

#ifndef SMACK_GROUP_ID
int SsServerDeleteFile(int sender_pid, const char* data_filepath, ssm_flag flag, const char* cookie, const char* group_id)
#else
int SsServerDeleteFile(int sender_pid, const char* data_filepath, ssm_flag flag, int sockfd, const char* group_id)
#endif
{
	const char* in_filepath = data_filepath;
	char out_filepath[MAX_FILENAME_LEN] = {0, };

	//0. get directory name and privilege check
	char dir[MAX_GROUP_ID_LEN] = {0,};
#ifdef SMACK_GROUP_ID
	if(GetProcessStorageDir(sockfd, sender_pid, group_id, dir) < 0)
#else
	if(GetProcessStorageDir(-1, sender_pid, group_id, dir) < 0)
#endif
	{
		SLOGE("Failed to get storage dir\n");
		return SS_SECURE_STORAGE_ERROR;
	}

#ifdef SMACK_GROUP_ID
	if(flag != SSM_FLAG_PRELOADED_WEB_APP)
	{
		if(check_privilege_by_sockfd(sockfd, dir, "w") < 0)
		{
			SLOGE("Permission denied\n");
			return SS_PERMISSION_DENIED;
		}
	}
#endif

	// create file path from filename
	ConvertFileName(sender_pid, out_filepath, in_filepath, flag, dir);

	// 2. delete designated file
	if(unlink(out_filepath) != 0)	// unlink fail?
	{
		SLOGE("error occured while deleting file\n");
		return SS_FILE_WRITE_ERROR;
	}
	
	return 1;
}

#ifndef SMACK_GROUP_ID
int SsServerGetInfo(int sender_pid, const char* data_filepath, char* file_info, ssm_flag flag, const char* cookie, const char* group_id)
#else
int SsServerGetInfo(int sender_pid, const char* data_filepath, char* file_info, ssm_flag flag, int sockfd, const char* group_id)
#endif
{
	size_t read = 0;
	FILE *fd_in = NULL;
	char in_filepath[MAX_FILENAME_LEN] = {0, };

	//0. get directory name and privilege check
	char dir[MAX_GROUP_ID_LEN] = {0,};
#ifdef SMACK_GROUP_ID
	if(GetProcessStorageDir(sockfd, sender_pid, group_id, dir) < 0)
#else
	if(GetProcessStorageDir(-1, sender_pid, group_id, dir) < 0)
#endif
	{
		SLOGE("Failed to get storage dir\n");
		return SS_SECURE_STORAGE_ERROR;
	}

#ifdef SMACK_GROUP_ID
	if(flag != SSM_FLAG_PRELOADED_WEB_APP)
	{
		if(check_privilege_by_sockfd(sockfd, dir, "r") < 0)
		{
			SLOGE("Permission denied\n");
			return SS_PERMISSION_DENIED;
		}
	}
#endif

	// 1. create in file name : convert file name in order to access secure storage
	if(flag == SSM_FLAG_WIDGET)
		strncpy(in_filepath, data_filepath, MAX_FILENAME_LEN - 1);
	else
		ConvertFileName(sender_pid, in_filepath, data_filepath, flag, dir);

	// 1. open file
	if(!(fd_in = fopen( in_filepath, "rb")))
	{
		SECURE_SLOGE("File open error:(in_filepath) [%s], [%s]\n", data_filepath, in_filepath );
		return SS_FILE_OPEN_ERROR;	// file related error
	}

	// 2. read metadata field - first 8 bytes
	read = fread(file_info, 1, sizeof(ssm_file_info_t), fd_in);

	if(read != sizeof(ssm_file_info_t))
	{
		fclose(fd_in);
		return SS_FILE_READ_ERROR;
	}
	
	fclose(fd_in);
	return 1;
}
