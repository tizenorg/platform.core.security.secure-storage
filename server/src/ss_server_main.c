/*
 * secure storage
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved 
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

#include <openssl/aes.h>
#include <openssl/sha.h>

#include "secure_storage.h"
#include "ss_server_main.h"
#include "ss_server_ipc.h"

#include "security-server.h"

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
	memset(buf, 0x00, 128);
	memset(retbuf, 0x00, 128);

	if(!(fp_conf = fopen(CONF_FILE_PATH, "r")))
	{
		SLOGE("[%s] Configuration file is not exist\n", __func__);
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
		if(retbuf != NULL)
			free(retbuf);
		return NULL;
	}

	return retbuf;
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
		SLOGE("[%s] Configuration file is not exist\n", __func__);
		memcpy(buf, skey, 16);
	}
	else
	{
		if(!(fp_key = fopen(key_path, "r")))
		{
			SLOGE("[%s] Secret key file opening error\n", __func__);
			memcpy(buf, skey, 16);
		}
		else
		{
			if(!fgets(buf, 33, fp_key))
			{
				SLOGE("[%s] Secret key file reading error\n", __func__);
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

int IsDirExist(char* dirpath)
{
	DIR* dp = NULL;
	
	if((dp = opendir(dirpath)) == NULL) // dir is not exist
	{
		SLOGE("[%s] directory [%s] is not exist.\n", __func__, dirpath);
		return 0; // return value '0' represents dir is not exist
	}
	else
	{
		closedir(dp);
		return 1;
	}

	return -1;
}

int check_privilege(const char* cookie, const char* group_id)
{
	int ret = -1;	// if success, return 0
	int gid = -1;
	
	if(!strncmp(group_id, "NOTUSED", 7))	// group_id is NULL
		return 0;
	else
	{
		gid = security_server_get_gid(group_id);
		ret = security_server_check_privilege(cookie, gid);
	}

	return ret;
}

/* convert normal file path to secure storage file path  */
int ConvertFileName(int sender_pid, char* dest, const char* src, ssm_flag flag, const char* group_id)
{
	char* if_pointer = NULL;
	unsigned short h_code = 0;
	unsigned short h_code2 = 0;
	unsigned char path_hash[SHA_DIGEST_LENGTH + 1];
	char s[33+1];
	const char* dir = NULL;
	char tmp_cmd[32] = {0, };
	char tmp_buf[10] = {0, };
	const unsigned char exe_path[256] = {0, };
	FILE* fp_proc = NULL;
	char* preserved_dir = NULL;
	int is_dir_exist = -1;

	if(!dest || !src)
	{
		SLOGE( "[%s] Parameter error in ConvertFileName()...\n", __func__);
		return SS_FILE_OPEN_ERROR;	// file related error
	}

	memset(tmp_cmd, 0x00, 32);
	snprintf(tmp_cmd, 32, "/proc/%d/cmdline", sender_pid);

	if(!(fp_proc = fopen(tmp_cmd, "r")))
	{
		SLOGE("[%s] file open error: [%s]", __func__, tmp_cmd);
		return SS_FILE_OPEN_ERROR;
	}
	
	fgets((char*)exe_path, 256, fp_proc);
	fclose(fp_proc);

	if(!strncmp(group_id, "NOTUSED", 7))	// don't share
	{
		h_code2 = GetHashCode(exe_path);
		memset(tmp_buf, 0x00, 10);
		snprintf(tmp_buf, 10, "%u", h_code2);
		dir = tmp_buf;
	}
	else	// share
		dir = group_id;

	if_pointer = strrchr(src, '/');
	
	if(flag == SSM_FLAG_DATA) // /opt/share/secure-storage/*
	{
		// check whether directory is exist or not
		is_dir_exist = IsDirExist(SS_STORAGE_DEFAULT_PATH);
		
		if (is_dir_exist == 0) // SS_STORAGE_FILE_PATH is not exist
		{
			SLOGI("[%s] directory [%s] is making now.\n", __func__, SS_STORAGE_DEFAULT_PATH);
			if(mkdir(SS_STORAGE_DEFAULT_PATH, 0700) < 0)	// fail to make directory
			{
				SLOGE("[%s] [%s] cannot be made\n", __func__, SS_STORAGE_DEFAULT_PATH);
				return SS_FILE_OPEN_ERROR;
			}
		}
		else if (is_dir_exist == -1) // Unknown error
		{
			SLOGE("[%s] Unknown error in the function IsDirExist().\n", __func__);
			return SS_PARAM_ERROR;
		}

		// TBD
		strncpy(dest, SS_STORAGE_DEFAULT_PATH, MAX_FILENAME_LEN - 1);
		strncat(dest, dir, (strlen(dest) - 1));
		strncat(dest, "/", 1);

		// make directory
		dest[strlen(SS_STORAGE_DEFAULT_PATH) + strlen(dir) + 2] = '\0';
		is_dir_exist = IsDirExist(dest);

		if(is_dir_exist == 0) // not exist
		{
			SLOGI("[%s] %s is making now.\n", __func__, dest);
			if(mkdir(dest, 0700) < 0)	// fail to make directory
			{
				SLOGE("[%s] [%s] cannot be made\n", __func__, dest);
				return SS_FILE_OPEN_ERROR;
			}
		}
		
		strncat(dest, if_pointer + 1, strlen(if_pointer) + 1);
		strncat(dest, "_", 1);

		SHA1((unsigned char*)src, (size_t)strlen(src), path_hash);
		h_code = GetHashCode(path_hash);
		memset(s, 0x00, 34);
		snprintf(s, 34, "%u", h_code);
		strncat(dest, s, strlen(s));
		strncat(dest, SS_FILE_POSTFIX, strlen(SS_FILE_POSTFIX));

		dest[strlen(SS_STORAGE_DEFAULT_PATH) + strlen(dir) + strlen(if_pointer) + strlen(s) + strlen(SS_FILE_POSTFIX) + 4] = '\0';
	}
	else if(flag == SSM_FLAG_SECRET_PRESERVE) // /tmp/csa/
	{
		preserved_dir = get_preserved_dir();
		if(preserved_dir == NULL)	// fail to get preserved directory
		{
			SLOGE("[%s] fail to get preserved dir\n", __func__);
			return SS_FILE_OPEN_ERROR;
		}
		
		if(strncmp(src, preserved_dir, strlen(preserved_dir)) == 0) //src[0] == '/')
		{
			strncpy(dest, src, MAX_FILENAME_LEN - 1);
			strncat(dest, SS_FILE_POSTFIX, strlen(SS_FILE_POSTFIX));

			dest[strlen(src) + strlen(SS_FILE_POSTFIX)] = '\0';
		}
		else if(if_pointer != NULL)	// absolute path == file
		{
			strncpy(dest, preserved_dir, MAX_FILENAME_LEN - 1);
			strncat(dest, if_pointer + 1, strlen(if_pointer) + 1);
			strncat(dest, SS_FILE_POSTFIX, strlen(SS_FILE_POSTFIX));
			dest[strlen(preserved_dir) + strlen(if_pointer) + strlen(SS_FILE_POSTFIX) + 1] = '\0';
		}
		else	// relative path == buffer
		{
			strncpy(dest, preserved_dir, MAX_FILENAME_LEN - 1);
			strncat(dest, src, strlen(src));
			strncat(dest, SS_FILE_POSTFIX, strlen(SS_FILE_POSTFIX));
			dest[strlen(preserved_dir) + strlen(src) + strlen(SS_FILE_POSTFIX)] = '\0';
		}

		free(preserved_dir);

	}
	else if(flag == SSM_FLAG_SECRET_OPERATION) // /opt/share/secure-storage/
	{
		if(if_pointer != NULL) 	// absolute path == input is a file
		{
			// check whether directory is exist or not
			is_dir_exist = IsDirExist(SS_STORAGE_DEFAULT_PATH);

			if (is_dir_exist == 0) // SS_STORAGE_FILE_PATH is not exist
			{
				SLOGI("[%s] %s is making now.\n", __func__, SS_STORAGE_DEFAULT_PATH);
				if(mkdir(SS_STORAGE_DEFAULT_PATH, 0700) < 0)	// fail to make directory
				{
					SLOGE("[%s] [%s] cannnot be made\n", __func__, SS_STORAGE_DEFAULT_PATH);
					return SS_FILE_OPEN_ERROR;
				}
			}
			else if (is_dir_exist == -1) // Unknown error
			{
				SLOGE("[%s] Unknown error in the function IsDirExist().\n", __func__);
				return SS_PARAM_ERROR;
			}
			
			strncpy(dest, SS_STORAGE_DEFAULT_PATH, MAX_FILENAME_LEN - 1);
			strncat(dest, dir, strlen(dir));
			strncat(dest, "/", 1);

			// make directory
			dest[strlen(SS_STORAGE_DEFAULT_PATH) + strlen(dir) + 2] = '\0';
			is_dir_exist = IsDirExist(dest);

			if(is_dir_exist == 0) // not exist
			{
				SLOGI("[%s] %s is making now.\n", __func__, dest);
				if(mkdir(dest, 0700) < 0)
				{
					SLOGE("[%s] [%s] cannot be made\n", __func__, dest);
					return SS_FILE_OPEN_ERROR;
				}
			}
			
			strncat(dest, if_pointer + 1, strlen(if_pointer) + 1);
			strncat(dest, "_", 1);
			SHA1((unsigned char*)src, (size_t)strlen(src), path_hash);
			h_code = GetHashCode(path_hash);
			memset(s, 0x00, 34);
			snprintf(s, 34, "%u", h_code);
			strncat(dest, s, strlen(s));
			strncat(dest, SS_FILE_POSTFIX, strlen(SS_FILE_POSTFIX));

			dest[strlen(SS_STORAGE_DEFAULT_PATH) + strlen(dir) + strlen(if_pointer) + strlen(s) + strlen(SS_FILE_POSTFIX) + 4] = '\0';
		}
		else	// relative path == input is a buffer
		{
			// check whether directory is exist or not
			is_dir_exist = IsDirExist(SS_STORAGE_DEFAULT_PATH);

			if (is_dir_exist == 0) // SS_STORAGE_BUFFER_PATH is not exist
			{
				SLOGI("[%s] %s is making now.\n", __func__, SS_STORAGE_DEFAULT_PATH);
				if(mkdir(SS_STORAGE_DEFAULT_PATH, 0700) < 0)
				{
					SLOGE("[%s] [%s] cannot be made\n", __func__, SS_STORAGE_DEFAULT_PATH);
					return SS_FILE_OPEN_ERROR;
				}
			}
			else if (is_dir_exist == -1) // Unknown error
			{
				SLOGE("[%s] Unknown error in the function IsDirExist().\n", __func__);
				return SS_PARAM_ERROR;
			}

			strncpy(dest, SS_STORAGE_DEFAULT_PATH, MAX_FILENAME_LEN - 1);
			strncat(dest, dir, strlen(dir));
			strncat(dest, "/", 1);

			// make directory
			dest[strlen(SS_STORAGE_DEFAULT_PATH) + strlen(dir) + 2] = '\0';
			is_dir_exist = IsDirExist(dest);

			if(is_dir_exist == 0) // not exist
			{
				SLOGI("[%s] %s is making now.\n", __func__, dest);
				if(mkdir(dest, 0700) < 0)
				{
					SLOGE("[%s] [%s] cannot be made\n", __func__, dest);
					return SS_FILE_OPEN_ERROR;
				}
			}

			strncat(dest, src, strlen(src));
			strncat(dest, SS_FILE_POSTFIX, strlen(SS_FILE_POSTFIX));

			dest[strlen(SS_STORAGE_DEFAULT_PATH) + strlen(dir) + strlen(src) + strlen(SS_FILE_POSTFIX) + 2] = '\0';
		}
	}
	else
	{
		SLOGE("[%s] flag mispatch. cannot convert file name.\n", __func__);
		return SS_PARAM_ERROR;
	}

	return 1;
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

int SsServerDataStoreFromFile(int sender_pid, const char* data_filepath, ssm_flag flag, const char* cookie, const char* group_id)
{
	char key[16] = {0, };
	unsigned char iv[16] = {0, };
	const char* in_filepath = data_filepath;
	char out_filepath[MAX_FILENAME_LEN] = {0, };
	FILE* fd_in = NULL;
	FILE* fd_out = NULL;
	struct stat file_info;
	ssm_file_info_convert_t sfic;
	int res = -1;

	unsigned char p_text[ENCRYPT_SIZE]= {0, };
	unsigned char e_text[ENCRYPT_SIZE]= {0, };

	size_t read = 0, rest = 0;

	//0. privilege check and get directory name
	if(check_privilege(cookie, group_id) != 0)
	{
		SLOGE("[%s][%s] permission denied\n", __func__, group_id);
		return SS_PERMISSION_DENIED;
	}

	// 1. create out file name
	ConvertFileName(sender_pid, out_filepath, in_filepath, flag, group_id);
	
	// 2. file open 
	if(!(fd_in = fopen(in_filepath, "rb")))
	{
		SLOGE("[%s]File open error:(in_filepath) %s\n", __func__, in_filepath);
		return SS_FILE_OPEN_ERROR;	// file related error
	}
	
	if(!(fd_out = fopen(out_filepath, "wb")))
	{
		SLOGE("[%s]File open error:(out_filepath) %s\n", __func__, out_filepath);
		fclose(fd_in);
		return SS_FILE_OPEN_ERROR;	// file related error
	}
	chmod(out_filepath, 0600);

	// 3. write metadata 
	if(!stat(in_filepath, &file_info))
	{
		sfic.fInfoStruct.originSize = (unsigned int)file_info.st_size;
		sfic.fInfoStruct.storedSize = (unsigned int)(sfic.fInfoStruct.originSize/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
		sfic.fInfoStruct.reserved[0] = flag & 0x000000ff;
	}
	else
	{
		SLOGE("[%s] the function stat() fail.\n", __func__);
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
		SLOGE("[%s] fail to execute fflush().\n", __func__);
		return SS_FILE_WRITE_ERROR;
	}
	else {
		SLOGI("[%s] success to execute fflush().\n", __func__);
		if((res = fsync(fd_out->_fileno)) == -1) {
			SLOGE("[%s] fail to execute fsync().\n", __func__);
			return SS_FILE_WRITE_ERROR;
		}
		else
			SLOGI("[%s] success to execute fsync(). read=[%d], rest=[%d]\n", __func__, read, rest);
	}

	fclose(fd_in);
	fclose(fd_out);
	
	return 1;
}

int SsServerDataStoreFromBuffer(int sender_pid, char* writebuffer, size_t bufLen, const char* filename, ssm_flag flag, const char* cookie, const char* group_id)
{
	char key[16] = {0, };
	unsigned char iv[16] = {0, };
	char out_filepath[MAX_FILENAME_LEN+1];
	char *buffer = NULL;
	unsigned int writeLen = 0, loop, rest, count;
	FILE *fd_out = NULL;
	ssm_file_info_convert_t sfic;
	unsigned char p_text[ENCRYPT_SIZE]= {0, };
	unsigned char e_text[ENCRYPT_SIZE]= {0, };
	int res = -1;
	
	writeLen = (unsigned int)(bufLen / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
	buffer = (char*)malloc(writeLen + 1);
	if(!buffer)
	{
		SLOGE("[%s] Memory Allocation Fail in SsServerDataStoreFromBuffer()..\n", __func__);
		return SS_MEMORY_ERROR;
	}
	memset(buffer, 0x00, writeLen);
	memcpy(buffer, writebuffer, bufLen);

	//0. privilege check and get directory name
	if(check_privilege(cookie, group_id) != 0)
	{
		SLOGE("[%s] permission denied\n", __func__);
		free(buffer);
		return SS_PERMISSION_DENIED;
	}
	
	// create file path from filename
	ConvertFileName(sender_pid, out_filepath, filename, flag, group_id); 

	// open a file with write mode
	if(!(fd_out = fopen(out_filepath, "wb")))
	{
		SLOGE("[%s] File open error:(out_filepath) %s\n", __func__, out_filepath);
		free(buffer);
		return SS_FILE_OPEN_ERROR;	// file related error
	}
	chmod(out_filepath, 0600);
	
	// write metadata
	sfic.fInfoStruct.originSize = (unsigned int)bufLen;
	sfic.fInfoStruct.storedSize = writeLen;
	sfic.fInfoStruct.reserved[0] = flag & 0x000000ff;

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
		SLOGE("[%s] fail to execute fflush().\n", __func__);
		return SS_FILE_WRITE_ERROR;
	}
	else {
		SLOGI("[%s] success to execute fflush().\n", __func__);
		if((res = fsync(fd_out->_fileno)) == -1) {
			SLOGE("[%s] fail to execute fsync().\n", __func__);
			return SS_FILE_WRITE_ERROR;
		}
		else
			SLOGI("[%s] success to execute fsync(). loop=[%d], rest=[%d]\n", __func__, loop, rest);
	}

	fclose(fd_out);	
	free(buffer);
	
	return 1;
}

int SsServerDataRead(int sender_pid, const char* data_filepath, char* pRetBuf, unsigned int count, unsigned int* readLen, ssm_flag flag, const char* cookie, const char* group_id)
{
	unsigned int offset = count * MAX_RECV_DATA_LEN;
	char key[16] = {0, };
	unsigned char iv[16] = {0, };
	char in_filepath[MAX_FILENAME_LEN] = {0, };
	FILE* fd_in = NULL;
	char *out_data = pRetBuf;
	unsigned char p_text[ENCRYPT_SIZE]= {0, };
	unsigned char e_text[ENCRYPT_SIZE]= {0, };
	size_t read = 0;
	
	*readLen = 0;

	//0. privilege check and get directory name
	if(check_privilege(cookie, group_id) != 0)
	{
		SLOGE("[%s] permission denied\n", __func__);
		return SS_PERMISSION_DENIED;
	}

	// 1. create in file name : convert file name in order to access secure storage
	if(flag == SSM_FLAG_WIDGET)
		strncpy(in_filepath, data_filepath, MAX_FILENAME_LEN - 1);
	else
		ConvertFileName(sender_pid, in_filepath, data_filepath, flag, group_id);

	// 2. open file
	if(!(fd_in = fopen(in_filepath, "rb")))
	{
		SLOGE("[%s] File open error:(in_filepath) %s\n", __func__, in_filepath);
		return SS_FILE_OPEN_ERROR;	// file related error
	}
	
	// 3. skip to offset
	fseek(fd_in, (long)offset + sizeof(ssm_file_info_t), SEEK_SET);
	
	// 4. decrypt data
	GetKey(key, iv);
	
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

int SsServerDeleteFile(int sender_pid, const char* data_filepath, ssm_flag flag, const char* cookie, const char* group_id)
{
	const char* in_filepath = data_filepath;
	char out_filepath[MAX_FILENAME_LEN] = {0, };

	//0. privilege check and get directory name
	if(check_privilege(cookie, group_id) != 0)
	{
		SLOGE("[%s] permission denied\n", __func__);
		return SS_PERMISSION_DENIED;
	}

	// 1. create out file name
	ConvertFileName(sender_pid, out_filepath, in_filepath, flag, group_id);
	
	// 2. delete designated file
	if(unlink(out_filepath) != 0)	// unlink fail?
	{
		SLOGE("[%s] error occured while deleting file\n", __func__);
		return SS_FILE_WRITE_ERROR;
	}
	
	return 1;
}

int SsServerGetInfo(int sender_pid, const char* data_filepath, char* file_info, ssm_flag flag, const char* cookie, const char* group_id)
{
	size_t read = 0;
	FILE *fd_in = NULL;
	char in_filepath[MAX_FILENAME_LEN] = {0, };

	//0. privilege check and get directory name
	if(check_privilege(cookie, group_id) != 0)
	{
		SLOGE("[%s] permission denied, [%s]\n", __func__, group_id);
		return SS_PERMISSION_DENIED;
	}
	
	// 1. create in file name : convert file name in order to access secure storage
	if(flag == SSM_FLAG_WIDGET)
		strncpy(in_filepath, data_filepath, MAX_FILENAME_LEN - 1);
	else
		ConvertFileName(sender_pid, in_filepath, data_filepath, flag, group_id);
	
	// 1. open file
	if(!(fd_in = fopen( in_filepath, "rb")))
	{
		SLOGE("[%s] File open error:(in_filepath) [%s], [%s]\n", __func__, data_filepath, in_filepath );
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
