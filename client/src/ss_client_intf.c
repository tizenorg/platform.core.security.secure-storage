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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "secure_storage.h"
#include "ss_client_intf.h"
#include "ss_client_ipc.h"
#include "ss_manager.h"

#include "security-server.h"

int SsClientDataStoreFromFile(const char* filepath, ssm_flag flag, const char* group_id)
{
	ReqData_t* send_data = NULL;
	RspData_t recv_data;
	int temp_len = 0;
	int cookie_size;
	
	cookie_size = security_server_get_cookie_size();
	char cookie_content[cookie_size];
	
	if(security_server_request_cookie(cookie_content, cookie_size) < 0)	// error while getting cookie
	{
		SLOGE("[%s] Fail to get cookie\n", __func__);
		recv_data.rsp_type = SS_SECURE_STORAGE_ERROR;
		goto Error;
	}

	if(!filepath)
	{
		SLOGE( "[%s] Parameter error in SsClientDataStoreFromFile..\n", __func__);
		recv_data.rsp_type = SS_PARAM_ERROR;
		goto Error;
	}
	
	send_data = (ReqData_t*)malloc(sizeof(ReqData_t));

	if(!send_data)
	{
		SLOGE( "[%s] Memory allocation fail in SsClientDataStoreFromFile..\n", __func__);
		recv_data.rsp_type = SS_MEMORY_ERROR;
		goto Error;
	}

	send_data->req_type = 1;	// file store
	send_data->enc_type = 1;	// initial type
	send_data->count = 0;
	send_data->flag = flag;		// flag 
	temp_len = strlen(filepath);
	if(temp_len < MAX_FILENAME_LEN)
	{
		strncpy(send_data->data_infilepath, filepath, MAX_FILENAME_LEN - 1);
		send_data->data_infilepath[temp_len] = '\0';
	}
	else
	{
		SLOGE("[%s] filepath is too long.\n", __func__);
		recv_data.rsp_type = SS_PARAM_ERROR;
		goto Free_and_Error;
	}
	memset(send_data->cookie, 0x00, MAX_COOKIE_LEN);
	memset(send_data->group_id, 0x00, MAX_GROUP_ID_LEN);
	memcpy(send_data->cookie, cookie_content, cookie_size);
	if(group_id)
		strncpy(send_data->group_id, group_id, MAX_GROUP_ID_LEN - 1);
	else
		strncpy(send_data->group_id, "NOTUSED", MAX_GROUP_ID_LEN - 1);

	memset(send_data->buffer, 0x00, MAX_SEND_DATA_LEN + 1);
	recv_data = SsClientComm(send_data);
	
Free_and_Error:
	free(send_data);
Error:
	return recv_data.rsp_type;
}

int SsClientDataStoreFromBuffer(char* writebuffer, size_t bufLen, const char* filename, ssm_flag flag, const char* group_id)
{
	ReqData_t* send_data = NULL;
	RspData_t recv_data;
	int temp_len = 0;
	int cookie_size;
		
	cookie_size = security_server_get_cookie_size();
	char cookie_content[cookie_size];
	
	if(security_server_request_cookie(cookie_content, cookie_size) < 0)	// error while getting cookie
	{
		SLOGE("[%s] Fail to get cookie\n", __func__);
		recv_data.rsp_type = SS_SECURE_STORAGE_ERROR;
		goto Error;
	}

	if(!writebuffer || !filename)
	{
		SLOGE("[%s] Parameter error in SsClientDataStoreFromBuffer..\n", __func__);
		recv_data.rsp_type = SS_PARAM_ERROR;
		goto Error;
	}

	send_data = (ReqData_t*)malloc(sizeof(ReqData_t));
	if(!send_data)
	{
		SLOGE("[%s] Memory allocation fail in SsClientDataStoreFromBuffer..\n", __func__);
		recv_data.rsp_type = SS_MEMORY_ERROR;
		goto Error;
	}
	
	send_data->req_type = 2; 	// buffer store
	send_data->enc_type = 1; 
	send_data->count = bufLen; 
	send_data->flag = flag;
	temp_len = strlen(filename);
	if(temp_len < MAX_FILENAME_LEN)
	{
		strncpy(send_data->data_infilepath, filename, MAX_FILENAME_LEN - 1);
		send_data->data_infilepath[temp_len] = '\0';
	}
	else
	{
		SLOGE("[%s] filepath is too long.\n", __func__);
		recv_data.rsp_type = SS_PARAM_ERROR;
		goto Free_and_Error;
	}
	memset(send_data->cookie, 0x00, MAX_COOKIE_LEN);
	memset(send_data->group_id, 0x00, MAX_GROUP_ID_LEN);
	memcpy(send_data->cookie, cookie_content, cookie_size);
	if(group_id)
		strncpy(send_data->group_id, group_id, MAX_GROUP_ID_LEN - 1);
	else
		strncpy(send_data->group_id, "NOTUSED", MAX_GROUP_ID_LEN - 1);

	memcpy(send_data->buffer, writebuffer, bufLen);
	recv_data = SsClientComm(send_data);

Free_and_Error:
	free(send_data);
Error:
	return recv_data.rsp_type;
}

int SsClientDataRead(const char* filepath, char* pRetBuf, size_t bufLen, size_t *readLen, ssm_flag flag, const char* group_id)
{
	unsigned int count = (unsigned int)(bufLen / MAX_RECV_DATA_LEN + 1);
	unsigned int rest = (unsigned int)(bufLen % MAX_RECV_DATA_LEN);
	char* buffer;
	ReqData_t* send_data = NULL;
	RspData_t recv_data;
	int temp_len = 0;
	int cookie_size;
		
	cookie_size = security_server_get_cookie_size();
	char cookie_content[cookie_size];
	
	if(security_server_request_cookie(cookie_content, cookie_size) < 0)	// error while getting cookie
	{
		SLOGE("[%s] Fail to get cookie\n", __func__);
		recv_data.rsp_type = SS_SECURE_STORAGE_ERROR;
		goto Error;
	}

	if(!filepath)
	{
		SLOGE("[%s] filepath Parameter error in SsClientDataRead..\n", __func__);
		recv_data.rsp_type = SS_PARAM_ERROR;
		goto Error;
	}
	if(!readLen)
	{
		SLOGE("[%s] readLen Parameter error in SsClientDataRead..\n", __func__);
		recv_data.rsp_type = SS_PARAM_ERROR;
		goto Error;
	}

	*readLen = 0;
	buffer = pRetBuf;

	send_data = (ReqData_t*)malloc(sizeof(ReqData_t));

	if(!send_data)
	{
		SLOGE("[%s] Memory allocation fail in SsClientDataRead..\n", __func__);
		recv_data.rsp_type = SS_MEMORY_ERROR;
		goto Error;
	}

	// fill send_data
	send_data->req_type = 3;	// read data from storage
	send_data->enc_type = 1;	// initial type
	send_data->count = 0;
	send_data->flag = flag & 0x000000ff;	//flag;
	temp_len = strlen(filepath);
	if(temp_len < MAX_FILENAME_LEN)
	{
		strncpy(send_data->data_infilepath, filepath, MAX_FILENAME_LEN - 1);
		send_data->data_infilepath[temp_len] = '\0';
	}
	else
	{
		SLOGE("[%s] filepath is too long.\n", __func__);
		recv_data.rsp_type = SS_PARAM_ERROR;
		goto Free_and_Error;
	}
	memset(send_data->cookie, 0x00, MAX_COOKIE_LEN);
	memset(send_data->group_id, 0x00, MAX_GROUP_ID_LEN);
	memcpy(send_data->cookie, cookie_content, MAX_COOKIE_LEN);
	if(group_id)
		strncpy(send_data->group_id, group_id, MAX_GROUP_ID_LEN - 1);
	else
		strncpy(send_data->group_id, "NOTUSED", MAX_GROUP_ID_LEN - 1);
	memset(send_data->buffer, 0x00, MAX_SEND_DATA_LEN+1);
	
	// Call Server per 4KB data (count from 0 to ~)
	for ( ; send_data->count < count; send_data->count++)
	{
		//receive data from server
		recv_data = SsClientComm(send_data);
	
		// check response type
		if(recv_data.rsp_type != 1)
		{
			SLOGE("[%s] data read error from server...\n", __func__);
			goto Free_and_Error;
		}
		// copy the last data (last count)
		if(send_data->count == (count - 1))
		{
			memcpy(buffer, recv_data.buffer, rest);
			*readLen += (size_t)rest;
			goto Last;
			//break;
		}
		
		memcpy(buffer, recv_data.buffer, MAX_RECV_DATA_LEN);
		*readLen += (size_t)recv_data.readLen;
		buffer += recv_data.readLen;
	}
Last : 	
	if(bufLen != *readLen)
	{
		SLOGE( "[%s] Decrypted abnormally\n", __func__);
		recv_data.rsp_type = SS_DECRYPTION_ERROR;
		goto Free_and_Error;
	}

	SLOGE("[%s] Decrypted file name : %s\n", __func__,  recv_data.data_filepath);
Free_and_Error:
	free(send_data);
Error:
	return recv_data.rsp_type;
}

int SsClientGetInfo(const char* filepath, ssm_file_info_t* sfi, ssm_flag flag, const char* group_id)
{

	ReqData_t* send_data = NULL;
	RspData_t recv_data;
	ssm_file_info_convert_t sfic;
	int temp_len = 0;
	int cookie_size;
		
	cookie_size = security_server_get_cookie_size();
	char cookie_content[cookie_size];
	
	if(security_server_request_cookie(cookie_content, cookie_size) < 0)	// error while getting cookie
	{
		SLOGE("[%s] Fail to get cookie\n", __func__);
		recv_data.rsp_type = SS_SECURE_STORAGE_ERROR;
		goto Error;
	}

	if(!filepath || !sfi)
	{
		SLOGE("[%s] Parameter error in SsClientGetInfo..\n", __func__);
		recv_data.rsp_type = SS_PARAM_ERROR;
		goto Error;
	}
	
	send_data = (ReqData_t*)malloc(sizeof(ReqData_t));

	if(!send_data)
	{
		SLOGE("[%s] Memory allocation fail in SsClientGetInfo..\n", __func__);
		recv_data.rsp_type = SS_MEMORY_ERROR;
		goto Error;
	}

	// fill send_data 
	send_data->req_type = 4;	// get info type
	send_data->enc_type = 1;	// initial type
	send_data->count = 0;
	send_data->flag = flag & 0x000000ff;	//flag;
	temp_len = strlen(filepath);
	if(temp_len < MAX_FILENAME_LEN)
	{
		strncpy(send_data->data_infilepath, filepath, MAX_FILENAME_LEN - 1);
		send_data->data_infilepath[temp_len] = '\0';
	}
	else
	{
		SLOGE("[%s] filepath is too long.\n", __func__);
		recv_data.rsp_type = SS_PARAM_ERROR;
		goto Free_and_Error;
	}
	memset(send_data->cookie, 0x00, MAX_COOKIE_LEN);
	memset(send_data->group_id, 0x00, MAX_GROUP_ID_LEN);
	memcpy(send_data->cookie, cookie_content, cookie_size);
	if(group_id)
		strncpy(send_data->group_id, group_id, MAX_GROUP_ID_LEN - 1);
	else
		strncpy(send_data->group_id, "NOTUSED", MAX_GROUP_ID_LEN - 1);
	memset(send_data->buffer, 0x00, MAX_SEND_DATA_LEN + 1);

	recv_data = SsClientComm(send_data);

	memcpy(sfic.fInfoArray, recv_data.buffer, sizeof(ssm_file_info_t));
	sfi->originSize = sfic.fInfoStruct.originSize;
	sfi->storedSize = sfic.fInfoStruct.storedSize;
	memcpy(sfi->reserved, sfic.fInfoStruct.reserved, 8);

Free_and_Error:
	free(send_data);
Error:
	return recv_data.rsp_type;
}

int SsClientDeleteFile(const char *pFilePath, ssm_flag flag, const char* group_id)
{
	ReqData_t* send_data = NULL;
	RspData_t recv_data;
	int temp_len = 0;
	int cookie_size;
		
	cookie_size = security_server_get_cookie_size();
	char cookie_content[cookie_size];
	
	if(security_server_request_cookie(cookie_content, cookie_size) < 0)	// error while getting cookie
	{
		SLOGE("[%s] Fail to get cookie\n", __func__);
		recv_data.rsp_type = SS_SECURE_STORAGE_ERROR;
		goto Error;
	}

	if(!pFilePath)
	{
		SLOGE("[%s] Parameter error in SsClientDeleteFile..\n", __func__);
		recv_data.rsp_type = SS_PARAM_ERROR;
		goto Error;
	}
	
	send_data = (ReqData_t*)malloc(sizeof(ReqData_t));

	if(!send_data)
	{
		SLOGE("[%s] Memory allocation fail in SsClientDeleteFile..\n", __func__);
		recv_data.rsp_type = SS_MEMORY_ERROR;
		goto Error;
	}

	send_data->req_type = 10;	// delete file
	send_data->enc_type = 1;	// initial type
	send_data->count = 0;
	send_data->flag = flag;		// flag 
	temp_len = strlen(pFilePath);
	if(temp_len < MAX_FILENAME_LEN)
	{
		strncpy(send_data->data_infilepath, pFilePath, MAX_FILENAME_LEN - 1);
		send_data->data_infilepath[temp_len] = '\0';
	}
	else
	{
		SLOGE("[%s] filepath is too long.\n", __func__);
		recv_data.rsp_type = SS_PARAM_ERROR;
		goto Free_and_Error;
	}
	memset(send_data->cookie, 0x00, MAX_COOKIE_LEN);
	memset(send_data->group_id, 0x00, MAX_GROUP_ID_LEN);
	memcpy(send_data->cookie, cookie_content, cookie_size);
	if(group_id)
		strncpy(send_data->group_id, group_id, MAX_GROUP_ID_LEN - 1);
	else
		strncpy(send_data->group_id, "NOTUSED", MAX_GROUP_ID_LEN - 1);
	memset(send_data->buffer, 0x00, MAX_SEND_DATA_LEN+1);

	recv_data = SsClientComm(send_data);

Free_and_Error:
	free(send_data);

	SLOGE("[%s] Deleted file name: %s\n", __func__, recv_data.data_filepath);
	
Error:
	return recv_data.rsp_type;
}
