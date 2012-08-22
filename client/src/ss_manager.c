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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "secure_storage.h"
#include "ss_client_intf.h"

#ifndef SS_API
#define SS_API __attribute__((visibility("default")))
#endif

/*****************************************************************************
 * Internal Functions
 *****************************************************************************/
SS_API
int ssm_getinfo(const char* pFilePath, ssm_file_info_t *sfi, ssm_flag flag, const char* group_id)
{
	int ret = 0;

	if(!pFilePath || !sfi)
	{
		SLOGE("[%s] Parameter error in ssm_getinfo()..\n", __func__);
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	
	ret = SsClientGetInfo(pFilePath, sfi, flag, group_id);

	if(ret == 1)
	{
		SLOGI("[%s] Getinfo Success.\n", __func__);
		ret = 0;	// return true
	}
	else
		SLOGE("[%s] Getinfo Fail.\n", __func__);

Error:
	return -(ret);
}

/*****************************************************************************
 * Manager APIs
 *****************************************************************************/
SS_API
int ssm_write_file(const char* pFilePath, ssm_flag flag, const char* group_id)
{
	int ret = 0;

	if(!pFilePath)
	{
		SLOGE("[%s] Parameter error in ssm_write_file()..\n", __func__);
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	
	if(flag <= SSM_FLAG_NONE || flag >= SSM_FLAG_MAX)
	{
		SLOGE("[%s] Parameter error in ssm_write_file()..\n", __func__);
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	
	ret = SsClientDataStoreFromFile(pFilePath, flag, group_id);
	if(ret == 1)
	{
		if(unlink(pFilePath) != 0)	// if fail
		{
			SLOGE("[%s] unlink fail. [%s]\n", __func__, pFilePath);
			return -1;	// return false
		}
		SLOGI("[%s] Write file Success.\n", __func__);
		return 0;	// return true
	}
	else
		SLOGE( "[%s] Write file Fail.\n", __func__);
	
Error:
	return -(ret);
}

SS_API
int ssm_write_buffer(char* pWriteBuffer, size_t bufLen, const char* pFileName, ssm_flag flag, const char* group_id)
{
	int ret = 0;

	if(!pWriteBuffer || !pFileName || (pFileName[0] == '/'))
	{
		SLOGE("[%s] Parameter error in ssm_write_buffer()..\n", __func__);
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	if(bufLen <= 0 || bufLen > 4096)
	{
		SLOGE( "[%s] Parameter error in ssm_write_buffer()..\n", __func__ );
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	if(flag <= SSM_FLAG_NONE || flag >= SSM_FLAG_MAX)
	{
		SLOGE( "[%s] Parameter error in ssm_write_buffer()..\n", __func__ );
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	ret = SsClientDataStoreFromBuffer(pWriteBuffer, bufLen, pFileName, flag, group_id);
	if(ret == 1)
	{
		SLOGI("[%s] Write buffer Success.\n", __func__);
		return 0;	// return true
	}
	else
		SLOGE("[%s] Write buffer Fail.\n", __func__);

Error:	
	return -(ret);
}

SS_API
int ssm_read(const char* pFilePath, char* pRetBuf, size_t bufLen, size_t *readLen, ssm_flag flag, const char* group_id)
{
	int ret = 0;
	ssm_file_info_t sfi;

	if(!pFilePath || !pRetBuf)
	{
		SLOGE( "[%s] Parameter error in ssm_read()..\n", __func__ );
		ret = SS_PARAM_ERROR;
		goto Error;
	}
	if(!readLen)
	{
		SLOGE("[%s] Parameter error in ssm_read()...\n", __func__);
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	// get info 
	ret = ssm_getinfo(pFilePath, &sfi, flag, group_id);
	if(ret != 0)	// ret != true?
	{
		SLOGE("[%s] getinfo error in ssm_read()..\n", __func__);
		goto Error;
	}
	// in case of flag mismatch...
	// check flag...
	// To do :
	if((bufLen > sfi.originSize) || (sfi.reserved[0] != (flag & 0x000000ff)))
	{
		SLOGE("[%s] Flag mismatch or buffer length error in ssm_read()..\n", __func__);
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	ret = SsClientDataRead(pFilePath, pRetBuf, sfi.originSize, readLen, flag, group_id);

	if(ret == 1)
	{
		SLOGI("[%s] Read Success.\n", __func__);
		return 0;	// return true
	}
	else
		SLOGE("[%s] Read Fail.\n", __func__);

Error:
	return -(ret);
}

SS_API
int ssm_delete_file(const char *pFilePath, ssm_flag flag, const char* group_id)
{
	int ret = 0;

	if(!pFilePath)
	{
		SLOGE("[%s] Parameter error in ssm_delete_file()..\n", __func__);
		ret = SS_PARAM_ERROR;
		goto Error;
	}

	ret = SsClientDeleteFile(pFilePath, flag, group_id);

	if(ret == 1)	// success
	{
		SLOGI("[%s] Delete file Success.\n", __func__);
		return 0;
	}
	else	// fail
		SLOGE("[%s] Delete file Fail.\n", __func__);

Error:
	return -(ret);
}
