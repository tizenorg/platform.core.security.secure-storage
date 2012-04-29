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

#include <ss_manager.h>
#include <tet_api.h>

static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_SecurityFW_ssm_getinfo_func_01(void);
static void utc_SecurityFW_ssm_getinfo_func_02(void);

enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};

struct tet_testlist tet_testlist[] = {
	{ utc_SecurityFW_ssm_getinfo_func_01, POSITIVE_TC_IDX },
	{ utc_SecurityFW_ssm_getinfo_func_02, NEGATIVE_TC_IDX },
	{ NULL, 0 }
};

static void startup(void)
{
	printf("Make temporary directory - /opt/secure-storage/test/\n");
	system("mkdir -p /opt/secure-storage/test");
	printf("Make temporary file\n");
	system("touch /opt/secure-storage/test/input.txt");
	system("echo \"abcdefghij\" > /opt/secure-storage/test/input.txt");
	system("cp /opt/secure-storage/test/input.txt /opt/secure-storage/test/input2.txt");
}

static void cleanup(void)
{
	printf("Remove tamporary file and directory\n");
	system("rm -rf /opt/secure-storage/test");
}

/**
 * @brief Positive test case of ssm_getinfo()
 */
static void utc_SecurityFW_ssm_getinfo_func_01(void)
{
	int tetResult = TET_FAIL;
	/* variables for ssm_write_file */
	int ret = -1;
	char* filepath = "/opt/secure-storage/test/input.txt";
	ssm_flag flag = SSM_FLAG_DATA;
	char* group_id = NULL;
	ssm_file_info_t sfi;

	/* write file to secure-storage */
	ret = ssm_write_file(filepath, flag, group_id);
	if(ret != 0)	// if fail,
	{
		tetResult = TET_UNINITIATED;
		goto error;
	}

	/* get information */
	ret = ssm_getinfo(filepath, &sfi, flag, group_id);
	if(ret == 0)	// success
		tetResult = TET_PASS;
	else
		tetResult = TET_FAIL;

	/* delete encrypted file */
	ret = ssm_delete_file(filepath, flag, group_id);
	if(ret != 0)
		tetResult = TET_UNINITIATED;

error:
	printf("[%d] [%s]\n", tetResult, __FILE__);
	tet_result(tetResult);
}

/**
 * @brief Negative test case of ssm_getinfo()
 */
static void utc_SecurityFW_ssm_getinfo_func_02(void)
{
	int tetResult = TET_FAIL;
	/* variables for ssm_write_file */
	int ret = -1;
	char* filepath = "/opt/secure-storage/test/input2.txt";
	ssm_flag flag = SSM_FLAG_DATA;
	char* group_id = NULL;
	ssm_file_info_t sfi;

	printf("[%s] checkpoint1\n", __func__);
	
	/* write file to secure-storage */
	ret = ssm_write_file(filepath, flag, group_id);
	printf("[%s] checkpoint2 [%d]\n", __func__, ret);
	if(ret != 0)	// if fail,
	{
		tetResult = TET_UNINITIATED;
		goto error;
	}

	/* get information */
	ret = ssm_getinfo(NULL, &sfi, flag, group_id);
	printf("[%s] checkpoint3 [%d]\n", __func__, ret);
	if(ret == 0)	// success
		tetResult = TET_FAIL;
	else
		tetResult = TET_PASS;

	/* delete encrypted file */
	ret = ssm_delete_file(filepath, flag, group_id);
	printf("[%s] checkpoint4 [%d]\n", __func__, ret);
	if(ret != 0)
		tetResult = TET_UNINITIATED;

error:
	printf("[%d] [%s]\n", tetResult, __FILE__);
	tet_result(tetResult);
}
