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

#ifndef __SECURE_STORAGE__
#define __SECURE_STORAGE__

#include "ss_manager.h"

#define	SS_SOCK_PATH			"/tmp/SsSocket"

#define		MAX_FILENAME_LEN	256	// for absolute path
//#define 	MAX_RECV_DATA_LEN	16384	// internal buffer = 4KB
#define 	MAX_RECV_DATA_LEN	4096	// internal buffer = 4KB
//#define 	MAX_SEND_DATA_LEN	16384	// internal buffer = 4KB
#define 	MAX_SEND_DATA_LEN	4096	// internal buffer = 4KB
#define		MAX_GROUP_ID_LEN	32
#define		MAX_COOKIE_LEN		20

#define SS_STORAGE_DEFAULT_PATH		"/opt/share/secure-storage/"

/* using dlog */
#ifdef SS_DLOG_USE

#define LOG_TAG	"SECURE_STORAGE"
#include <dlog.h>

#elif SS_CONSOLE_USE // debug msg will be printed in console

#define SLOGD(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)
#define SLOGV(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)
#define SLOGI(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)
#define SLOGW(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)
#define SLOGE(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)
#define SLOGF(FMT, ARG ...)	fprintf(stderr, FMT, ##ARG)

#else // don't use logging
			
#define SLOGD(FMT, ARG ...)	{}
#define SLOGV(FMT, ARG ...)	{}
#define SLOGI(FMT, ARG ...)	{}
#define SLOGW(FMT, ARG ...)	{}
#define SLOGE(FMT, ARG ...)	{}
#define SLOGF(FMT, ARG ...)	{}
			
#endif

#define	SS_FILE_POSTFIX			".e"

typedef union {
	ssm_file_info_t fInfoStruct;
	char		fInfoArray[16];
} ssm_file_info_convert_t;

typedef struct {
	int				req_type;
	int				enc_type;
	unsigned int	count; 	// 1 count = 4KB
   	unsigned int	flag;	
	char			data_infilepath[MAX_FILENAME_LEN];
	char			buffer[MAX_SEND_DATA_LEN+1];
	char			group_id[MAX_GROUP_ID_LEN];
	char			cookie[MAX_COOKIE_LEN];
} ReqData_t;

typedef struct {
	int				rsp_type;
	unsigned int	readLen;
	char			data_filepath[MAX_FILENAME_LEN];
	char			buffer[MAX_RECV_DATA_LEN+1];
} RspData_t;

#endif
