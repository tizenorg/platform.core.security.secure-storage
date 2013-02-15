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
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include "ss_client_ipc.h"
#include "secure_storage.h"

RspData_t SsClientComm(ReqData_t* client_data)
{
	int sockfd = 0;
	int client_len = 0;
	struct sockaddr_un clientaddr;
	ReqData_t send_data = {0, };
	RspData_t recv_data = {0, };
	int temp_len_in = 0;
	int temp_len_sock = 0;
	int cookie_size = 20;

	send_data.req_type = client_data->req_type;
	send_data.enc_type = client_data->enc_type;
	send_data.count = client_data->count;
	send_data.flag = client_data->flag;

	temp_len_in = strlen(client_data->data_infilepath);
	
	strncpy(send_data.data_infilepath, client_data->data_infilepath, MAX_FILENAME_LEN - 1);
	send_data.data_infilepath[temp_len_in] = '\0';

//	cookie_size = security_server_get_cookie_size();
	memcpy(send_data.cookie, client_data->cookie, cookie_size);
	strncpy(send_data.group_id, client_data->group_id, MAX_GROUP_ID_LEN - 1);

	memcpy(send_data.buffer, client_data->buffer, MAX_SEND_DATA_LEN);
	
	if((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		SLOGE("Error in function socket()..\n");
		recv_data.rsp_type = SS_SOCKET_ERROR;	// ipc error
		goto Error_exit;
	}

	temp_len_sock = strlen(SS_SOCK_PATH);

	bzero(&clientaddr, sizeof(clientaddr));
	clientaddr.sun_family = AF_UNIX;
	strncpy(clientaddr.sun_path, SS_SOCK_PATH, temp_len_sock);
	clientaddr.sun_path[temp_len_sock] = '\0';
	client_len = sizeof(clientaddr);

	if(connect(sockfd, (struct sockaddr*)&clientaddr, client_len) < 0)
	{
		SLOGE("Error in function connect()..\n");
		recv_data.rsp_type = SS_SOCKET_ERROR;	// ipc error
		goto Error_close_exit;
	}

	if(write(sockfd, (char*)&send_data, sizeof(send_data)) < 0)
	{
		SLOGE("Error in function write()..\n");
		recv_data.rsp_type = SS_SOCKET_ERROR;	// ipc error
		goto Error_close_exit;
	}
	
	if(read(sockfd, (char*)&recv_data, sizeof(recv_data)) < 0)
	{
		SLOGE("Error in function read()..\n");
		recv_data.rsp_type = SS_SOCKET_ERROR;	// ipc error
		goto Error_close_exit;
	}

Error_close_exit:
	close(sockfd);
	
Error_exit:
	return recv_data;
}
