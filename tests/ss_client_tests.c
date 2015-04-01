
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ss_manager.h>

#define TET_UNINITIATED -1
#define TET_PASS 0
#define TET_FAIL 1

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

static void tet_result(char *tc_name, int tetResult)
{
    if(tetResult == TET_PASS)
        printf("[%s]...PASS\n\n", tc_name);
    else
        printf("[%s]...FAIL\n\n", tc_name);
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
    if(ret != 0)    // if fail,
    {
        tetResult = TET_UNINITIATED;
        goto error;
    }

    /* get information */
    ret = ssm_getinfo(filepath, &sfi, flag, group_id);
    if(ret == 0)    // success
        tetResult = TET_PASS;
    else
        tetResult = TET_FAIL;

    /* delete encrypted file */
    ret = ssm_delete_file(filepath, flag, group_id);
    if(ret != 0)
        tetResult = TET_UNINITIATED;

error:
    tet_result(__func__, tetResult);
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
    if(ret != 0)    // if fail,
    {
        tetResult = TET_UNINITIATED;
        goto error;
    }

    /* get information */
    ret = ssm_getinfo(NULL, &sfi, flag, group_id);
    printf("[%s] checkpoint3 [%d]\n", __func__, ret);
    if(ret == 0)    // success
        tetResult = TET_FAIL;
    else
        tetResult = TET_PASS;

    /* delete encrypted file */
    ret = ssm_delete_file(filepath, flag, group_id);
    printf("[%s] checkpoint4 [%d]\n", __func__, ret);
    if(ret != 0)
        tetResult = TET_UNINITIATED;

error:
    tet_result(__func__, tetResult);
}


/**
 * @brief Positive test case of ssm_read()
 */
static void utc_SecurityFW_ssm_read_func_01(void)
{
    int tetResult = TET_FAIL;
    /* variables for ssm_write_file */
    int ret = -1;
    char* filepath = "/opt/secure-storage/test/input.txt";
    ssm_flag flag = SSM_FLAG_DATA;
    char* group_id = NULL;

    /* variables for ssm_read */
    FILE* fp_original = NULL;
    char buf[20];
    char* retbuf = NULL;
    int readlen = 0;
    ssm_file_info_t sfi;

    /* get original file content. after encrypting, original file will be deleted */
    memset(buf, 0x00, 20);
    fp_original = fopen(filepath, "r");
    fgets(buf, 20, fp_original);
    fclose(fp_original);

    /* write file to secure-storage */
    ret = ssm_write_file(filepath, flag, group_id);
    if(ret != 0)    // if fail,
    {
        tetResult = TET_UNINITIATED;
        goto error;
    }

    /* read and compare */
    ssm_getinfo(filepath, &sfi, flag, group_id);
    retbuf = (char*)malloc(sizeof(char) * (sfi.originSize + 1));
    memset(retbuf, 0x00, (sfi.originSize + 1));
    ret = ssm_read(filepath, retbuf, sfi.originSize, &readlen, flag, group_id);
    if(ret != 0)    // if fail,
    {
        tetResult = TET_UNINITIATED;
        goto free_error;
    }

    if(tetResult != TET_UNINITIATED)
    {
        if(!memcmp(buf, retbuf, strlen(retbuf)))    // if same
            tetResult = TET_PASS;
        else
            tetResult = TET_FAIL;
    }

    /* delete encrypted file */
    ret = ssm_delete_file(filepath, flag, group_id);
    if(ret != 0)
        tetResult = TET_UNINITIATED;

free_error:
    free(retbuf);
error:
    tet_result(__func__, tetResult);
}


/**
 * @brief Negative test case of ssm_read()
 */
static void utc_SecurityFW_ssm_read_func_02(void)
{
    int tetResult = TET_FAIL;
    /* variables for ssm_write_file */
    int ret = -1;
    char* filepath = "/opt/secure-storage/test/input2.txt";
    ssm_flag flag = SSM_FLAG_DATA;
    char* group_id = NULL;

    /* variables for ssm_read */
    FILE* fp_original = NULL;
    char buf[20];
    char* retbuf = NULL;
    int readlen = 0;
    ssm_file_info_t sfi;

    /* get original file content. after encrypting, original file will be deleted */
    memset(buf, 0x00, 20);
    fp_original = fopen(filepath, "r");
    fgets(buf, 20, fp_original);
    fclose(fp_original);

    printf("[%s] checkpoint1\n", __func__);

    /* write file to secure-storage */
    ret = ssm_write_file(filepath, flag, group_id);
    printf("[%s] checkpoint2 [%d]\n", __func__, ret);
    if(ret != 0)    // if fail,
    {
        tetResult = TET_UNINITIATED;
        goto error;
    }


    /* read and compare */
    ret = ssm_getinfo(filepath, &sfi, flag, group_id);
    printf("[%s] checkpoint3 [%d]\n", __func__, ret);
    retbuf = (char*)malloc(sizeof(char) * (sfi.originSize + 1));
    memset(retbuf, 0x00, (sfi.originSize + 1));
    ret = ssm_read(NULL, retbuf, sfi.originSize, &readlen, flag, group_id);
    printf("[%s] checkpoint4 [%d]\n", __func__, ret);
    if(ret != 0)    // if fail,
        tetResult = TET_PASS;
    else
        tetResult = TET_FAIL;

    /* delete encrypted file */
    ret = ssm_delete_file(filepath, flag, group_id);
    printf("[%s] checkpoint5 [%d]\n", __func__, ret);
    if(ret != 0)
        tetResult = TET_UNINITIATED;

    free(retbuf);
error:
    tet_result(__func__, tetResult);
}



/**
 * @brief Positive test case of ssm_write_buffer()
 */
static void utc_SecurityFW_ssm_write_buffer_func_01(void)
{
    int tetResult = TET_FAIL;
    /* variables for ssm_write_buffer */
    int ret = -1;
    char oribuf[20];
    ssm_flag flag = SSM_FLAG_SECRET_OPERATION;
    char* group_id = NULL;
    char* filename = "write_buffer.txt";
    int buflen = 0;

    /* variables for ssm_read */
    char buf[20];
    char* retbuf = NULL;
    int readlen = 0;
    ssm_file_info_t sfi;

    /* set contents in buffers */
    memset(oribuf, 0x00, 20);
    memset(buf, 0x00, 20);
    strncpy(oribuf, "abcdefghij", 10);  // original buffer
    strncpy(buf, "abcdefghij", 10);     // encrypting

    buflen = strlen(buf);

    /* write file to secure-storage */
    ret = ssm_write_buffer(buf, buflen, filename, flag, group_id);
    if(ret != 0)    // if fail,
    {
        tetResult = TET_UNINITIATED;
        goto error;
    }

    /* read and compare */
    ssm_getinfo(filename, &sfi, flag, group_id);
    retbuf = (char*)malloc(sizeof(char) * (sfi.originSize + 1));
    memset(retbuf, 0x00, (sfi.originSize + 1));

    ret = ssm_read(filename, retbuf, sfi.originSize, &readlen, flag, group_id);
    if(ret != 0)    // if fail,
    {
        tetResult = TET_UNINITIATED;
        goto free_error;
    }

    if(tetResult != TET_UNINITIATED)
    {
        if(!memcmp(oribuf, retbuf, strlen(retbuf))) // if same
            tetResult = TET_PASS;
        else
            tetResult = TET_FAIL;
    }

    /* delete encrypted file */
    ret = ssm_delete_file(filename, flag, group_id);
    if(ret != 0)
        tetResult = TET_UNINITIATED;

free_error:
    free(retbuf);
error:
    tet_result(__func__, tetResult);
}


/**
 * @brief Negative test case of ssm_write_buffer()
 */
static void utc_SecurityFW_ssm_write_buffer_func_02(void)
{
    int tetResult = TET_FAIL;
    /* variables for ssm_write_buffer */
    int ret = -1;
    char* filename = "write_buffer.txt";
    ssm_flag flag = SSM_FLAG_SECRET_OPERATION;
    char buf[20];
    int buflen = 0;
    char* group_id = NULL;

    /* write file to secure-storage */
    ret = ssm_write_buffer(NULL, buflen, filename, flag, group_id);
    if(ret != 0)    // if fail,
        tetResult = TET_PASS;
    else
        tetResult = TET_FAIL;

    tet_result(__func__, tetResult);
}


/**
 * @brief Positive test case of ssm_write_file()
 */
static void utc_SecurityFW_ssm_write_file_func_01(void)
{
    int tetResult = TET_FAIL;
    /* variables for ssm_write_file */
    int ret = -1;
    char* filepath = "/opt/secure-storage/test/input.txt";
    ssm_flag flag = SSM_FLAG_DATA;
    char* group_id = NULL;

    /* variables for ssm_read */
    FILE* fp_original = NULL;
    char buf[20];
    char* retbuf = NULL;
    int readlen = 0;
    ssm_file_info_t sfi;

    /* get original file content. after encrypting, original file will be deleted */
    memset(buf, 0x00, 20);
    fp_original = fopen(filepath, "r");
    fgets(buf, 20, fp_original);
    fclose(fp_original);

    /* write file to secure-storage */
    ret = ssm_write_file(filepath, flag, group_id);
    if(ret != 0) {  // if fail,
        tetResult = TET_UNINITIATED;
        goto error;
    }

    /* read and compare */
    ssm_getinfo(filepath, &sfi, flag, group_id);
    retbuf = (char*)malloc(sizeof(char) * (sfi.originSize + 1));
    memset(retbuf, 0x00, (sfi.originSize + 1));
    ret = ssm_read(filepath, retbuf, sfi.originSize, &readlen, flag, group_id);
    if(ret != 0) {  // if fail,
        tetResult = TET_UNINITIATED;
        goto free_error;
    }

    if(tetResult != TET_UNINITIATED)
    {
        if(!memcmp(buf, retbuf, strlen(retbuf)))    // if same
            tetResult = TET_PASS;
        else
            tetResult = TET_FAIL;
    }

    /* delete encrypted file */
    ret = ssm_delete_file(filepath, flag, group_id);
    if(ret != 0)
        tetResult = TET_UNINITIATED;

free_error:
    free(retbuf);
error:
    tet_result(__func__, tetResult);
}

/**
 * @brief Negative test case of ssm_write_file()
 */
static void utc_SecurityFW_ssm_write_file_func_02(void)
{
    int tetResult = TET_FAIL;
    /* variables for ssm_write_file */
    int ret = -1;
    char* filepath = "/opt/secure-storage/test/input.txt";
    ssm_flag flag = SSM_FLAG_DATA;
    char* group_id = NULL;

    /* write file to secure-storage */
    ret = ssm_write_file(NULL, flag, group_id);
    if(ret != 0)    // if fail,
        tetResult = TET_PASS;
    else
        tetResult = TET_FAIL;

    tet_result(__func__, tetResult);
}


/**
 * @brief Positive test case of ssm_delete_file()
 */
static void utc_SecurityFW_ssm_delete_file_func_01(void)
{
    int tetResult = TET_FAIL;
    /* variables for ssm_delete_file */
    int ret = -1;
    char* filepath = "/opt/secure-storage/test/input.txt";
    ssm_flag flag = SSM_FLAG_DATA;
    char* group_id = NULL;

    /* write file to secure-storage */
    ret = ssm_write_file(filepath, flag, group_id);
    if(ret != 0)    // if fail,
    {
        tetResult = TET_UNINITIATED;
        goto error;
    }

    /* delete file */
    ret = ssm_delete_file(filepath, flag, group_id);
    if(ret == 0)
        tetResult = TET_PASS;
    else
        tetResult = TET_FAIL;

error:
    tet_result(__func__, tetResult);
}

/*
 * @brief Negative test case of ssm_delete_file()
 */
static void utc_SecurityFW_ssm_delete_file_func_02(void)
{
    int tetResult = TET_FAIL;
    /* variables for ssm_delete_file */
    int ret = -1;
    char* filepath = "/opt/secure-storage/test/input2.txt";
    ssm_flag flag = SSM_FLAG_DATA;
    char* group_id = NULL;

    printf("[%s] checkpoint1\n", __func__);

    /* write file to secure-storage */
    ret = ssm_write_file(filepath, flag, group_id);
    printf("[%s] checkpoint2 [%d]\n", __func__, ret);
    if(ret != 0)    // if fail,
    {
        tetResult = TET_UNINITIATED;
        goto error;
    }

    /* delete file */
    ret = ssm_delete_file(NULL, flag, group_id);
    printf("[%s] checkpoint3 [%d]\n", __func__, ret);
    if(ret != 0)
        tetResult = TET_PASS;
    else
        tetResult = TET_FAIL;

    /* delete encrypted file */
    ret = ssm_delete_file(filepath, flag, group_id);
    printf("[%s] checkpoint4 [%d]\n", __func__, ret);
    if(ret != 0)
        tetResult = TET_UNINITIATED;

error:
    tet_result(__func__, tetResult);
}


int main()
{
    startup();
    utc_SecurityFW_ssm_getinfo_func_01();
    utc_SecurityFW_ssm_getinfo_func_02();
    cleanup();

    startup();
    utc_SecurityFW_ssm_read_func_01();
    utc_SecurityFW_ssm_read_func_02();
    cleanup();

    startup();
    utc_SecurityFW_ssm_write_buffer_func_01();
    utc_SecurityFW_ssm_write_buffer_func_02();
    cleanup();

    startup();
    utc_SecurityFW_ssm_write_file_func_01();
    utc_SecurityFW_ssm_write_file_func_02();
    cleanup();

    startup();
    utc_SecurityFW_ssm_delete_file_func_01();
    utc_SecurityFW_ssm_delete_file_func_02();
    cleanup();

    return 0;
}
