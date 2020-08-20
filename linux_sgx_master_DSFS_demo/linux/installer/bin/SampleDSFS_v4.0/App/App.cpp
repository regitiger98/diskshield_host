/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include<unistd.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<time.h>
#include<stdlib.h>

#define P_SIZE 4096
#define K_SIZE 1024
#define IO_SIZE 8192
#define PAGE_BIT 12

#define barrier() __asm__ __volatile__("": : :"memory")
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");

    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{

	int pid,pid2;
	int process,  mode, c,filename,cnt=0,new_open;
	char name[50]={0};
	int i,fd;
	int access,key,mode2,tmp;
	int s;
	struct timespec start,end,now;
	long long j,iter,file_size,write_cnt=0;
	double start_time,end_time,rate,r;
	unsigned long seed;
	unsigned short rw_rand_state[3];
	int file_num=0,file_cnt=1;

	unsigned char enclave_id,file_id;
	size_t position=10;
	
//	char *dd,*sig,*read_sig;
//	char *buf,*buf2;



	if(argc<6){
		printf("./test [1:name, 2: process, 3: filesize, 4: mode(0:read,1:write), 5: work(0:original,1:key_systemcall), [8 : file_start_num]\n");
		return 0;
	}

	process=atoi(argv[2]);
	file_size=atoi(argv[3]);
	mode=atoi(argv[4]);
	new_open=atoi(argv[5]);
	access=S_IREAD|S_IWRITE;
	/////////////////
	file_size=(file_size*K_SIZE);
	iter=file_size/IO_SIZE;
	switch(mode){
		case 0:	mode2=O_RDWR|__O_DIRECT; break;
		case 1: mode2=O_RDWR|O_CREAT|__O_DIRECT; break;
	}
	printf("test_%s : process %d, file_size %lld, mode %d\n",
			argv[1],process,file_size,mode);
	barrier();
	/////////////////////////////fork 
	tmp=process/2;
	cnt=1;
	barrier();
	for(i=2;i<=process;i*=2){
	    barrier();
	    pid=fork();
	    barrier();
	    switch(pid){
		case -1 : printf("fork error %d\n",i); return 0;
		case 0 : cnt+=tmp; break;
	    }
	    tmp/=2;
	}
	barrier();
	//////////////////////////////
	printf("Start main in Enclave\n");
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
    }
	
	char buf[P_SIZE*3],sig[P_SIZE],read_sig[P_SIZE];
//	buf2=(char*)malloc(P_SIZE*3*sizeof(char));
//	dd=(char*)malloc(P_SIZE*3*sizeof(char));
//	sig=(char*)malloc(P_SIZE*sizeof(char));
//	read_sig=(char*)malloc(P_SIZE*sizeof(char));
	memset(buf,0,sizeof(buf));
	memset(sig,0,sizeof(sig));
	memset(read_sig,0,sizeof(read_sig));

	for(i=0;i<IO_SIZE;i++){
		buf[i]=0x11;
		//		buf[i]=(rand()%10)+'0';
	}

	filename=(cnt-1)*file_cnt+1+file_num;

	enclave_id=1;
	file_id=(unsigned char)filename;
	position=4096;

	char file_name[5];
	size_t data_size=8192;	//fixed

	clock_gettime(CLOCK_MONOTONIC, &start);	
	//position=12288;
	if(new_open==1){//new systemcall
		if(mode==0){
			file_name[0]=2;//read flag;	
			for(j=0;j<iter;j++){
				ecall_IPFS_function(global_eid, file_name, buf, position,data_size);	//in this function , I will write and read the code from IPFS
			//	s=enc_read(enclave_id,file_id,position,buf,IO_SIZE);
				position+=IO_SIZE;
			//	if(s<=0){ printf("fail sequential enc_read\n");  return 0;}
			}
		}
		else{
			file_name[0]=1;//write flag
			for(j=0;j<iter;j++){
				//printf("fuc\n");
				//char file_name[5];
//				char datas[8192];
//				printf("pos ::::%d\n", position);
//				size_t offset=4096;
//				size_t data_size=8192;
//				for(i=0; i<8192; i++)	datas[i]=0x11;
//				file_name[0]=1;
//				ecall_IPFS_function(global_eid, file_name, buf, offset, data_size);
				printf("%d %d %d\n", global_eid, position, data_size);
			//	printf("%d,%d,%d,%d,%d\n",file_name[0],file_name[1],file_name[2],file_name[3],file_name[4]);
			//	printf("%x %x %x %x %x\n",buf[0],buf[1],buf[2],buf[3],buf[4]);
//
//position=10;
				ecall_IPFS_function(global_eid, file_name, buf, position,data_size);	//in this function , I will write and read the code from IPFS
				printf("%d %d %d\n", global_eid, position, data_size);
			//	printf("%d,%d,%d,%d,%d\n",file_name[0],file_name[1],file_name[2],file_name[3],file_name[4]);
			//	printf("%x %x %x %x %x\n",buf[0],buf[1],buf[2],buf[3],buf[4]);
			//s=enc_write(enclave_id,file_id,position,buf,sig,IO_SIZE,read_sig);
				position+=IO_SIZE;
				printf("kkk %d\n",j);
			//	if(s<=0){ printf("fail sequential enc_read\n");  return 0;}
			}
		}

	}
	clock_gettime(CLOCK_MONOTONIC,&end);
	start_time=(start.tv_nsec/10e9)+start.tv_sec;
	end_time=(end.tv_nsec/10e9)+end.tv_sec;
	printf("process %d, start_time: %.9lf seconds, end_time : %.9lf seconds,\n",cnt,start_time,end_time);

    sgx_destroy_enclave(global_eid);
//	free(buf2); free(dd); free(sig); free(read_sig);
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
//    getchar();
    return 0;
}
    
