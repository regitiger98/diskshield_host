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
#include<sys/wait.h>

#include<pthread.h>
#include<sys/mman.h>

#define P_SIZE 4096
#define K_SIZE 1024
#define IO_SIZE 8192
#define PAGE_BIT 12

#define MODE_RD 0
#define MODE_WR 1
#define MODE_W_R 2
#define MODE_SEQ 0
#define MODE_RAND 1
#define MODE_IPFS 0
#define MODE_DSFS 1
#define MODE_SMALL 3
#define MODE_DEMO 4

int b_pshared=1;
pthread_barrierattr_t *b_attr;
pthread_barrier_t* barrier;
int b_count;


//#define barrier() __asm__ __volatile__("": : :"memory")
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
	//printf("init enclave\nhome directoyr : %s\n",home_dir);   

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
	//printf("TOKEN FILE NAME : %s\n", TOKEN_FILENAME);
    FILE *fp = fopen(token_path, "rb");
	//printf("token path : %s\n", token_path);
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
    //printf("DEBUG FLAG: %d\n", SGX_DEBUG_FLAG);
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
    int cnt;
    int num_process, mode_rw, mode_size, work_load;
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
	struct timespec ipfs_clk, ipfs_clk_end;
	double ipfs_time, ipfs_time_end;


	//순서
	//1 1 0 1 (SeqWR) init write
	//1 0 0 1 (SeqRD)
	//1 1 0 1 (SeqWR) - overwrite
	//1 0 1 1 (RandRD)
	//1 1 1 1 (RandWR)

//	1 1 3 1(SmallWrite) initial write
	//	1 1 3 1(SmallWrite)0 OVERWRITE
	//  1 0 3 1	(SmallRead)
    
    //DEMO
    //1 1 4 1

	//모든 시간 측정
	if(argc!=5){
		//printf("/test 1: process, 2: I/O mode(0:READ, 1:WRITE 2:WR+RD), 3:size(0:SEQ, 1:RAND), 4: work load(0:IPFS, 1:DSFS)\n");
        return 0;
	}
    //printf("argc : %d\n", argc);
	num_process=atoi(argv[1]);
	mode_rw=atoi(argv[2]);
	mode_size=atoi(argv[3]);
    work_load = atoi(argv[4]);
	access=S_IREAD|S_IWRITE;
/*
	switch(mode){
		case 0:	mode2=O_RDWR|__O_DIRECT; break;
		case 1: mode2=O_RDWR|O_CREAT|__O_DIRECT; break;
	}
*/
	//printf("process : %d, 2: I/O mode(0:READ, 1:WRITE 2:WR+RD) : %d, 3:size(0:SEQ, 1:RAND) : %d, 4: work load(0:IPFS, 1:DSFS) : %d\n"\
            , num_process, mode_rw, mode_size, work_load);

	//barrier();	//Q1)왜 있지? memory access barrier : 이전, 이후 메모리 억세스 순서 그대로.
    b_count= num_process;
	b_attr = (pthread_barrierattr_t*) malloc (sizeof(pthread_barrierattr_t));
	//barrier= (pthread_barrier_t*) malloc(sizeof(pthread_barrier_t));
	barrier = (pthread_barrier_t*)mmap(NULL,sizeof(pthread_barrier_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pthread_barrierattr_setpshared(b_attr, b_pshared);
	pthread_barrier_init(barrier, b_attr, b_count);


    //1. 멀티 프로세스 실험
	tmp=num_process/2;
	cnt=1;
//	barrier();
	for(i=2;i<=num_process;i*=2){
	  //  barrier();
	    pid=fork();
	  //  barrier();
	    switch(pid){
		case -1 : printf("fork error %d\n",i); return 0;
		case 0 : cnt+=tmp; break;
	    }
	    tmp/=2;
	}
	
    //barrier();
    char n_proc_s[5];
	//sprintf(n_proc_s, "%d", getpid());
	if(cnt<10)	sprintf(n_proc_s, "000%d", cnt);
	else		sprintf(n_proc_s, "00%d", cnt);

    // Initialize the enclave
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
    }


    //여기부터 재야하는데 어케재지?
   // printf("before barreir// cnt %d %s\n", cnt, n_proc_s);

    pthread_barrier_wait(barrier);
   
	//printf("after barreir// cnt %d\n", cnt);
    
	clock_gettime(CLOCK_MONOTONIC, &start);	
	//barrier();
/*
	clock_gettime(CLOCK_MONOTONIC, &ipfs_clk);
	ipfs_time=(ipfs_clk.tv_nsec/1e9)+ipfs_clk.tv_sec;

	IPFS_simple(global_eid, 1); //WRITE OPEN
    //IPFS_simple(global_eid, 4);	//READ OPEN

	clock_gettime(CLOCK_MONOTONIC, &ipfs_clk_end);
	ipfs_time_end=(ipfs_clk_end.tv_nsec/1e9)+ipfs_clk_end.tv_sec;
	//ipfs_time = ipfs_time_end;

	printf("App open : %.9lf %.9lf\n", ipfs_time_end, ipfs_time_end - ipfs_time);
	ipfs_time = ipfs_time_end;


	int ii;
    for(ii=0; ii<1; ii++)
    {
    	IPFS_simple(global_eid, 2);	//WRITE
    	//IPFS_simple(global_eid, 5);	//READ

    	clock_gettime(CLOCK_MONOTONIC, &ipfs_clk_end);
    	ipfs_time_end=(ipfs_clk_end.tv_nsec/1e9)+ipfs_clk_end.tv_sec;
    	printf("App write : %.9lf %.9lf\n", ipfs_time_end, ipfs_time_end - ipfs_time);
    	ipfs_time = ipfs_time_end;
    }
    IPFS_simple(global_eid, 3);
    clock_gettime(CLOCK_MONOTONIC, &ipfs_clk);
    ipfs_time_end=(ipfs_clk.tv_nsec/1e9)+ipfs_clk.tv_sec;
    printf("App close : %.9lf %.9lf\n", ipfs_time_end, ipfs_time_end - ipfs_time);
*/


    if(mode_rw==MODE_W_R || mode_rw == MODE_WR)
    {
        if(mode_size == MODE_SEQ)
        {
            IPFS_write_seq(global_eid, work_load, n_proc_s, num_process);
        }
        else if(mode_size == MODE_RAND)
        {
            IPFS_write_rand(global_eid, work_load, n_proc_s, num_process);
        }
    }

    if(mode_rw==MODE_W_R || mode_rw == MODE_RD)
    {
        if(mode_size == MODE_SEQ)
        {
            IPFS_read_seq(global_eid, work_load, n_proc_s, num_process);
        }
        else if(mode_size == MODE_RAND)
        {
            IPFS_read_rand(global_eid, work_load, n_proc_s, num_process);
        }   
    }

    if(mode_size == MODE_SMALL)
    {
        int file_no = (4096/num_process)*(cnt-1);
        if(file_no==0)	            sprintf(n_proc_s, "0000");
        else if(file_no<10)         sprintf(n_proc_s, "000%d", file_no);
        else if(file_no<100)        sprintf(n_proc_s, "00%d", file_no);
	    else if(file_no<1000)		sprintf(n_proc_s, "0%d", file_no);
	    else if(file_no>=1000)		sprintf(n_proc_s, "%d", file_no);
       // printf("EVAL file_no: %s", n_proc_s);
    	if(mode_rw == MODE_WR)
    	{
    		IPFS_write_small(global_eid, work_load, n_proc_s, num_process);

    	}
    	if(mode_rw == MODE_RD)
    	{
    		IPFS_read_small(global_eid, work_load, n_proc_s, num_process);
    	}
    }

    if(mode_size== MODE_DEMO)
    {
        printf("DEMO\n");
        IPFS_demo(global_eid);
    }


	//open, cloase latency measurement
	/*
	char file_name[16]="4KB.txt";
	//make_file(global_eid, file_name);

	struct timespec oc_clk_s, oc_clk_e;
	double oc_time_s, oc_time_e;

	clock_gettime(CLOCK_MONOTONIC, &oc_clk_s);
	open_close(global_eid, 1, file_name);
	clock_gettime(CLOCK_MONOTONIC, &oc_clk_e);

	oc_time_s=(oc_clk_s.tv_nsec/10e9)+oc_clk_s.tv_sec;
	oc_time_e=(oc_clk_e.tv_nsec/10e9)+oc_clk_e.tv_sec;

	printf("open : %.9lf %.9lf %.9lf\n", oc_time_s, oc_time_e, oc_time_e-oc_time_s);

	clock_gettime(CLOCK_MONOTONIC, &oc_clk_s);
	open_close(global_eid, 2, file_name);
	clock_gettime(CLOCK_MONOTONIC, &oc_clk_e);

	oc_time_s=(oc_clk_s.tv_nsec/10e9)+oc_clk_s.tv_sec;
	oc_time_e=(oc_clk_e.tv_nsec/10e9)+oc_clk_e.tv_sec;

	printf("close : %.9lf %.9lf %.9lf\n", oc_time_s, oc_time_e, oc_time_e-oc_time_s);
*/


/*
	//position=12288;
	//new_open=1; //임시
	if(new_open==1){//new systemcall
	//	file_name[0]=2;//read flag;	
	//	file_name[1]=fid;
		if(mode==MD_RD_SMALL){
			//for(j=0;j<iter;j++){
              //			ecall_IPFS_function(global_eid, file_name, buf, position,data_size);	//in this function , I will write and read the code from IPFS
			//	s=enc_read(enclave_id,file_id,position,buf,IO_SIZE);
	//			position+=IO_SIZE;
			//	if(s<=0){ printf("fail sequential enc_read\n");  return 0;}
			//}
            IPFS_read_small();
		}
		else if(mode==MD_WR_SMALL){
            IPFS_write_small();
		//	file_name[0]=1;//write flag
		//	file_name[1]=fid;
		//	for(j=0;j<iter;j++){
             //   IPFS_read_small();
				//printf("fuc\n");
				//char file_name[5];
//				char datas[8192];
//				printf("pos ::::%d\n", position);
//				size_t offset=4096;
//				size_t data_size=8192;
//				for(i=0; i<8192; i++)	datas[i]=0x11;
//				file_name[0]=1;
//				ecall_IPFS_function(global_eid, file_name, buf, offset, data_size);
//				printf("%d %d %d\n", global_eid, position, data_size);
			//	printf("%d,%d,%d,%d,%d\n",file_name[0],file_name[1],file_name[2],file_name[3],file_name[4]);
			//	printf("%x %x %x %x %x\n",buf[0],buf[1],buf[2],buf[3],buf[4]);
//
//position=10;
//				ecall_IPFS_function(global_eid, file_name, buf, position,data_size);	//in this function , I will write and read the code from IPFS
//				printf("%d %d %d\n", global_eid, position, data_size);
			//	printf("%d,%d,%d,%d,%d\n",file_name[0],file_name[1],file_name[2],file_name[3],file_name[4]);
			//	printf("%x %x %x %x %x\n",buf[0],buf[1],buf[2],buf[3],buf[4]);
			//s=enc_write(enclave_id,file_id,position,buf,sig,IO_SIZE,read_sig);
//				position+=IO_SIZE;
//				printf("kkk %d\n",j);
			//	if(s<=0){ printf("fail sequential enc_read\n");  return 0;}
			}
		}
        else if (mode==MR_RD_BIG)
        {
            IPFS_read_big();
        }
        else if(mode==MD_WR_BIG)
        {
            IPFS_write_small();
        }
	}
    */
   // barrier();
    if(pid > 0)
	{
		while(wait(NULL)!=-1);
		//wait(NULL);
		//printf("it has finished! %d %d\n", cnt, getpid());
	}
	if(cnt==1)
	{
		//printf("Process has finished.\n");
	   
        clock_gettime(CLOCK_MONOTONIC,&end);
	    start_time=(start.tv_nsec/1e9)+start.tv_sec;
	    end_time=(end.tv_nsec/1e9)+end.tv_sec;
	//end_time = (1e1);
	//printf("clock check : %ld, %ld %.9lf\n", end.tv_sec, end.tv_nsec, end_time);
	   // printf("process %d, start_time: %.9lf seconds, end_time : %.9lf seconds, %.9lf\n",cnt,start_time,end_time, end_time-start_time);
        printf("\nEVAL %d threads: %.9lf seconds\n", num_process, end_time-start_time);
    }
    
    munmap(barrier, sizeof(pthread_barrier_t));
    sgx_destroy_enclave(global_eid);
  //  printf("Info: SampleEnclave successfully returned.\n");

   // printf("Enter a character before exit ...\n");
//    getchar();
    return 0;
}
    
