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


/* Test Pointer Auttributes */
#include <sys/types.h>
#include <string.h>

#include "sgx_trts.h"
#include "sgx_lfence.h"
#include "../Enclave.h"
#include "Enclave_t.h"
#include "sgx_tprotected_fs.h"
#include "sgx_tcrypto.h"

#define DSFS 1
#define IPFS 0
#define IPFS_INIT 2
#define NAME_LEN (16)

void threads_write_seq(int pid)
{
	//char file_name[30]="/home/regitiger/SSD/big0007.txt";   // IPFS
	char file_name[16]="big0005.txt";   // DISKSHIELD

	file_name[6] += pid%10;
	file_name[5] += pid/10;
	printf("file_name : %s\n", file_name);

	SGX_FILE* fp = sgx_fopen_auto_key(file_name, "w");
	int res;

	if(fp==NULL)
	{
		printf("sw OPEN ERROR!!!1\n");
		return;
	}

	unsigned char buf[4*1024];	//4KB
	int i=0;

	for(i=0; i<(16384); i++)	//64MB/4KB = 16*1024
	{
		memcpy(buf, &(i), sizeof(int));
		res=sgx_fwrite(buf, 1, 4096, fp);

		if(i%100==0)
			printf("res : %d %d\n", res, i);

		if(res!=4096)
		{
			printf("EVAL Write FAIL!!");
			return;
		}

	}
	sgx_fclose(fp);

}

//void ecall_IPFS_function(char *file_name, size_t file_name, size_t flag)
//void ecall_IPFS_function(char* file_name, char* datas, size_t cnt_filename, size_t cnt_datas)
//write 512 MB to single file
void IPFS_write_seq(int work_load, char *n_proc_s, int n_thread)
{
	char file_name[30];
	SGX_FILE* fp;
	if(work_load==DSFS)	
	{
		//char file_name[16]="foo0001.txt"; //Diskshield
		memcpy(file_name, "0000_00000.txt", 15);
		memcpy(file_name,n_proc_s,sizeof(char)*4);
		//strcpy(file_name, "foo0001.txt");

		fp = sgx_fopen_auto_key(file_name, "w");
	}

	else if(work_load==IPFS || work_load==IPFS_INIT)
	{
		memcpy(file_name, "/home/regitiger/SSD/0000_00000.txt",30);
		memcpy(&(file_name[15]),n_proc_s,sizeof(char)*4);
		//strcpy(file_name, "/home/regitiger/SSD/foo0001.txt");
		if(work_load == IPFS_INIT)
			fp = sgx_fopen_auto_key(file_name, "w");
		else if(work_load==IPFS)
			fp = sgx_fopen_auto_key(file_name, "rb+");//Overwrite
	}	
	//sgx_fseek(fp, 0, SEEK_SET);


	int res;

	if(fp==NULL)
	{
		printf("sw OPEN ERROR!!!2\n");
		return;
	}

	unsigned char buf[4*1024];	//4KB
	int i=0;
	for(i=0; i<4096; i++)
		buf[i]=1;
	buf[0]=3;
	buf[1]=2;

	//for(i=0; i<(16*1024/n_thread/*Thread수*/); i++)	//64MB/4KB = 16*1024//Thread수에 따라 달라지는것으로 구상함.
	for(i=0; i<1024; i++)	// each thread will have a 16MB file.
	{
		//memcpy(buf, &(i), sizeof(int));
		res=sgx_fwrite(buf, 1, 4096, fp);

		if(res!=4096)
		{
			printf("EVAL Write FAIL!!");
			return;
		}

	}
	sgx_fclose(fp);
}
//read 512 MB to single file
void IPFS_read_seq(int work_load, char *n_proc_s, int n_thread)
{
	char file_name[30];
	SGX_FILE* fp;

	if(work_load==DSFS)
	{
		memcpy(file_name, "0000_00000.txt", 15);
		memcpy(file_name,n_proc_s,sizeof(char)*4);
	//	memcpy(file_name, "foo0001.txt", 12);
	//	strcpy(file_name, "foo0001.txt");
	}
	else if(work_load==IPFS || work_load==IPFS_INIT) 
	{
		memcpy(file_name, "/home/regitiger/SSD/0000_00000.txt",30);
		memcpy(&(file_name[15]),n_proc_s,sizeof(char)*4);
	//	memcpy(file_name, "/home/regitiger/SSD/foo0001.txt",27);
		///strcpy(file_name, "/home/regitiger/SSD/foo0001.txt");
	}

	int res;
	fp = sgx_fopen_auto_key(file_name, "r");


	if(fp==NULL)
	{
		printf("sw OPEN ERROR!!!3\n");
		return;
	}

	unsigned char buf[4*1024];	//4MB
	int i=0;

	//for(i=0; i<(16*1024/n_thread/*Thread수*/); i++)	//64MB/4KB = 16*1024
	for(i=0; i<1024; i++)	//each thread will have a 16MB file.
	{
		memcpy(buf, &(i), sizeof(int));
		res = sgx_fread(buf, 1, 4096, fp);

		if(res!=4096)
		{
			printf("EVAL Read FAIL!!");
			return;
		}

	}

	sgx_fclose(fp);
}

void IPFS_write_rand(int work_load, char *n_proc_s, int n_thread)
{
	char file_name[30];
	SGX_FILE* fp;
//	char file_name
	if(work_load==DSFS)
	{
		memcpy(file_name, "0000_00000.txt", 15);
		memcpy(file_name,n_proc_s,sizeof(char)*4);
		fp = sgx_fopen_auto_key(file_name, "w");
		//memcpy(file_name, "foo0001.txt", 12);
		//strcpy(file_name, "foo0001.txt");
	}
	else if (work_load==IPFS || work_load==IPFS_INIT) 
	{
		memcpy(file_name, "/home/regitiger/SSD/0000_00000.txt",30);
		memcpy(&(file_name[15]),n_proc_s,sizeof(char)*4);

		//if(work_load==IPFS_INIT)
		//	fp = sgx_fopen_auto_key(file_name, "w");
		//else if(work_load==IPFS)
			fp = sgx_fopen_auto_key(file_name, "rb+");	//overweite
	}

	

	int res;
	if(fp==NULL)
	{
		printf("sw OPEN ERROR!!!4\n");
		return;
	}
	unsigned char buf[4*1024];	//4KB
	int i=0;
	unsigned int offset;
	//int max_size = 64*1024*1024;
	int max_size = 4*1024*1024/n_thread;/*Thread수*/

	for(i=0; i<(1024/n_thread/*Thread수*/); i++)	//64MB/4KB = 16*1024
	{
		sgx_read_rand((unsigned char*)&offset, 4);
		offset = offset % (max_size-4096);

		memcpy(buf, &(i), sizeof(int));
		sgx_fseek(fp, offset, SEEK_SET);
		res=sgx_fwrite(buf, 1, 4096, fp);

		if(res!=4096)
		{
			printf("EVAL Write FAIL!!");
			return;
		}
	//	printf("res : %d %d\n", res, i);
	}
	sgx_fclose(fp);
}

//read 512 MB to single file
void IPFS_read_rand(int work_load, char *n_proc_s, int n_thread)
{
	char file_name[30];
	SGX_FILE* fp;

	if(work_load==DSFS)
	{
		memcpy(file_name, "0000_00000.txt", 15);
		memcpy(file_name,n_proc_s,sizeof(char)*4);
		//memcpy(file_name, "foo0001.txt", 12);
		//strcpy(file_name, "foo0001.txt");
	}
	else if (work_load==IPFS || work_load==IPFS_INIT)
	{
		memcpy(file_name, "/home/regitiger/SSD/0000_00000.txt",30);
		memcpy(&(file_name[15]),n_proc_s,sizeof(char)*4);

		//memcpy(file_name, "/home/regitiger/SSD/foo0001.txt",27);
		//strcpy(file_name, "/home/regitiger/SSD/foo0001.txt");
	}

	int res;
	fp = sgx_fopen_auto_key(file_name, "r");


	if(fp==NULL)
	{
		printf("EVAL sw OPEN ERROR!!!5\n");
		return;
	}

	

	unsigned char buf[4*1024];	//4MB
	int i=0;
	unsigned int offset;

	for(i=0; i<1024; i++)	//each thread will have a 16MB file.
	{
		memcpy(buf, &(i), sizeof(int));
		res = sgx_fread(buf, 1, 4096, fp);

		if(res!=4096)
		{
			printf("EVAL Read FAIL!!");
			return;
		}

	}
	//int max_size = 64*1024*1024;
	int max_size = 4*1024*1024/n_thread;/*Thread수*/
	for(i=0; i<(4096/n_thread/*Thread수*/); i++)	//64MB/4KB = 16*1024
	{
		sgx_read_rand((unsigned char*)&offset, 4);
		offset = offset % (max_size-4096);

		memcpy(buf, &(i), sizeof(int));
		//printf("offset %u\n", offset);
		sgx_fseek(fp, offset, SEEK_SET);
		res = sgx_fread(buf, 1, 4096, fp);

		if(res!=4096)
		{
			printf("EVAL Read FAIL!!");
			return;
		}
		//printf("res : %d\n", res);
	}
	sgx_fclose(fp);
}


//write 4KB to 1024*128 files
void IPFS_write_small(int work_load, char *n_proc_s, int n_thread)
{

	int i,j;
	char full_name[30];
	char file_name[16];
	//char full_name[30]="/home/regitiger/SSD/";
	//char file_name[16] = "foo0001.txt";
	unsigned char buf[4*1024];	//4KB
	int p_one = 0;


	//memcpy(file_name, "0000_00000.txt", 15);
	memcpy(file_name, "0000.txt", 9);
	memcpy(file_name,n_proc_s,sizeof(char)*4);
	
	//memcpy(full_name, "/home/regitiger/SSD/0000_00000.txt",30);
	memcpy(full_name, "/home/regitiger/SSD/0000.txt",24);
	memcpy(&(full_name[15]),n_proc_s,sizeof(char)*4);

	//첫번쨰 쓰레드는 1제거해야.(4095개만 실험할거임)
	p_one=0;
	if(memcmp(n_proc_s, "0000", 4)==0)	p_one=1;	//thread_no=0;

	SGX_FILE* fp;
	int result;
	for(i=0; i<1; i++)
	{
	//	memcpy(file_name, "foo0000.txt", 12);
		for (j=0; j<1024*4/n_thread-p_one; j++)
		{
			//printf("%d file\n", j);

			//memcpy(file_name, &j, sizeof(int));
			file_name[3]++;
			if(file_name[3]>'9')
			{
				file_name[2]++;
				file_name[3]='0';
			}
			if(file_name[2]>'9')
			{
				file_name[1]++;
				file_name[2]='0';
			}
			if(file_name[1]>'9')
			{
				file_name[0]++;
				file_name[1]='0';
			}
			memcpy(buf, &(j), sizeof(int));

			if(work_load==DSFS)
			{
				fp = sgx_fopen_auto_key(file_name, "w");

			}
			else if(work_load==IPFS || work_load==IPFS_INIT)
			{
			//IPFS
				//memcpy(&full_name[15], file_name, 10);
				//printf("%s\n", file_name);
				memcpy(&full_name[15], file_name, 14);
				//printf("%s\n", full_name);
				if(work_load == IPFS_INIT)
					fp = sgx_fopen_auto_key(full_name, "w");
				else if(work_load == IPFS)
					fp = sgx_fopen_auto_key(full_name, "rb+");
			}
		
			if(fp==NULL)
			{
				printf("EVAL sw OPEN ERROR!!!6\n");
				break;
			}


			result=sgx_fwrite(buf, 1, 4*1024, fp);
			//printf("result : %d\n", result);
			if(result != 4*1024)
			{
				printf("EVAL sw WRITE ERROR!!!\n");
				break;
			}

			sgx_fclose(fp);
		//	printf("flie_name %s\n",file_name);

		}
	}
}
//read 4KB from 1024*128 files
void IPFS_read_small(int work_load, char *n_proc_s, int n_thread)
{
		
	int i,j;
	char file_name[16];
	char full_name[30];
	//char file_name[16]="foo0001.txt";
	//char full_name[30]="/home/regitiger/SSD/";
	unsigned char buf[4*1024];	//4KB
	int result;
	SGX_FILE* fp;
	int p_one=0;

	//memcpy(file_name, "0000_00000.txt", 15);
	memcpy(file_name, "0000.txt", 9);
	memcpy(file_name,n_proc_s,sizeof(char)*4);
	
	//memcpy(full_name, "/home/regitiger/SSD/0000_00000.txt",30);
	memcpy(full_name, "/home/regitiger/SSD/0000.txt",24);
	memcpy(&(full_name[15]),n_proc_s,sizeof(char)*4);


	//첫번쨰 쓰레드는 1제거해야.(4095개만 실험할거임)
	p_one=0;
	//if(memcmp(n_proc_s, "0001", 4)==0)	p_one=1;
	if(memcmp(n_proc_s, "0000", 4)==0)	p_one=1;

	for(i=0; i<1; i++)
	{
		//memcpy(file_name, "foo0000.txt", 12);
		for (j=0; j<4*1024/n_thread-p_one; j++)
		{
		//	printf("%d file", j);
			//memcpy(file_name, &j, sizeof(int));
			file_name[3]++;
			if(file_name[3]>'9')
			{
				file_name[2]++;
				file_name[3]='0';
			}
			if(file_name[2]>'9')
			{
				file_name[1]++;
				file_name[2]='0';
			}
			if(file_name[1]>'9')
			{
				file_name[0]++;
				file_name[1]='0';
			}
			memcpy(buf, &(j), sizeof(int));

			if(work_load==DSFS)
			{
				//printf("EVAL read %s", file_name);
				//diskshield
				fp = sgx_fopen_auto_key(file_name, "r");

			}
			else if(work_load==IPFS || work_load == IPFS_INIT)
			{
				//ipfs
				//memcpy(&full_name[15], file_name, 10);
				memcpy(&full_name[15], file_name, 14);
	
				fp = sgx_fopen_auto_key(full_name, "r");
			}
	
			if(fp==NULL)
			{
				printf("EVAL sr OPEN ERROR!!! %s", file_name);
				break;
			}


			result=sgx_fread(buf, 1, 4*1024, fp);
	//		printf("res : %d\n", result);


			 if(result != 4*1024)
			{
				printf("EVAL sr READ ERROR!!!");
				break;
			}

			sgx_fclose(fp);
		}
	}
}

void IPFS_demo()
{
	SGX_FILE* fp;
	int res;

	char file_name[16]="foo.txt";
	unsigned char buf_w[4*1024];	//4KB
	unsigned char buf_r[4*1024];
	printf("EVAL DEMO name: %s", file_name);
	fp = sgx_fopen_auto_key(file_name, "w");
	if(fp==NULL)
		printf("EVAL File Open Error\n");

	res=sgx_fwrite(buf_w, 1, 4*1024, fp);
	if(res==-1)
		printf("EVAL File Write Error\n");

	//res=sgx_fread(buf_r, 1, 4*1024, fp);
	//if(res==-1)
	//	printf("EVAL File Read Error\n");

	res=sgx_fflush(fp);
	if(res!=0)
		printf("EVAL File Flush Error\n");

	res = sgx_fclose(fp);
	if(res!=0)
		printf("EVAL file Close Error\n");

	//fp = sgx_fopen_auto_key(file_name, "r");
	//res=sgx_fread(buf_r, 1, 4*1024, fp);
	//sgx_fclose(fp);
}


SGX_FILE* fp;

void IPFS_simple(int flag, char *n_proc_s)
{
//	char file_name[30]="/home/regitiger/SSD/foo0001.txt";
	char file_name[16]="foo0014.txt";
	unsigned char buf_w[4*1024];	//4KB
	unsigned char buf_r[4*1024];
	int i;
	//SGX_FILE* fp;
	int res;

	memset(buf_w, 0x11, 4*1024);

	if(flag==1)
		fp = sgx_fopen_auto_key(file_name, "w");
	else if(flag==2)
	{
		for(i=0; i<0; i++)
			res=sgx_fwrite(buf_w, 1, 4*1024, fp);

		if(res!=4*1024)
			printf("write res : %d\n", res);
	}
	else if(flag==3)
		sgx_fclose(fp);

	if(flag==4)
		fp = sgx_fopen_auto_key(file_name, "r");
	else if(flag==5)
	{
		res=sgx_fread(buf_r, 1, 4*1024, fp);
		printf("read res : %d\n", res);
	}
}

void open_close(int flag, char file_name[16])
{
	char full_name[30]="/home/regitiger/SSD/";
	memcpy(&full_name[15], file_name, 10);
	if(flag==1)
		fp = sgx_fopen_auto_key(full_name, "w");
	else if(flag==2)
		sgx_fclose(fp);

}

void make_file(char file_name[16])
{
	char full_name[30]="/home/regitiger/SSD/";
	memcpy(&full_name[15], file_name, 10);

	unsigned char buf_w[4*1024];	//4KB
	int i;
	SGX_FILE* fp;
	int res;
	int N;

	memset(buf_w, 0x11, 4*1024);

	fp = sgx_fopen_auto_key(full_name, "w");
	if(fp==NULL)
	{
		printf("EVAL Error Open");
		return;
	}

	if(memcmp(file_name, "4KB.txt", 8)==0)	N=1;
	if(memcmp(file_name, "2MB.txt", 8)==0)	N=512;
	if(memcmp(file_name, "32MB.txt", 8)==0)	N=8192;
	if(memcmp(file_name, "128MB.txt", 8)==0)N=32768;
	if(memcmp(file_name, "512MB.txt", 8)==0)N=131072;

	for(i=0; i<N; i++)
	{
		res=sgx_fwrite(buf_w, 1, 4*1024, fp);
		if(res != 4096)
		{
			printf("EVAL Error Write!");
		}
	}
	sgx_fclose(fp);
}







