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
#include <malloc.h>
#include <assert.h>
#include <errno.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "sgx_tprotected_fs_u.h"
#include <uprotected_fs.h>
#include "sgx_tcrypto.h" 

#include <time.h>
//#include "sgx_tprotected_fs.h"
//#include "DS_api.h"

#ifndef KEY_VALUE_API
#define KEY_VALUE_API

#include<linux/unistd.h>
#include<linux/kernel.h>
#include<sys/syscall.h>
#include<string.h>
#include<stdlib.h>

#include<dumpcode.h>

#define SECTOR_SIZE 512
#define SECTOR_BIT 9
#define KEY_SIZE 16
#define MAC_SIZE (KEY_SIZE*2)
#define VERSION_SIZE 4
#define FD_SIZE 4

#define __NR_enc_rdafwr 333

#define P_SIZE 4096
#define K_SIZE 1024
#define IO_SIZE 8192
#define RESPONSE_SIZE SECTOR_SIZE
#define PAGE_BIT 12
#define NAME_LEN 16
#define NODE_SIZE 4096
//DS_param, ds_cmd는 개발에 따라 정책이 수정될 수 있다.
//fs_open.c와 openssd jasmine펌웨어 sata_table.c, sata.h 와 반드시 맞춰줄것.
typedef struct DS_param{
	unsigned int fd;
	unsigned char cmd;
	unsigned long offset; //여기가 LBA영역에 들어감 6bytes
	unsigned int size; //이건 lba처럼 count영역에 들어가니, 섹터단위일듯.
}DS_PARAM;

enum ds_cmd{
	DS_WR_RANGE_MIN = 0x43,
	DS_CREATE_WR = 0x44,
	DS_OPEN_WR = 0x45,
	DS_CLOSE_WR = 0x46,
	DS_REMOVE_WR = 0x47,
	DS_WRITE_WR = 0x48,
	DS_WR_RANGE_MAX = 0x49,
	DS_RD_RANGE_MIN = 0x4A,
	DS_READ_RD = 0x4B,
	DS_AUTH_RD = 0x4C ,
	DS_CREATE_RD = 0x4D,
	DS_OPEN_RD = 0x4E,
	DS_CLOSE_RD = 0x4F,
	DS_REMOVE_RD =0x50,
	DS_WRITE_RD = 0x51,
	DS_RD_RANGE_MAX= 0x52
};
/*
 * #define __enc_open 333
#define __enc_close 334
#define __enc_read 335
#define __enc_write 336

#define KEY_PAGE_SIZE 4096
#define PAGE_BIT 12
#define KEY_DEFAULT_BUF (KEY_PAGE_SIZE*256)
*/
/*
int enc_open(unsigned char enclave_id,unsigned char file_id, char* exmac, char* public_key){
	char *buf,*dd;
	int ret;
	dd=(char*)malloc(KEY_PAGE_SIZE*2*sizeof(char));
	buf=(char*)( (((unsigned long)dd+KEY_PAGE_SIZE-1)>>PAGE_BIT)<<PAGE_BIT);
	//??????
	memcpy(buf,exmac,256);
	memcpy(buf+256,public_key,256);
	ret=(int)syscall(__enc_open,enclave_id,file_id,buf);
	free(dd);
	return ret;
}
int enc_close(unsigned char enclave_id,unsigned char file_id, char* exmac){
	char *buf,*dd;
	int ret;
	dd=(char*)malloc(KEY_PAGE_SIZE*2*sizeof(char));
	buf=(char*)( (((unsigned long)dd+KEY_PAGE_SIZE-1)>>PAGE_BIT)<<PAGE_BIT);
	memcpy(buf,exmac,KEY_PAGE_SIZE);
	ret=(int)syscall(__enc_close,enclave_id,file_id,buf);

	free(dd);
	return ret;
}
int enc_read(unsigned char enclave_id,unsigned char file_id, unsigned int position,char* u_buf,size_t count){
	char *buf,*dd;
	int ret;
	
	count=KEY_PAGE_SIZE*2;

	dd=(char*)malloc(KEY_PAGE_SIZE*3*sizeof(char));
	buf=(char*)( (((unsigned long)dd+KEY_PAGE_SIZE-1)>>PAGE_BIT)<<PAGE_BIT);
	//??????
//	memcpy(buf,exmac,KEY_PAGE_SIZE);
//	memcpy(buf,u_buf,KEY_PAGE_SIZE);
	
	ret=(int)syscall(__enc_read,enclave_id,file_id,position,buf,count);
	if(ret>=0) memcpy(u_buf,buf,KEY_PAGE_SIZE*2);

	free(dd);
	return ret;
}



int enc_write(unsigned char enclave_id,unsigned char file_id, unsigned int position,char* u_buf,char *exmac,size_t count,char* read_exmac){
	char *buf,*dd;
	int ret;
	
	count=KEY_PAGE_SIZE*2;

	dd=(char*)malloc(KEY_PAGE_SIZE*3*sizeof(char));
	buf=(char*)( (((unsigned long)dd+KEY_PAGE_SIZE-1)>>PAGE_BIT)<<PAGE_BIT);
	memset(buf,0,KEY_PAGE_SIZE*2);
	//printf("%lu %lu\n",(unsigned long)dd,(unsigned long)buf);
	//??????
	exmac[0]=0; read_exmac[0]=0; u_buf[0]=u_buf[0];
	memcpy(buf,exmac,32);
	memcpy(buf+KEY_PAGE_SIZE,u_buf,KEY_PAGE_SIZE);
	
	ret=(int) syscall(__enc_write,enclave_id,file_id,position,buf,count);
	if(ret>0)	memcpy(read_exmac,buf,512);//64);

	free(dd);
	return ret;
}
*/

//8KB가 넘으면, 쪼개주는정도만..아닌가.....
//넘으면 mac다시계산해야할거같은데.
//얘를 호출할당시부터 8KB쪼개졌다가정 즉 u_buf사이즈 <=8KB
int enc_rdafwr(DS_PARAM *ds_param, char* u_buf, char* response, int count)
{
	uint32_t response_size=40;
	
	//direct I/O 할 버퍼에 저장.
	if(((uint64_t)u_buf & 0x01ff) != 0)	//sector단위라 마지막 9bit 가 0이어야함.
	{
		fprintf(stdout, "Error wrong I/O buffer address\n");
	}

	//char *response = (char*) c (sizeof(char)*RESPONSE_SIZE);
	int ret;
	ret = (int) syscall(__NR_enc_rdafwr, ds_param, u_buf, count);

	if(ret>0)
	{
		//read 일경우 count만큼 읽어온다.
		if(ds_param->cmd == DS_READ_RD)
		{
			;
	//		memcpy(response, u_buf, count);
		}
		else
		{
			if(ds_param->cmd == DS_OPEN_WR)
			{
				response_size=44;
			}
			//response = (char*)malloc(sizeof(char)*response_size);
			memcpy(response, u_buf, response_size);
			//dumpcode((unsigned char*)response, 512);

		
		}
	}	
	return ret;
}

/*
int enc_wr(){
}
int enc_rd(){

}
*/
#endif

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) fprintf(stderr, "[sgx_uprotected_fs.h:%d] " fmt, __LINE__, ##args)
#else
#define DEBUG_PRINT(...)
#endif


//모든 DiskShield file operation은 DS_file_control로 통한다.

//19.2.2 create, open, close, read, write가 들어온다.
// parameter(reg fis) | parameter(data fis) | return
//
//	create : cmd		| mac, version, name, key	| cmd, version, mac, fid
//create는 좀더 달라질 양상이 존재 가능. 여기서 고려할 필요가 있을까싶음
//그래도 일단은 넣자.
//	open   : cmd		| mac, version, name 	  	| cmd, version, mac, fid
//	close  : cmd, fid	| mac, version				| cmd, version, mac, msg
//	write  : cmd, fid, offset, size | mac, version, data | cmd, version, mac, msg
//	read   : cmd, fid, offset, size | 				| cmd, version, mac, data

/*
//file creation

int32_t u_diskshieldfs_exclusive_file_create(const char* filename, int32_t* error_code, uint8_t* mac, uint32_t* version, char *response, char* key)
//int32_t u_diskshieldfs_exclusive_file_open(const char* filename, int64_t* file_size, int32_t* error_code, uint8_t* mac, uint32_t* version)
{
	//int result = 0;
	int fd = -1;
	//int64_t *file_size = (int64_t*) malloc (sizeof(uint64_t));
	DS_PARAM *ds_param = (DS_PARAM*) malloc (sizeof(DS_PARAM));
//	uint8_t *ds_buf = (uint8_t*) malloc (RESPONSE_SIZE);
//	char *response = (char*) malloc (RESPONSE_SIZE);
	
	//read_only=read_only;
	//direct I/O 할 버퍼는 반드시 512bytes단위!	
	char *u_buf_ = (char*) malloc (sizeof(char)*(RESPONSE_SIZE + SECTOR_SIZE));
	char *u_buf = (char*) ((((unsigned long)u_buf_ + SECTOR_SIZE -1 ) >> SECTOR_BIT) << SECTOR_BIT);

	if (filename == NULL || strnlen(filename, 1) == 0)
	{
		DEBUG_PRINT("filename is NULL or empty\n");
		*error_code = EINVAL;
		return 0;
	}
	
	//변수 대입
	fprintf(stdout, "[DS_fopen] mac : ");
	for(int i=0; i<MAC_SIZE; i++)
	{
		fprintf(stdout, "%x ", mac[i]);
	}
	fprintf(stdout, ", fd : %d, version : %x\n", fd, *version);
	fprintf(stdout, "[DS_fopen] name : %s\n", filename);
	
	ds_param->cmd = DS_CREATE_WR;
	ds_param->fd = -1;
	ds_param->offset = 0;
	ds_param->size = RESPONSE_SIZE;
	
	
	memcpy((char*)u_buf, mac, MAC_SIZE);
	memcpy((char*)(u_buf+MAC_SIZE), version, 4);//이전 close때 받은 버전 기록해둔다하자. 
	memcpy((char*)(u_buf+MAC_SIZE+4), filename, NAME_LEN);
	memcpy((char*)(u_buf+MAC_SIZE+4+NAME_LEN), key, KEY_SIZE);
	dumpcode((unsigned char*)u_buf, 512);
	
	enc_rdafwr(ds_param, u_buf, response, ds_param->size);
	free(u_buf_);
	//fprintf(stdout, "Hello Debugger\n");
	//response로부터 정보 추출
	//mac(kEY_SIZE) | msg(4B) | version
	
	//이걸 여기서 하는게 아니라, trusted zone에서 하는게 나아보임
	//enclave내에서 인증 후! 뽑아내야함
	//얘는 디버깅용, 실제 실험시 지워라!!
	//그런데 조심해서 지워야함.
	//호출부 바꾸자.
	memcpy(mac, response, MAC_SIZE);//불필요
	memcpy(&fd, &response[MAC_SIZE], FD_SIZE);//필요...?
	memcpy(version, &response[MAC_SIZE+FD_SIZE], VERSION_SIZE); //불필요
	//memcpy(file_size, &response[MAC_SIZE+FD_SIZE+VERSION_SIZE], 4); //불필요
*/
/*
	if(*file_size>0)
	{
		//file_size는 NODE_SIZE의 배수이다 나머지 군더더기는 MAC, version, dummy 사이즈...
		*file_size = *file_size/NODE_SIZE*NODE_SIZE;	
	}
*/

/*	dumpcode((unsigned char*)response, 512);
	
	fprintf(stdout, "[DS_fopen] mac : ");
	for(int i=0; i<MAC_SIZE; i++)
	{
		fprintf(stdout, "%x ", mac[i]);
	}
	fprintf(stdout, ", fd : %d, version : %x\n", fd, *version);
	return fd;
}
*/

//DISKSHIELD file CREATE/OPEN
int32_t u_diskshieldfs_exclusive_file_open(const char* filename, int32_t* error_code, uint8_t* mac, uint32_t* version, char *response, uint8_t* DS_key)
//int32_t u_diskshieldfs_exclusive_file_open(const char* filename, int64_t* file_size, int32_t* error_code, uint8_t* mac, uint32_t* version)
{
	int fd = -1;
	unsigned int *file_size = (unsigned int*) malloc (sizeof(uint64_t));
	DS_PARAM *ds_param = (DS_PARAM*) malloc (sizeof(DS_PARAM));
	
	//direct I/O 할 버퍼는 반드시 512bytes단위로 주소를 초기화해야 한다.
	char *u_buf_ = (char*) malloc (sizeof(char)*(RESPONSE_SIZE + SECTOR_SIZE));
	char *u_buf = (char*) ((((unsigned long)u_buf_ + SECTOR_SIZE -1 ) >> SECTOR_BIT) << SECTOR_BIT);

	if (filename == NULL || strnlen(filename, 1) == 0)
	{
		DEBUG_PRINT("filename is NULL or empty\n");
		*error_code = EINVAL;
		return 0;
	}
	
	if(DS_key == NULL)//file open
		ds_param->cmd = DS_OPEN_WR;
	else//file create
		ds_param->cmd = DS_CREATE_WR;

	ds_param->fd = -1;
	ds_param->offset = 0;
	ds_param->size = RESPONSE_SIZE;
	
	//user buffer 정책대로 대입한다.
	memcpy((char*)u_buf, mac, MAC_SIZE);
	memcpy((char*)(u_buf+MAC_SIZE), version, 4);//이전 close때 받은 버전 기록해둔다하자. 
	memcpy((char*)(u_buf+MAC_SIZE+4), filename, NAME_LEN);
	if(ds_param->cmd == DS_CREATE_WR)
	{
		fprintf(stdout, "[u_diskshieldfs_exclusive_file_open] File Create. name: %s\n", filename);
		memcpy((char*)(u_buf+MAC_SIZE+4+NAME_LEN), DS_key, KEY_SIZE);
		//fprintf(stdout, "create key is ");
		//for(int i=0; i<KEY_SIZE; i++)
		//	fprintf(stdout, "0x%x ", DS_key[i]);
		//fprintf(stdout, "\n");
	}	
	else if(ds_param->cmd == DS_OPEN_WR)
	{
		fprintf(stdout, "[u_diskshieldfs_exclusive_file_open] File Open. name: %s\n", filename);
	}
	
	//dumpcode((unsigned char*)u_buf, 512);
	

	//시스템콜 호출
	enc_rdafwr(ds_param, u_buf, response, ds_param->size);
	
	//response로부터 정보 추출
	//mac(kEY_SIZE) | msg(4B) | version
	
	//이걸 여기서 하는게 아니라, trusted zone에서 하는게 나아보임
	//enclave내에서 인증 후! 뽑아내야함
	//얘는 디버깅용, 실제 실험시 지워라!!
	//그런데 조심해서 지워야함.
	//호출부 바꾸자.
	memcpy(mac, response, MAC_SIZE);//불필요
	memcpy(&fd, &response[MAC_SIZE], FD_SIZE);//필요...?
	memcpy(version, &response[MAC_SIZE+FD_SIZE], VERSION_SIZE); //불필요
	memcpy(file_size, &response[MAC_SIZE+FD_SIZE+VERSION_SIZE], 4); //불필요
	if(*file_size>0)
	{
		//file_size는 NODE_SIZE의 배수이다 나머지 군더더기는 MAC, version, dummy 사이즈...
		*file_size = *file_size/NODE_SIZE*NODE_SIZE;	
	}

	//dumpcode((unsigned char*)response, 512);
	free(u_buf_);
	free(file_size);
	free(ds_param);
	return fd;
}

//DiskShield file close
//int32_t u_sgxprotectedfs_fclose(void* f)
int32_t u_diskshieldfs_fclose(int32_t fd, uint8_t *mac, uint32_t *version, char *response)
{
	int result = 0;
	DS_PARAM *ds_param = (DS_PARAM*) malloc (sizeof(DS_PARAM));

//direct I/O 할 버퍼는 반드시 512bytes단위!
	char *u_buf_ = (char*) malloc (sizeof(char)*(RESPONSE_SIZE + SECTOR_SIZE));
	char *u_buf = (char*) ((((unsigned long)u_buf_ + SECTOR_SIZE -1 ) >> SECTOR_BIT) << SECTOR_BIT);

	fprintf(stdout, "[u_diskshieldfs_fclose] File Close. fd: %d\n", fd);
	//diskshield는 fd만 사용할 계획임
	// closing the file handle should also remove the lock, but we try to remove it explicitly
	if (fd == -1)
	{
		DEBUG_PRINT("fileno returned -1\n");
	}

	ds_param->cmd = DS_CLOSE_WR;
	ds_param->fd = fd;
	ds_param->offset = 0;
	ds_param->size = RESPONSE_SIZE;
	
	memcpy((char*)u_buf, mac, MAC_SIZE);
	memcpy((char*)(u_buf+MAC_SIZE), version, 4);
	
	//dumpcode((unsigned char*)u_buf, 512);
	
	enc_rdafwr(ds_param, u_buf, response, ds_param->size);
	free(u_buf_);
	//response로부터 정보 추출
	//mac(kEY_SIZE) | msg(4B) | version
	memcpy(mac, response, MAC_SIZE);	//불필요
	memcpy(&result, &response[MAC_SIZE], FD_SIZE);	//필요?? 일단은
	memcpy(version, &response[MAC_SIZE+FD_SIZE], VERSION_SIZE); //불필요
	
	//dumpcode((unsigned char*)response, 512);
	
	if(result==1)
		result = 0;
	else
		result = -1;

	//fprintf(stdout, "[DS_fclose] mac : ");
	/*
	for(int i=0; i<MAC_SIZE; i++)
	{
		fprintf(stdout, "%x ", mac[i]);
	}
	*/
	//fprintf(stdout, ", result : %d, version : %x\n", result, *version);

	//memcpy(&version, &response[KEY_SIZE+FD_SIZE], VERSION_SIZE);
	if(result != 0)
	{
		if (errno != 0)
		{
			int err = errno;
			DEBUG_PRINT("fclose returned %d, errno: %d\n", result, err);
			return err;
		}
		DEBUG_PRINT("fclose returned %d\n", result);
		free(ds_param);
		return -1;
	}
	free(ds_param);
	return 0;
}

//DiskShield에서 구현한다면
//file pointer을 fd가 대체한다.
//int32_t u_sgxprotectedfs_fwrite_node(void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)//sgx_ec256_signature_t p_signature)
//int32_t u_diskshieldfs_fwrite_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t *mac, uint32_t *version)
int cntw=0;
double timewr=0;
int32_t u_diskshieldfs_fwrite_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t *mac, uint32_t *version, char* response)
{
	uint64_t offset = node_number * node_size;
	uint32_t ret_msg;
	uint32_t file_size = node_size;
	uint32_t reserved;
	DS_PARAM *ds_param = (DS_PARAM*) malloc (sizeof(DS_PARAM));
	
	char *u_buf_ = (char*) malloc (sizeof(char)*(IO_SIZE + SECTOR_SIZE));	//IO_SIZE??
	char *u_buf = (char*) ((((unsigned long)u_buf_ + SECTOR_SIZE -1 ) >> SECTOR_BIT) << SECTOR_BIT);
	
	ds_param->cmd = DS_WRITE_WR;
	ds_param->fd = fd;
	ds_param->offset = offset;
	//ds_param->size = node_size ;	//이게 몇일지 뽑아보기.
	ds_param->size = (((node_size + MAC_SIZE+4)+SECTOR_SIZE-1) >> SECTOR_BIT) << SECTOR_BIT;
	//ds_param->size = 512;
	//fprintf(stdout,"ds_param->size : %d\n", ds_param->size);
	
	memcpy((char*)u_buf, buffer, file_size);
	
	if((reserved=file_size%512)!= 0)	//섹터단위로 안나뉘면 dummy값넣어줘야
	{
		fprintf(stdout, "never be called!!!\n");
		memset((char*)(u_buf+file_size), 0x00, 512-reserved);
		file_size += (512-reserved);
	}
	//fprintf(stdout, "file size: %d, reserved :%d", file_size, reserved);
	memcpy((char*)(u_buf+file_size), mac, MAC_SIZE);
	memcpy((char*)(u_buf+file_size+MAC_SIZE), version, VERSION_SIZE);//수정
//	memcpy((char*)u_buf, mac, MAC_SIZE);
//	memcpy((char*)(u_buf+MAC_SIZE), version, VERSION_SIZE);
//	memcpy((char*)(u_buf+MAC_SIZE+VERSION_SIZE), buffer, node_size);//수정
	
	//dumpcode((unsigned char*)u_buf, 512);

	struct timespec wr_clk;
	double wr_time_s, wr_time_f;
	clock_gettime(CLOCK_MONOTONIC, &wr_clk);
	wr_time_s = (double)(((double)wr_clk.tv_nsec/1e9)+(double)wr_clk.tv_sec);
//	fprintf(stdout, "u_wr_bf time : %.9lf \n", wr_time);
//	fprintf(stdout,"write fd(%d) offset(%d) nodesize/size(%d %d) version(%d) \n", fd, offset, node_size, ds_param->size, *version);
//	fprintf(stdout,"MAC is ");
//	for(int i=0; i<MAC_SIZE; i++)
//		fprintf(stdout, "0x%x ", mac[i]);
//	fprintf(stdout,"\n");
	fprintf(stdout, "[u_diskshieldfs_fwrite_node] File Write. fd: %d, offset: %d, size: %d\n", ds_param->fd, ds_param->offset, ds_param->size);

	enc_rdafwr(ds_param, u_buf, response, ds_param->size);
	free(u_buf_);	//free더해야.

	
	  clock_gettime(CLOCK_MONOTONIC, &wr_clk);
	wr_time_f = (double)(((double)wr_clk.tv_nsec/1e9)+(double)wr_clk.tv_sec);
	//fprintf(stdout, "u_wr_af time : %.9lf \n", wr_time);
	cntw++;
	timewr+=wr_time_f-wr_time_s;
	//fprintf(stdout, "DS_fwrite %.9lf %.9lf\n", wr_time_f - wr_time_s, timewr);
	

	//memcpy(mac, response, MAC_SIZE);	//불필요
	//memcpy(&ret_msg, &response[MAC_SIZE], FD_SIZE);	//필요?
	//memcpy(version, &response[MAC_SIZE+FD_SIZE], VERSION_SIZE);	//불필요
	//dumpcode((unsigned char*)response, 512);
	
	//fprintf(stdout, "[DS_fwrite] mac : ");
	/*
	for(int i=0; i<MAC_SIZE; i++)
	{
		fprintf(stdout, "%x ", mac[i]);
	}
	*/
	//fprintf(stdout, ", ret_msg : %d, version : %x\n", ret_msg, *version);
	//return ret_msg;
	free(ds_param);
	return 0;
	
}

//Diskshield read
//int32_t u_sgxprotectedfs_fread_node(void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)
//int32_t u_diskshieldfs_fread_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t *mac, uint32_t *version)
int cntr=0;
double timerd=0;
int32_t u_diskshieldfs_fread_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size)
//int32_t u_diskshieldfs_fread_node(int32_t fd, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t *mac, uint32_t *version)
{
	char *u_buf_ = (char*) malloc (sizeof(char)*(IO_SIZE + SECTOR_SIZE)); //IO_SIZE??
	char *u_buf = (char*) ((((unsigned long)u_buf_ + SECTOR_SIZE -1 ) >> SECTOR_BIT) << SECTOR_BIT);
	DS_PARAM *ds_param = (DS_PARAM*) malloc (sizeof(DS_PARAM));
	
	uint64_t offset = node_number * node_size;
//	int result = 0;
//	size_t size = 0;
//
	//fprintf(stdout, "[DS_fread] node_size : %d", node_size);
	//fprintf(stdout, "fd, offset : %d %ld\n", fd, offset);	
	/*fprintf(stdout, "[DS_fread] mac : ");
	for(int i=0; i<MAC_SIZE; i++)
	{
		fprintf(stdout, "%x ", mac[i]);
	}
*/
	ds_param->cmd = DS_READ_RD;
	ds_param->fd = fd;
	ds_param->offset = offset;
	ds_param->size = node_size;
	//ds_param->size = (((node_size + MAC_SIZE+4)+SECTOR_SIZE-1) >> SECTOR_BIT) << SECTOR_BIT;

	struct timespec rd_clk;
	double rd_times, rd_timef;
	clock_gettime(CLOCK_MONOTONIC, &rd_clk);
	rd_times = (double)(((double)rd_clk.tv_nsec/1e9)+(double)rd_clk.tv_sec);
	//fprintf(stdout, "u_rd_bf time : %.9lf \n", rd_time);

	fprintf(stdout, "[u_diskshieldfs_fread_node] File Read. fd: %d, offset: %d, size: %d\n", ds_param->fd, ds_param->offset, ds_param->size);
	enc_rdafwr(ds_param, u_buf, NULL, ds_param->size);
	 
	clock_gettime(CLOCK_MONOTONIC, &rd_clk);
	rd_timef = (double)(((double)rd_clk.tv_nsec/1e9)+(double)rd_clk.tv_sec);
	//fprintf(stdout, "u_rd_af time : %.9lf \n", rd_time);
	cntr++;
	timerd += rd_timef-rd_times;
	//fprintf(stdout, "DS_fread %.9lf %.9lf\n", rd_timef-rd_times, timerd);

	//memcpy(mac, u_buf, MAC_SIZE);	//필요
	//memcpy(version, &u_buf[MAC_SIZE], VERSION_SIZE);	//필요 
	//memcpy(buffer, &u_buf[MAC_SIZE+VERSION_SIZE], node_size);	//필요
	memcpy(buffer, u_buf, node_size);	//필요
	//dumpcode((unsigned char*)u_buf, 512);

	/*
	fprintf(stdout, "[DS_fread] mac : ");
	for(int i=0; i<MAC_SIZE; i++)
	{
		fprintf(stdout, "%x ", mac[i]);
	}
	fprintf(stdout, ", version : %x\n", *version);
*/
	free(u_buf_);
	free(ds_param);
	return 0;
}


void* u_sgxprotectedfs_exclusive_file_open(const char* filename, uint8_t read_only, int64_t* file_size, int32_t* error_code)
{
	FILE* f = NULL;
	int result = 0;
	int fd = -1;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	struct stat stat_st;
	
	memset(&stat_st, 0, sizeof(struct stat));

	if (filename == NULL || strnlen(filename, 1) == 0)
	{
		DEBUG_PRINT("filename is NULL or empty\n");
		*error_code = EINVAL;
		return NULL;
	}
	// open the file with OS API so we can 'lock' the file and get exclusive access to it
	//여기가 diskshield가 deviceopen으로 해줘야 할 부분이지.
	//여기서 open 실패시 craete해야지
	fd = open(filename,	O_CREAT | (read_only ? O_RDONLY : O_RDWR) | O_LARGEFILE, mode); // create the file if it doesn't exists, read-only/read-write
	if (fd == -1)
	{
		DEBUG_PRINT("open returned %d, errno %d\n", result, errno);
		*error_code = errno;
		return NULL;
	}

	// this lock is advisory only and programs with high priviliges can ignore it
	// it is set to help the user avoid mistakes, but it won't prevent intensional DOS attack from priviliged user
	//LOCK_SH :여러 프로세스가 lock 공유 가능 / LOCK_EX: 한 프로세스만이 락을 가진다. LOCK_NB  : non blocking.
	//write면 exclusive lock을 점유해야하고, read 면 shared lock을 점유해야함.
	//shared lock이면 read동안 write불가능 
	result = flock(fd, (read_only ? LOCK_SH : LOCK_EX) | LOCK_NB); // NB - non blocking
	if (result != 0)
	{
		DEBUG_PRINT("flock returned %d, errno %d\n", result, errno);
		*error_code = errno;
		result = close(fd);
		assert(result == 0);
		return NULL;
	}
	//file state 반환 필요할까?
	//error 체크용으로 보인다. 제거가능.
	result = fstat(fd, &stat_st);
	if (result != 0)
	{
		DEBUG_PRINT("fstat returned %d, errno %d\n", result, errno);
		*error_code = errno;
		flock(fd, LOCK_UN);
		result = close(fd);
		assert(result == 0);
		return NULL;
	}
	
	// convert the file handle to standard 'C' API file pointer
	f = fdopen(fd, read_only ? "rb" : "r+b");
	if (f == NULL)
	{
		DEBUG_PRINT("fdopen returned NULL\n");
		*error_code = errno;
		flock(fd, LOCK_UN);
		result = close(fd);
		assert(result == 0);
		return NULL;
	}

	if (file_size != NULL)
		*file_size = stat_st.st_size;

	return f;
}


uint8_t u_sgxprotectedfs_check_if_file_exists(const char* filename)
{
	struct stat stat_st;
	
	memset(&stat_st, 0, sizeof(struct stat));

	if (filename == NULL || strnlen(filename, 1) == 0)
	{
		DEBUG_PRINT("filename is NULL or empty\n");
		return 1;
	}
	
	return (stat(filename, &stat_st) == 0); 
}
int cntrr=0;
int32_t u_sgxprotectedfs_fread_node(void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)
{
	FILE* file = (FILE*)f;
	uint64_t offset = node_number * node_size;
	int result = 0;
	size_t size = 0;

	cntrr++;
	fprintf(stdout, "fread!! %d\n", cntrr);
	if (file == NULL)
	{
		DEBUG_PRINT("file is NULL\n");
		return -1;
	}

	if ((result = fseeko(file, offset, SEEK_SET)) != 0)
	{
		DEBUG_PRINT("fseeko returned %d\n", result);
		if (errno != 0)
		{
			int err = errno;
			return err;
		}
		else
			return -1;
	}

	if ((size = fread(buffer, node_size, 1, file)) != 1)
	{
		int err = ferror(file);
		if (err != 0)
		{
			DEBUG_PRINT("fread returned %ld [!= 1], ferror: %d\n", size, err);
			return err;
		}
		else if (errno != 0)
		{
			err = errno;
			DEBUG_PRINT("fread returned %ld [!= 1], errno: %d\n", size, err);
			return err;
		}
		else
		{
			DEBUG_PRINT("fread returned %ld [!= 1], no error code\n", size);
			return -1;
		}
	}

	return 0;
}


/*
int32_t u_sgxprotectedfs_fread_node_ecdsa(void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t* p_signature)//sgx_ec256_signature_t p_signature)
{
	uint64_t offset = node_number;
	uint8_t* data = buffer;
	uint32_t data_size = node_size;
//	uint8_t *h_mac = p_signature;
//	char *dd, *buf;
	uint64_t unused;
	//int i;
	unused = node_number;
	unused = node_size;
	unused = unused;
	int ret;
//	dd=(char*)malloc(sizeof(char)*(4096*3));
//	memset(dd,0,sizeof(char)*(4096*3));
//	buf=(char*)malloc(sizeof(char)*(4096*3));
//	memset(buf, 0, sizeof(char)*(4096*3));
	p_signature = p_signature;
//fprintf(stdout,"DSFS3.0 : u_sgxprotectedfs_fread_node ecdsa\n");
	//fprintf(stdout, "data : %s\n", buffer);
	
	*/
/*
	fprintf(stdout, "H-mac: \n");
	
	for(i=0; i<32; i++)
	{
		fprintf(stdout, "%x, ",h_mac[i]);
		if(i==31)	fprintf(stdout, "\n");
	}
	*/
/*
//buffer=buffer;
	//p_signature=p_signature;
	//
	unsigned char eid=1;
	unsigned char fid;
	
	//fprintf(stdout, "offset : %d, data_size :%d\n", (unsigned int)offset, (unsigned int)data_size);
	//char auth_SSD[10+32+4096];
//	char auth_SSD[512];
	fid=(unsigned char) data[0];	
//	fprintf(stdout,"read / fid:%d\n", fid);
	if(fid>16){	fid=fid%17; fprintf(stdout,"fid %d error\n",fid);}
	//fid=1;
	ret=enc_read(eid,fid, (unsigned int) offset,(char*) data,(size_t) data_size);
	if(ret<=0) fprintf(stdout,"fail to read!\n");
	
	//fprintf(stdout, "data:\n");
	//for(i=0; i<(int)data_size; i++)
	//	fprintf(stdout, "%x", data[i]);
	//fprintf(stdout, "\n");
//	ret=enc_write(eid,fid,(unsigned int)offset,(char*)data,(char*)h_mac, (size_t)data_size, auth_SSD);
	//auth_SSD=auth_SSD;
	
//	eid=eid, fid=fid, offset=offset, data[0]=data[0], h_mac[0]=h_mac[0], data_size=data_size;
	ret=1;
	f=f;
	
	//auth_SSD는 10bytes의 data, 32bytes의 HMAC이 있음. 이를 인증해야.
	unused=ret;
	return 0;
}
*/


/*
//nuint8_t hmac_authentication(unsigned char *auth_SSD) ;
int32_t u_sgxprotectedfs_fwrite_node_ecdsa(void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size, uint8_t* p_signature)//sgx_ec256_signature_t p_signature)
{
	uint64_t offset = node_number;:/
	uint8_t* data = buffer;
	uint32_t data_size = node_size;
	uint8_t *h_mac = p_signature;
//	char *dd, *buf;
	uint64_t unused;
//	int i;
	unused = node_number;
	unused = node_size;
	unused = unused;
	int ret;

	fprintf(stdout, "Hello Debugger\n");
//	dd=(char*)malloc(sizeof(char)*(4096*3));
//	memset(dd,0,sizeof(char)*(4096*3));
//	buf=(char*)malloc(sizeof(char)*(4096*3));
//	memset(buf, 0, sizeof(char)*(4096*3));

fprintf(stdout,"DSFS4.5 : u_sgxprotectedfs_fwrite_node ecdsa\n");
	fprintf(stdout, "data : %s\n", buffer);
	fprintf(stdout, "H-mac: \n");
	for(i=0; i<32; i++)
	{
		fprintf(stdout, "%x, ",h_mac[i]);
		if(i==31)	fprintf(stdout, "\n");
	}
	
	//buffer=buffer;
	//p_signature=p_signature;
	//
	unsigned char eid=1;
	unsigned char fid;
	fprintf(stdout, "offset : %d, data_size :%d\n", (unsigned int)offset, (unsigned int)data_size);

	for(i=0; i<(int)data_size; i++)
		fprintf(stdout, "%x", data[i]);
//	fprintf(stdout, "\n");

	//char auth_SSD[10+32+4096];
	char auth_SSD[512];
	fid=(unsigned char) data[0];	
	//fid=1;
	//fprintf(stdout,"write / fid:%d\n", fid);
	if(fid>16){	fid=fid%17; fprintf(stdout,"fid %d error\n",fid);}
	//if(fid>200)	fid=fid%200;
	//fprintf(stdout,"111111\n");
	ret=enc_write(eid,fid,(unsigned int)offset,(char*)data,(char*)h_mac, (size_t)data_size, auth_SSD);
	if(ret<=0)	fprintf(stdout,"fail to write!\n");	
	//fprintf(stdout,"22222\n");
	//auth_SSD=auth_SSD;
		
	auth_SSD[0]=auth_SSD[0],eid=eid, fid=fid, offset=offset, data[0]=data[0], h_mac[0]=h_mac[0], data_size=data_size;
	ret=1;
	f=f;
	
	//auth_SSD는 10bytes의 data, 32bytes의 HMAC이 있음. 이를 인증해야.
	unused=ret;
	return 0;
}
*/
int cntww=0;
int32_t u_sgxprotectedfs_fwrite_node(void* f, uint64_t node_number, uint8_t* buffer, uint32_t node_size)//sgx_ec256_signature_t p_signature)
{
//		sgx_ec256_signature_t p_signature;
	FILE* file = (FILE*)f;
	uint64_t offset = node_number * node_size;
	int result = 0;
	size_t size = 0;
	fprintf(stdout, "fwrite!!!! %d\n", cntww);
//fprintf(stdout,"DSFS1.2 : u_sgxprotectedfs_fwrite_node\n");
	if (file == NULL)
	{
		DEBUG_PRINT("file is NULL\n");
		return -1;
	}

	if ((result = fseeko(file, offset, SEEK_SET)) != 0)
	{
		DEBUG_PRINT("fseeko returned %d\n", result);
		if (errno != 0)
		{
			int err = errno;
			return err;
		}
		else
			return -1;
	}

	if ((size = fwrite(buffer, node_size, 1, file)) != 1)
	{
		DEBUG_PRINT("fwrite returned %ld [!= 1]\n", size);
		int err = ferror(file);
		if (err != 0)
			return err;
		else if (errno != 0)
		{
			err = errno;
			return err;
		}
		else
			return -1;
	}

	return 0;
}

int32_t u_sgxprotectedfs_fclose(void* f)
{
	FILE* file = (FILE*)f;
	int result = 0;
	int fd = 0;

	if (file == NULL)
	{
		DEBUG_PRINT("file is NULL\n");
		return -1;
	}
	//diskshield는 fd만 사용할 계획임
	// closing the file handle should also remove the lock, but we try to remove it explicitly
	fd = fileno(file);
	if (fd == -1)
		DEBUG_PRINT("fileno returned -1\n");
	else
		flock(fd, LOCK_UN);	//닫을꺼니까 lock 해제
	//file close	
	if ((result = fclose(file)) != 0)
	{
		if (errno != 0)
		{
			int err = errno;
			DEBUG_PRINT("fclose returned %d, errno: %d\n", result, err);
			return err;
		}
		DEBUG_PRINT("fclose returned %d\n", result);
		return -1;
	}

	return 0;
}


uint8_t u_sgxprotectedfs_fflush(void* f)
{
	FILE* file = (FILE*)f;
	int result;

	if (file == NULL)
	{
		DEBUG_PRINT("file is NULL\n");
		return 1;
	}
	
	if ((result = fflush(file)) != 0)
	{
		DEBUG_PRINT("fflush returned %d\n", result);
		return 1;
	}
	
	return 0;
}


int32_t u_sgxprotectedfs_remove(const char* filename)
{
	int result;

	if (filename == NULL || strnlen(filename, 1) == 0)
	{
		DEBUG_PRINT("filename is NULL or empty\n");
		return -1;
	}

	if ((result = remove(filename)) != 0)
	{// this function is called from the destructor which is called when calling fclose, if there were no writes, there is no recovery file...we don't want endless prints...
		//DEBUG_PRINT("remove returned %d\n", result);
		if (errno != 0)
			return errno;
		return -1;
	}
	
	return 0;
}

#define MILISECONDS_SLEEP_FOPEN 10
#define MAX_FOPEN_RETRIES       10
void* u_sgxprotectedfs_recovery_file_open(const char* filename)
{
	FILE* f = NULL;
	if (filename == NULL || strnlen(filename, 1) == 0)
	{
		DEBUG_PRINT("recovery filename is NULL or empty\n");
		return NULL;
	}
	
	for (int i = 0; i < MAX_FOPEN_RETRIES; i++)
	{
		f = fopen(filename, "wb");
		if (f != NULL)
			break;
		usleep(MILISECONDS_SLEEP_FOPEN);
	}
	if (f == NULL)
	{
		DEBUG_PRINT("fopen (%s) returned NULL\n", filename);
		return NULL;
	}
	
	return f;
}


uint8_t u_sgxprotectedfs_fwrite_recovery_node(void* f, uint8_t* data, uint32_t data_length)
{
	FILE* file = (FILE*)f;

	if (file == NULL)
	{
		DEBUG_PRINT("file is NULL\n");
		return 1;
	}
		
	// recovery nodes are written sequentially
	size_t count = fwrite(data, 1, data_length, file);
	if (count != data_length)
	{
		DEBUG_PRINT("fwrite returned %ld instead of %d\n", count, data_length);
		return 1;
	}

	return 0;
}


int32_t u_sgxprotectedfs_do_file_recovery(const char* filename, const char* recovery_filename, uint32_t node_size)
{
	FILE* recovery_file = NULL;
	FILE* source_file = NULL;
	int32_t ret = -1;
	uint32_t nodes_count = 0;
	uint32_t recovery_node_size = (uint32_t)(sizeof(uint64_t)) + node_size; // node offset + data
	uint64_t file_size = 0;
	int err = 0;
	int result = 0;
	size_t count = 0;
	uint8_t* recovery_node = NULL;
	uint32_t i = 0;

	fprintf(stdout, "do_file_recovery!!\n");
	do 
	{
		if (filename == NULL || strnlen(filename, 1) == 0)
		{
			DEBUG_PRINT("filename is NULL or empty\n");
			return (int32_t)NULL;
		}

		if (recovery_filename == NULL || strnlen(recovery_filename, 1) == 0)
		{
			DEBUG_PRINT("recovery filename is NULL or empty\n");
			return (int32_t)NULL;
		}
	
		recovery_file = fopen(recovery_filename, "rb");
		if (recovery_file == NULL)
		{
			DEBUG_PRINT("fopen of recovery file returned NULL - no recovery file exists\n");
			ret = -1;
			break;
		}

		if ((result = fseeko(recovery_file, 0, SEEK_END)) != 0)
		{
			DEBUG_PRINT("fseeko returned %d\n", result);
			if (errno != 0)
				ret = errno;
			break;
		}

		file_size = ftello(recovery_file);
	
		if ((result = fseeko(recovery_file, 0, SEEK_SET)) != 0)
		{
			DEBUG_PRINT("fseeko returned %d\n", result);
			if (errno != 0)
				ret = errno;
			break;
		}

		if (file_size % recovery_node_size != 0)
		{
			// corrupted recovery file
			DEBUG_PRINT("recovery file size is not the right size [%lu]\n", file_size);
			ret = ENOTSUP;
			break;
		}

		nodes_count = (uint32_t)(file_size / recovery_node_size);

		recovery_node = (uint8_t*)malloc(recovery_node_size);
		if (recovery_node == NULL)
		{
			DEBUG_PRINT("malloc failed\n");
			ret = ENOMEM;
			break;
		}

		source_file = fopen(filename, "r+b");
		if (source_file == NULL)
		{
			DEBUG_PRINT("fopen returned NULL\n");
			ret = -1;
			break;
		}

		//여기가 recovery 핵심.
		//recovery file 읽어와서 file 복구
		for (i = 0 ; i < nodes_count ; i++)
		{
			if ((count = fread(recovery_node, recovery_node_size, 1, recovery_file)) != 1)
			{
				DEBUG_PRINT("fread returned %ld [!= 1]\n", count);
				err = ferror(recovery_file);
				if (err != 0)
					ret = err;
				else if (errno != 0) 
					ret = errno;
				break;
			}

			// seek the regular file to the required offset
			if ((result = fseeko(source_file, (*((uint64_t*)recovery_node)) * node_size, SEEK_SET)) != 0)
			{
				DEBUG_PRINT("fseeko returned %d\n", result);
				if (errno != 0)
					ret = errno;
				break;
			}

			// write down the original data from the recovery file
			if ((count = fwrite(&recovery_node[sizeof(uint64_t)], node_size, 1, source_file)) != 1)
			{
				DEBUG_PRINT("fwrite returned %ld [!= 1]\n", count);
				err = ferror(source_file);
				if (err != 0)
					ret = err;
				else if (errno != 0) 
					ret = errno;
				break;
			}
		}

		if (i != nodes_count) // the 'for' loop exited with error
			break;

		if ((result = fflush(source_file)) != 0)
		{
			DEBUG_PRINT("fflush returned %d\n", result);
			ret = result;
			break;
		}

		ret = 0;

	} while(0);

	if (recovery_node != NULL)
		free(recovery_node);

	if (source_file != NULL)
	{
		result = fclose(source_file);
		assert(result == 0);
	}

	if (recovery_file != NULL)
	{
		result = fclose(recovery_file);
		assert(result == 0);
	}

	if (ret == 0)
		remove(recovery_filename);
	
	return ret;
}



void HMAC(const unsigned char key[], unsigned char h_mac[], const unsigned char text[], const int text_size)
{
	const unsigned char HASHED_OUTPUT=32;
	const unsigned char input_blocksize = 64;
	//const unsigned char KEY_SIZE=16;
	const unsigned char HASH_BLOCK_SIZE = 64;
    unsigned char Ki[HASH_BLOCK_SIZE] = {0,}; // K0 ^ ipad
    unsigned char Ko[HASH_BLOCK_SIZE] = {0,}; //K0 ^ opad
    const int DATA_BUFFERLEN = text_size + input_blocksize + HASHED_OUTPUT + 1;   //8192+64+32+1 =
    uint8_t data[DATA_BUFFERLEN];
    int i;
	sgx_sha256_hash_t p_hash;
   // SHA256_CTX ctx;

//    printf("key : %x %x %x %x \n", key[0],key[1],key[2],key[3]);
    memset(data, 0x00, DATA_BUFFERLEN);
    memcpy(Ki, key, KEY_SIZE);
    memcpy(Ko, Ki, KEY_SIZE);        //Ko, Ki는 해쉬된 키값

//이후 B만큼 나머지 길이를 0으로 채운다 여기도 돌아갈일없음.
    for(i=KEY_SIZE; i<input_blocksize; i++)
    {
        Ki[i]=0x00;
        Ko[i]=0x00;
    }
    //ipad opad를 이용해서 Ko를 미리 계산한다.
    for(i=0; i<input_blocksize; i++)
    {
        Ki[i] ^= 0x36;
        Ko[i] ^= 0x5c;
    }
    //위에서 계산한 ;Ki ^ ipad와 HMAC대상인 test를 연접
    memcpy(data, Ki, input_blocksize);
    memcpy(data+input_blocksize, text, text_size);  //여기서 data길이 = 자른KI(64bit) + data임
    //해시한다.
    //printf("h:%x %x %x\n",h_mac[0],h_mac[1],h_mac[2]);
    //Hash(data,input_blocksize + text_size,  h_mac, &ctx);  // O(hash(data size + 256biy))
	//sgx_sha256_msg(data, (uint32_t)input_blocksize+text_size, &p_hash);   
	//printf("h:%x %x %x\n",h_mac[0],h_mac[1],h_mac[2]);
    //Ko ^ opad와 위에 해쉬 결과를 연접
    memset(data, 0x00, DATA_BUFFERLEN);
    memcpy(data, Ko, input_blocksize);
    memcpy(data+input_blocksize, p_hash, HASHED_OUTPUT);   //여기서 data길이 = 64bit+256bit(hashed)
   // /sgx_sha256_msg(data, (uint32_t)input_blocksize+HASHED_OUTPUT, &p_hash);
	memcpy(h_mac, p_hash, HASHED_OUTPUT);
	//H//ash(data, input_blocksize + HASHED_OUTPUT, h_mac, &ctx); //O(hash(256+64bit))
    //예측 복잡도 = O( hash(128) + hash(data+256bit) + hash(320)) //결국 O(Hash(data)) 랑 비슷.
    //=O(hash(data))
}

uint8_t hmac_authentication(unsigned char *auth_SSD)
{
	//size = 10+32(data, mac)
	//mac  인증하려면?
	unsigned char key[16];
	unsigned char h_mac[32];
	unsigned char text[10];
	int text_size=10;
	memcpy(text, auth_SSD, 10);
//	protected_fs_file f;
	//f.hmac(key, h_mac, text, text_size);
	HMAC(key, h_mac, text, text_size);
	if(memcmp(h_mac, auth_SSD+10, 32)==0)	return 1;
	else return 0;
}

