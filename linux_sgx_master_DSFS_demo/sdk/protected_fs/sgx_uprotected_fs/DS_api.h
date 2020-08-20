#ifndef KEY_VALUE_API
#define KEY_VALUE_API

#include<linux/unistd.h>
#include<linux/kernel.h>
#include<sys/syscall.h>
#include<string.h>
#include<stdlib.h>
#define __enc_open 333
#define __enc_close 334
#define __enc_read 335
#define __enc_write 336

#define KEY_PAGE_SIZE 4096
#define PAGE_BIT 12
#define KEY_DEFAULT_BUF (KEY_PAGE_SIZE*256)

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
	memcpy(buf,exmac,4096);
	memcpy(buf+KEY_PAGE_SIZE,u_buf,KEY_PAGE_SIZE);
	
	ret=(int)syscall(__enc_write,enclave_id,file_id,position,buf,count);
	if(ret>0)	memcpy(read_exmac,buf,KEY_PAGE_SIZE);//64);

	free(dd);
	return ret;
}
#endif
