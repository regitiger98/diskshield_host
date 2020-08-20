#include<stdio.h>
#include<stdlib.h>
#include<sys/syscall.h>
#include<linux/kernel.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<time.h>
#include"key_api.h"
#define P_SIZE 4096
#define K_SIZE 1024
#define IO_SIZE 8192
#define PAGE_BIT 12

#define barrier() __asm__ __volatile__("": : :"memory")


//0, 1:name, 2: process 수(4개가 최대), 3:파일크기, 4: mode(여부)-read(0),write(1), 5:original:0 or new_systemcall:1
int main(int argc, char **argv)
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
	unsigned int position=0;
	
	char *dd,*sig,*read_sig;
	char *buf,*buf2;

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
	buf2=(char*)malloc(P_SIZE*3*sizeof(char));
	dd=(char*)malloc(P_SIZE*3*sizeof(char));
	sig=(char*)malloc(P_SIZE*sizeof(char));
	read_sig=(char*)malloc(P_SIZE*sizeof(char));
	memset(dd,0,sizeof(dd));
	memset(sig,0,sizeof(sig));
	memset(read_sig,0,sizeof(read_sig));
	buf=(char*)( (((unsigned long)dd+KEY_PAGE_SIZE-1)>>PAGE_BIT)<<PAGE_BIT);

	for(i=0;i<IO_SIZE;i++){
		buf[i]=(rand()%10)+'0';
	}

	filename=(cnt-1)*file_cnt+1+file_num;

	enclave_id=1;
	file_id=(unsigned char)filename;
	position=0;

	clock_gettime(CLOCK_MONOTONIC, &start);

	if(new_open==1){//new systemcall
		if(mode==0){
			for(j=0;j<iter;j++){
				s=enc_read(enclave_id,file_id,position,buf,IO_SIZE);
				position+=IO_SIZE;
				if(s<=0){ printf("fail sequential enc_read\n");  return 0;}
			}
		}
		else{
			for(j=0;j<iter;j++){
				s=enc_write(enclave_id,file_id,position,buf,sig,IO_SIZE,read_sig);
				position+=IO_SIZE;
				if(s<=0){ printf("fail sequential enc_read\n");  return 0;}
			}
		}

	}
	clock_gettime(CLOCK_MONOTONIC,&end);
	start_time=(start.tv_nsec/10e9)+start.tv_sec;
	end_time=(end.tv_nsec/10e9)+end.tv_sec;
	printf("process %d, start_time: %.9lf seconds, end_time : %.9lf seconds, buf2[10]:%c\n",cnt,start_time,end_time,buf2[3]);
	free(buf2); free(dd); free(sig); free(read_sig);

	exit(0);
}
