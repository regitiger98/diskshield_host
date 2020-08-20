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


//argument로 어떻게 
// processor 할당 어떻게? -1. priority, 2. tasklet, ?????
//0, 1:name, 2: process 수(4개가 최대), 3:파일크기, 4: mode(여부)-read(0),write(1), 5:original:0 or new_systemcall:1
//8:key_start, 9:file_start
//char buf[FILE_SIZE+5],buf2[FILE_SIZE+5];
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
//	if(argc==9){
//		file_num=atoi(argv[8]);
//	}
//	access=0644;
//	printf("argc %d\n",argc);
/*
	if(argc>8){
		key_start[0]=atoi(argv[8]);
		file_start[0]=atoi(argv[9]);
	}
	else{
		key_start[0]=1;
		file_start[0]=1;
	}
	for(i=1;i<4;i++){
		key_start[i]=key_start[i-1]+file_cnt;
		file_start[i]=file_start[i-1]+file_cnt;
	}
*/
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
//	seed=time(NULL)+(unsigned long)cnt;
//	rw_rand_state[2]=seed >>16;
//	rw_rand_state[1]=seed & 0xffff;
//	rw_rand_state[0]=0x330e;
//	srand(time(NULL));

//	char dd[P_SIZE*3],sig[P_SIZE],read_sig[P_SIZE];
//	char dd[P_SIZE*3],sig[P_SIZE],read_sig[P_SIZE];
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

//	key=10000+(cnt-1)*file_cnt+1+file_num;
	clock_gettime(CLOCK_MONOTONIC, &start);

	if(new_open==0){
	///////////////////////////////////
//	printf("process %d,filename:%d,key:%d\n",cnt,filename,key); return 0;
		sprintf(name,"file_%d.txt",filename);

		//if(new_open)	fd=syscall(OPEN_KEY,name,mode2,access,key);
		fd=open(name,mode2,access);
		if(fd==-1){  //원래는 이런 일 없어야
			printf("%s open error!\n",name); return 0;
		}
		if(mode==0){
			for(j=0;j<iter;j++){
				s=read(fd, buf, IO_SIZE);
	//			buf2[j%IO_SIZE]=buf[j%IO_SIZE];
				//printf("s : %d,buf[10]:%c\n",s,buf[10]);
				if(s<=0){ printf("fail sequential read\n");  return 0;}
			}
		}
		else if(mode==1){
			for(j=0;j<iter;j++){
				s=write(fd,buf,IO_SIZE);
				if(s<=0){ printf("fail sequential write\n"); return 0;}
			}
		}
		fsync(fd);
		close(fd);
	}
	else{//new systemcall
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
	//	runtime=end.tv_nsec-start.tv_nsec;
	//	runtime/=10e9;
	//	runtime+=end.tv_sec-start.tv_sec;
	start_time=(start.tv_nsec/10e9)+start.tv_sec;
	end_time=(end.tv_nsec/10e9)+end.tv_sec;
	printf("process %d, start_time: %.9lf seconds, end_time : %.9lf seconds, buf2[10]:%c\n",cnt,start_time,end_time,buf2[3]);
		//printf("process %d, start_time: %.9lf seconds, end_time : %.9lf seconds:%c\n",cnt,start_time,end_time);
	free(buf2); free(dd); free(sig); free(read_sig);

	exit(0);
}
