#include<pthread.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/syscall.h>
#include<linux/kernel.h>
#include<unistd.h>
//#include<sys/fnctl.h>
#include<fcntl.h>
//#include"fnctl.h"
#include<sys/stat.h>
#include<time.h>
//#include<dumpcode.h>
#include <string.h>
#include<sys/stat.h>
#include<stdlib.h>
#include<time.h>
#include <sys/mman.h>

#include<sys/types.h>
#include<sys/wait.h>
#define P_SIZE 4096
#define K_SIZE 1024
#define IO_SIZE 8192
#define RESPONSE_SIZE 512
#define PAGE_BIT 12
#define NAME_LEN 16

#define __NR_enc_rdafwr 333

//#define barrier() __asm__ __volatile__("": : :"memory")
int b_pshared=1;
pthread_barrierattr_t *b_attr;
pthread_barrier_t* barrier;
int b_count;
   
#define FILE_NO 9


typedef struct DS_param{
	unsigned int fd;
	unsigned char cmd;
	unsigned long offset; //여기가 LBA영역에 들어감 6bytes
	unsigned int size; //이건 lba처럼 count영역에 들어가니, 섹터단위일듯.
}DS_PARAM;

enum ds_cmd{
	DS_WR_RANGE_MIN = 0x43,
	DS_CREATE_WR,	//0x44
	DS_OPEN_WR,		//0x45
	DS_CLOSE_WR,	//0x46
	DS_REMOVE_WR,	//0x47
	DS_WRITE_WR,	//0x48
	DS_WR_RANGE_MAX,	
	DS_RD_RANGE_MIN,
	DS_READ_RD,		//0x4b
	DS_AUTH_RD,		//0x4c
	DS_CREATE_RD,	//0x4d
	DS_OPEN_RD,		//0x4e
	DS_CLOSE_RD,	//0x4f
	DS_REMOVE_RD,	//0x50
	DS_WRITE_RD,	//0x51
	DS_RD_RANGE_MAX	//0x52
};

int file_operation(int cmd, int fd, char file_name[NAME_LEN], int offset);
int file_eval(char mode, int iters, char file_name[NAME_LEN]);
int enc_rdafwr(const DS_PARAM *ds_param, const char* u_buf, char* response, int count);
int version=1234;

/*
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
int enc_rdafwr(const DS_PARAM *ds_param, const char* u_buf, char* response, int count){
	
	int ret;
	ret = (int) syscall(__NR_enc_rdafwr, ds_param, u_buf, count);
	if(ret>0)	memcpy(response, u_buf, 512);
	return ret;

}

#define SECTOR_SIZE 512
#define SECTOR_BIT 9
#define KEY_SIZE 16
#define MAC_SIZE 32
//IPFS+단 가장 마지막에서 어떻게 가는가.
//
int main(int argc, char *argv[])
{
	int fd=1;
//	char file_name[NAME_LEN]="big0000.txt";
//	char file_name[NAME_LEN]="foo00000.txt";
	char file_name[NAME_LEN]="0000_00000.txt";
//	char file_name[NAME_LEN]="512MB.txt";
	int i,j;
	int N;
	int n_proc;
	char mode;
	//int iters;
	int n_files;
	int pid, cnt, tmp;
	
	if(argc!=4)
	{
		printf("Error: Wrong input\n");
		return 0;
	}
	
	mode = argv[1][0];
	n_files = atoi(argv[2]);
	n_proc = atoi(argv[3]);

	//process shared barrier 초기화

	b_count= n_proc;
	b_attr = (pthread_barrierattr_t*) malloc (sizeof(pthread_barrierattr_t));
	//barrier= (pthread_barrier_t*) malloc(sizeof(pthread_barrier_t));
	barrier = (pthread_barrier_t*)mmap(NULL,sizeof(pthread_barrier_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pthread_barrierattr_setpshared(b_attr, b_pshared);
	pthread_barrier_init(barrier, b_attr, b_count);

	printf("mode: %c, num: %d, n_process: %d\n", mode, n_files, n_proc);
	//printf("getpid : %d\n", getpid());
	//멀티 프로세스 실험: 1,2,4,8,16
	tmp=n_proc/2;
	cnt=1;
	//barrier();
	for(i=2;i<=n_proc;i*=2){
	    //barrier();
	    pid=fork();
	    //barrier();
	    switch(pid){
		case -1 : printf("fork error %d\n",i); return 0;
		case 0 : cnt+=tmp; break;
	    }
	    tmp/=2;
	}
	//barrier();
	printf("before barreir// cnt %d\n", cnt);

	
    pthread_barrier_wait(barrier);
   
	printf("after barreir// cnt %d\n", cnt);

	char n_proc_s[5];
	//sprintf(n_proc_s, "%d", getpid());
	if(cnt<10)	sprintf(n_proc_s, "000%d", cnt);
	else		sprintf(n_proc_s, "00%d", cnt);

	memcpy(file_name,n_proc_s,sizeof(char)*4);
//	printf("%s\n", file_name);
	//	version = getpid();	//process별로 다른 version갖게하기	//과연 진짜 필요한지 의문.
	memcpy(file_name, "0000_00000.txt", 15);
	memcpy(file_name,n_proc_s,sizeof(char)*4);
	
	//if(cnt==1)	n_files--;
	file_eval(mode, n_files, file_name);

	if(pid > 0)
	{
		while(wait(NULL)!=-1);
		//wait(NULL);
		//printf("it has finished! %d %d\n", cnt, getpid());
	}
	if(cnt==1)
	{
		printf("Process has finished.\n");
	}
	//pthread_barrier_destroy(barrier);
	munmap(barrier, sizeof(pthread_barrier_t));
	
	return 0;	
}


int file_eval(char mode, int iters, char file_name_[NAME_LEN])
{
	int offset;
	int fd;
	int i,j,k;
	char file_name[NAME_LEN];
	memcpy(file_name, file_name_, NAME_LEN);
//	for(i=0; i<N; i++)
	//for(i=0; i<1024*4-1; i++)
	for(i=0; i<iters; i++)
	{
	//memcpy(file_name, &j, sizeof(int));

		file_name[FILE_NO]++;
		for(j=FILE_NO; j>=FILE_NO-3; j--)
		{
			//file_name[j]++;
			if(file_name[j]>'9')
			{
				file_name[j-1]++;
				file_name[j]='0';
			}
		}
		printf("%s\n", file_name);

		if(mode=='D' || mode=='d')
		{
			printf("DEMO %s\n", file_name);
			fd=file_operation(DS_CREATE_WR, fd, file_name, 0);
			file_operation(DS_WRITE_WR, fd, file_name, 0);
			file_operation(DS_CLOSE_WR, fd, file_name, 0);
			//printf("Open&Write fd(%d), name(%s)\n", fd, file_name);
		}
		
		if(mode=='C' || mode=='c')	//file creation
		{
//			printf("CREATE\n");
			fd=file_operation(DS_CREATE_WR, fd, file_name, 0);
		//	fd=2;
			/* 임시 코드*/
			/*
			printf("fd %d %s\n",fd, file_name);
			file_name[FILE_NO]++;
			fd=file_operation(DS_CREATE_WR, fd, file_name);
			printf("fd %d %s\n",fd, file_name);
			file_name[FILE_NO]--;
			fd=1;
			file_operation(DS_CLOSE_WR, fd, file_name);
			file_name[FILE_NO]++;
			fd=2;
*/
			///////////////////////////////////////////////
			printf("CREATE fd %d %s\n",fd, file_name);
			file_operation(DS_CLOSE_WR, fd, file_name, 0);
		}

		if(mode=='W' || mode=='w')
		{
			offset=0;
			fd = file_operation(DS_OPEN_WR, fd, file_name, 0);
			file_operation(DS_WRITE_WR, fd, file_name, 0);
			file_operation(DS_CLOSE_WR, fd, file_name, 0);
			printf("Open&Write fd(%d), name(%s)\n", fd, file_name);
		}

		if(mode=='I' || mode=='i')
		{
			offset=0;
			fd = file_operation(DS_CREATE_WR, fd, file_name, 0);
			file_operation(DS_WRITE_WR, fd, file_name, 0);
			file_operation(DS_CLOSE_WR, fd, file_name, 0);
			printf("Create&Write fd(%d), name(%s)\n", fd, file_name);
		}



		if(mode=='R' || mode=='r')
		{
			offset=0;
			fd = file_operation(DS_OPEN_WR, fd, file_name, 0);
			file_operation(DS_READ_RD, fd, file_name, 0);
			file_operation(DS_CLOSE_WR, fd, file_name, 0);
		
		}

		if(mode=='B' || mode=='b')
		{
			fd = file_operation(DS_OPEN_WR, fd, file_name, 0);
			for(offset=0; offset<4096*4; offset++)
				file_operation(DS_WRITE_WR, fd, file_name, offset);
			file_operation(DS_CLOSE_WR, fd, file_name, 0);
			
		}

		if(mode=='Z' || mode=='z')
		{
			//static int fakefd=0;//Donotuseit
			fd = file_operation(DS_OPEN_WR, fd, file_name, 0);
		//	fd=file_operation(DS_CREATE_WR, fd, file_name, 0);
		//	fd = ++fakefd;
		//	
			file_operation(DS_WRITE_WR, fd, file_name, 1);
			file_operation(DS_CLOSE_WR, fd, file_name, 0);
			printf("Open fd(%d), name(%s)\n", fd, file_name);
		}
	
	}
}


int file_operation(int cmd, int fd, char file_name[NAME_LEN], int offset)
{
	char *u_buf_ = (char*) malloc (sizeof(char)*(IO_SIZE + SECTOR_SIZE));
	char *u_buf = (char*) ((((unsigned long)u_buf_ + SECTOR_SIZE -1 ) >> SECTOR_BIT) << SECTOR_BIT);
//	printf("u_buf address : %x\n", u_buf);
	char *response = (char*) malloc (sizeof(char)*RESPONSE_SIZE);
	DS_PARAM *ds_param = (DS_PARAM*) malloc (sizeof(DS_PARAM));	

	//char file_name[NAME_LEN]="foo4.txt";
	unsigned int mac[MAC_SIZE/4]={0x12121212, 0x34343434, 0x56565656, 0x78787878, 0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA};
	
	char key[KEY_SIZE];
	int i;
	//int version=0x99999999;
	//version++;
	//printf("file_name : %s\n", file_name);

	for(i=0; i<KEY_SIZE; i++)
	{
		key[i] = i+1;
	}
	//char key[KEY_SIZE]={0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

	ds_param->cmd = cmd;

	if(ds_param->cmd == DS_CREATE_WR)
	{
		printf("DS_CREATE_WR name(%s)\n", file_name);
		ds_param->cmd = DS_CREATE_WR;
		ds_param->fd = -1;
		ds_param->offset = 0;
		ds_param->size = 512;//16+16+4+16; //name, mac, version, key
		//ds_param->size = NAME_LEN+KEY_SIZE*2+4;//16+16+4+16; //name, mac, version, key

		memcpy((char*)u_buf, mac, MAC_SIZE);
		memcpy((char*)(u_buf+MAC_SIZE), &version, 4);
		memcpy((char*)(u_buf+MAC_SIZE+4), file_name, NAME_LEN);
		memcpy((char*)(u_buf+MAC_SIZE+4+NAME_LEN), key, KEY_SIZE);

		//for debugging
	}
	else if(ds_param->cmd == DS_OPEN_WR)
	{
		printf("DS_OPEN_WR name(%s)\n", file_name);
		ds_param->cmd = DS_OPEN_WR;
		ds_param->fd = -1;
		ds_param->offset = 0;
		ds_param->size = 512;//16+16+4;	//name, mac, version
		//ds_param->size = NAME_LEN+KEY_SIZE+4;//16+16+4;	//name, mac, version
		
		memcpy((char*)u_buf, mac, MAC_SIZE);
		memcpy((char*)(u_buf+MAC_SIZE), &version, 4);
		memcpy((char*)(u_buf+MAC_SIZE+4), file_name, NAME_LEN);
	}
	else if(ds_param->cmd == DS_CLOSE_WR)
	{
		printf("DS_CLOSE_WR fd(%d)\n", fd);
		ds_param->cmd = DS_CLOSE_WR;
		ds_param->fd = fd;
		ds_param->offset = 0;
		ds_param->size = 512;//16+4;	//name, mac, version
		//ds_param->size = NAME_LEN+4;//16+4;	//name, mac, version
		
		memcpy((char*)u_buf, mac, MAC_SIZE);
		memcpy((char*)(u_buf+MAC_SIZE), &version, 4);
	}
	else if(ds_param->cmd == DS_WRITE_WR)
	{
		printf("DS_WRITE_WR fd(%d) offset(%d)\n", fd, offset*4096);
		ds_param->cmd = DS_WRITE_WR;
		ds_param->fd = fd;
		
		ds_param->offset = offset*4096;
		ds_param->size = 4096+512 ;
		//ds_param->size = 512;

		for(int i=0; i<4096; i++)
		{
			u_buf[i]=0x45;
		}
		memcpy((char*)(u_buf+4096), mac, MAC_SIZE);
		memcpy((char*)(u_buf+4096+MAC_SIZE), &version, 4);
		//memcpy((char*)u_buf, mac, MAC_SIZE);
		//memcpy((char*)(u_buf+MAC_SIZE), &version, 4);
	}

	else if(ds_param->cmd == DS_REMOVE_WR)
	{
		;
	}
	else if(ds_param->cmd == DS_READ_RD)
	{
		printf("DS_READ_RD fd(%d)\n", fd);
		ds_param->cmd = DS_READ_RD;
		ds_param->fd = fd;
		ds_param->offset = 0;
	//	ds_param->size = 512+512;
		ds_param->size = IO_SIZE;
	}
	/*
	if(ds_param->cmd!=DS_WRITE_WR)
		dumpcode((unsigned char*)u_buf, 128);
	else	
		dumpcode((unsigned char*)u_buf, 4096+512);
	*/

//	if(ds_param->cmd==DS_CLOSE_WR)
//		dumpcode((unsigned char*)u_buf, 128);

	enc_rdafwr(ds_param, u_buf, response, ds_param->size);

	if(ds_param->cmd==DS_CLOSE_WR)
	{
		int c_retmsg;
		int c_version;

		memcpy(&c_retmsg, &(u_buf[32]), sizeof(char)*4);
		memcpy(&c_version, &(u_buf[36]), sizeof(char)*4);

		printf("...CLOSE... fd, retmsg, version is %d %d %d\n", fd,c_retmsg, c_version);
	}

	//dumpcode((unsigned char*)u_buf, 512);
	
	if(ds_param->cmd == DS_OPEN_WR || ds_param->cmd == DS_CREATE_WR)
	{
		memcpy(&fd, &u_buf[32], 4);
		free(u_buf_);
		if(ds_param->cmd == DS_OPEN_WR)
			printf("...OPEN...fd is %d\n", fd);		
		if(ds_param->cmd == DS_CREATE_WR)
			printf("...CREATE...fd is %d\n", fd);
		return fd;
	}
	else
	{
		free(u_buf_);
		return 0;
	}

}












