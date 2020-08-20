#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#define PG_SIZE 4096
#define CNT 1024
#define MODE_WR 0
#define MODE_RD 1

int main()
{
	int mode;
	

	printf("WRITE MODE: 0, READ MODE: 1\n");
	scanf("%d", &mode);

	int fd = open("/home/jinu/SSD/test.txt", O_CREAT | O_RDWR | O_SYNC);

	printf("%d\n", fd);
	if(mode==MODE_WR)
	{
		printf("z");
		char buf[PG_SIZE];
		memset(buf, 0xff, sizeof(char)*PG_SIZE);
		for(int i=0; i<CNT; i++)
			write(fd, buf, PG_SIZE);
	}

	else if(mode==MODE_RD)
	{
		system("echo 3 > /proc/sys/vm/drop_caches");
		char buf[PG_SIZE];
		for(int i=0; i<CNT; i++)
		{
			read(fd, buf, PG_SIZE);
			for(int j=0; j<PG_SIZE; j++)
			{
				printf("%x", buf[j]);
				buf[j]=NULL;
			}
		}
	}

	close(fd);
}
