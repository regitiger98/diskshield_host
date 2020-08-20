#include<stdio.h>
#define M 1000
char a[M+5];
int main()
{
	FILE *fp=fopen("middle.txt","r");
	FILE *fi=fopen("last.txt","w");
	freopen("result.txt","w",stdout);
	
	char name[100];
	long long file_size,total_size;
	int i,process,file_count, c, mode;
	double min, max,actual_time;
	char m[3][100]={"sequential read","sequential write","read_write"};
	double tmp,tmp2,mbs,total;
	while(fgets(a,M,fp)!=NULL){
		if( !(a[0]=='t' && a[1]=='e' && a[2]=='s' && a[3]=='t' )) continue;
		sscanf(a,"%[^':']: process %d, file_size %lld, mode %d%*s",name,&process,&file_size,&mode);
		printf("%s\n",a);
		file_count=1; //file_size :byte
		for(i=0;i<process;i++){
			fgets(a,M,fp);
			if(a[0]=='t' && a[1]=='e' && a[2]=='s' && a[3]=='t'){i--; continue;}
			sscanf(a,"process %*d, start_time: %lf seconds, end_time : %lf seconds%*s",&tmp,&tmp2);
			if(i==0){ min=tmp; max=tmp2;}
			if(min>tmp) min=tmp;
			if(max<tmp2) max=tmp2;
		}
		actual_time=max-min;
		total_size=file_size*process;
		mbs=(((double)total_size)/actual_time);
		mbs/=(1024*1024);
		total=((double)total_size)/(1024*1024);
		printf("mode %s, total_size : %.2lf MB, actual_time : %.9lfs, %lf MB/s\n"
				,m[mode],total,actual_time,mbs);
		printf("---------------------------------------------------------\n");
		fprintf(fi,"%s, %.2lf, %.9lf, %lf\n",m[mode],total,actual_time,mbs);
	}
	fclose(fp);
	fclose(fi);
	return 0;
}
