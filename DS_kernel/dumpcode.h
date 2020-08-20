// dumpcode.h by ohhara

//#ifdef WIN32
#include <ctype.h>
//#endif

void printchar(unsigned char c)
{
 if(isprint(c))
  printf("%c",c);
 else
  printf(".");
}
void dumpcode(unsigned char *buff, int len)
{
 int i;
 for(i=0;i<len;i++)
 {
  if(i%16==0)
   printf("0x%08x  ",&buff[i]);
  printf("%02x ",buff[i]);

  if(i%16-7==0)
   printf("- ");

  if(i%16-15==0)
  {
   int j;
   printf("  ");
   for(j=i-15;j<=i;j++)
    printchar(buff[j]);
   printf("\n\r");
  }
 }
 if(i%16!=0)
 {
  int j;
  int spaces=(len-i+16-i%16)*3+2;
  for(j=0;j<spaces;j++)
   printf(" ");
  for(j=i-i%16;j<len;j++)
   printchar(buff[j]);
 }
 printf("\n\r");
}
