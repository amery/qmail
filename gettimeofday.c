#include   <stdio.h>
#include   <sys/time.h>

struct timeval sincepoch = {0,0};
struct timezone notimezone = {0,0};

int main()
{
  gettimeofday(&sincepoch, &notimezone);
  printf("%d\n", sincepoch.tv_sec);
  return 0;
}

