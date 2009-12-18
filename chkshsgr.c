#include <sys/types.h>
#include <unistd.h>
#include "exit.h"

int main(int argc, char ** argv)
{
 short x[4];

 x[0] = x[1] = 0;
 if (getgroups(1,x) == 0) if (setgroups(1,x) == -1) _exit(1);
 return 0;
}
