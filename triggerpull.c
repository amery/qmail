#include <unistd.h>
#include "readwrite.h"
#include "ndelay.h"
#include "open.h"
#include "triggerpull.h"

void triggerpull(void)
{
 int fd;

 fd = open_write("lock/trigger");
 if (fd >= 0)
  {
   ndelay_on(fd);
   write(fd,"",1); /* if it fails, bummer */
   close(fd);
  }
}
