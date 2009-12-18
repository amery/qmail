#include <time.h>
#include "datetime.h"
#include "now.h"

datetime_sec now(void)
{
  return time((void *)0);
}
