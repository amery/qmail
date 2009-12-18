#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ndelay.h"
#include "select.h"
#include "error.h"
#include "readwrite.h"
#include "ip.h"
#include "byte.h"
#include "timeoutconn.h"

int timeoutconn(int s, struct ip_address *ip, struct ip_address *outip,
    unsigned int port, int timeout)
{
  char ch;
  struct sockaddr_in s_in;
  char *x;
  fd_set wfds;
  struct timeval tv;
 
 
  if (ndelay_on(s) == -1) return -1;
 
  /* bind() an outgoing ipaddr */
  byte_zero(&s_in,sizeof(s_in));
  byte_copy(&s_in.sin_addr.s_addr,4,outip);
  s_in.sin_family = AF_INET;

  if (bind(s,(struct sockaddr *) &s_in,sizeof(s_in)) == -1) return -1;
  
  byte_zero(&s_in,sizeof(s_in));
  byte_copy(&s_in.sin_addr,4,ip);
  x = (char *) &s_in.sin_port;
  x[1] = port; port >>= 8; x[0] = port;
  s_in.sin_family = AF_INET;
 
  if (connect(s,(struct sockaddr *) &s_in,sizeof(s_in)) == 0) {
    ndelay_off(s);
    return 0;
  }
  if ((errno != error_inprogress) && (errno != error_wouldblock)) return -1;
 
  FD_ZERO(&wfds);
  FD_SET(s,&wfds);
  tv.tv_sec = timeout; tv.tv_usec = 0;
 
  if (select(s + 1,(fd_set *) 0,&wfds,(fd_set *) 0,&tv) == -1) return -1;
  if (FD_ISSET(s,&wfds)) {
    int dummy;
    dummy = sizeof(s_in);
    if (getpeername(s,(struct sockaddr *) &s_in,&dummy) == -1) {
      subread(s,&ch,1);
      return -1;
    }
    ndelay_off(s);
    return 0;
  }
 
  errno = error_timeout; /* note that connect attempt is continuing */
  return -1;
}
