/* endian.c
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <jeker@n-r-g.com> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.       Claudio Jeker
 * ----------------------------------------------------------------------------
 *
 *  This is a lowest-common-denominator (endian) program which should compile
 *  under the default cc on any system, no matter how primitite ...
 *  (even the SunOS one ;-) )
 */

#include <stdio.h>


union endian_t {
   unsigned char   c[8];
   long   l;
} endian;

int main()
{

	endian.c[0]=0x80; endian.c[1]=0; endian.c[2]=0; endian.c[3]=0;
	endian.c[4]=0;    endian.c[5]=0; endian.c[6]=0; endian.c[7]=0;
   
	if( endian.l < 0 )
		printf( "-D__BIG_ENDIAN__" );
	else
		printf( "-D__LITTLE_ENDIAN__" );

	return(0);
}
