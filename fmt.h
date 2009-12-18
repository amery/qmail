#ifndef FMT_H
#define FMT_H

#define FMT_ULONG 40 /* enough space to hold 2^128 - 1 in decimal, plus \0 */
#define FMT_LEN ((char *) 0) /* convenient abbreviation */

extern unsigned int fmt_uint(char *, unsigned int);
extern unsigned int fmt_uint0(char *, unsigned int, unsigned int);
/* XXX not available in qmail-1.03
extern unsigned int fmt_xint();
extern unsigned int fmt_nbbint();
extern unsigned int fmt_ushort();
extern unsigned int fmt_xshort();
extern unsigned int fmt_nbbshort();
*/
extern unsigned int fmt_ulong(char *, unsigned long);
/* XXX not available in qmail-1.03
extern unsigned int fmt_xlong();
extern unsigned int fmt_nbblong();

extern unsigned int fmt_plusminus();
extern unsigned int fmt_minus();
extern unsigned int fmt_0x();
*/

extern unsigned int fmt_str(char *, const char *);
extern unsigned int fmt_strn(char *, const char *, unsigned int);

#endif
