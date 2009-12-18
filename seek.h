#ifndef SEEK_H
#define SEEK_H

typedef unsigned long seek_pos;

extern seek_pos seek_cur(int fd);

extern int seek_set(int fd, seek_pos);
extern int seek_end(int fd);

extern int seek_trunc(int fd, seek_pos);

#define seek_begin(fd) (seek_set((fd),(seek_pos) 0))

#endif
