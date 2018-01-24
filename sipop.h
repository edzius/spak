#ifndef __SIPOP_H__
#define __SIPOP_H__

int sip_check(const char *srcfile);
int sip_encode(const char *srcfile, const char *dstfile, const char *mark);
int sip_decode(const char *srcfile, const char *dstfile);

#endif //__SIPOP_H__
