#ifndef _SYNC_H_
#define _SYNC_H_

extern int64_t mns_dx;
extern int64_t mns_dy;
extern double slope;
extern double yntercept;

uint64_t getLocalTime(int precision);
void *threadSync(void *arg);

#endif

