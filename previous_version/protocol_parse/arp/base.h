#ifndef __BASE_H__
#define __BASE_H__

// 包含需要的头文件

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ether.h>  // ethernet协议定义头文件
#include <net/if_arp.h>     // arp协议
#include <iostream>
#define INVALID_FILE                            -1
#define MAX_FILE_PATH                           255

#define JUDGE_RETURN(Condition, ErrorCode)      if ((Condition)) { return (ErrorCode); } 
#define JUDGE_BREAK(Condition)                  if ((Condition)) { break; }

#define OPPOSIZE_BYTE_ORDER(x)                  ((((x) & 0x000000FF) << 24) | \
                                                    (((x) & 0x0000FF00) << 8) | \
                                                    (((x) & 0x00FF0000) >> 8) | \
                                                    (((x) & 0xFF000000) >> 24))

#define OPPOSIZE_SHORT_ORDER(x)                 ((((x) & 0x00FF) << 8) |\
                                                    (((x) & 0xFF00) >> 8))

#endif 

