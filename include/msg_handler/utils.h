#ifndef __MSG_HANDLER_UTILS__
#define __MSG_HANDLER_UTILS__

#ifdef ANDROID
#ifndef LOG_TAG
#define LOG_TAG "[MSG_HANDLER]"
#endif
#include<cutils/log.h>
#endif

#ifdef IF_LOG

#ifdef ANDROID
#   define _TO_STR(str) #str
#   define TO_STR(str)  _TO_STR(str)
#   define _IF_LOG(level, args) \
    ALOG##level##("[@"__FILE__":"TO_STR(__LINE__)"]"args)
#   define IF_LOGI(args...) _IF_LOG(I, args)
#   define IF_LOGW(args...) _IF_LOG(W, args)
#   define IF_LOGE(args...) _IF_LOG(E, args)
#else
// TODO :
#   define IF_LOGI(args...) (void)0
#   define IF_LOGW(args...) (void)0
#   define IF_LOGE(args...) (void)0
#endif

#else
#   define IF_LOGI(args...) (void)0
#   define IF_LOGW(args...) (void)0
#   define IF_LOGE(args...) (void)0

#endif

#endif
