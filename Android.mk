LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    msg_queue.c \
    looper.c \
    handler.c

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include

LOCAL_CFLAGS := -DIF_LOG

LOCAL_SHARED_LIBRARIES := \
    liblog

LOCAL_MODULE := libmsg_handler

include $(BUILD_SHARED_LIBRARY)
