LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  device_database.c

LOCAL_MODULE := libdevice_database
LOCAL_MODULE_TAGS := optional

include $(BUILD_STATIC_LIBRARY)
