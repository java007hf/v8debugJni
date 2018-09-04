//
// Created by wangyingli on 2018/9/4.
//
#include <jni.h>
#include <string.h>

namespace tt {
    JavaVM *vm;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    tt::vm = vm;
    return JNI_VERSION_1_6;
}

