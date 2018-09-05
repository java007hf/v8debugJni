//
// Created by wangyingli on 2018/9/4.
//
#include <jni.h>
#include <string.h>
#include "v8.h"

/**
 * Must stub in case external snapshot files are used.
 */
namespace v8::internal {
    void ReadNatives() {}

    void DisposeNatives() {}

    void SetNativesFromFile(v8::StartupData *s) {}

    void SetSnapshotFromFile(v8::StartupData *s) {}
}

namespace tt {
    JavaVM *vm;
}


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    tt::vm = vm;
    return JNI_VERSION_1_6;
}

