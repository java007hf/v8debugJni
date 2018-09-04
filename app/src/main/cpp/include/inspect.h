
#ifndef V8_INSPECT_H
#define V8_INSPECT_H

#include "v8.h"

namespace tt {
    namespace inspect {
        extern void onException(v8::Isolate *isolate, v8::TryCatch &catcher);
    }
}

#endif // V8_INSPECT_H
