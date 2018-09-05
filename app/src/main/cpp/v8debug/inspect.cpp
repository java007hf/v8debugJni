
//#include "v8.h"
#include "../include/v8-inspector.h"
#include <time.h>

#include <map>
#include <deque>
#include <condition_variable>
#include "../include/websocket.h"


namespace tt {
    using namespace v8;
    using namespace v8_inspector;

    class Inspect;

    using InspectMap = std::map<std::string, std::unique_ptr<Inspect>>;
    InspectMap inspects;
    static uint16_t port;
}


#ifdef ANDROID

#include "jni.h"
#include "android/log.h"
#include "../include/inspect.h"

namespace tt {
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "inspect.cpp", __VA_ARGS__)
}
#else
#define LOG printf

#endif

namespace tt {
    class Inspect final : public V8InspectorClient,
                          public websocket::WebSocket::MessageHandler,
                          public V8Inspector::Channel {
        websocket::WebSocket *conn = nullptr;

        std::mutex mutex_devtool_message;
        std::condition_variable cond_devtool_message;

        void postMessages() {
            while (!messages.empty()) {
                std::unique_ptr<StringBuffer> &str = messages.front();
                session->dispatchProtocolMessage(str->string());
                messages.pop_front();
            }
        }

        static void _onMessage(Isolate *, Inspect *inspect) {
            std::unique_lock<std::mutex> lock_guard(inspect->mutex_devtool_message);
            inspect->postMessages();
        }

        static void _on_disconnect(Isolate *, Inspect *inspect) {
            inspect->conn = nullptr;
            inspect->session.reset();
        }

        std::deque<std::unique_ptr<StringBuffer>> messages;
        std::unique_ptr<V8InspectorSession> session;
        Isolate *isolate;
        std::unique_ptr<V8Inspector> inspector;

        inline void schedule_callback(void(callback)(Isolate *, Inspect *)) {
            auto fn = reinterpret_cast<InterruptCallback>(callback);
            isolate->RequestInterrupt(fn, this);
        }

    public:
        const std::string title;

        inline bool connected() const {
            return conn != nullptr;
        }

        inline bool is(Isolate *that) {
            return isolate == that;
        }

        void onException(TryCatch &catcher) {
            HandleScope hs(isolate);
            Local<Context> ctx = isolate->GetCurrentContext();

            Local<Message> msg = catcher.Message();
            String::Value str(isolate, msg->Get());
            String::Value url(isolate, msg->GetScriptResourceName());
            uint32_t scriptId = msg->GetScriptOrigin().ScriptID()->Uint32Value(ctx).FromMaybe(0);

//            inspector->exceptionThrown(
//                    ctx,
//                    StringView(*str, str.length()),
//                    catcher.Exception(),
//                    StringView(*str, str.length()),
//                    StringView(*url, url.length()),
//                    msg->GetLineNumber(ctx),
//                    msg->GetStartColumn(),
//                    inspector->createStackTrace(msg->GetStackTrace()),
//                    scriptId
//            );
        }

        // 必须在 v8 线程内执行
        inline Inspect(std::string title) : title(title) {}

        void setup(Isolate *isolate) {
            this->isolate = isolate;
            LOG("create inspect, isolate=%p", isolate);
            inspector = V8Inspector::create(isolate, this);
            Local<Context> ctx = isolate->GetCurrentContext();

            V8ContextInfo v8info(ctx, 1, StringView((const uint8_t *) "default", 7));
            v8info.origin = StringView((const uint16_t *) nullptr, 0);
            inspector->contextCreated(v8info);
        }

        void onDispose() {
            // isolate disposed
            if (conn) {
                conn->disconnect();
                // 因 isolate 关闭后 session 无法删除，此处将泄漏内存
                session.release();
            }
        }

        void on_connect(websocket::WebSocket *conn) override {
            this->conn = conn;
            session = inspector->connect(1, this, StringView());
        }

        void on_close() override {
            if (!conn) return;
            if (Isolate::GetCurrent() == isolate) {
                _on_disconnect(isolate, this);
            } else {
                schedule_callback(_on_disconnect);
            }
            if (paused) {
                paused = false;
                std::unique_lock<std::mutex> lock_guard(mutex_devtool_message);
                cond_devtool_message.notify_all();
            }

        }

        // 发送消息到 Inspect
        void on_message(int, const uint8_t *bytes, size_t size) override {
            std::unique_lock<std::mutex> lock_guard(mutex_devtool_message);
            bool is_empty = messages.empty();
            messages.push_back(StringBuffer::create(StringView(bytes, size)));
            if (paused) {
                cond_devtool_message.notify_all();
            } else if (is_empty) {
                schedule_callback(_onMessage);
            }
            // LOG("sendMessage: %s queue.length=%d", bytes, size);
        }

        bool paused = false;

        void runMessageLoopOnPause(int contextId) override {
            std::unique_lock<std::mutex> lock_guard(mutex_devtool_message);
            paused = true;
            while (paused) {
                if (messages.empty())
                    cond_devtool_message.wait(lock_guard);
                postMessages();
            }
        }

        void quitMessageLoopOnPause() override {
            paused = false;
        }

        double currentTimeMS() override {
            struct timespec res;
            clock_gettime(CLOCK_REALTIME, &res);
            return 1000.0 * res.tv_sec + (double) res.tv_nsec / 1e6;
        }

        inline void sendToDevtool(const StringView &sv) {
            if (!conn) return;
            conn->send(sv.characters16(), sv.length());
        }

        virtual void sendResponse(int callId, std::unique_ptr<StringBuffer> message) override {
            sendToDevtool(message->string());
        }

        virtual void sendNotification(std::unique_ptr<StringBuffer> message) override {
            sendToDevtool(message->string());
        }

        virtual void flushProtocolNotifications() override {
        }

    };

    std::string on_get_version() {
        char buf[4096];
        int written = snprintf(buf, sizeof(buf), "{"
                "\"Browser\": \"Toutiao JS Debugger\","
                "\"Protocol-Version\": \"1.3\","
                "\"V8-Version\":\"%s\""
                "}", v8::V8::GetVersion());
        return std::string(buf, written);
    }

    std::string on_get_json() {
        char buf[4096];
        int pos = 0;

        for (InspectMap::iterator it = inspects.begin(), end = inspects.end();
             it != end; it++) {
            if (it->second->connected()) continue;
            if (pos) {
                buf[pos++] = ',';
            } else {
                buf[pos++] = '[';
            }
            const char *uuid = it->first.c_str();
            int written = snprintf(buf + pos, sizeof(buf) - pos, "{\"description\":\"tt_v8_inspect\","
                    "\"devtoolsFrontendUrl\":\"chrome-devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws=127.0.0.1:%u/%s\","
                    "\"faviconUrl\":\"https://s3a.pstatp.com/toutiao/resource/ntoutiao_web/static/image/favicon_8e9c9c7.ico\","
                    "\"title\":\"%s\","
                    "\"id\":\"%s\","
                    "\"type\":\"node\","
                    "\"url\":\"file://\","
                    "\"webSocketDebuggerUrl\":\"ws://127.0.0.1:%u/%s\"}", port, uuid, it->second->title.c_str(), uuid, port, uuid);
            pos += written;
        }
        if (!pos) return "[]";
        buf[pos++] = ']';
        buf[pos] = '\0';
        return std::string(buf, pos);
    }

    static HttpResponse on_request(std::string url) {
        if (url == "json") {
            return std::make_tuple(200, on_get_json());
        }
        if (url == "json/version") {
            return std::make_tuple(200, on_get_version());
        }
        return std::make_tuple(404, std::string());
    }

    void on_connect(websocket::WebSocketRequest &req) {
        InspectMap::iterator it = inspects.find(req.url);
        if (it == inspects.end() || it->second->connected()) {
            return req.reject(404, std::string());
        }
        Inspect *inspect = it->second.get();
        req.accept(inspect);
    }

    static void setupInspectLater(Isolate *isolate, void *p) {
        Inspect *inspect = static_cast<Inspect *>(p);
        inspect->setup(isolate);
    }

    void inspect::onException(Isolate *isolate, TryCatch &catcher) {
        for (InspectMap::iterator it = inspects.begin(), last = inspects.end();
             it != last; it++) {
            std::unique_ptr<Inspect> &inspect = it->second;
            if (inspect->is(isolate)) {
                inspect->onException(catcher);
                break;
            }
        }
    };
}

extern "C" {
/*
 * Class:     com_bytedance_v8_inspect_Inspect
 * Method:    _listen
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_com_bytedance_v8_1inspect_Inspect__1listen
        (JNIEnv *, jclass, jint port) {
    char tmp[8];
    int len = sprintf(tmp, "%d", port);
    tt::port = port;
    tt::websocket::listen(port, tt::on_request, tt::on_connect);
}

/*
 * Class:     com_bytedance_v8_inspect_Inspect
 * Method:    onNewIsolate
 * Signature: (Ljava/lang/String;J)V
 */
JNIEXPORT void JNICALL Java_com_bytedance_v8_1inspect_Inspect_onNewIsolate
        (JNIEnv *env, jclass, jstring title, jstring uuid) {
    using v8::Isolate;
    Isolate *current = Isolate::GetCurrent();
    if (!current) {
        LOG("could not create isolate");
        return;
    }

    const char *ch = env->GetStringUTFChars(uuid, nullptr);
    const char *_title = env->GetStringUTFChars(title, nullptr);
    LOG("%s: isolate created, visit: chrome-devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws=127.0.0.1:%u/%s", _title, tt::port, ch);
    std::string $uuid(ch);
    std::string $title(_title);
    env->ReleaseStringUTFChars(uuid, ch);

    tt::Inspect *inspect = new tt::Inspect($title);
    tt::inspects[$uuid] = std::unique_ptr<tt::Inspect>(inspect);
    inspect->setup(current);
}
/*
 * Class:     com_bytedance_v8_inspect_Inspect
 * Method:    onDispose
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_com_bytedance_v8_1inspect_Inspect_onDispose
        (JNIEnv *env, jclass, jstring uuid) {
    jboolean isCopy;
    const char *ch = env->GetStringUTFChars(uuid, &isCopy);
    auto it = tt::inspects.find(ch);
    env->ReleaseStringUTFChars(uuid, ch);

    if (it == tt::inspects.end()) return;

    tt::Inspect *inspect = it->second.get();
    inspect->onDispose();
    tt::inspects.erase(it);
}

}