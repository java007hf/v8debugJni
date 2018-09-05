#include <sys/types.h>
#include <unistd.h>
#include "netinet/tcp.h"
#include "netinet/in.h"
#include "pthread.h"
#include "stdio.h"
#include "../include/websocket.h"
#include "zlib.h"
#include <string.h>

#define DEBUG_WS 0

#ifdef ANDROID

#include "android/log.h"
#include "jni.h"

#define LOG(...)    __android_log_print(ANDROID_LOG_INFO, "websocket.cpp", __VA_ARGS__)


namespace tt {
    extern JavaVM *vm;
    static pthread_key_t $env;
    static jobject $sha1;
    static jmethodID digest;

    static void thread_init() {
        JNIEnv *env;
        vm->GetEnv((void **) &env, JNI_VERSION_1_6);

        pthread_key_create(&$env, nullptr);

        jclass MessageDigest = env->FindClass("java/security/MessageDigest");
        jmethodID getInstance = env->GetStaticMethodID(
                MessageDigest, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
        digest = env->GetMethodID(MessageDigest, "digest", "([B)[B");
        jstring algorithm = env->NewStringUTF("SHA-1");

        jobject instance = env->CallStaticObjectMethod(MessageDigest, getInstance, algorithm);
        env->DeleteLocalRef(MessageDigest);
        env->DeleteLocalRef(algorithm);
        $sha1 = env->NewGlobalRef(instance);
        env->DeleteLocalRef(instance);
    }

    inline void thread_setup() {
        JNIEnv *env;
        vm->AttachCurrentThread(&env, nullptr);
        pthread_setspecific($env, env);
    }

    inline void thread_pulldown() {
        vm->DetachCurrentThread();
    }

    void sha1(const void *ptr, size_t len, char *out28) {
        JNIEnv *env = (JNIEnv *) pthread_getspecific($env);

        jbyteArray bytes = env->NewByteArray(len);
        env->SetByteArrayRegion(bytes, 0, len, reinterpret_cast<const jbyte *>(ptr));

        jobject ret = env->CallObjectMethod($sha1, digest, bytes);
        env->DeleteLocalRef(bytes);

        bytes = static_cast<jbyteArray>(ret);
        jbyte *in = env->GetByteArrayElements(bytes, nullptr);
        // 转 base64
        const char *b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0, index = 0; i < 18; i += 3) {
            out28[index++] = b64_chars[(in[i] & 0xff) >> 2];
            out28[index++] = b64_chars[((in[i] & 0x03) << 4) | ((in[i + 1] & 0xff) >> 4)];
            out28[index++] = b64_chars[((in[i + 1] & 0x0f) << 2) | ((in[i + 2] & 0xff) >> 6)];
            out28[index++] = b64_chars[(in[i + 2] & 0x3f)];
        }
        out28[24] = b64_chars[(in[18] & 0xff) >> 2];
        out28[25] = b64_chars[((in[18] & 0x03) << 4) | ((in[19] & 0xff) >> 4)];
        out28[26] = b64_chars[((in[18 + 1] & 0x0f) << 2)];
        out28[27] = '=';
        env->ReleaseByteArrayElements(bytes, in, JNI_ABORT);
        env->DeleteLocalRef(bytes);
    }
}
#else
namespace tt {
    inline void thread_init() {}
    inline void thread_setup() {}

    inline void thread_pulldown() {}
}
#endif


#if DEBUG_WS
#define LOGV   LOG
#else
#define LOGV(...)
#endif

namespace tt {
    namespace websocket {
        const int FLAG_RSV1 = 4;

        struct Headers {
            bool connection_upgrade = false;
            bool upgrade_websocket = false;
            std::string sec_websocket_key;
        };

        struct conn_s {
            int fno;

            std::tuple<int, std::string> (*request_handle)(std::string url);

            void (*callback)(WebSocketRequest &);
        };

        const static std::string unique_key = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#define READV(buf) if (!fread(buf, sizeof(buf), 1, fd)) {LOGV("failed reading bytes[%d]", sizeof(buf));return false;}
#define READ(ref) if (!fread(&ref, sizeof(ref), 1, fd)) {LOG("failed reading ref{%d}", sizeof(ref));return false;}

        struct StreamReader {
            uint8_t buf[256];

            virtual int read() = 0;

            uint8_t *readAll(int &length) {
                uint8_t stack_allocated_buf[1024];
                uint8_t *heap_allocated_buf = nullptr;
                uint8_t *current_buf = stack_allocated_buf;
                size_t capacity = sizeof(stack_allocated_buf);
                size_t len = 0;
                for (;;) {
                    int red = read();
                    if (!red) break;
                    if (red == -1) { // failed
                        length = -1;
                        if (heap_allocated_buf) delete heap_allocated_buf;
                        return nullptr;
                    }
                    if (red + len > capacity) {
                        capacity <<= 1;
                        uint8_t *new_buf = new uint8_t[capacity];
                        memcpy(new_buf, current_buf, len);
                        if (heap_allocated_buf) delete heap_allocated_buf;
                        heap_allocated_buf = current_buf = new_buf;
                    }
                    memcpy(current_buf + len, buf, red);
                    len += red;

                }
                length = len;
                if (!heap_allocated_buf) {
                    heap_allocated_buf = new uint8_t[len];
                    memcpy(heap_allocated_buf, current_buf, len);
                }
                return heap_allocated_buf;
            }
        };

        struct FdReader : public StreamReader {
            FILE *fd;
            size_t length;
            size_t remains;

            inline FdReader(FILE *fd, size_t length) : fd(fd), length(length), remains(length) {}

            virtual int read() override {
                // LOG("FdReader::read %d remains", remains);
                if (!remains) return 0;
                size_t to_read = remains > 64 ? 64 : remains;
                if (!fread(buf, to_read, 1, fd)) return -1;
                remains -= to_read;
                // LOG("FdReader::read %d bytes from fd, remains %d", to_read, remains);
                return to_read;
            }
        };


        struct MaskedReader : public FdReader {
            uint32_t mask;

            inline MaskedReader(uint32_t mask, FILE *fd, size_t length) :
                    mask(mask), FdReader(fd, length) {}

            virtual int read() override {
                const int len = FdReader::read();
                if (len != -1) {
                    for (int i = 0; i < len; i += 4) {
                        *reinterpret_cast<uint32_t *>(buf + i) ^= mask;
                    }
                }
                return len;
            }
        };

        struct ZlibReader : public StreamReader {
            z_stream strm;
            StreamReader *pseudo;
            bool ended = false;
            bool flushed = false;

            inline ZlibReader() {
                strm.zalloc = Z_NULL;
                strm.zfree = Z_NULL;
            }

            virtual void init() = 0;

            virtual int process() = 0;

            uint8_t *readAll(StreamReader &in, int &length) {
                pseudo = &in;
                ended = false;
                flushed = false;
                strm.avail_in = 0;
                return StreamReader::readAll(length);
            }

            virtual int read() override {
                if (flushed) return 0;
                LOGV("ZlibReader::read");
                strm.avail_out = sizeof(buf);
                strm.next_out = buf;
                while (strm.avail_out) {
                    LOGV("iterate start avail_in=%d ended=%d", strm.avail_in, ended);
                    if (!strm.avail_in && !ended) { // input buf drain
                        int red = pseudo->read();
                        LOGV("pseudo->read returned %d", red);
                        if (red == -1) {
                            inflateEnd(&strm);
                            return -1;
                        }
                        if (red) {
                            strm.avail_in = red;
                            strm.next_in = pseudo->buf;
                        } else {
                            ended = true;
                        }
                    }
                    int ret = process(); // TODO
                    LOGV("processed, %d bytes remains, %d bytes out ret=%d", strm.avail_in,
                         sizeof(buf) - strm.avail_out, ret);
                    if (ret != Z_OK) {
                        inflateEnd(&strm);
                        return -1;
                    }
                    if (ended && strm.avail_out) {
                        flushed = true;
                        break;
                    }
                }
                // output buf full or eof
                return sizeof(buf) - strm.avail_out;
            }
        };

        struct InflateReader : public ZlibReader {
            void init() override {
                int ret = inflateInit2(&strm, -15);
                if (ret != Z_OK) LOG("inflateInit2 failed %d", ret);
            }

            int process() override {
                if (ended) {
                    strm.avail_in = 4;
                    strm.next_in = (uint8_t *) "\x00\x00\xff\xff";
                }
                return inflate(&strm, Z_NO_FLUSH);
            }
        };

        struct DeflateReader : public ZlibReader {
            void init() override {
                int ret = deflateInit2(&strm, Z_BEST_COMPRESSION, Z_DEFLATED,
                                       -15, Z_BEST_COMPRESSION, Z_DEFAULT_STRATEGY);
                if (ret != Z_OK) LOG("deflateInit2 failed %d", ret);
            }

            int process() override {
                if (ended) LOGV ("flushing deflate stream");
                return deflate(&strm, ended ? Z_SYNC_FLUSH : Z_NO_FLUSH);
            }
        };

        struct BytesReader : public StreamReader {
            const void *bytes;
            size_t len;
            size_t loc;

            inline BytesReader(const void *bytes, size_t len) :
                    bytes(bytes), len(len), loc(0) {}

            int read() override {
                if (loc == len) return 0;
                size_t remains = len - loc;
                size_t red = sizeof(buf);
                if (red > remains) red = remains;
                memcpy(buf, bytes, red);
                loc += red;
                return red;
            }
        };

        struct Utf8Reader : public StreamReader {
            const uint16_t *chars;
            size_t len;
            size_t loc;

            inline Utf8Reader(const uint16_t *chars, size_t len) :
                    chars(chars), len(len), loc(0) {}

            int read() override {
                if (loc == len) return 0;
                int avail = sizeof(buf);
                uint8_t *current = buf;
                while (avail && loc < len) {
                    uint16_t ch = chars[loc];
                    if (ch <= 0x7f) {
                        *current++ = ch;
                        avail--;
                    } else if (ch <= 0x7ff) {
                        if (avail < 2) break;
                        *current++ = 0xc0 | (ch >> 6);
                        *current++ = 0x80 | (ch & 0x3f);
                        avail -= 2;
                    } else {
                        if (avail < 3) break;
                        *current++ = 0xe0 | (ch >> 12);
                        *current++ = 0x80 | ((ch >> 6) & 0x3f);
                        *current++ = 0x80 | (ch & 0x3f);
                        avail -= 3;
                    }
                    loc++;
                }
                // LOG("Utf8Reader::read %d:%d chars %s", loc, len, std::string(reinterpret_cast<char *>(buf), 64 - avail).c_str());
                return sizeof(buf) - avail;
            }
        };

        inline bool write_fully(int fno, const uint8_t *ptr, size_t len) {
#if DEBUG_WS
            char tmp[1024];
            for (int i = 0; i < len && i < 256; i++) {
                sprintf(tmp + (i * 3), "%02x ", ptr[i]);
            }
            LOG("send: fno=%d bytes[%d]={%s}", fno, len, tmp);
#endif

            while (len) {
                int written = write(fno, ptr, len);
                if (written == -1) {
                    LOGV("write failed, %d bytes remain", len);
                    return false;
                }
                ptr += written;
                len -= written;
            }
            return true;
        }

        class WebSocketImpl : public WebSocket {
            void close() {
                disconnect();
                handler->on_close();
            }

        public:
            MessageHandler *handler;
            int fno;
            FILE *fd;
            bool is_server;
            bool use_deflate;
            InflateReader inflateReader;
            DeflateReader deflateReader;


            void disconnect() override {
                LOGV("disconnecting");
                ::shutdown(fno, SHUT_RDWR);
                ::close(fno);
            }

            void send(StreamReader &reader) {
                uint8_t *buf;
                int payloadLen;
                if (use_deflate) {
                    buf = deflateReader.readAll(reader, payloadLen);
                } else {
                    buf = reader.readAll(payloadLen);
                }
                LOGV("will send %d bytes %p", payloadLen, buf);
                if (payloadLen == -1) return close();

                if (*reinterpret_cast<uint16_t *>(buf + payloadLen - 4) == 0
                    && *reinterpret_cast<uint16_t *>(buf + payloadLen - 2) == 0xffff)
                    payloadLen -= 4;

                uint8_t prefix[14];
                size_t prefix_len = 2;

                prefix[0] = OP_TEXT | 0x80;
                if (use_deflate) prefix[0] |= FLAG_RSV1 << 4;

                if (payloadLen > 65535) {
                    prefix[1] = 127;
                    *reinterpret_cast<uint32_t *>(prefix + 2) = 0;
                    prefix[6] = payloadLen >> 24;
                    prefix[7] = payloadLen >> 16;
                    prefix[8] = payloadLen >> 8;
                    prefix[9] = payloadLen;
                    prefix_len += 8;
                } else if (payloadLen > 125) {
                    prefix[1] = 126;
                    prefix[2] = payloadLen >> 8;
                    prefix[3] = payloadLen;
                    prefix_len += 2;
                } else {
                    prefix[1] = payloadLen;
                }

                if (!is_server) { // masked
                    prefix[1] |= 0x80;
                    *reinterpret_cast<uint32_t *>(prefix + prefix_len) = 0;
                    prefix_len += 4;
                }
                int succ = write_fully(fno, prefix, prefix_len)
                           && write_fully(fno, buf, payloadLen);
                delete[] buf;
                if (!succ) close();
            }

            virtual void send(const char *chars, size_t len) override {
                BytesReader br(chars, len);
                send(br);
            }

            virtual void send(const uint16_t *chars, size_t len) override {
                Utf8Reader ur(chars, len);
                LOGV("send(Utf8Reader(%d))", len);
                send(ur);
            }

            void init_deflate() {
                use_deflate = false;
                inflateReader.init();
                deflateReader.init();
            }

            bool read_message() {
                union {
                    uint8_t bytes[2];
                    struct {
                        uint8_t flag_opcode;
                        uint8_t mask_payload_len;
                    };
                } head;

                READV(head.bytes);

                LOGV("on read chunk head %x %x", head.flag_opcode, head.mask_payload_len);
                if (!(head.flag_opcode >> 7)) { // abort
                    return false;
                }
                bool masked = head.mask_payload_len >> 7;

                if (masked != is_server) {
                    LOG("wrong chunk mask flag, stopping...");
                    return false;
                }

                const uint8_t flags = head.flag_opcode >> 4, opcode = head.flag_opcode & 0xf;
                if (opcode == 8) return false;

                size_t payloadLen = head.mask_payload_len & 0x7f;
                bool deflated = (flags & FLAG_RSV1) != 0;
                use_deflate = use_deflate || deflated;

                if (payloadLen == 126) { // payload len is 2 bytes
                    uint8_t len[2];
                    READV(len);
                    payloadLen = (len[0] << 8) | len[1];
                } else if (payloadLen == 127) {
                    uint8_t len[8];
                    READV(len);
                    payloadLen = (len[4] << 24) | (len[5] << 16) | (len[6] << 8) | len[7];
                }
                LOGV("flags=%x opcode=%x len=%d deflated=%d", flags, opcode, payloadLen, deflated);

                uint8_t *payload;
                int red;

                if (masked && deflated) {
                    uint32_t mask;
                    READ(mask);
                    MaskedReader mr(mask, fd, payloadLen);
                    LOGV("inflateReader.readAll(MaskedReader(%d))", payloadLen);
                    payload = inflateReader.readAll(mr, red);
                } else if (masked) {
                    uint32_t mask;
                    READ(mask);
                    payload = MaskedReader(mask, fd, payloadLen).readAll(red);
                } else if (deflated) {
                    FdReader fr(fd, payloadLen);
                    payload = inflateReader.readAll(fr, red);
                } else {
                    payload = FdReader(fd, payloadLen).readAll(red);
                }
                if (red == -1) return false;
                handler->on_message(opcode, payload, red);
                delete[] payload;
                return true;
            }
        };

        static void write_resp(int fno, int status, std::string msg) {
            char buf[1024];
            int len = sprintf(
                    buf, "HTTP/1.1 %d TODO\r\n"
                            "Connection: close\r\n"
                            "Content-Length: %d\r\n\r\n%.*s",
                    status, msg.size(), msg.size(), msg.c_str());
            write_fully(fno, (uint8_t *) buf, len);
        }

        class WebSocketRequestImpl : public WebSocketRequest {
            int fno;
            FILE *fd;
            Headers &headers;
            WebSocketImpl &ws;
            bool rejected = false;
        public:

            inline WebSocketRequestImpl(
                    int fno, FILE *fd, std::string url, Headers &headers,
                    WebSocketImpl &ws)
                    : fno(fno), fd(fd), headers(headers), ws(ws) {
                WebSocketRequest::url = url;
            }

            virtual void accept(WebSocket::MessageHandler *handler) override {
                std::string to_digest = headers.sec_websocket_key + unique_key;
                char sha1_b64[28];
                sha1(to_digest.c_str(), to_digest.size(), sha1_b64);
                char buf[256];
                int written = sprintf(
                        buf, "HTTP/1.1 101 Switch Protocol\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: %.28s\r\n"
                                "Sec-Websocket-Extensions: permessage-deflate; client_max_window_bits=15\r\n\r\n",
                        sha1_b64);
                LOGV("write accept: len=%d %s", written, buf);
                if (!write_fully(fno, (uint8_t *) buf, written)) return;
                ws.fd = fd;
                ws.fno = fno;
                ws.is_server = true;
                ws.init_deflate();
                ws.handler = handler;
                handler->on_connect(&ws);
            }

            virtual void reject(int status, std::string msg) override {
                write_resp(fno, status, msg);
                rejected = true;
            }

            inline bool test(void(callback)(WebSocketRequest &)) {
                callback(*this);
                return !rejected;
            }
        };

        inline void on_bad_request(int fno) {
            write_resp(fno, 400, std::string());
        }

        static void _on_accept(conn_s *conn) {
            int fno = conn->fno;
            FILE *fd = fdopen(fno, "r");
            char _url[36];

            // 读取 URL
            int fields = fscanf(fd, "GET /%36s HTTP/1.%*d\r\n", _url);
            if (fields != 1) return on_bad_request(fno);
            std::string url(_url);
            LOGV("url=%s", url.c_str());

            // read headers
            Headers headers;
            for (;;) {
                char buf[512];
                if (!fgets(buf, sizeof(buf), fd)) {
                    fclose(fd);
                    return;
                }
                LOGV("on header line %s", buf);

                if (buf[0] == '\r') break;
                char lower[512];
                uint32_t len = 0;
                for (;;) {
                    char p = buf[len];
                    if (!p || p == '\r') {
                        break;
                    }
                    if (p >= 'A' && p <= 'Z') p |= 0x20;
                    lower[len] = p;
                    len++;
                }

                std::string line(lower, len);
                int pos = line.find(": ");
                if (pos == std::string::npos) continue;
                std::string name = line.substr(0, pos);
                if (name == "connection") {
                    headers.connection_upgrade = line.substr(pos + 2) == "upgrade";
                } else if (name == "upgrade") {
                    headers.upgrade_websocket = line.substr(pos + 2) == "websocket";
                    if (!headers.upgrade_websocket) return on_bad_request(fno);
                } else if (name == "sec-websocket-key") {
                    headers.sec_websocket_key = std::string(buf + pos + 2, len - pos - 2);
                }
            }
            if (!headers.connection_upgrade || !headers.upgrade_websocket) {
                std::tuple<int, std::string> resp = conn->request_handle(url);
                return write_resp(fno, std::get<0>(resp), std::get<1>(resp));
            }

            WebSocketImpl ws;
            if (!WebSocketRequestImpl(conn->fno, fd, url, headers, ws).test(conn->callback)) return;
            LOGV("begin read");
            while (ws.read_message());
            LOGV("read_message loop stopped");
            ws.handler->on_close();
            close(fno);
        }

        void *on_accept(void *ptr) {
            thread_setup();
            conn_s *conn = static_cast<conn_s *>(ptr);
            _on_accept(conn);
            delete conn;

            thread_pulldown();
            pthread_exit(nullptr);
        }

        struct startup_data {
            uint16_t port;

        };


        static uint16_t port;

        std::tuple<int, std::string> (*request_handle)(std::string url);

        void (*callback)(WebSocketRequest &);


        void *on_start(void *) {
            thread_setup();
            thread_init();

            int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            int on = 1; // 设置 SO_REUSEADDR 以解决程序 crash 后的端口占用问题
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
            struct sockaddr_in address;
            address.sin_family = AF_INET;
//            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_addr.s_addr = htonl(INADDR_ANY);
            address.sin_port = htons(port);
            if (-1 == bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address))
                || -1 == ::listen(fd, 10)) {
                LOG("failed creating websocket server on port %d", port);

                thread_pulldown();
                pthread_exit(nullptr);
            };
            conn_s default_conn = {0, request_handle, callback};
            for (;;) {
                socklen_t len = sizeof(address);
                int s = accept(fd, reinterpret_cast<sockaddr *>(&address), &len);
                if (s == -1) {
                    LOG("on socket error");

                    thread_pulldown();
                    pthread_exit(nullptr);
                }
                int on = 1; // 设置 TCP_NODELAY
                setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
                // 创建子线程并进行 socket 对话
                conn_s *conn = new conn_s(default_conn);
                conn->fno = s;

                pthread_t thread;
                pthread_create(&thread, NULL, on_accept, conn);
            }
        }

        void listen(uint16_t port,
                    std::tuple<int, std::string> (request_handle)(std::string url),
                    void(callback)(WebSocketRequest &)) {
            websocket::port = port;
            websocket::request_handle = request_handle;
            websocket::callback = callback;

            pthread_t thread;
            pthread_create(&thread, NULL, on_start, nullptr);
        }
    }
}