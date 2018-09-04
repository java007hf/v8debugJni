//
// Created by LI ZHENG on 2018/4/2.
//

#ifndef V8_INSPECT_WEBSOCKET_H
#define V8_INSPECT_WEBSOCKET_H

#include <tuple>
#include <string>

namespace tt {
    using HttpResponse = std::tuple<int, std::string>;
    namespace websocket {
        const int OP_TEXT = 1, OP_BINARY = 2;

        class WebSocket {
        public:
            class MessageHandler {
            public:
                virtual void on_connect(WebSocket *) = 0;

                virtual void on_message(int op, const uint8_t *, size_t) = 0;

                virtual void on_close() = 0;
            };

            virtual void send(const char *, size_t) = 0;

            virtual void send(const uint16_t *, size_t) = 0;

            virtual void disconnect() = 0;
        };

        class WebSocketRequest {
        public:
            std::string url;

            virtual void accept(WebSocket::MessageHandler *) = 0;

            virtual void reject(int status, std::string msg) = 0;

        };

        void listen(uint16_t port, HttpResponse (request_handle)(std::string url),
                    void(callback)(WebSocketRequest &));
    }
};

#endif //V8_INSPECT_WEBSOCKET_H
