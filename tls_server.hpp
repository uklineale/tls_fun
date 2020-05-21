#include <string.h>

class SslObject {
    public:
        std::string host;
        unsigned short int port;

        std::string get_host() {
            return host;
        }

        unsigned short int get_port() {
            return port;
        }

}

class SslServer : public SslObject {
    

}

class SslClient : public SslObject {
    
}