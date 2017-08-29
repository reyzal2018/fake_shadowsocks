#include "common.h"

Log* Log::instance = NULL;

int main(int argc, char *argv[])
{
#ifdef _WIN32
    int err = 0;
    WSADATA wsaData;
    if (0 != (err = WSAStartup(MAKEWORD(2, 2), &wsaData)))
    {
        WSASetLastError(err);
        return 1;
    }
#endif
    //server --server -p 8881 -s 0.0.0.0
    //		   --server --server-port 8881 --server-address 0.0.0.0
    //client --client -p 8881 -l 1081 -s 127.0.0.1 -b 127.0.0.1
    //		   --client --server-port 8881 --server-address 127.0.0.1 --local-port 1081 --local-address 127.0.0.1
    //parse command line
    Config* config = new Config(argc, argv);
    bool is_local = config->GetInt("is_local") == 1;

    list<string> dns_servers;
    dns_servers.push_back("114.114.114.114");
    DNSResolve* dns_resolver = NULL;

    EventLoop* event_loop = NULL;
    TCPRelay* tcp_server = NULL;
    UDPRelay* udp_server = NULL;
    try
    {
        event_loop = new EventLoop();
        dns_resolver = new DNSResolve(dns_servers);
        tcp_server = new TCPRelay(config, dns_resolver, is_local);
        udp_server = new UDPRelay(config, dns_resolver, is_local);
        dns_resolver->AddToLoop(event_loop);
        if (tcp_server->Init() && udp_server->Init())
        {
            if (is_local)
                LOGI << "listen " << config->GetStr("local_address") << ":" << config->GetStr("local_port") <<
                     " forward to " << config->GetStr("server_address") << ":" << config->GetStr("server_port") << "\n";
            else
                LOGI << "listen " << config->GetStr("server_address") << ":" << config->GetStr("server_port") << "\n";
            tcp_server->AddToLoop(event_loop);
            udp_server->AddToLoop(event_loop);
            event_loop->Run();
        }
        LOGE << "error occurred, exit...\n";
    }
    catch (const std::exception&)
    {
        LOGE << "exception occurred, exit...\n";
    }
    if (tcp_server)
    {
        tcp_server->Close();
        delete tcp_server;
        tcp_server = NULL;
    }
    if (udp_server)
    {
        delete udp_server;
        udp_server = NULL;
    }
    if (dns_resolver)
    {
        dns_resolver->Close();
        delete dns_resolver;
        dns_resolver = NULL;
    }
    if (event_loop)
    {
        delete event_loop;
        event_loop = NULL;
    }
    return 0;
}
