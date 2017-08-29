#ifndef _UDP_RELAY_H_
#define _UDP_RELAY_H_

class UDPRelay: public ISockNotify
{
public:
    UDPRelay(Config * config, DNSResolve * dns_resolver, bool is_local);
    bool Init();
    ~UDPRelay();
    virtual void HandleEvent(SOCKET s, int event) override;
    bool AddToLoop(EventLoop * event_loop);
private:
    bool is_local_;
    Config* config_;
    bool is_closed_;
    string listen_addr_;
    int listen_port_;
    string remote_addr_;
    int remote_port_;
    EventLoop* event_loop_;
    DNSResolve* dns_resolver_;
    SOCKET server_socket_;
    set<SOCKET> sockets_;
    map<string, string> dns_cache_;
    map<string, SOCKET> key_sockets_;
    map<SOCKET, sockaddr_in> socket_to_addr_;
    string select_server_;
    int    select_port_;

    void SelectAServer();
    void HandleServer();
    void HandleClient(SOCKET s);
    string GetClientKey(sockaddr_in dest_addr, int server_af);
};

#endif