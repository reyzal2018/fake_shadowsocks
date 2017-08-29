#ifndef _TCP_RELAY_H_
#define _TCP_RELAY_H_

class BadSocksHeader : exception {

};

class NoAcceptableMethods : exception {

};


//tcp protocol socket
class TCPRelay : public ISockNotify {
public:
    bool Init();
    TCPRelay(Config * config, DNSResolve * dns_resolve, bool is_local);
    ~TCPRelay() {};
    bool AddToLoop(EventLoop* event_loop);
    void AddHandler(SOCKET s, ISockNotify* handler) ;
    void RemoveHandler(SOCKET s) ;
    virtual void HandleEvent(SOCKET s, int event) override;
    void Close();
private:
    bool is_local_;
    Config* config_;
    bool is_closed_;
    EventLoop* event_loop_;
    DNSResolve* dns_resolver_;
    int listen_port_;
    SOCKET server_socket_;
    map<SOCKET, ISockNotify*> socket_handler_;
};

class TCPRelayHandler : public IDNSNotify, ISockNotify {
public:
    TCPRelayHandler(
        TCPRelay* server,
        EventLoop* event_loop,
        DNSResolve* dns_resolver,
        SOCKET local_socket,
        Config* config,
        bool is_local);
    virtual void HandleEvent(SOCKET s, int event) override;

    virtual void DNSResolved(string hostname, string ip, string err) override;

    bool IsDestroyed();

private:
	int recv_data_size;
	int send_data_size;
	~TCPRelayHandler() ;
    TCPRelay* server_;
    EventLoop* event_loop_;
    DNSResolve* dns_resolver_;
    SOCKET local_socket_;
    SOCKET remote_socket_;
    Config* config_;
    bool is_local_;
    int stage_;

	string		local_address_;
	uint16_t	local_port_;

	string		remote_address_;
	uint16_t	remote_port_;

	vector<char> data_write_to_local_;
    vector<char> data_write_to_remote_;
    int upstream_status_;
    int downstream_status_;

    void SelectAServer();

    void UpdateStream(int stream, int status);

    bool WriteToSock(vector<char>& data, SOCKET s);

    void HandleStageConnecting(vector<char>& data);

    void HandleStageAddr(vector<char>& data);

    SOCKET CreateRemoteSocket(string ip, int port);

    void HandleStageStream(vector<char>& data);
    void CheckAuthMethod(vector<char>& data);
    void HandleStageInit(vector<char>& data);
    void OnLocalRead();
    void OnRemoteRead();

    void OnLocalWrite();
    void OnRemoteWrite();

    void OnLocalError();
    void OnRemoteError();

    void Destroy();
};

#endif
