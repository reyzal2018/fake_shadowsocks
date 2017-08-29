#ifndef _DNS_RESOLVE_H_
#define _DNS_RESOLVE_H_


//dns resolve£¬get host from dns server
class DNSResolve : public ISockNotify
{
    enum DNS_TYPE
    {
        kDnsTypeA = 0x0001, //1 a host address
        kDnsTypeAAAA = 28 //28 a host address
    };
    enum HOSTSTATUS
    {
        kHostStatusFirst,//first resolve
        kHostStatusSecond,//second resolve
    };
    struct DNSHeader
    {
        uint16_t trans_id;
        uint16_t flags;
        uint16_t question_count;
        uint16_t answer_count;
        uint16_t authority_count;
        uint16_t additional_count;
    };
    const unsigned short kMaxDownmainNameLen = 255;
    const unsigned short kDnsPort = 53;
    const unsigned short kDnsTypeSize = 2;
    const unsigned short kDnsClassSzie = 2;
    const unsigned short kDnsTtlSize = 4;
    const unsigned short kDnsDatalenSize = 2;
    const unsigned short kDnsTypeCname = 0x0005; //5 the canonical name for an alias
public:
    DNSResolve(list<string>& listServer);
    ~DNSResolve();

    int AddToLoop(EventLoop* event_loop);

    void RemoveCallback(IDNSNotify * callback);

    virtual void HandleEvent(SOCKET s, int event) override;

    void Close();

    void Resolve(const string & hostname, IDNSNotify * pNotify);

private:
    bool is_local_;
    Config* config_;
    bool is_closed_;
    EventLoop* event_loop_;
    int listen_port_;
    SOCKET dns_socket_;
    time_t last_time_;
    map<string, string> hosts_;//hosts file rules
    map<IDNSNotify*, string> cb_to_hostname_;//callback to hostname
    multimap<string, IDNSNotify*> hostname_to_cb_;//hostname to callback
    LRUCache<string, string> dns_cache_;
    list<sockaddr_in> servers_;//4 bytes dns server list(ipv4)
    map<string, int> hostname_status_;//current hostname resolve status
    char* dns_packet_;

    void ParseHosts();

    bool EncodeDotStr(const char * dot_str, char * encoded_str, size_t encoded_str_size);

    bool DecodeDotStr(char * encoded_str, uint16_t * encoded_str_len, char * dot_str, uint16_t dot_str_size, char * packet_start_pos = NULL);

    bool ParseResponse(char * recv_data, string & hostname, vector<string>& ip_result, vector<string>& cname_result);

    int HandleData(char * recv_data);

    void CallCallback(string hostname, string ip);

    void SendRequest(const string & hostname, DNS_TYPE type);

};

#endif