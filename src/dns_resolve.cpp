#include "common.h"
#include "dns_resolve.h"
#include <fstream>

#define kDnsPacketMaxSize (sizeof(DNSHeader) + kMaxDownmainNameLen + kDnsTypeSize + kDnsClassSzie)
const int kCacheSweepInterval = 30;

DNSResolve::DNSResolve(list<string>& servers): dns_cache_(300)
{
    dns_packet_ = new char[kDnsPacketMaxSize];
    this->event_loop_ = NULL;
    dns_socket_ = INVALID_SOCKET;
    for (auto& server : servers)
    {
        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(kDnsPort);
        inet_pton(AF_INET, server.c_str(), &server_addr.sin_addr);
        servers_.push_back(server_addr);
    }
    last_time_ = time(NULL);
    is_closed_ = false;
    ParseHosts();
}

DNSResolve::~DNSResolve()
{
    delete dns_packet_;
}

void DNSResolve::ParseHosts()
{
    char host_path[260];
#ifdef _WIN32
    GetWindowsDirectoryA(host_path, 260);
    strcat(host_path, "\\system32\\drivers\\etc\\hosts");
#else
    strcpy(host_path, "/etc/hosts");
#endif
    ifstream fhost(host_path);
    char line[400];
    while (fhost.getline(line, 400))
    {
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;
        string hostname, ip;
        while (*p != ' ' && *p != '\t' && *p != '\0')
        {
            ip.push_back(*p++);
        }
        if (*p == '\0') continue;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') continue;
        while (*p != ' ' && *p != '\t' && *p != '\0')
        {
            hostname.push_back(*p++);
        }
        hosts_[hostname] = ip;
    }
    fhost.close();
}

int DNSResolve::AddToLoop(EventLoop * event_loop)
{
    if (event_loop_)
    {
        LOGE << "already add to loop\n";
        return -1;
    }
    if (is_closed_)
    {
        LOGE << "already closed\n";
        return -1;
    }
    dns_socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SetNoBlocking(dns_socket_);
    event_loop_ = event_loop;
    event_loop_->Add(dns_socket_, kPollIn, this);
    return 0;
}

bool DNSResolve::EncodeDotStr(const char* dot_str, char *encoded_str, size_t encoded_str_size)
{
    size_t dot_str_len = strlen(dot_str);

    if (dot_str == NULL || encoded_str == NULL || encoded_str_size < dot_str_len + 2)
    {
        return false;
    }

    char *dot_str_copy = new char[dot_str_len + 1];
    strcpy(dot_str_copy, dot_str);

    char *label = strtok(dot_str_copy, ".");
    size_t label_len = 0;
    size_t encoded_str_len = 0;
    while (label != NULL)
    {
        if ((label_len = strlen(label)) != 0)
        {
            sprintf(encoded_str + encoded_str_len, "%c%s", (int)label_len, label);
            encoded_str_len += (label_len + 1);
        }
        label = strtok(NULL, ".");
    }
    delete dot_str_copy;
    return true;
}

bool DNSResolve::DecodeDotStr(
    char *encoded_str,
    uint16_t *encoded_str_len,
    char *dot_str,
    uint16_t dot_str_size,
    char *packet_start_pos)
{
    if (encoded_str == NULL || encoded_str_len == NULL || dot_str == NULL)
    {
        return false;
    }

    char *decode_pos = encoded_str;
    uint16_t plain_str_len = 0;
    uint8_t label_data_len = 0;
    *encoded_str_len = 0;

    while ((label_data_len = *decode_pos) != 0x00)
    {
        if ((label_data_len & 0xc0) == 0)   //normal mode£¬LabelDataLen + Label
        {
            if (plain_str_len + label_data_len + 1 > dot_str_size)
            {
                return false;
            }
            memcpy(dot_str + plain_str_len, decode_pos + 1, label_data_len);
            memcpy(dot_str + plain_str_len + label_data_len, ".", 1);
            decode_pos += (label_data_len + 1);
            plain_str_len += (label_data_len + 1);
            *encoded_str_len += (label_data_len + 1);
        }
        else
        {
            //compression scheme£¬11000000 00000000£¬
            //first two bits are ones£¬next is OFFSET field
            if (packet_start_pos == NULL)
            {
                return false;
            }
            uint16_t jump_pos = ntohs(*(uint16_t*)(decode_pos)) & 0x3fff;
            uint16_t encode_str_len = 0;
            if (!DecodeDotStr(packet_start_pos + jump_pos, &encode_str_len,
                              dot_str + plain_str_len, dot_str_size - plain_str_len,
                              packet_start_pos))
            {
                return false;
            }
            else
            {
                *encoded_str_len += 2;
                return true;
            }
        }
    }

    dot_str[plain_str_len - 1] = '\0';
    *encoded_str_len += 1;

    return true;
}


bool DNSResolve::ParseResponse(
    char* recv_data,
    string& hostname,
    vector<string>& ip_result,
    vector<string>& cname_result)
{
    char dot_name[128] = { '\0' };
    uint16_t encoded_name_len = 0;

    DNSHeader *dns_header = (DNSHeader*)recv_data;
    uint16_t question_count = 0;
    uint16_t answer_count = 0;

    if ((ntohs(dns_header->flags) & 0xfb7f) == 0x8100 //RFC1035 4.1.1(Header section format)
            && (question_count = ntohs(dns_header->question_count)) >= 0
            && (answer_count = ntohs(dns_header->answer_count)) > 0)
    {
        char *dns_data = recv_data + sizeof(DNSHeader);

        //resolve Question fields
        for (int question_index = 0; question_index != question_count; ++question_index)
        {
            if (!DecodeDotStr(dns_data, &encoded_name_len, dot_name, sizeof(dot_name)))
            {
                return false;
            }
            if (hostname.empty() && strlen(dot_name) > 0)
            {
                hostname = dot_name;
            }
            dns_data += (encoded_name_len + kDnsTypeSize + kDnsClassSzie);
        }

        //resolve Answer fields
        for (int answer_index = 0; answer_index != answer_count; ++answer_index)
        {
            if (!DecodeDotStr(dns_data, &encoded_name_len, dot_name, sizeof(dot_name), recv_data))
            {
                return false;
            }
            dns_data += encoded_name_len;

            uint16_t answer_type = ntohs(*(uint16_t*)(dns_data));
            uint16_t answer_class = ntohs(*(uint16_t*)(dns_data + kDnsTypeSize));
            uint32_t answer_ttl = ntohl(*(uint32_t*)(dns_data + kDnsTypeSize + kDnsClassSzie));
            uint16_t answer_data_len = ntohs(*(uint16_t*)(dns_data + kDnsTypeSize + kDnsClassSzie + kDnsTtlSize));
            dns_data += (kDnsTypeSize + kDnsClassSzie + kDnsTtlSize + kDnsDatalenSize);

            if (answer_type == kDnsTypeA)
            {
                in_addr addr;
                addr.s_addr = *(u_long*)dns_data;
                char ip_str[16];
                inet_ntop(AF_INET, &addr, ip_str, 16);
                ip_result.push_back(ip_str);
            }
            else if (answer_type == kDnsTypeCname)
            {
                if (!DecodeDotStr(dns_data, &encoded_name_len, dot_name, sizeof(dot_name), recv_data))
                {
                    return false;
                }
                cname_result.push_back(dot_name);
            }
            dns_data += (answer_data_len);
        }
    }
    return true;
}

int DNSResolve::HandleData(char* recv_data)
{
    vector<string> ip_result;
    vector<string> cname_result;
    string hostname;
    if (!ParseResponse(recv_data, hostname, ip_result, cname_result))
    {
        return -1;
    }
    string ip = "";
    if (ip_result.size() > 0)
    {
        ip = ip_result[0];
    }
    if (!ip.empty())
    {
        dns_cache_[hostname] = ip;
        CallCallback(hostname, ip);
    }
    else
    {
        if (hostname_status_.count(hostname) > 0 &&
                hostname_status_[hostname] == kHostStatusFirst)
        {
            //send again
            hostname_status_[hostname] = kHostStatusSecond;
            SendRequest(hostname, kDnsTypeAAAA);
        }
        else
        {
            CallCallback(hostname, "");
        }
    }
    return 0;
}

void DNSResolve::RemoveCallback(IDNSNotify* callback)
{
    if (cb_to_hostname_.count(callback) == 0)
    {
        return;
    }
    string hostname = cb_to_hostname_[callback];

    auto range_callbacks = hostname_to_cb_.equal_range(hostname);
    while (range_callbacks.first != range_callbacks.second)
    {
        if (range_callbacks.first->second == callback)
        {
            hostname_to_cb_.erase(range_callbacks.first);
        }
        ++range_callbacks.first;
    }
    if (hostname_to_cb_.count(hostname) == 0)
    {
        hostname_status_.erase(hostname);
    }
    cb_to_hostname_.erase(callback);
}

void DNSResolve::CallCallback(string hostname, string ip)
{
    auto cb_range = hostname_to_cb_.equal_range(hostname);
    if (cb_range.first == cb_range.second)
        return;
    while (cb_range.first != cb_range.second)
    {
        if (cb_to_hostname_.count(cb_range.first->second) > 0)
        {
            cb_to_hostname_.erase(cb_range.first->second);
        }
        cb_range.first->second->DNSResolved(hostname, ip, "");
        ++cb_range.first;
    }
    hostname_to_cb_.erase(hostname);
    hostname_status_.erase(hostname);
}

void DNSResolve::SendRequest(const string& hostname, DNS_TYPE type)
{
    char *write_dns_packet_ptr = dns_packet_;
    memset(write_dns_packet_ptr, 0, kDnsPacketMaxSize);

    //fill dns request header
    DNSHeader *dns_header = (DNSHeader*)write_dns_packet_ptr;
    dns_header->trans_id = 0;
    dns_header->flags = htons(0x0100);
    dns_header->question_count = htons(0x0001);
    dns_header->answer_count = 0x0000;
    dns_header->authority_count = 0x0000;
    dns_header->additional_count = 0x0000;

    //set dns request packet
    uint16_t qtype = htons(0x0001);
    uint16_t qclass = htons(0x0001);
    size_t domain_name_len = hostname.length();
    char *encode_domain_name = new char[domain_name_len + 2];
    if (encode_domain_name == NULL)
    {
        LOGE << "malloc failed\n";
        return;
    }
    if (!EncodeDotStr(hostname.c_str(), encode_domain_name, domain_name_len + 2))
    {
        LOGE << "EncodeDotStr Failed\n";
        delete encode_domain_name;
        return;
    }

    //fill dns request packet
    size_t encode_domain_name_len = strlen(encode_domain_name) + 1;
    memcpy(write_dns_packet_ptr += sizeof(DNSHeader), encode_domain_name, encode_domain_name_len);
    memcpy(write_dns_packet_ptr += encode_domain_name_len, (char*)(&qtype), kDnsTypeSize);
    memcpy(write_dns_packet_ptr += kDnsTypeSize, (char*)(&qclass), kDnsClassSzie);
    delete encode_domain_name;

    size_t dns_packet_size = sizeof(DNSHeader) + encode_domain_name_len + kDnsTypeSize + kDnsClassSzie;
    for (auto& dns_server_addr : servers_)
    {
        BufferSendTo(dns_socket_, dns_packet_, dns_packet_size, (sockaddr*)&dns_server_addr, sizeof(dns_server_addr));
    }
}

void DNSResolve::HandleEvent(SOCKET s, int event)
{
    if (s != dns_socket_)
    {
        LOGE << "handle event from a error socket\n";
        return;
    }
    if (event & kPollErr)
    {
        //socket error,create new
        LOGI << "dns socket error";
        event_loop_->Remove(dns_socket_);
        dns_socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        SetNoBlocking(dns_socket_);
        event_loop_->Add(dns_socket_, kPollIn, this);
    }
    else
    {
        char recv_data[1024];
        sockaddr_in addr;
        int addr_len = sizeof(sockaddr_in);
        BufferRecvFrom(s, recv_data, 1024, (sockaddr*)&addr, &addr_len);
        //check packet is from our dns server
        bool find = false;
        for (auto& dns_server_addr : servers_)
        {
            if (addr.sin_addr.s_addr ==
                    dns_server_addr.sin_addr.s_addr)
            {
                find = true;
                break;
            }
        }
        if (!find)
        {
            LOGW << "received a packet other than our dns\n";
            return;
        }
        if (0 != HandleData(recv_data))
        {
            LOGW << "resolve dns failed\n";
        }
    }
    time_t now = time(NULL);
    if (now - this->last_time_ >= kCacheSweepInterval)
    {
        dns_cache_.Sweep();
        this->last_time_ = now;
    }
}

void DNSResolve::Close()
{
    LOGI << "DNSResolve close\n";
    is_closed_ = true;
    if (event_loop_)
    {
        event_loop_->Remove(dns_socket_);
    }
    CloseSocket(dns_socket_);
}

void DNSResolve::Resolve(const string& hostname, IDNSNotify* callback)
{
    if (hostname.empty())
    {
        callback->DNSResolved(hostname, hostname, "hostname is empty!");
    }
    else if (IsIp(hostname.c_str()))
    {
        callback->DNSResolved(hostname, hostname, "");
    }
    else if (dns_cache_.Count(hostname) > 0)
    {
        LOGI << "hit cached\n";
        callback->DNSResolved(hostname, dns_cache_[hostname], "");
    }
    else if (hosts_.count(hostname) > 0)
    {
        LOGI << "hit hosts\n";
        callback->DNSResolved(hostname, hosts_[hostname], "");
    }
    else
    {
        if (hostname_to_cb_.find(hostname) != hostname_to_cb_.end())
        {
            hostname_to_cb_.insert(make_pair(hostname, callback));
            assert(cb_to_hostname_.count(callback) == 0);
            cb_to_hostname_[callback] = hostname;
            SendRequest(hostname, kDnsTypeA);
        }
        else
        {
            hostname_status_[hostname] = kHostStatusFirst;
            hostname_to_cb_.insert(make_pair(hostname, callback));
            assert(cb_to_hostname_.count(callback) == 0);
            cb_to_hostname_[callback] = hostname;
            SendRequest(hostname, kDnsTypeA);
        }
    }
}

