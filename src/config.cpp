#include "common.h"
#include "config.h"

string Config::GetStr(string key, string val)
{
    if (config_.count(key) == 0)
        return val;
    return config_[key];
}

int Config::GetInt(string key, int val)
{
    if (config_.count(key) == 0)
        return val;
    return atoi(config_[key].c_str());
}

void Config::SetStr(string key, string val)
{
    config_[key] = val;
}

void Config::SetInt(string key, int val)
{
    stringstream ss;
    ss << val;
    config_[key] = ss.str();
}

Config::Config(int argc, char *argv[])
{
    int opt;
    static struct option long_options[] =
    {
        { "server-port", required_argument,    0, 1 },
        { "local-port", required_argument,    0, 1 },
        { "server-address", required_argument,    0, 1 },
        { "local-address", required_argument,    0, 1 },
        { "server", no_argument,    0, 1 },
        { "client", no_argument,    0, 1 },
        { NULL, 0, 0, 0 }
    };
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "p:l:s:b:", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
        case 'p':
            this->SetStr("server_port", optarg);
            break;
        case 'l':
            this->SetStr("local_port", optarg);
            break;
        case 's':
            this->SetStr("server_address", optarg);
            break;
        case 'b':
            this->SetStr("local_address", optarg);
            break;
        case 1:
            if (strcmp(long_options[option_index].name, "server-port") == 0)
            {
                this->SetStr("server_port", optarg);
            }
            else if (strcmp(long_options[option_index].name, "local-port") == 0)
            {
                this->SetStr("local_port", optarg);
            }
            else if (strcmp(long_options[option_index].name, "server-address") == 0)
            {
                this->SetStr("server_address", optarg);
            }
            else if (strcmp(long_options[option_index].name, "local-address") == 0)
            {
                this->SetStr("local_address", optarg);
            }
            else if (strcmp(long_options[option_index].name, "server") == 0)
            {
                this->SetInt("is_local", 0);
            }
            else if (strcmp(long_options[option_index].name, "client") == 0)
            {
                this->SetInt("is_local", 1);
            }
            break;
        default:
            LOGW << "unknown option <" << (char)opt << ">";
        }
    }
}
