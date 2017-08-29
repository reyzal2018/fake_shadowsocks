#ifndef _CONFIG_H_
#define _CONFIG_H_

class Config
{
    typedef map<string, string> ConfigMap;
public:
    Config(int argc, char * argv[]);
    string GetStr(string key, string val = "");
    int GetInt(string key, int val = 0);
    void SetStr(string key, string val);
    void SetInt(string key, int val);
private:
    ConfigMap config_;
};

#endif