#ifndef _LOG_HPP_
#define _LOG_HPP_
#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <time.h>

#ifdef WIN32
#pragma warning(disable:4996)
#endif

#define LOGI *(Log::GetInstance())<<white<<Log::FormatTime()<<" [info] "
#define LOGW *(Log::GetInstance())<<yellow<<Log::FormatTime()<<" [warning] "
#define LOGE *(Log::GetInstance())<<red<<Log::FormatTime()<<" [error] "


inline std::ostream& blue(std::ostream &s)
{
#ifdef WIN32
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hStdout, FOREGROUND_BLUE
                            | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
#endif
    return s;
}

inline std::ostream& red(std::ostream &s)
{
#ifdef WIN32
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hStdout,
                            FOREGROUND_RED | FOREGROUND_INTENSITY);
#endif
    return s;
}

inline std::ostream& green(std::ostream &s)
{
#ifdef WIN32
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hStdout,
                            FOREGROUND_GREEN | FOREGROUND_INTENSITY);
#endif
    return s;
}

inline std::ostream& yellow(std::ostream &s)
{
#ifdef WIN32
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hStdout,
                            FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);
#endif
    return s;
}

inline std::ostream& white(std::ostream &s)
{
#ifdef WIN32
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hStdout,
                            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#endif
    return s;
}

class Log
{
public:
    Log()
    {
    }
    ~Log()
    {
        if(m_fs.is_open())
            m_fs.close();
    }
    void SetLogFile(std::string filename)
    {
        m_fs.open(filename, std::ios::app | std::ios::out);
        std::streambuf* fileBuf = m_fs.rdbuf();
        std::cout.rdbuf(fileBuf);
    }
    template <typename T> Log& operator<<(const T& value)
    {
        std::cout << value;
        return (*this);
    }
    static std::string FormatTime()
    {
        time_t t;
        struct tm *tm = NULL;

        time(&t);
        tm = localtime(&t);
        char buf[100];
        sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
        return std::string(buf);
    }
    static Log* GetInstance()
    {
        if (instance == NULL)
        {
            return new Log();
        }
        return instance;
    }
    void Destory()
    {
        if(instance)
            delete instance;
    }
private:
    std::ofstream m_fs;
    static Log* instance;
};

#ifdef WIN32
#pragma warning(default:4996)
#endif

#endif