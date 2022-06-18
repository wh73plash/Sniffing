#ifndef tracemanager_h
#define tracemanager_h

#include <iostream>
#include <cstdio>
#include <vector>
#include <string>
#include <ctime>
#include <iomanip>
#include <chrono>
#include <sstream>

using namespace std;

static std::string path = "/Users/jeinkim/Desktop/ACS/logs/";

class TraceManager{
private:
    inline static std::string& ltrim(std::string& s, const char* t = "\t\n\r\f\v") {
        s.erase(0, s.find_first_not_of(t));
        return s;
    }

    inline static std::string& rtrim(std::string& s, const char* t = "\t\n\r\f\v") {
        s.erase(s.find_last_not_of(t) + 1);
        return s;
    }

    inline static  std::string& trim(std::string& s, const char* t = "\t\n\r\f\v") {
        return ltrim(rtrim(s, t), t);
    }
    
public:
    inline void static AddLog(std::string log){
        try{
            std::FILE* fp = NULL;
            time_t current_time = time(nullptr);
            struct tm* t = localtime(&current_time);
            std::string buffer = std::to_string(t->tm_year + 1900) + std::to_string(t->tm_mon + 1) + std::to_string(t->tm_mday);
            path += buffer + ".log";
            fp = std::fopen(path.c_str(), "a+");
            if(fp == NULL){
                std::cout << "file open error" << std::endl;
                return;
            }
            
            auto now = std::chrono::system_clock::now();
            auto in_time_t = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&in_time_t), "%Y/%m/%d - %H:%M:%S [%Z]     ");
            
            std::string now_s = ss.str();
            now_s += log;
            trim(now_s);
            now_s + '\n';
            std::fputs(now_s.c_str(), fp);
            
            std::fclose(fp);
            
            return;
        }catch(exception ex){
            std::cout << ex.what() << std::endl;
            return;
        }
    }
    
    inline void static AddLog(std::string state, std::string title, std::string contents){
        try{
            std::FILE* fp = NULL;
            time_t current_time = time(nullptr);
            struct tm* t = localtime(&current_time);
            std::string buffer = std::to_string(t->tm_year + 1900) + std::to_string(t->tm_mon + 1) + std::to_string(t->tm_mday);
            path += buffer + ".log";
            fp = std::fopen(path.c_str(), "a+");
            if(fp == NULL){
                std::cout << "file open error" << std::endl;
                return;
            }
            
            auto now = std::chrono::system_clock::now();
            auto in_time_t = std::chrono::system_clock::to_time_t(now);
            std::stringstream ss;
            ss << std::put_time(std::localtime(&in_time_t), "%Y/%m/%d - %H:%M:%S [%Z]     ");
            
            std::string now_s = ss.str();
            now_s += state + "    #" + title + "  @" + contents;
            trim(now_s);
            now_s + '\n';
            std::fputs(now_s.c_str(), fp);
            
            std::fclose(fp);
            
            return;
        }catch(exception ex){
            std::cout << ex.what() << std::endl;
            return;
        }
    }
    
};

#endif
