
#define TOTP_HPP

#define UNIX_TIME_START 0
#include <time.h>
#include <string>
#include <memory.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <algorithm>
#include "three/codec/cppcodec/base32_rfc4648.hpp"

using namespace std;

namespace TOTP
{

const short SHA1 = 1;
const short SHA_256 = 2;
const short SHA_512 = 3;

const long digits[9] = {1,10,100,1000, 10000, 100000,1000000,10000000, 100000000};

long getUnixTimeCount(unsigned int diff = 30)
{
    time_t t = time(0);
    long count = (t - UNIX_TIME_START) / diff; //获得间隔
    return count;
}

/**
 * 处理计数器，
 * @param int counter 输入计数器的值
 * @param char result[8] 输出值，目前固定长度为8
 * */
void processCounter(int counter, char *result)
{
    char data[8];
    for (int i = 7; i >= 0; --i)
    {
        data[i] = counter & 0xFF;
        counter = counter >> 8;
    }
    memcpy(result, data, 8);
}

bool truncate(std::string& in, std::string& out, int length = 6)
{
    if (length > (sizeof(TOTP::digits)-1)){
        return false;
    }
    auto last = in.at(in.length()-1);
    auto offset = last & 0xf;
    auto bin = ((in.at(offset) & 0x7f) << 24) | ((in.at(offset+1) & 0xff)<<16) | ((in.at(offset+2) & 0xff)<<8) | (in.at(offset+3) & 0xff);
    auto mod = TOTP::digits[length];
    auto password = std::to_string(bin % mod);
    if (password.length() < length) {
        password = std::string(length - password.length(), '0') + password;
    }
    out = password;
    return true;
}

string createSecret(unsigned short length = 16)
{
    if (length > 32) {
        length = 32;
    }
    unsigned char in[128];
    RAND_bytes(in, 128);
    auto secret = cppcodec::base32_rfc4648::encode(in);
    //替换屌其中的 =
    secret.erase(std::remove(secret.begin(), secret.end(), '='), secret.end());
    if (secret.length() < length) {
        return std::string("");
    }
    return secret.substr(0, length);
}

void decodeSecret(string &in, string& out)
{
    auto s2 = cppcodec::base32_rfc4648::decode(in);
    out.clear();
    for(auto i: s2) {
        out.push_back(i);
    }
}

/**
 * 生成一个一次性密码，密码长度最多9位，且，不能为0，否者会产生未知错误
 * @param int counter  计数器
 * @param string secret base32编码后的密钥
 * @param unsigned int passwdLength 生成动态密码的密码长度
 * */
std::string generatePasswordByHOTP(int counter, string secret, int passwdLength = 6)
{
    char counterResult[8];
    processCounter(counter, counterResult);
    string decodeScret;
    decodeSecret(secret, decodeScret);
    char digist[1024];
    unsigned int length;
    HMAC(EVP_sha1(), decodeScret.c_str(), decodeScret.length(), (const unsigned char*)counterResult, sizeof(counterResult), (unsigned char * )digist, &length);
    std::string s;
    int i = 0;
    // if (length > 1024) {  //hmac sha1 输出空间只有20字节
    //     length = 1024;
    // }
    for (;i<length;i++) {
        s.push_back(digist[i]);
    }
    std::string result;
    truncate(s, result, passwdLength);
    return result;
}

/**
 * 生成一次性密码
 * @param string secret base32编码后的密钥
 * @param int step 基于时间的步长
 * @param int passwordLength 生成一次性密码的密码长度，最小为1，最大为9，否者会产生未知错误
 * @return string 返回一次性密码
 * */
std::string generatePasswordByTOTP(string secret,int step = 30, int passwordLength = 6)
{
    step = getUnixTimeCount(step);
    return generatePasswordByHOTP(step, secret, passwordLength);
}

} // namespace TOTP