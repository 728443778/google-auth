#include "totp.hpp"
#include <iostream>

int main()
{
    auto createSecret = TOTP::createSecret(16); //创建一个不是8的偶数secret 用来解码
    std::cout<<"create secret:"<<createSecret<<std::endl;
    std::string secret("5FERSOMZHKN4CQU7");
    std::cout<<"used secret:"<<secret<<std::endl;
    std::cout<<TOTP::generatePasswordByTOTP(secret)<<std::endl;
    auto password = TOTP::generatePasswordByTOTP(createSecret);
    assert(TOTP::veriPasswordByTOTP(password, createSecret)); //使用生成的secret 验证，5F开头的是某个交易所的密钥
    return 0;
}