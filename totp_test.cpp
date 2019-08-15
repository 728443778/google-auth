#include "totp.hpp"
#include <iostream>

int main()
{
    auto createSecret = TOTP::createSecret(16);
    std::cout<<"create secret:"<<createSecret<<std::endl;
    std::string secret("5FERSOMZHKN4CQU7");
    std::cout<<"used secret:"<<secret<<std::endl;
    std::cout<<TOTP::generatePasswordByTOTP(secret)<<std::endl;
    auto password = TOTP::generatePasswordByTOTP(createSecret);
    assert(TOTP::veriPasswordByHOTP(password, createSecret)); //使用生成的secret 验证，5F开头的是某个交易所的密钥
    return 0;
}