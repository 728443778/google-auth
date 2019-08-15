#include "totp.hpp"
#include <iostream>

int main()
{
    std::cout<<"create secret:"<<TOTP::createSecret(16)<<std::endl;
    std::string secret("5FERSOMZHKN4CQU7");
    std::cout<<"used secret:"<<secret<<std::endl;
    std::cout<<TOTP::generatePasswordByTOTP(secret)<<std::endl;
    return 0;
}