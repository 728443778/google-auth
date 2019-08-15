#include "totp.hpp"
#include <iostream>

int main()
{
    std::string secret("5FERSOMZHKN4CQU7");
    std::cout<<TOTP::generatePasswordByTOTP(secret)<<std::endl;
    return 0;
}