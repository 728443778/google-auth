
#define TOTP_HPP

#define UNIX_TIME_START  0
#include <time.h>
#include <string>
#include <sodium.h>


namespace TOTP 
{

    std::string truncate()
    {

    }

    int getUnixTimeCount(int diff = 30)
    {
        time_t t = time(0);
        int count = (t - UNIX_TIME_START) / diff; //获得间隔
        return count;
    }


}