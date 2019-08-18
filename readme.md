## C++ 版本
```
git submodule init
git submodule update
mkdir build
cd build
cmake ..
nmake
```
c++ 的好的库，std都没有进行提供，要么自己写，要么用第三方的，这儿加密用的openssl，我在windows编译使用的，  
base32的编码，在github上搜到个，是可以不用编译，直接引入使用。

## elixr 版本的使用 
iex totp.ex
