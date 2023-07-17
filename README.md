kohezion staging tree 25.x
==========================

https://chainworksindustries.com/


What is Kohezion?
-----------------

Kohezion is another quality product released by Chainworks Industries, combining cutting-edge Bitcoin Core code with the Equihash 200/9 hashing algorithm, whilst simultaneously running full Particl PoS with a 256bit modifier per block. 


How do I build the software?
----------------------------

Using an up to date linux installation, with a standard build environment (including build-essential, autotools, git etc):

    git clone https://github.com/chainworksindustries/kohezion
    cd kohezion/depends
    make HOST=x86_64-pc-linux-gnu -j4
    cd ..
    ./autogen.sh
    CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure
    make -j4



License
-------

kohezion is released under the terms of the MIT license. See [COPYING](COPYING) for more information or see https://opensource.org/licenses/MIT.

