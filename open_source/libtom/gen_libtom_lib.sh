CURRENT_PATH=`pwd`

TOOLCHAIN_PREFIX=riscv32-corev-elf
export CC=${TOOLCHAIN_PREFIX}-gcc
export AR=${TOOLCHAIN_PREFIX}-ar
export LD=${TOOLCHAIN_PREFIX}-ld
export CFLAGS=""

BUILD_TREE_PATH=$CURRENT_PATH/../../build_tree
LIB_SOURCE_PATH=$CURRENT_PATH/$TOOLCHAIN_PREFIX
echo $CURRENT_PATH

function fDownLoad()
{
    rm -rf $LIB_SOURCE_PATH
    mkdir -p $LIB_SOURCE_PATH

    echo -e "\033[33mDownload libtomcrypt\033[0m"
    cd $LIB_SOURCE_PATH
    git clone https://github.com/libtom/libtomcrypt.git
    cd $LIB_SOURCE_PATH/libtomcrypt
    git checkout 7e863d21429f94ed6a720e24499a12a3f852bb31

    echo -e "\033[33mDownload libtommath\033[0m"
    cd $LIB_SOURCE_PATH
    git clone https://github.com/libtom/libtommath.git
    cd $LIB_SOURCE_PATH/libtommath
    git checkout 8314bde5e5c8e5d9331460130a9d1066e324f091
}

function fPatch()
{
    echo -e "\033[33mpatch for build error\033[0m"
    sed -i 's/mp_kronecker(\&Dz, a, \&J)/mp_kronecker(\&Dz, a, (int *)\&J)/' $CURRENT_PATH/$TOOLCHAIN_PREFIX/libtommath/mp_prime_strong_lucas_selfridge.c
    sed -i 's/#define LTC_CLOCK_GETTIME/\/\/#define LTC_CLOCK_GETTIME/' $CURRENT_PATH/$TOOLCHAIN_PREFIX/libtomcrypt/src/headers/tomcrypt_custom.h
}

function fBuild()
{
    echo -e "\033[33mbuild libtomcrypt\033[0m"
    cd $LIB_SOURCE_PATH/libtomcrypt; make clean;make

    echo -e "\033[33mbuild libtommatch\033[0m"
    cd $LIB_SOURCE_PATH/libtommath; make clean;make

    echo -e "\033[33mcopy lib / header to build_tree\033[0m"
    cp $LIB_SOURCE_PATH/libtomcrypt/libtomcrypt.a $BUILD_TREE_PATH/lib/libtom/$TOOLCHAIN_PREFIX/libtomcrypt.a
    cp $LIB_SOURCE_PATH/libtommath/libtommath.a   $BUILD_TREE_PATH/lib/libtom/$TOOLCHAIN_PREFIX/libtommath.a

    cp $LIB_SOURCE_PATH/libtomcrypt/src/headers/tomcrypt*.h $BUILD_TREE_PATH/inc/libtom/

}

fDownLoad
fPatch
fBuild

