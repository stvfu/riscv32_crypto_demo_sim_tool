#!/bin/bash -
CURRENT_PATH=`pwd`
echo $CURRENT_PATH

rm -rf $CURRENT_PATH/mbedtls
git clone https://github.com/Mbed-TLS/mbedtls.git
cd mbedtls
git checkout 0315123cfb08ef1842fe8b641e4a77d0dcce4451

#git reset --hard
sed -i 's/#define MBEDTLS_HAVE_TIME/\/\/#define MBEDTLS_HAVE_TIME/' $CURRENT_PATH/mbedtls/include/mbedtls/mbedtls_config.h
sed -i 's/#define MBEDTLS_HAVE_TIME_DATE/\/\/#define MBEDTLS_HAVE_TIME_DATE/' $CURRENT_PATH/mbedtls/include/mbedtls/mbedtls_config.h
sed -i 's/#define MBEDTLS_FS_IO/\/\/#define MBEDTLS_FS_IO/'  $CURRENT_PATH/mbedtls/include/mbedtls/mbedtls_config.h
sed -i 's/\/\/#define MBEDTLS_NO_PLATFORM_ENTROPY/#define MBEDTLS_NO_PLATFORM_ENTROPY/' $CURRENT_PATH/mbedtls/include/mbedtls/mbedtls_config.h
sed -i 's/#define MBEDTLS_NET_C/\/\/#define MBEDTLS_NET_C/'  $CURRENT_PATH/mbedtls/include/mbedtls/mbedtls_config.h
sed -i 's/#define MBEDTLS_PSA_CRYPTO_STORAGE_C/\/\/#define MBEDTLS_PSA_CRYPTO_STORAGE_C/'  $CURRENT_PATH/mbedtls/include/mbedtls/mbedtls_config.h
sed -i 's/#define MBEDTLS_PSA_ITS_FILE_C/\/\/#define MBEDTLS_PSA_ITS_FILE_C/'  $CURRENT_PATH/mbedtls/include/mbedtls/mbedtls_config.h
sed -i 's/#define MBEDTLS_TIMING_C/\/\/#define MBEDTLS_TIMING_C/'  $CURRENT_PATH/mbedtls/include/mbedtls/mbedtls_config.h

export CC="riscv32-corev-elf-gcc"
export AR="riscv32-corev-elf-ar"
export LD="riscv32-corev-elf-ld"
export CFLAGS=""

cd $CURRENT_PATH/mbedtls; make clean;make lib
cp -r library/*.a $CURRENT_PATH/
cp -r include/mbedtls $CURRENT_PATH/../../../inc/mbedtls/
cp -r include/psa $CURRENT_PATH/../../../inc/mbedtls/
