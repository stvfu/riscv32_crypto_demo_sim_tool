#!/bin/bash -
CURRENT_PATH=`pwd`
echo $CURRENT_PATH
SPIKE_PATH=$CURRENT_PATH/../open_source/riscv_tool/riscv_tool_rel/spike/bin
PK_PATH=$CURRENT_PATH/../open_source/riscv_tool/riscv_tool_rel/pk/riscv32-unknown-elf/bin
ISA_OPTION="--isa=rv32imac"


echo -e "\033[33m###############################################\033[0m"
echo -e "\033[33m# Start Build sample code                     #\033[0m"
echo -e "\033[33m###############################################\033[0m"
make clean
make
cp $CURRENT_PATH/out/libMyLib.a $CURRENT_PATH/customer_app_template/cust_app_dev/lib/sec_api/libMyLib.a
cp $CURRENT_PATH/customer_api_wrapper/*.h $CURRENT_PATH/customer_app_template/cust_app_dev/inc/

cd $CURRENT_PATH/customer_app_template/cust_app_dev
make clean
make

cd $CURRENT_PATH

echo -e "\033[33m###############################################\033[0m"
echo -e "\033[33m# Start test sample image                     #\033[0m"
echo -e "\033[33m###############################################\033[0m"
if [[ -x "$SPIKE_PATH/spike" ]] && [[ -x "$PK_PATH/pk" ]]; then
    echo "start test"
    $SPIKE_PATH/spike $ISA_OPTION $PK_PATH/pk ./out/demo
    $SPIKE_PATH/spike $ISA_OPTION $PK_PATH/pk ./out/demo_suite
else
    echo "Either spike or pk does not exist or is not executable."
    echo "Please go to open_source/riscv_tool and run script ./gen_riscv_tool_script.sh"
fi
