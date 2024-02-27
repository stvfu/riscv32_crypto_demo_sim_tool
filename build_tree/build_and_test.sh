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

echo -e "\033[33m###############################################\033[0m"
echo -e "\033[33m# Start test sample image                     #\033[0m"
echo -e "\033[33m###############################################\033[0m"
if [[ -x "$SPIKE_PATH/spike" ]] && [[ -x "$PK_PATH/pk" ]]; then
    echo "start test"
    $SPIKE_PATH/spike $ISA_OPTION $PK_PATH/pk ./out/demo
else
    echo "Either spike or pk does not exist or is not executable."
    echo "Please go to open_source/riscv_tool and run script ./gen_riscv_tool_script.sh"
fi
