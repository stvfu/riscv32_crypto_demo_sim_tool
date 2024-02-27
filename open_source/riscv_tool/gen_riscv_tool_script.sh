#!/bin/bash -
CURRENT_PATH=`pwd`
echo $CURRENT_PATH

TOOL_REL_PATH=$CURRENT_PATH/riscv_tool_rel
SPIKE_SOURCE_PATH=$CURRENT_PATH/riscv-isa-sim
PK_SOURCE_PATH=$CURRENT_PATH/riscv-pk

SPIKE_COMMIT_ID="v1.1.0"
PK_COMMIT_ID="v1.0.0"

ENABLE_GEN_SPIKE=enable
ENABLE_GEN_PK=enable

function fPreparetoolchain()
{
    echo -e "\033[33m###############################################\033[0m"
    echo -e "\033[33m# Start Download Toolchain                    #\033[0m"
    echo -e "\033[33m###############################################\033[0m"

}

function fDownloadRiscvTool()
{
    echo -e "\033[33m###############################################\033[0m"
    echo -e "\033[33m# Start Download Riscv tool                   #\033[0m"
    echo -e "\033[33m###############################################\033[0m"
    # download spike tool
    if [ "$ENABLE_GEN_SPIKE" = "enable" ]; then
        cd $CURRENT_PATH
        rm -rf $SPIKE_SOURCE_PATH
        git clone https://github.com/riscv-software-src/riscv-isa-sim.git
        cd $SPIKE_SOURCE_PATH
        git checkout $SPIKE_COMMIT_ID
    fi

    # download pk tool
    if [ "$ENABLE_GEN_PK" = "enable" ]; then
        cd $CURRENT_PATH
        rm -rf $PK_SOURCE_PATH
        git clone https://github.com/riscv-software-src/riscv-pk.git
        cd $PK_SOURCE_PATH
        git checkout $PK_COMMIT_ID
    fi
}

function fRelPackageInfo()
{
    echo "RISCV tool release info"          > $TOOL_REL_PATH/release_package_info.txt
    echo ""                                >> $TOOL_REL_PATH/release_package_info.txt
    echo "SPIKE:"                          >> $TOOL_REL_PATH/release_package_info.txt
    echo "  git repo: https://github.com/riscv-software-src/riscv-isa-sim.git"  >> $TOOL_REL_PATH/release_package_info.txt
    echo "  commit/TAG: $SPIKE_COMMIT_ID"  >> $TOOL_REL_PATH/release_package_info.txt
    echo "  config setting:"               >> $TOOL_REL_PATH/release_package_info.txt
    echo "  ../configure --prefix=$TOOL_REL_PATH/spike --with-target=riscv32-corev-elf" >>  $TOOL_REL_PATH/release_package_info.txt
    echo ""                                >> $TOOL_REL_PATH/release_package_info.txt
    echo "PK:"                             >> $TOOL_REL_PATH/release_package_info.txt
    echo "  git repo: https://github.com/riscv-software-src/riscv-pk.git"  >> $TOOL_REL_PATH/release_package_info.txt
    echo "  commit/TAG: $PK_COMMIT_ID"     >> $TOOL_REL_PATH/release_package_info.txt
    echo "  config setting:"               >> $TOOL_REL_PATH/release_package_info.txt
    echo "  ../configure  --prefix=$TOOL_REL_PATH/pk --host=riscv32-unknown-elf" >>  $TOOL_REL_PATH/release_package_info.txt

    cp $CURRENT_PATH/gen_riscv_tool_script.sh $TOOL_REL_PATH
}

function fBuildRiscTool()
{
    echo -e "\033[33m###############################################\033[0m"
    echo -e "\033[33m# Start Build Riscv tool                      #\033[0m"
    echo -e "\033[33m###############################################\033[0m"
    # gen package
    rm -rf $TOOL_REL_PATH
    mkdir -p $TOOL_REL_PATH
    mkdir -p $TOOL_REL_PATH/spike
    mkdir -p $TOOL_REL_PATH/pk
    fRelPackageInfo

    # build SPIK tool
    if [ "$ENABLE_GEN_SPIKE" = "enable" ]; then
        mkdir -p $SPIKE_SOURCE_PATH/build
        cd $SPIKE_SOURCE_PATH/build 
        ../configure --prefix=$TOOL_REL_PATH/spike --with-target=riscv32-corev-elf
        make
        make install
    fi

    # build PK tool
    if [ "$ENABLE_GEN_PK" = "enable" ]; then
        mkdir -p $PK_SOURCE_PATH/build
        cd $PK_SOURCE_PATH/build     
        ../configure --prefix=$TOOL_REL_PATH/pk --host=riscv32-unknown-elf
        make
        make install
    fi
    
    echo "Start tar rel package"
    rm -rf riscv_tool_rel.tar.gz tar.log
    cd $CURRENT_PATH
    tar zcvf riscv_tool_rel.tar.gz riscv_tool_rel/ > tar.log
}

start_time=$(date +%s)
fPreparetoolchain
fDownloadRiscvTool
fBuildRiscTool

end_time=$(date +%s)
execution_time=$((end_time - start_time))
echo "Execution time: $execution_time seconds"


