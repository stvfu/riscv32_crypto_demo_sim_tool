# RISC-V crypto demo sim tool

## RISC-V Tool Preparation and Crypto Test Instructions

This README provides instructions on how to prepare the RISC-V tools (`spike` and `pk`) and how to run the crypto test suite.

## Preparing the Spike and PK Tools

To prepare the `spike` simulator and `pk` (proxy kernel), follow these steps:

1. Navigate to the `riscv_tool` directory in the `open_source` folder:

```bash
cd open_source/riscv_tool/
sh ./gen_riscv_tool_script.sh
```

## Testing Crypto Test Items
To run the crypto test suite, follow these steps:

Change to the 'build_tree' directory:
```bash
cd build_tree
./build_and_test.sh
```

