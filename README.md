# RISC-V crypto demo sim tool
[繁體中文](README_TW.md) | English

## RISC-V Tool Preparation and Crypto Test Instructions

This README provides instructions on how to prepare the RISC-V tools (`spike` and `pk`) and how to run the crypto test suite.

## Preparing the Spike and PK Tools

To prepare the `spike` simulator and `pk` (proxy kernel), follow these steps:

Navigate to the `riscv_tool` directory in the `open_source` folder:

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

## Support demo function
| Type | Algo | impl |
|-------|-------|-------|
| Random | gen random data | libtom |
| HASH | SHA1 | libtom |
| HASH | SHA224/SHA256/SHA384/SHA512 | libtom |
| HASH | SHA512/SHA512-224/SHA512-256 | libtom |
| HASH | SHA3: 224/256/384/512 | libtom |
| AES | ECB encrypt/decrypt | mbedtls |
| AES | CBC encrypt/decrypt | mbedtls |
| AES | CTR encrypt/decrypt | libtom |
| AES | CMAC | mbedtls |
| RSA | genkey/sign/verify | mbedtls |
| ECC | genkey keypair | mbedtls |
| ECDSA | secp256r1/secp384r1/secp521r1 | mbedtls |
| ECDSA | brainpool256r1/brainpool384r1/brainpool512r1 | mbedtls |
