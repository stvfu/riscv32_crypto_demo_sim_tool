# RISC-V security SW function 開發包 demo
繁體中文 | [English](README.md)

## 準備 RISC-V Tool 與 security function 的 demo

這份 README 提供開發者架設環境的方式 RISC-V tools (`spike` and `pk`) 
以及提供了 security 相關的基於opensource mbedtls/libtom的 function 實作

## 準備 Spike and PK 工具

請根據以下的flow來建立 `spike` 指令模擬器 以及 `pk` (proxy kernel):

進入 `riscv_tool/open_source` 資料夾執行 `./gen_riscv_tool_script.sh` 
一鍵完成開發工具的download + source build

```bash
cd open_source/riscv_tool/
sh ./gen_riscv_tool_script.sh
```

## 編譯+測試 security demo function
請按照此流程來編譯 

進入 'build_tree' 資料夾:
```bash
cd build_tree
./build_and_test.sh
```

## 支援的演算法
| 類型 | 演算法 | 實現 |
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
