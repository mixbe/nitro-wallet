package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// 生成 EVM 地址
func generateAddress() string {
	key, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	address := crypto.PubkeyToAddress(key.PublicKey).Hex()
	fmt.Println("EVM 地址:", address)
	// 保存私钥到文件
	privBytes := crypto.FromECDSA(key)
	os.WriteFile("evm_wallet.key", []byte(hex.EncodeToString(privBytes)), 0600)
	return address
}

// 离线签名
func signTx(to string, value float64, nonce uint64, chainId int64, gasLimit uint64, gasPriceGwei float64) string {
	privHex, _ := os.ReadFile("evm_wallet.key")
	privBytes, _ := hex.DecodeString(strings.TrimSpace(string(privHex)))
	privKey, err := crypto.ToECDSA(privBytes)
	if err != nil {
		log.Fatal(err)
	}
	toAddr := common.HexToAddress(to)
	amount := big.NewInt(int64(value * 1e18))
	gasPrice := big.NewInt(int64(gasPriceGwei * 1e9))
	tx := types.NewTransaction(nonce, toAddr, amount, gasLimit, gasPrice, nil)
	chainID := big.NewInt(chainId)
	signer := types.NewEIP155Signer(chainID)
	signedTx, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		log.Fatal(err)
	}
	rawTxBytes, _ := signedTx.MarshalBinary()
	fmt.Println("签名后的原始交易:", hex.EncodeToString(rawTxBytes))
	return hex.EncodeToString(rawTxBytes)
}

// 广播交易
func broadcastTx(rawTxHex string, rpcURL string) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatal(err)
	}
	rawTx, _ := hex.DecodeString(rawTxHex)
	var tx types.Transaction
	tx.UnmarshalBinary(rawTx)
	err = client.SendTransaction(context.Background(), &tx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("广播成功，TxHash:", tx.Hash().Hex())
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: go run main.go [gen|sign|send]")
		fmt.Println("\n命令说明:")
		fmt.Println("  gen  : 生成 EVM 地址，并保存私钥到 evm_wallet.key")
		fmt.Println("  sign : 离线签名交易，生成原始交易数据")
		fmt.Println("         用法: go run main.go sign [to] [value] [nonce] [chainId] [gasLimit] [gasPriceGwei]")
		fmt.Println("         示例: go run main.go sign 0xF0109fC8DF283027b6285cc889F5aA624EaC1F55 0.0001 0 97 21000 10")
		fmt.Println("  send : 广播已签名交易到链上")
		fmt.Println("         用法: main.go send [rawTxHex] [rpcURL]")
		fmt.Println("         示例: main.go send <rawTxHex> https://data-seed-prebsc-1-s1.binance.org:8545/")
		return
	}
	cmd := os.Args[1]
	if cmd == "gen" {
		generateAddress()
	} else if cmd == "sign" {
		if len(os.Args) < 8 {
			fmt.Println("用法: go run main.go sign [to] [value] [nonce] [chainId] [gasLimit] [gasPriceGwei]")
			fmt.Println("示例: go run main.go sign 0xF0109fC8DF283027b6285cc889F5aA624EaC1F55 0.0001 0 97 21000 10")
			return
		}
		to := os.Args[2]; value := os.Args[3]; nonce := os.Args[4]; chainId := os.Args[5]; gasLimit := os.Args[6]; gasPriceGwei := os.Args[7]
		// 转换参数
		val, _ := strconv.ParseFloat(value, 64)
		non, _ := strconv.ParseUint(nonce, 10, 64)
		cid, _ := strconv.ParseInt(chainId, 10, 64)
		gl, _ := strconv.ParseUint(gasLimit, 10, 64)
		gp, _ := strconv.ParseFloat(gasPriceGwei, 64)
		signTx(to, val, non, cid, gl, gp)
	} else if cmd == "send" {
		if len(os.Args) < 4 {
			fmt.Println("用法: go run main.go send [rawTxHex] [rpcURL]")
			fmt.Println("示例: go run main.go send <rawTxHex> https://data-seed-prebsc-1-s1.binance.org:8545/")
			return
		}
		rawTxHex := os.Args[2]
		rpcURL := os.Args[3]
		broadcastTx(rawTxHex, rpcURL)
	}
}
