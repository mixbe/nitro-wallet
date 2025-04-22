package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// 生成 EVM 地址并保存私钥到文件
func generateAddress() string {
	// 生成新的私钥
	key, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal("生成私钥失败:", err)
	}

	// 从私钥派生地址
	address := crypto.PubkeyToAddress(key.PublicKey).Hex()
	fmt.Println("EVM 地址:", address)

	// 将私钥转换为十六进制格式并保存到文件
	privBytes := crypto.FromECDSA(key)
	privHex := hex.EncodeToString(privBytes)

	// 保存到文件，设置权限为 0600（只有所有者可读写）
	err = os.WriteFile("evm_wallet.key", []byte(privHex), 0600)
	if err != nil {
		log.Fatal("保存私钥失败:", err)
	}

	fmt.Println("私钥已保存到 evm_wallet.key 文件")
	return address
}

// 离线签名交易
func signTx(to string, value float64, nonce uint64, chainId int64, gasLimit uint64, gasPriceGwei float64) string {
	// 读取私钥文件
	privHex, err := os.ReadFile("evm_wallet.key")
	if err != nil {
		log.Fatal("读取私钥文件失败:", err)
	}

	// 解码私钥
	privBytes, err := hex.DecodeString(strings.TrimSpace(string(privHex)))
	if err != nil {
		log.Fatal("解码私钥失败:", err)
	}

	// 转换为 ECDSA 私钥
	privKey, err := crypto.ToECDSA(privBytes)
	if err != nil {
		log.Fatal("转换私钥失败:", err)
	}

	// 准备交易参数
	toAddr := common.HexToAddress(to)
	// 将 ETH 值转换为 wei（乘以 10^18）
	amount := big.NewFloat(value)
	amount.Mul(amount, big.NewFloat(1e18))
	amountInt, _ := amount.Int(nil)

	// 将 Gwei 转换为 wei（乘以 10^9）
	gasPrice := big.NewFloat(gasPriceGwei)
	gasPrice.Mul(gasPrice, big.NewFloat(1e9))
	gasPriceInt, _ := gasPrice.Int(nil)

	// 创建交易对象
	tx := types.NewTransaction(nonce, toAddr, amountInt, gasLimit, gasPriceInt, nil)

	// 创建签名器
	chainID := big.NewInt(chainId)
	signer := types.NewEIP155Signer(chainID)

	// 签名交易
	signedTx, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		log.Fatal("签名交易失败:", err)
	}

	// 将签名后的交易序列化为字节数组
	rawTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		log.Fatal("序列化交易失败:", err)
	}

	// 转换为十六进制字符串
	rawTxHex := hex.EncodeToString(rawTxBytes)

	// 打印交易详情
	fmt.Println("交易详情:")
	fmt.Println("  接收地址:", to)
	fmt.Println("  金额:", value, "ETH")
	fmt.Println("  Nonce:", nonce)
	fmt.Println("  Chain ID:", chainId)
	fmt.Println("  Gas Limit:", gasLimit)
	fmt.Println("  Gas Price:", gasPriceGwei, "Gwei")
	fmt.Println("rawTxHex:", rawTxHex)

	// 将签名数据保存到文件，避免手动复制粘贴错误
	txFileName := "signed_tx.hex"
	err = os.WriteFile(txFileName, []byte(rawTxHex), 0600)
	if err != nil {
		log.Fatal("保存签名交易失败:", err)
	}
	fmt.Println("签名交易已保存到", txFileName, "文件")
	fmt.Println("推荐使用以下命令广播，避免复制粘贴错误:")
	fmt.Println("  go run main.go send-file", txFileName, "<rpcURL>")

	return rawTxHex
}

// 广播交易到区块链网络
func broadcastTx(rawTxHex string, rpcURL string) {
	fmt.Println("开始广播交易...")
	fmt.Println("连接到 RPC 节点:", rpcURL)
	fmt.Println("broadcastTx | 1 rawTxHex: ", rawTxHex)

	// 连接到以太坊节点
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatal("连接 RPC 失败:", err)
	}
	fmt.Println("成功连接到节点")
	fmt.Println("broadcastTx | 2 rawTxHex: ", rawTxHex)

	// 检查连接是否正常
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 尝试获取区块链网络 ID
	chainID, err := client.ChainID(ctx)
	if err != nil {
		log.Fatal("无法获取网络 ID，请检查 RPC 连接:", err)
	}
	fmt.Println("当前网络 Chain ID:", chainID)

	fmt.Println("broadcastTx | 3 rawTxHex: ", rawTxHex)

	// 验证原始交易数据
	// fmt.Println("broadcastTx | 原始交易数据(十六进制):", rawTxHex)
	fmt.Println("broadcastTx | 4 rawTxHex: ", rawTxHex)

	fmt.Println("原始交易数据长度(十六进制):", len(rawTxHex), "字符")

	// 检查原始交易数据长度是否合理
	if len(rawTxHex) < 100 || len(rawTxHex) > 1000 {
		log.Fatal("原始交易数据长度异常，可能存在复制粘贴错误")
	}

	// 解码十六进制字符串为字节数组
	rawTx, err := hex.DecodeString(rawTxHex)
	if err != nil {
		log.Fatal("解码交易数据失败:", err)
	}
	fmt.Println("原始交易数据长度(字节):", len(rawTx), "字节")

	// 使用正确的方法解析交易
	tx := new(types.Transaction)
	err = tx.UnmarshalBinary(rawTx)
	if err != nil {
		// 如果解析失败，打印详细信息并退出
		fmt.Println("原始交易数据:", rawTxHex)
		log.Fatal("解析交易失败:", err)
	}

	// 检查交易的 chainID 是否与网络匹配
	txChainID := tx.ChainId()
	if txChainID != nil && chainID != nil && txChainID.Cmp(chainID) != 0 {
		fmt.Printf("警告: 交易的 Chain ID (%s) 与网络 Chain ID (%s) 不匹配\n",
			txChainID.String(), chainID.String())
		fmt.Println("这可能导致交易失败或被拒绝")
	}

	// 打印交易详情供参考
	fmt.Println("交易详情:")
	fmt.Println("  交易哈希:", tx.Hash().Hex())

	// 如果有接收地址，则显示
	if tx.To() != nil {
		fmt.Println("  接收地址:", tx.To().Hex())
	} else {
		fmt.Println("  接收地址: 无（可能是合约创建交易）")
	}

	// 将 Wei 转换为 ETH 显示
	weiValue := new(big.Float).SetInt(tx.Value())
	ethValue := new(big.Float).Quo(weiValue, big.NewFloat(1e18))
	fmt.Printf("  交易金额: %s Wei (%.18f ETH)\n", tx.Value().String(), ethValue)

	fmt.Println("  交易 Nonce:", tx.Nonce())
	fmt.Println("  交易 Gas Limit:", tx.Gas())

	// 将 Wei 转换为 Gwei 显示
	weiGasPrice := new(big.Float).SetInt(tx.GasPrice())
	gweiGasPrice := new(big.Float).Quo(weiGasPrice, big.NewFloat(1e9))
	fmt.Printf("  交易 Gas Price: %s Wei (%.9f Gwei)\n", tx.GasPrice().String(), gweiGasPrice)

	// 计算最大交易费
	maxFee := new(big.Int).Mul(tx.GasPrice(), big.NewInt(int64(tx.Gas())))
	maxFeeWei := new(big.Float).SetInt(maxFee)
	maxFeeEth := new(big.Float).Quo(maxFeeWei, big.NewFloat(1e18))
	fmt.Printf("  最大交易费: %s Wei (%.18f ETH)\n", maxFee.String(), maxFeeEth)

	// 使用 SendTransaction 方法发送交易
	fmt.Println("正在广播交易...")
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		log.Fatal("发送交易失败:", err)
	}

	fmt.Println("✅ 交易广播成功!")
	fmt.Println("交易哈希:", tx.Hash().Hex())
	fmt.Println("可以在区块链浏览器中查看交易状态")
}

// 对任意字符串做 secp256k1 签名
func signString(message string) string {
	privHex, err := os.ReadFile("evm_wallet.key")
	if err != nil {
		log.Fatal("读取私钥文件失败:", err)
	}
	privBytes, err := hex.DecodeString(strings.TrimSpace(string(privHex)))
	if err != nil {
		log.Fatal("解码私钥失败:", err)
	}
	privKey, err := crypto.ToECDSA(privBytes)
	if err != nil {
		log.Fatal("转换私钥失败:", err)
	}
	hash := crypto.Keccak256Hash([]byte(message))
	signature, err := crypto.Sign(hash.Bytes(), privKey)
	if err != nil {
		log.Fatal("签名失败:", err)
	}
	fmt.Println("签名数据(hex):", hex.EncodeToString(signature))
	return hex.EncodeToString(signature)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: go run main.go [gen|sign|send|send-file|sign-string]")
		fmt.Println("\n命令说明:")
		fmt.Println("  gen        : 生成 EVM 地址，并保存私钥到 evm_wallet.key")
		fmt.Println("  sign       : 离线签名交易，生成原始交易数据")
		fmt.Println("               用法: go run main.go sign [to] [value] [nonce] [chainId] [gasLimit] [gasPriceGwei]")
		fmt.Println("               示例: go run main.go sign 0x5e418ee491709c9547a33bd79253b41f1e7eb8f8 0.0001 0 97 21000 10")
		fmt.Println("  send       : 广播已签名交易到链上")
		fmt.Println("               用法: go run main.go send [rawTxHex] [rpcURL]")
		fmt.Println("               示例: go run main.go send <rawTxHex> https://api.zan.top/bsc-testnet")
		fmt.Println("  send-file  : 从文件读取签名交易并广播到链上（推荐，避免复制粘贴错误）")
		fmt.Println("               用法: go run main.go send-file [txFile] [rpcURL]")
		fmt.Println("               示例: go run main.go send-file signed_tx.hex https://api.zan.top/bsc-testnet")
		fmt.Println("  sign-string: 对任意字符串做 secp256k1 签名（用于测试）")
		fmt.Println("               用法: go run main.go sign-string \"要签名的消息\"")
		return
	}
	cmd := os.Args[1]
	if cmd == "send-file" {
		if len(os.Args) < 4 {
			fmt.Println("用法: go run main.go send-file [txFile] [rpcURL]")
			fmt.Println("示例: go run main.go send-file signed_tx.hex https://api.zan.top/bsc-testnet")
			return
		}
		txFile := os.Args[2]
		rpcURL := os.Args[3]

		// 从文件读取签名交易数据
		rawTxHex, err := os.ReadFile(txFile)
		if err != nil {
			log.Fatal("读取交易文件失败:", err)
		}

		// 广播交易
		broadcastTx(strings.TrimSpace(string(rawTxHex)), rpcURL)
		return
	}
	if cmd == "sign-string" {
		if len(os.Args) < 3 {
			fmt.Println("用法: go run main.go sign-string \"要签名的消息字符串\"")
			return
		}
		message := os.Args[2]
		signString(message)
		return
	}
	if cmd == "gen" {
		generateAddress()
	} else if cmd == "sign" {
		if len(os.Args) < 8 {
			fmt.Println("用法: go run main.go sign [to] [value] [nonce] [chainId] [gasLimit] [gasPriceGwei]")
			fmt.Println("示例: go run main.go sign 0xF0109fC8DF283027b6285cc889F5aA624EaC1F55 0.0001 0 97 21000 10")
			return
		}
		to := os.Args[2]
		value := os.Args[3]
		nonce := os.Args[4]
		chainId := os.Args[5]
		gasLimit := os.Args[6]
		gasPriceGwei := os.Args[7]
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
			fmt.Println("示例: go run main.go send <rawTxHex> https://bsc-testnet.drpc.org")
			return
		}
		rawTxHex := os.Args[2]
		rpcURL := os.Args[3]
		// fmt.Println("rawTxHex: ", rawTxHex)
		broadcastTx(rawTxHex, rpcURL)
	}
}
