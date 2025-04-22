package main

//
//import (
//	"context"
//	"encoding/base64"
//	"encoding/hex"
//	"fmt"
//	"log"
//	"os"
//	"strconv"
//	"strings"
//
//	"github.com/portto/solana-go-sdk/client"
//	"github.com/portto/solana-go-sdk/common"
//	"github.com/portto/solana-go-sdk/types"
//	"github.com/portto/solana-go-sdk/program/system"
//)
//
//// 生成 Solana 地址
//func generateAddress() string {
//	acc := types.NewAccount()
//	fmt.Println("Solana 地址:", acc.PublicKey.ToBase58())
//	os.WriteFile("solana_wallet.key", []byte(base64.StdEncoding.EncodeToString(acc.PrivateKey)), 0600)
//	return acc.PublicKey.ToBase58()
//}
//
//// 离线签名
//func signTx(to string, lamports uint64, recentBlockhash string) string {
//	privBase64, _ := os.ReadFile("solana_wallet.key")
//	privBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privBase64)))
//	acc := types.AccountFromPrivateKeyBytes(privBytes)
//	tx, err := types.NewTransaction(
//		types.NewTransactionParam{
//			Message: types.NewMessage(
//				types.NewMessageParam{
//					FeePayer:        acc.PublicKey,
//					RecentBlockhash: recentBlockhash,
//					Instructions: []types.Instruction{
//						system.NewTransferInstruction(lamports, acc.PublicKey, common.PublicKeyFromString(to)).Build(),
//					},
//				},
//			),
//			Signers: []types.Account{acc},
//		},
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//	tx.Sign([]types.Account{acc})
//	rawTx, err := tx.Serialize()
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println("签名后的原始交易:", base64.StdEncoding.EncodeToString(rawTx))
//	return base64.StdEncoding.EncodeToString(rawTx)
//}
//
//// 广播交易
//func broadcastTx(rawTxBase64 string, rpcURL string) {
//	c := client.NewClient(rpcURL)
//	rawTx, _ := base64.StdEncoding.DecodeString(rawTxBase64)
//	txHash, err := c.SendRawTransaction(context.Background(), rawTx)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println("广播成功，TxHash:", txHash)
//}
//
//func main() {
//	if len(os.Args) < 2 {
//		fmt.Println("用法: main.go [gen|sign|send]")
//		fmt.Println("\n命令说明:")
//		fmt.Println("  gen  : 生成 Solana 地址，并保存私钥到 solana_wallet.key")
//		fmt.Println("  sign : 离线签名交易，生成原始交易数据")
//		fmt.Println("         用法: main.go sign [to] [lamports] [recentBlockhash]")
//		fmt.Println("         示例: main.go sign 目标地址 100000 <recentBlockhash>")
//		fmt.Println("         说明: lamports=100000 即 0.0001 SOL，推荐用 Devnet 测试")
//		fmt.Println("  send : 广播已签名交易到链上")
//		fmt.Println("         用法: main.go send [rawTxBase64] [rpcURL]")
//		fmt.Println("         示例: main.go send <rawTxBase64> https://api.devnet.solana.com")
//		return
//	}
//	cmd := os.Args[1]
//	if cmd == "gen" {
//		// 生成 Solana 地址
//		// 用法: go run main.go gen
//		// 会自动生成新私钥并保存到 solana_wallet.key，同时输出地址
//		generateAddress()
//	} else if cmd == "sign" {
//		// 离线签名交易
//		// 用法: go run main.go sign [to] [lamports] [recentBlockhash]
//		// 示例: go run main.go sign 目标地址 100000 <recentBlockhash>
//		// 说明: lamports=100000 即 0.0001 SOL，recentBlockhash 可通过 RPC 获取
//		if len(os.Args) < 5 {
//			fmt.Println("用法: go run main.go sign [to] [lamports] [recentBlockhash]")
//			fmt.Println("示例: go run main.go sign 目标地址 100000 <recentBlockhash>")
//			return
//		}
//		to := os.Args[2]
//		lamports, _ := strconv.ParseUint(os.Args[3], 10, 64)
//		recentBlockhash := os.Args[4]
//		signTx(to, lamports, recentBlockhash)
//	} else if cmd == "send" {
//		// 广播已签名的原始交易
//		// 用法: go run main.go send [rawTxBase64] [rpcURL]
//		// 示例: go run main.go send <rawTxBase64> https://api.devnet.solana.com
//		if len(os.Args) < 4 {
//			fmt.Println("用法: go run main.go send [rawTxBase64] [rpcURL]")
//			fmt.Println("示例: go run main.go send <rawTxBase64> https://api.devnet.solana.com")
//			return
//		}
//		rawTxBase64 := os.Args[2]
//		rpcURL := os.Args[3]
//		broadcastTx(rawTxBase64, rpcURL)
//	}
//}
