package main

import (
	"context"
	"fmt"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

func main() {
	// Create a new account:
	account := solana.NewWallet()
	fmt.Println("account private key:", account.PrivateKey)
	fmt.Println("account public key:", account.PublicKey())

	client := rpc.New(rpc.DevNet_RPC)

	// Airdrop 1 SOL to the new account:
	out, err := client.RequestAirdrop(
		context.TODO(),
		account.PublicKey(),
		solana.LAMPORTS_PER_SOL*1,
		rpc.CommitmentFinalized,
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("airdrop transaction signature:", out)

}
