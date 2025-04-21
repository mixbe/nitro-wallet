package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"
)

type requestPlayload struct {
	ApiCall               string
	Aws_access_key_id     string
	Aws_secret_access_key string
	Aws_session_token     string
	KeyId                 string // this is for generateAccount
	ChainType             string // chain type (EVM, SOLANA, etc.)
	//this 3 is for sign
	EncryptedPrivateKey string
	EncryptedDataKey    string
	Transaction         string
}

type generateDataKeyResponse struct {
	datakey_plaintext_base64  string
	datakey_ciphertext_base64 string
}

type generateAccountResponse struct {
	EncryptedPrivateKey string
	Address             string
	EncryptedDataKey    string
}

func call_kms_generate_datakey(aws_access_key_id string, aws_secret_access_key string, aws_session_token string, keyId string) generateDataKeyResponse {
	var result generateDataKeyResponse
	cmd := exec.Command(
		"/app/kmstool_enclave_cli",
		"genkey",
		"--region", os.Getenv("REGION"),
		"--proxy-port", "8000",
		"--aws-access-key-id", aws_access_key_id,
		"--aws-secret-access-key", aws_secret_access_key,
		"--aws-session-token", aws_session_token,
		"--key-id", keyId,
		"--key-spec", "AES-256")

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Println("kms generate datakey error:", err)
	}

	datakey_split := strings.Split(out.String(), "\n")
	fmt.Println("KMS output:", out.String())
	fmt.Println("Split length:", len(datakey_split))

	if len(datakey_split) < 2 {
		fmt.Println("Error: KMS tool did not return expected output format")
		// Return empty result or handle the error appropriately
		return result
	}

	// Check if each line contains the expected format with a colon
	cipherParts := strings.Split(datakey_split[0], ":")
	if len(cipherParts) < 2 {
		fmt.Println("Error: Ciphertext line does not contain expected format")
		return result
	}

	plainParts := strings.Split(datakey_split[1], ":")
	if len(plainParts) < 2 {
		fmt.Println("Error: Plaintext line does not contain expected format")
		return result
	}

	datakeyCiphertext_base64 := strings.TrimSpace(cipherParts[1])
	datakeyPlaintext_base64 := strings.TrimSpace(plainParts[1])
	result.datakey_plaintext_base64 = datakeyPlaintext_base64
	result.datakey_ciphertext_base64 = datakeyCiphertext_base64

	return result
}

func call_kms_decrypt(aws_access_key_id string, aws_secret_access_key string, aws_session_token string, ciphertext string) string {
	cmd := exec.Command(
		"/app/kmstool_enclave_cli",
		"decrypt",
		"--region", os.Getenv("REGION"),
		"--proxy-port", "8000",
		"--aws-access-key-id", aws_access_key_id,
		"--aws-secret-access-key", aws_secret_access_key,
		"--aws-session-token", aws_session_token,
		"--ciphertext", ciphertext)

	fmt.Println("datakey:", ciphertext)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal("kms call", err)
	}
	result := out.String()
	fmt.Println("decrypt result:", result)
	return result
}

func generateAccount(aws_access_key_id string, aws_secret_access_key string, aws_session_token string, keyId string, chainType string) generateAccountResponse {
	var privateKeyBytes []byte
	var address string

	// Default to EVM if chainType is not specified
	if chainType == "" {
		chainType = "EVM"
	}

	// Convert to uppercase for consistent comparison
	chainType = strings.ToUpper(chainType)

	switch chainType {
	case "EVM":
		// Generate EVM address
		privateKey, err := crypto.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}

		privateKeyBytes = crypto.FromECDSA(privateKey)
		fmt.Println("SAVE BUT DO NOT SHARE THIS (Private Key):", hexutil.Encode(privateKeyBytes))

		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
		}

		publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
		fmt.Println("Public Key:", hexutil.Encode(publicKeyBytes))

		address = crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
		fmt.Println("EVM Address:", address)

	case "SOLANA":
		// Generate Solana address
		account := solana.NewWallet()
		privateKeyBytes = account.PrivateKey
		fmt.Println("SAVE BUT DO NOT SHARE THIS (Private Key):", base58.Encode(privateKeyBytes))

		address = account.PublicKey().String()
		fmt.Println("Solana Address:", address)

	default:
		log.Fatalf("Unsupported chain type: %s", chainType)
	}

	// Generate and encrypt data key using AWS KMS
	datakeys := call_kms_generate_datakey(aws_access_key_id, aws_secret_access_key, aws_session_token, keyId)
	datakey_plaintext_base64 := datakeys.datakey_plaintext_base64
	datakey_ciphertext_base64 := datakeys.datakey_ciphertext_base64

	datakey_plaintext, _ := base64.StdEncoding.DecodeString(datakey_plaintext_base64)

	// Encrypt the private key
	encryptedPrivateKey := encrypt([]byte(datakey_plaintext), string(privateKeyBytes))

	response := generateAccountResponse{
		EncryptedPrivateKey: encryptedPrivateKey,
		Address:             address,
		EncryptedDataKey:    datakey_ciphertext_base64,
	}
	return response
}

func sign(aws_access_key_id string, aws_secret_access_key string, aws_session_token string, encryptedDataKey string, encryptedPrivateKey string, transaction string, chainType string) []byte {
	// Decrypt the data key using AWS KMS
	datakey_plaintext_base64 := call_kms_decrypt(aws_access_key_id, aws_secret_access_key, aws_session_token, encryptedDataKey)
	datakey_plaintext_base64_string := strings.TrimSpace(strings.Split(datakey_plaintext_base64, ":")[1])
	datakey_plaintext, err := base64.StdEncoding.DecodeString(datakey_plaintext_base64_string)
	if err != nil {
		log.Fatal("datakey", err)
	}
	
	// Decrypt the private key using the data key
	private_key := decrypt(datakey_plaintext, encryptedPrivateKey)
	
	// Default to EVM if chainType is not specified
	if chainType == "" {
		chainType = "EVM"
	}
	
	// Convert to uppercase for consistent comparison
	chainType = strings.ToUpper(chainType)
	
	var signature []byte
	
	switch chainType {
	case "EVM":
		// EVM signing process
		privateKey, err := crypto.ToECDSA([]byte(private_key))
		if err != nil {
			log.Fatal("EVM privateKey error", err)
		}
		data := []byte(transaction)
		hash := crypto.Keccak256Hash(data)
		signature, err = crypto.Sign(hash.Bytes(), privateKey)
		if err != nil {
			log.Fatal("EVM signing error:", err)
		}
		fmt.Println("EVM signature hex:", hexutil.Encode(signature))
		
	case "SOLANA":
		// Solana signing process
		privKeyBytes := []byte(private_key)
		
		// Create a new Solana wallet from the private key
		account, err := solana.WalletFromPrivateKeyBytes(privKeyBytes)
		if err != nil {
			log.Fatal("Solana wallet creation error:", err)
		}
		
		// Sign the transaction data
		data := []byte(transaction)
		signature = ed25519.Sign(account.PrivateKey, data)
		fmt.Println("Solana signature base58:", base58.Encode(signature))
		
	default:
		log.Fatalf("Unsupported chain type for signing: %s", chainType)
	}
	
	fmt.Println("Signature bytes:", signature)
	return signature
}

func encrypt(key []byte, message string) string {
	//Create byte array from the input string
	plainText := []byte(message)

	//Create a new AES cipher using the key
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		log.Fatal(err)
	}

	//Make the cipher text a byte array of size BlockSize + the length of the message
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	//iv is the ciphertext up to the blocksize (16)
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
	}

	//Encrypt the data:
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//Return string encoded in base64
	return base64.RawStdEncoding.EncodeToString(cipherText)
}

func decrypt(key []byte, secure string) string {
	//Remove base64 encoding:
	cipherText, err := base64.RawStdEncoding.DecodeString(secure)

	//IF DecodeString failed, exit:
	if err != nil {
		log.Fatal(err)
	}

	//Create a new AES cipher with the key and encrypted message
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		log.Fatal(err)
	}

	//IF the length of the cipherText is less than 16 Bytes:
	if len(cipherText) < aes.BlockSize {
		fmt.Println("Ciphertext block size is too short!")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	//Decrypt the message
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText)
}

func main() {
	fmt.Println("Start nitro enclave vsock server...")

	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		log.Fatal(err)
	}
	// Bind socket to cid 16, port 5000.
	sockaddr := &unix.SockaddrVM{
		CID:  unix.VMADDR_CID_ANY,
		Port: 5000,
	}
	err = unix.Bind(fd, sockaddr)
	if err != nil {
		log.Fatal("Bind ", err)
	}
	// Listen for up to 32 incoming connections.
	err = unix.Listen(fd, 32)
	if err != nil {
		log.Fatal("Listen ", err)
	}

	for {
		nfd, fromSockAdde, err := unix.Accept(fd)
		if err != nil {
			log.Fatal("Accept ", err)
		}
		fmt.Println("fromSockAdde: ", fromSockAdde)
		fmt.Println("conn is: ", nfd)

		requestData := make([]byte, 4096)
		var playload requestPlayload

		n, err := unix.Read(nfd, requestData)
		if err != nil {
			log.Fatal("Accept ", err)
		}

		err = json.Unmarshal(requestData[:n], &playload)
		if err != nil {
			fmt.Println(err.Error())
		}

		fmt.Println("apicall:", playload.ApiCall)

		apiCall := playload.ApiCall
		fmt.Println(apiCall)

		if apiCall == "generateAccount" {
			// Default to EVM if ChainType is not specified
			chainType := playload.ChainType
			if chainType == "" {
				chainType = "EVM"
				fmt.Println("No chain type specified, defaulting to EVM")
			}
			fmt.Println("Generating account for chain type:", chainType)
			
			result := generateAccount(playload.Aws_access_key_id, playload.Aws_secret_access_key,
				playload.Aws_session_token, playload.KeyId, chainType)

			b, err := json.Marshal(result)
			if err != nil {
				fmt.Println(err)
			}
			//  send back to parent instance
			unix.Write(nfd, b)
			fmt.Println("generateAccount finished for chain type:", chainType)
		} else if apiCall == "sign" {
			// Default to EVM if ChainType is not specified
			chainType := playload.ChainType
			if chainType == "" {
				chainType = "EVM"
				fmt.Println("No chain type specified for signing, defaulting to EVM")
			}
			fmt.Println("Sign request for chain type:", chainType)
			
			result := sign(playload.Aws_access_key_id, playload.Aws_secret_access_key, playload.Aws_session_token,
				playload.EncryptedDataKey, playload.EncryptedPrivateKey, playload.Transaction, chainType)
			fmt.Println("result is:", result)
			unix.Write(nfd, result)
			fmt.Println("sign finished for chain type:", chainType)
		} else {
			fmt.Println("nothing to do")
		}
		unix.Close(nfd)
	}
}
