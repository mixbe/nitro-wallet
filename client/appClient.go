package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"golang.org/x/sys/unix"
)

// dynamodb design
// table name: AccountTable

// colume:
// keyId: kms alias id which used for encryption for the private key
// Name: account name for this Account
// encryptedPrivateKey: encrypted Account private key
// address: the address of the Account
// encryptedDataKey: the data key used to encrypt the private key

type accountTable struct {
	KeyId               string
	Name                string
	ChainType           string
	Address             string
	EncryptedDataKey    string
	EncryptedPrivateKey string
}

type accountClient struct {
	region           string
	ddbTableName     string
	keyId            string
	cid              uint32
	port             uint32
	defaultChainType string
}

type generateAccountResponse struct {
	EncryptedPrivateKey string
	Address             string
	EncryptedDataKey    string
}

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

func (ac accountClient) generateAccount(name string, chainType string) {
	credential := getIAMTokenV2()

	socket, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		log.Fatal(err)
	}

	sockaddr := &unix.SockaddrVM{
		CID:  ac.cid,
		Port: ac.port,
	}

	err = unix.Connect(socket, sockaddr)
	if err != nil {
		log.Fatal(err)
	}

	// If chainType is empty, use the default chain type
	if chainType == "" {
		chainType = ac.defaultChainType
		fmt.Println("Using default chain type:", chainType)
	}

	playload := requestPlayload{
		ApiCall:               "generateAccount",
		Aws_access_key_id:     credential.aws_access_key_id,
		Aws_secret_access_key: credential.aws_secret_access_key,
		Aws_session_token:     credential.aws_session_token,
		KeyId:                 ac.keyId,
		ChainType:             chainType,
		EncryptedPrivateKey:   "",
		EncryptedDataKey:      "",
		Transaction:           "",
	}

	// Send AWS credential and KMS keyId to the server running in enclave
	b, err := json.Marshal(playload)
	if err != nil {
		fmt.Println(err)
	}
	unix.Write(socket, b)

	// receive data from the server and save to dynamodb with the walletName
	response := make([]byte, 4096)
	n, err := unix.Read(socket, response)
	if err != nil {
		fmt.Println(err)
	}
	var responseStruct generateAccountResponse
	json.Unmarshal(response[:n], &responseStruct)

	ac.saveEncryptAccountToDDB(name, responseStruct, ac.keyId, chainType)

}

func (ac accountClient) saveEncryptAccountToDDB(name string, response generateAccountResponse, keyId string, chainType string) {
	// Create Session
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(ac.region)},
	)

	if err != nil {
		panic(err)
	}

	svc := dynamodb.New(sess)

	at := accountTable{
		Name:                name,
		KeyId:               keyId,
		ChainType:           chainType,
		Address:             response.Address,
		EncryptedPrivateKey: response.EncryptedPrivateKey,
		EncryptedDataKey:    response.EncryptedDataKey,
	}

	av, err := dynamodbattribute.MarshalMap(at)

	if err != nil {
		fmt.Println("Got error marshalling map:")
		fmt.Println(err.Error())
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(ac.ddbTableName),
	}

	_, err = svc.PutItem(input)
	if err != nil {
		fmt.Println("Got error calling PutItem:")
		fmt.Println(err.Error())
	}
	fmt.Println("account", name, "info is saved to dynamodb")
}

func (ac accountClient) sign(keyId string, name string, chainType string, transaction string) string {
	credential := getIAMTokenV2()
	// get item from dynamodb
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(ac.region)},
	)

	if err != nil {
		panic(err)
	}

	svc := dynamodb.New(sess)

	result, _ := svc.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(ac.ddbTableName),
		Key: map[string]*dynamodb.AttributeValue{
			"KeyId": {
				S: aws.String(keyId),
			},
			"Name": {
				S: aws.String(name),
			},
			"ChainType": {
				S: aws.String(chainType),
			},
		},
	})

	if err != nil {
		fmt.Println("ddb query err:", err)
	}

	var at accountTable
	err = dynamodbattribute.UnmarshalMap(result.Item, &at)
	if err != nil {
		panic(fmt.Sprintf("Failed to unmarshal Record, %v", err))
	}
	var encryptedDataKey = at.EncryptedDataKey
	var encryptedPrivateKey = at.EncryptedPrivateKey

	fmt.Println(at)

	socket, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		log.Fatal(err)
	}

	sockaddr := &unix.SockaddrVM{
		CID:  ac.cid,
		Port: ac.port,
	}

	err = unix.Connect(socket, sockaddr)
	if err != nil {
		log.Fatal(err)
	}

	playload := requestPlayload{
		ApiCall:               "sign",
		Aws_access_key_id:     credential.aws_access_key_id,
		Aws_secret_access_key: credential.aws_secret_access_key,
		Aws_session_token:     credential.aws_session_token,
		KeyId:                 "",
		ChainType:             chainType,
		EncryptedPrivateKey:   encryptedPrivateKey,
		EncryptedDataKey:      encryptedDataKey,
		Transaction:           transaction,
	}

	// Send AWS credential and KMS keyId to the server running in enclave
	b, err := json.Marshal(playload)
	if err != nil {
		log.Fatal(err)
	}
	unix.Write(socket, b)
	// receive data from the server and save to dynamodb with the walletName
	response := make([]byte, 4096)
	n, err := unix.Read(socket, response)
	if err != nil {
		fmt.Println(err)
	}
	signedValue := hexutil.Encode(response[:n])
	return signedValue
}

type iamCredentialResponse struct {
	aws_access_key_id     string
	aws_secret_access_key string
	aws_session_token     string
}

// struct of response from metadata get function
type iamCredentialToken struct {
	Code            string
	LastUpdated     string
	Type            string
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      string
}

/**
* get the credential of the IAM Role attached on EC2 using IMDSv1 (legacy method)
 */
func getIAMToken() iamCredentialResponse {
	var token iamCredentialResponse
	res, err := http.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err != nil {
		log.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	instanceProfileName := string(body)
	profileUri := fmt.Sprintf("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", instanceProfileName)
	res, err = http.Get(profileUri)
	if err != nil {
		log.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	var result iamCredentialToken
	json.Unmarshal(body, &result)
	token.aws_access_key_id = result.AccessKeyId
	token.aws_secret_access_key = result.SecretAccessKey
	token.aws_session_token = result.Token

	return token
}

/**
* get the credential of the IAM Role attached on EC2 using IMDSv2 (more secure method)
* IMDSv2 requires a session token to be included in the request headers
 */
func getIAMTokenV2() iamCredentialResponse {
	var token iamCredentialResponse
	
	// Step 1: Get a session token
	tokenTTL := "60" // Time to live in seconds
	tokenReq, err := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		log.Fatalf("Error creating token request: %v", err)
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", tokenTTL)
	
	tokenClient := &http.Client{Timeout: 2 * time.Second}
	tokenResp, err := tokenClient.Do(tokenReq)
	if err != nil {
		log.Fatalf("Error getting token: %v", err)
	}
	defer tokenResp.Body.Close()
	
	tokenBytes, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		log.Fatalf("Error reading token response: %v", err)
	}
	sessionToken := string(tokenBytes)
	
	// Step 2: Use the token to get the instance profile name
	profileReq, err := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil)
	if err != nil {
		log.Fatalf("Error creating profile request: %v", err)
	}
	profileReq.Header.Set("X-aws-ec2-metadata-token", sessionToken)
	
	profileResp, err := http.DefaultClient.Do(profileReq)
	if err != nil {
		log.Fatalf("Error getting instance profile: %v", err)
	}
	defer profileResp.Body.Close()
	
	profileBytes, err := io.ReadAll(profileResp.Body)
	if err != nil {
		log.Fatalf("Error reading profile response: %v", err)
	}
	instanceProfileName := string(profileBytes)
	
	// Step 3: Get the credentials using the token
	credentialsURL := fmt.Sprintf("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", instanceProfileName)
	credentialsReq, err := http.NewRequest("GET", credentialsURL, nil)
	if err != nil {
		log.Fatalf("Error creating credentials request: %v", err)
	}
	credentialsReq.Header.Set("X-aws-ec2-metadata-token", sessionToken)
	
	credentialsResp, err := http.DefaultClient.Do(credentialsReq)
	if err != nil {
		log.Fatalf("Error getting credentials: %v", err)
	}
	defer credentialsResp.Body.Close()
	
	credentialsBytes, err := io.ReadAll(credentialsResp.Body)
	if err != nil {
		log.Fatalf("Error reading credentials response: %v", err)
	}
	
	var result iamCredentialToken
	err = json.Unmarshal(credentialsBytes, &result)
	if err != nil {
		log.Fatalf("Error unmarshaling credentials: %v", err)
	}
	
	fmt.Println("Retrieved credentials using IMDSv2")
	
	token.aws_access_key_id = result.AccessKeyId
	token.aws_secret_access_key = result.SecretAccessKey
	token.aws_session_token = result.Token
	
	return token
}

/**	
* 创建 EVM 账户
* go run appClient.go account1 EVM
*
* 创建 Solana 账户
* go run appClient.go solana_account1 SOLANA
*/
func main() {
	region := "ap-northeast-1"
	keyId := "fb852884-e2f0-4a06-9bfe-edd5d0792b46"
	tableName := "AccountTable"
	
	// 默认账户名和链类型
	walletAccountName := "account1"
	chainType := "EVM"
	
	// 从命令行参数获取账户名和链类型
	if len(os.Args) > 1 {
		walletAccountName = os.Args[1]
		fmt.Println("使用命令行指定的账户名:", walletAccountName)
	}
	
	if len(os.Args) > 2 {
		chainType = strings.ToUpper(os.Args[2])
		fmt.Println("使用命令行指定的链类型:", chainType)
	}
	
	// 检查链类型是否有效
	if chainType != "EVM" && chainType != "SOLANA" {
		fmt.Println("错误: 链类型必须是 EVM 或 SOLANA")
		fmt.Println("用法: go run appClient.go [账户名] [链类型]")
		fmt.Println("示例: go run appClient.go account1 EVM")
		fmt.Println("示例: go run appClient.go solana_account1 SOLANA")
		return
	}
	
	// check dynamodb AccountTable exist or not, create it if not exists
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region)},
	)

	if err != nil {
		panic(err)
	}

	svc := dynamodb.New(sess)
	describe_input := &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	}

	result, err := svc.DescribeTable(describe_input)
	if err != nil {
		fmt.Println(err)
		fmt.Println(result)
		fmt.Println("create the table", tableName)
		create_input := &dynamodb.CreateTableInput{
			AttributeDefinitions: []*dynamodb.AttributeDefinition{
				{
					AttributeName: aws.String("KeyId"),
					AttributeType: aws.String("S"),
				},
				{
					AttributeName: aws.String("Name"),
					AttributeType: aws.String("S"),
				},
				{
					AttributeName: aws.String("ChainType"),
					AttributeType: aws.String("S"),
				},
			},
			KeySchema: []*dynamodb.KeySchemaElement{
				{
					AttributeName: aws.String("KeyId"),
					KeyType:       aws.String("HASH"),
				},
				{
					AttributeName: aws.String("Name"),
					KeyType:       aws.String("RANGE"),
				},
			},
			GlobalSecondaryIndexes: []*dynamodb.GlobalSecondaryIndex{
				{
					IndexName: aws.String("ChainTypeIndex"),
					KeySchema: []*dynamodb.KeySchemaElement{
						{
							AttributeName: aws.String("KeyId"),
							KeyType:       aws.String("HASH"),
						},
						{
							AttributeName: aws.String("ChainType"),
							KeyType:       aws.String("RANGE"),
						},
					},
					Projection: &dynamodb.Projection{
						ProjectionType: aws.String("ALL"),
					},
					ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
						ReadCapacityUnits:  aws.Int64(5),
						WriteCapacityUnits: aws.Int64(5),
					},
				},
			},
			ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(5),
				WriteCapacityUnits: aws.Int64(5),
			},
			TableName: aws.String(tableName),
		}
		
		result, err := svc.CreateTable(create_input)
		if err != nil {
			fmt.Println(err.Error())
			fmt.Println(result)
		}
		// sleep 10 second to wait for dynamodb creating
		time.Sleep(10 * 1000 * time.Millisecond)
	}

	// 设置默认链类型
	defaultChainType := "EVM"
	client := accountClient{region, tableName, keyId, 16, 5000, defaultChainType}
	
	// 生成账户
	fmt.Printf("正在为账户 %s 生成 %s 类型的地址...\n", walletAccountName, chainType)
	client.generateAccount(walletAccountName, chainType)
	fmt.Println("账户生成完成!")
	
	// 如果需要测试签名，取消下面的注释
	/*
	//测试签名
	transaction := map[string]interface{}{
		"value":    1000000000,
		"to":       "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
		"nonce":    0,
		"chainId":  4,
		"gas":      100000,
		"gasPrice": 234567897654321,
	}

	b := new(bytes.Buffer)
	for key, value := range transaction {
		fmt.Fprintf(b, "%s=\"%s\"\n", key, value)
	}

	// 签名
	signedValue := client.sign(keyId, walletAccountName, chainType, b.String())
	fmt.Println("签名结果:", signedValue)
	*/
}