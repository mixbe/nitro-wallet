package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"golang.org/x/sys/unix"
)

// keyId: kms alias id which used for encryption for the private key
// Name: account name for this Account
// encryptedPrivateKey: encrypted Account private key
// address: the address of the Account
// encryptedDataKey: the data key used to encrypt the private key

type accountTable struct {
	KeyId               string
	Name                string
	Address             string
	EncryptedDataKey    string
	EncryptedPrivateKey string
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

type iamCredentialResponse struct {
	aws_access_key_id     string
	aws_secret_access_key string
	aws_session_token     string
}

type accountClient struct {
	region       string
	ddbTableName string // 表名前缀
	keyId        string
	cid          uint32 // CID for VSOCK
	port         uint32 // Port for VSOCK
	chainType    string
}

// 根据链类型获取表名
func (ac accountClient) getTableName(chainType string) string {
	return ac.ddbTableName + "_" + chainType
}

type generateAccountResponse struct {
	Address             string `json:"address"`
	EncryptedDataKey    string `json:"encryptedDataKey"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
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

	if tokenResp.StatusCode != 200 {
		log.Fatalf("Error getting token, status code: %d", tokenResp.StatusCode)
	}

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

	token.aws_access_key_id = result.AccessKeyId
	token.aws_secret_access_key = result.SecretAccessKey
	token.aws_session_token = result.Token

	return token
}

func (ac accountClient) generateAccount(name string, chainType string) {
	// 首先检查账户是否已存在
	existingAccount, exists := ac.checkAccountExists(name, chainType)
	if exists {
		fmt.Printf("账户 %s (链类型: %s) 已存在，地址: %s\n", name, chainType, existingAccount.Address)
		return
	}

	// 获取 IAM 凭证
	credential := getIAMTokenV2()

	// 创建 VSOCK 连接
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

	// 准备请求负载
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

	// 发送 AWS 凭证和 KMS keyId 到运行在 enclave 中的服务器
	b, err := json.Marshal(playload)
	if err != nil {
		fmt.Println(err)
		return
	}
	unix.Write(socket, b)

	// 接收来自服务器的数据并使用钱包名称保存到 DynamoDB
	response := make([]byte, 4096)
	n, err := unix.Read(socket, response)
	if err != nil {
		fmt.Println(err)
		return
	}
	var responseStruct generateAccountResponse
	err = json.Unmarshal(response[:n], &responseStruct)
	if err != nil {
		fmt.Println("解析响应失败:", err)
		return
	}

	// 保存账户信息到 DynamoDB
	ac.saveEncryptAccountToDDB(name, chainType, responseStruct)

	// 输出成功信息
	fmt.Printf("成功创建账户 %s (链类型: %s)，地址: %s\n", name, chainType, responseStruct.Address)
}

// 检查账户是否已存在于 DynamoDB 中
func (ac accountClient) checkAccountExists(name string, chainType string) (accountTable, bool) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(ac.region)},
	)
	if err != nil {
		fmt.Println("创建 AWS 会话失败:", err)
		return accountTable{}, false
	}

	svc := dynamodb.New(sess)

	// 获取特定链类型的表名
	tableName := ac.getTableName(chainType)

	// 准备查询参数
	result, err := svc.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"KeyId": {
				S: aws.String(ac.keyId),
			},
			"Name": {
				S: aws.String(name),
			},
		},
	})

	// 如果查询出错，返回 false
	if err != nil {
		fmt.Println("查询 DynamoDB 失败:", err)
		return accountTable{}, false
	}

	// 如果没有找到记录，返回 false
	if result.Item == nil || len(result.Item) == 0 {
		return accountTable{}, false
	}

	// 解析查询结果
	var account accountTable
	err = dynamodbattribute.UnmarshalMap(result.Item, &account)
	if err != nil {
		fmt.Println("解析 DynamoDB 结果失败:", err)
		return accountTable{}, false
	}

	return account, true
}

func (ac accountClient) saveEncryptAccountToDDB(name string, chainType string, response generateAccountResponse) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(ac.region)},
	)

	if err != nil {
		fmt.Println("Got error creating session:")
		fmt.Println(err.Error())
		return
	}

	svc := dynamodb.New(sess)

	// 获取特定链类型的表名
	tableName := ac.getTableName(chainType)

	// 准备保存的数据
	item := accountTable{
		KeyId:               ac.keyId,
		Name:                name,
		Address:             response.Address,
		EncryptedDataKey:    response.EncryptedDataKey,
		EncryptedPrivateKey: response.EncryptedPrivateKey,
	}

	av, err := dynamodbattribute.MarshalMap(item)

	if err != nil {
		fmt.Println("Got error marshalling map:")
		fmt.Println(err.Error())
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(tableName),
	}

	_, err = svc.PutItem(input)
	if err != nil {
		fmt.Println("Got error calling PutItem:")
		fmt.Println(err.Error())
	}
	fmt.Println("account", name, "info is saved to table", tableName)
}

func (ac accountClient) sign(keyId string, name string, chainType string, transaction string) string {
	// 获取 AWS 凭证
	credential := getIAMTokenV2()

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(ac.region)},
	)

	if err != nil {
		fmt.Println("Got error creating session:")
		fmt.Println(err.Error())
		return ""
	}

	svc := dynamodb.New(sess)

	// 获取特定链类型的表名
	tableName := ac.getTableName(chainType)

	// 使用表名和主键查询
	result, err := svc.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"KeyId": {
				S: aws.String(keyId),
			},
			"Name": {
				S: aws.String(name),
			},
		},
	})

	if err != nil {
		fmt.Println("DynamoDB 查询错误:", err)
		return ""
	}

	// 检查是否找到记录
	if result.Item == nil || len(result.Item) == 0 {
		fmt.Printf("未找到账户 KeyId=%s, Name=%s, ChainType=%s\n", keyId, name, chainType)
		return ""
	}

	// 解析查询结果
	var at accountTable
	err = dynamodbattribute.UnmarshalMap(result.Item, &at)
	if err != nil {
		fmt.Println("解析账户数据失败:", err)
		return ""
	}

	// 验证必要的字段是否存在
	if at.EncryptedDataKey == "" || at.EncryptedPrivateKey == "" {
		fmt.Println("账户数据不完整: 缺失加密私钥或数据密钥")
		return ""
	}

	// 创建 VSOCK 连接
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

	// 准备请求负载
	playload := requestPlayload{
		ApiCall:               "sign",
		Aws_access_key_id:     credential.aws_access_key_id,
		Aws_secret_access_key: credential.aws_secret_access_key,
		Aws_session_token:     credential.aws_session_token,
		KeyId:                 keyId,
		ChainType:             chainType,
		EncryptedPrivateKey:   at.EncryptedPrivateKey,
		EncryptedDataKey:      at.EncryptedDataKey,
		Transaction:           transaction,
	}

	// 发送请求到 enclave
	b, err := json.Marshal(playload)
	if err != nil {
		fmt.Println(err)
		return ""
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

// 创建按链类型分表的 DynamoDB 表
func createDynamoDBTable(region string, tableNamePrefix string, chainType string) {
	// 生成完整表名
	tableName := tableNamePrefix + "_" + chainType

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region)},
	)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	svc := dynamodb.New(sess)

	// 检查表是否已存在
	_, err = svc.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})

	if err != nil {
		// 如果表不存在，创建表
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
			},
			// 使用 KeyId 和 Name 作为复合主键
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
			ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(5),
				WriteCapacityUnits: aws.Int64(5),
			},
			TableName: aws.String(tableName),
		}

		// 创建表
		_, err := svc.CreateTable(create_input)
		if err != nil {
			fmt.Println("创建表失败:", err.Error())
			return // 如果创建表失败，直接返回
		}

		fmt.Println("表", tableName, "创建中，等待表变为活跃状态...")

		// 等待表变为活跃状态（使用轮询方式）
		for i := 0; i < 10; i++ { // 最多尝试 10 次，每次等待 3 秒
			describe, err := svc.DescribeTable(&dynamodb.DescribeTableInput{
				TableName: aws.String(tableName),
			})

			if err != nil {
				fmt.Println("检查表状态失败:", err.Error())
				time.Sleep(3 * time.Second)
				continue
			}

			if *describe.Table.TableStatus == "ACTIVE" {
				fmt.Println("表", tableName, "创建成功并已活跃")
				break
			}

			fmt.Println("表状态:", *describe.Table.TableStatus, "，继续等待...")
			time.Sleep(3 * time.Second)
		}
	} else {
		fmt.Println("表", tableName, "已存在")
	}
}

func main() {
	region := "ap-northeast-1"
	keyId := "fb852884-e2f0-4a06-9bfe-edd5d0792b46"
	tableNamePrefix := "AccountTable"

	walletAccountName := "account1"
	chainType := "EVM"

	if len(os.Args) > 1 {
		walletAccountName = os.Args[1]
		fmt.Println("使用命令行指定的账户名:", walletAccountName)
	}

	if len(os.Args) > 2 {
		chainType = strings.ToUpper(os.Args[2])
		fmt.Println("使用命令行指定的链类型:", chainType)
	}

	if chainType != "EVM" && chainType != "SOLANA" {
		fmt.Println("错误: 链类型必须是 EVM 或 SOLANA")
		fmt.Println("用法: go run appClient.go [账户名] [链类型]")
		fmt.Println("示例: go run appClient.go account1 EVM")
		fmt.Println("示例: go run appClient.go solana_account1 SOLANA")
		return
	}

	createDynamoDBTable(region, tableNamePrefix, chainType)

	// 创建客户端实例
	client := accountClient{
		region:       region,
		ddbTableName: tableNamePrefix,
		keyId:        keyId,
		cid:          16,   // CID for VSOCK
		port:         5000, // Port for VSOCK
		chainType:    chainType,
	}

	// 生成账户
	fmt.Printf("正在为账户 %s 生成 %s 类型的地址...\n", walletAccountName, chainType)
	client.generateAccount(walletAccountName, chainType)
	fmt.Println("账户生成完成!")

	// 如果需要测试签名，取消下面的注释

	//测试签名
	transaction := map[string]interface{}{
		"value":    10000000000000,
		"to":       "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
		"nonce":    0,
		"chainId":  97,
		"gas":      21000,
		"gasPrice": 10,
	}

	b := new(bytes.Buffer)
	for key, value := range transaction {
		fmt.Fprintf(b, "%s=\"%v\"\n", key, value)
	}

	// 签名
	signedValue := client.sign(keyId, walletAccountName, chainType, b.String())
	fmt.Println("Signed Response:", signedValue)
}
