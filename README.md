# Nitro Wallet - Secure Blockchain Wallet using AWS Nitro Enclaves

Nitro Wallet is a secure blockchain wallet application built on AWS Nitro Enclaves and EKS. It leverages the secure enclave technology to provide hardware-level isolation for cryptographic operations, ensuring that private keys never leave the secure environment.

## Features

- **Multi-Chain Support**: Generate and manage addresses for multiple blockchain networks
  - EVM-compatible chains (Ethereum, Binance Smart Chain, etc.)
  - Solana blockchain
- **Secure Key Management**: Private keys are generated and stored within AWS Nitro Enclaves
- **AWS KMS Integration**: Uses AWS KMS for encryption and decryption of sensitive data
- **Transaction Signing**: Sign blockchain transactions securely within the enclave
- **DynamoDB Storage**: Account information stored in AWS DynamoDB with secure encryption

## Architecture

The application consists of two main components:

### 1. Enclave Server (`/enclave`)

The enclave server runs inside an AWS Nitro Enclave and is responsible for:
- Generating blockchain addresses (EVM and Solana)
- Securely storing private keys (encrypted)
- Signing transactions
- Communicating with AWS KMS for encryption/decryption operations

### 2. Client Application (`/client`)

The client application runs on the host instance and is responsible for:
- Communicating with the enclave server via VSOCK
- Managing account information in DynamoDB
- Providing an interface for generating addresses and signing transactions
- Handling AWS IAM authentication

## Prerequisites

- AWS account with access to Nitro Enclaves and EKS
- AWS IAM role with appropriate permissions for KMS and DynamoDB
- Go 1.23 or higher
- Docker (for building the enclave image)

## Setup and Installation

### Building the Enclave Image

1. Navigate to the enclave directory:
   ```
   cd enclave
   ```

2. Build the Docker image:
   ```
   docker build -t nitro-wallet-enclave .
   ```

3. Convert the Docker image to an Enclave Image File (EIF):
   ```
   nitro-cli build-enclave --docker-uri nitro-wallet-enclave:latest --output-file nitro-wallet-enclave.eif
   ```

### Running the Enclave

1. Run the enclave with the EIF file:
   ```
   nitro-cli run-enclave --eif-path nitro-wallet-enclave.eif --memory 2048 --cpu-count 2
   ```

2. Verify that the enclave is running:
   ```
   nitro-cli describe-enclaves
   ```

### Building and Running the Client

1. Navigate to the client directory:
   ```
   cd client
   ```

2. Build the client application:
   ```
   go build -o nitro-wallet-client
   ```

3. Run the client application:
   ```
   ./nitro-wallet-client
   ```

## Usage

### Generating a New Account

To generate a new blockchain account, use the client application with the following parameters:

```go
// For EVM (Ethereum) account
client.generateAccount("account_name", "EVM")

// For Solana account
client.generateAccount("account_name", "SOLANA")
```

This will:
1. Generate a new key pair within the enclave
2. Encrypt the private key using AWS KMS
3. Store the encrypted private key and public address in DynamoDB

### Signing a Transaction

To sign a transaction, use the client application with the following parameters:

```go
// For EVM (Ethereum) transaction
signedValue := client.sign(keyId, accountName, "EVM", transactionData)

// For Solana transaction
signedValue := client.sign(keyId, accountName, "SOLANA", transactionData)
```

This will:
1. Retrieve the encrypted private key from DynamoDB
2. Send the encrypted private key and transaction data to the enclave
3. The enclave will decrypt the private key and sign the transaction
4. Return the signed transaction to the client

## DynamoDB Schema

The application uses a DynamoDB table with the following schema:

- **Table Name**: AccountTable
- **Primary Key**: 
  - Partition Key: KeyId (String) - KMS key ID used for encryption
  - Sort Key: Name (String) - Account name
- **Global Secondary Index**: ChainTypeIndex
  - Partition Key: KeyId (String)
  - Sort Key: ChainType (String)
- **Attributes**:
  - KeyId (String) - KMS key ID used for encryption
  - Name (String) - Account name
  - ChainType (String) - Blockchain type (EVM, SOLANA, etc.)
  - Address (String) - Public blockchain address
  - EncryptedPrivateKey (String) - Encrypted private key
  - EncryptedDataKey (String) - Encrypted data key from KMS

## Security Considerations

- Private keys are generated and never leave the Nitro Enclave in unencrypted form
- AWS KMS is used for key encryption with envelope encryption
- Communication between the client and enclave is done via secure VSOCK channels
- The enclave has no direct network access, enhancing security

## Extending Support for Additional Blockchains

To add support for additional blockchain networks:

1. Update the `enclaveServer.go` file to include the new chain type in the switch statement
2. Implement the address generation and transaction signing logic for the new chain
3. Add the appropriate SDK dependencies to the `go.mod` file
4. Update the client code to support the new chain type

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
