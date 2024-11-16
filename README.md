# TSS Wallet Generator Service

A Golang-based server that generates Ethereum TSS (Threshold Signature Scheme) wallets using Multi-Party Computation (MPC). This service allows for distributed key generation and signing using the tss-lib library.

## Features

- Generate new Ethereum-style TSS wallets with distributed key shares
- List all generated wallets
- Sign data using distributed signing protocol
- Persistent wallet storage
- Threshold-based signing (t-of-n signatures)

## Prerequisites

- Go 1.16 or higher
- Git

## Installation

1. Clone the repository:

```bash
git clone https://github.com/charles8200/tss-lib
cd tss-lib
```

2. Install dependencies:

```bash
go mod tidy
```

## Configuration

The service uses the following default configuration:
- Total Participants: 4 (configurable in demo.go)
- Threshold: 2 (50% of participants)
- Server Port: 8080

To modify the TSS configuration, update the constants in `demo.go`:
```go
const (
    TestParticipants = 4
    TestThreshold    = TestParticipants / 2
)
```

## Running the Service

Start the server:
```bash
cd demo
go run demo.go server.go
```

The server will start on `http://localhost:8080`

## API Endpoints

### 1. Create New Wallet
Creates a new TSS wallet with distributed key shares.

```bash
curl -X POST http://localhost:8080/wallet
```

Response:
```json
{
    "address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
}
```

### 2. List All Wallets
Returns a list of all generated wallet addresses.

```bash
curl http://localhost:8080/wallets
```

Response:
```json
{
    "wallets": [
        "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
        "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199"
    ]
}
```

### 3. Sign Data
Signs data using a specified wallet's distributed key shares.

```bash
curl "http://localhost:8080/sign?data=HelloWorld&wallet=0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
```

Response:
```json
{
    "signature": {
        "signature":"8uSZkBWyNpWl+S3QWFsahFrUhE+bXo3EmNFiBJayXdRE7Gso2q49EZt/PfXEGIhaWhfy1rbwzICayxLpN0v3Pg==",
        "signature_recovery":"AA==",
        "r":"8uSZkBWyNpWl+S3QWFsahFrUhE+bXo3EmNFiBJayXdQ=","s":"ROxrKNquPRGbfz31xBiIWloX8ta28MyAmssS6TdL9z4=","m":"hy5OUM6ZkNiwQTMMR8nd0Rvsa1A66ThqmdqFhOm7EsQ="
    }
}
```

## Technical Details

### Architecture

#### 1. Web Framework (Gin)
- Uses Gin for high-performance HTTP routing and middleware support
- RESTful API endpoints for wallet creation, listing, and signing operations
- Request validation and error handling middleware
- JSON response formatting

#### 2. TSS Implementation
- Implements Threshold Signature Scheme (TSS) using tss-lib
- Configuration:
  - Default: 4 participants (TestParticipants)
  - Threshold: 2 participants (50% requirement for signing)
- Key components referenced in `demo.go`:

#### Key Components Detail

1. **Distributed Key Generation (DKG)**
   - Implements Pedersen DKG protocol
   - Secure communication between parties
   - Verifiable secret sharing
   - Threshold access control

2. **Threshold Signature Scheme**
   - t-of-n signature generation
   - ECDSA compatibility
   - Signature verification
   - Party coordination

3. **Ethereum Integration**
   - Compatible address format
   - Keccak-256 hashing
   - ECDSA signature format
   - Public key aggregation

4. **Storage System**
   - JSON serialization
   - File-based persistence
   - Atomic write operations
   - Error handling and recovery

5. **API Layer**
   - RESTful endpoints
   - Request validation
   - Error handling
   - JSON response formatting
