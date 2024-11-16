package main

import (
	"crypto/sha256"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
)

// SignRequest represents the structure for signing data
// Required fields are enforced through form binding tags
type SignRequest struct {
	Data   string `form:"data" binding:"required"`   // Raw data to be signed
	Wallet string `form:"wallet" binding:"required"` // Wallet address for signing
}

func setupRouter() *gin.Engine {
	r := gin.Default()

	// Register API endpoints
	registerWalletEndpoints(r)
	registerSigningEndpoints(r)

	return r
}

// registerWalletEndpoints handles wallet-related routes
func registerWalletEndpoints(r *gin.Engine) {
	// Create new wallet - POST /wallet
	r.POST("/wallet", createWalletHandler)

	// Get all wallets - GET /wallets
	r.GET("/wallets", getAllWalletsHandler)
}

// registerSigningEndpoints handles signing-related routes
func registerSigningEndpoints(r *gin.Engine) {
	// Sign data with wallet - GET /sign
	r.GET("/sign", signDataHandler)
}

// Handler functions
func createWalletHandler(c *gin.Context) {
	address, err := GenerateNewWallet()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"address": address})
}

func getAllWalletsHandler(c *gin.Context) {
	addresses := GetAllWalletAddresses()
	c.JSON(http.StatusOK, gin.H{"wallets": addresses})
}

func signDataHandler(c *gin.Context) {
	// Validate request parameters
	var req SignRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameters"})
		return
	}

	// Hash the input data using SHA256
	hasher := sha256.New()
	hasher.Write([]byte(req.Data))
	hashedData := hasher.Sum(nil)

	// Convert hashed data to big.Int for signing
	messageInt := new(big.Int)
	messageInt.SetBytes(hashedData)

	// Perform distributed signing
	signature, err := DistibutedSigning(messageInt, req.Wallet)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"signature": signature})
}
