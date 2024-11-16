package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"

	"github.com/charles8200/tss-lib/common"
	"github.com/charles8200/tss-lib/ecdsa/keygen"
	"github.com/charles8200/tss-lib/ecdsa/signing"
	"github.com/charles8200/tss-lib/test"
	"github.com/charles8200/tss-lib/tss"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

// Constants for TSS configuration
const (
	// TestParticipants defines the total number of participants in the TSS setup
	// To modify these parameters, delete fixture files in test/_fixtures/ and rerun keygen test
	TestParticipants = 4
	TestThreshold    = TestParticipants / 2
)

// File path constants for test fixtures
const (
	testFixtureDirFormat  = "%s/_fixtures"
	testFixtureFileFormat = "keygen_data_%d.json"
)

// WalletData stores the TSS key shares and participant IDs for a wallet
type WalletData struct {
	GeneratedKeys []keygen.LocalPartySaveData
	SignIDs       tss.SortedPartyIDs
}

// Global wallet storage
var walletStore = make(map[string]WalletData)

func makeTestFixtureFilePath(partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}

func tryWriteTestFixtureFile(index int, data keygen.LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(index)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Errorf("unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			fmt.Errorf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			fmt.Errorf("unable to write to fixture file %s", fixtureFileName)
		}
		fmt.Errorf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		fmt.Errorf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}

func LoadKeygenTestFixtures(qty int, optionalStart ...int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]keygen.LocalPartySaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := start; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		for _, kbxj := range key.BigXj {
			kbxj.SetCurve(tss.S256())
		}
		key.ECDSAPub.SetCurve(tss.S256())
		keys = append(keys, key)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	for i, key := range keys {
		pMoniker := fmt.Sprintf("%d", i+start+1)
		partyIDs[i] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	return keys, sortedPIDs, nil
}

func LoadKeygenTestFixturesRandomSet(qty, fixtureCount int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]keygen.LocalPartySaveData, 0, qty)
	plucked := make(map[int]interface{}, qty)
	for i := 0; len(plucked) < qty; i = (i + 1) % fixtureCount {
		_, have := plucked[i]
		if pluck := rand.Float32() < 0.5; !have && pluck {
			plucked[i] = new(struct{})
		}
	}
	for i := range plucked {
		fixtureFilePath := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		for _, kbxj := range key.BigXj {
			kbxj.SetCurve(tss.S256())
		}
		key.ECDSAPub.SetCurve(tss.S256())
		keys = append(keys, key)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	j := 0
	for i := range plucked {
		key := keys[j]
		pMoniker := fmt.Sprintf("%d", i+1)
		partyIDs[j] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
		j++
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ShareID.Cmp(keys[j].ShareID) == -1 })
	return keys, sortedPIDs, nil
}
func LoadKeygenWithSignIDsOrRandom(keys []keygen.LocalPartySaveData, signIDs tss.SortedPartyIDs, randomQty int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	selectedKeys := []keygen.LocalPartySaveData{}
	selectedPartyIDs := tss.UnSortedPartyIDs{}

	if len(signIDs) > 0 {
		// Deterministic selection based on signIDs
		for _, pid := range signIDs {
			found := false
			for _, key := range keys {
				if key.ShareID.Cmp(pid.KeyInt()) == 0 { // Match PartyID with key's ShareID
					selectedKeys = append(selectedKeys, key)
					selectedPartyIDs = append(selectedPartyIDs, pid)
					found = true
					break
				}
			}
			if !found {
				return nil, nil, fmt.Errorf("no matching key found for PartyID: %s", pid.Id)
			}
		}
	} else {
		// Random selection if signIDs is empty
		if randomQty > len(keys) {
			return nil, nil, fmt.Errorf("requested random quantity (%d) exceeds available keys (%d)", randomQty, len(keys))
		}

		rand.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
		selectedKeys = keys[:randomQty]

		for i, key := range selectedKeys {
			pMoniker := fmt.Sprintf("Random-Party-%d", i+1)
			selectedPartyIDs = append(selectedPartyIDs, tss.NewPartyID(pMoniker, pMoniker, key.ShareID))
		}
	}

	// Sort the Party IDs for consistency
	sortedPIDs := tss.SortPartyIDs(selectedPartyIDs)

	return selectedKeys, sortedPIDs, nil
}

// DistibutedKeyGeneration performs the distributed key generation protocol
// Returns generated key shares, participant IDs, and any errors
func DistibutedKeyGeneration() ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	testThreshold := TestThreshold
	testParticipants := TestParticipants

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*keygen.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan keygen.LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	// startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *keygen.LocalParty
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), testThreshold)
		if i < len(fixtures) {
			P = keygen.NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*keygen.LocalParty)
		} else {
			P = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
		}
		parties = append(parties, P)
		go func(P *keygen.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
	var generatedKeys []keygen.LocalPartySaveData

keygen:
	for {
		// fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					fmt.Errorf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return nil, nil, errors.New("party tried to send a message to itself")
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, _ := save.OriginalIndex()

			// Collect the generated key
			generatedKeys = append(generatedKeys, save)

			// Display the public and private keys
			fmt.Printf("Party %d Public Key: %v\n", index, save.ECDSAPub)
			fmt.Printf("Party %d Private Key: %v\n", index, save.LocalPreParams)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				break keygen
			}
		}
	}

	return generatedKeys, pIDs, nil
}

// DistibutedSigning performs the distributed signing protocol
// Parameters:
//   - messageToSign: the message to be signed as a big.Int
//   - walletAddress: the address of the wallet to use for signing
//
// Returns the signature data and any errors
func DistibutedSigning(messageToSign *big.Int, walletAddress string) (common.SignatureData, error) {
	testThreshold := TestThreshold

	// Retrieve wallet data from store
	walletData, exists := walletStore[walletAddress]
	if !exists {
		return common.SignatureData{}, fmt.Errorf("wallet not found for address: %s", walletAddress)
	}

	generatedKeys := walletData.GeneratedKeys
	signIDs := walletData.SignIDs

	keys, signPIDs, err := LoadKeygenWithSignIDsOrRandom(generatedKeys, signIDs, testThreshold)

	fmt.Println("-----------------------------------: ", len(keys))
	if err != nil {
		common.Logger.Error("should load keygen fixtures")
		return common.SignatureData{}, err
	}

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	// init the parties
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*signing.LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), testThreshold)

		P := signing.NewLocalParty(messageToSign, params, keys[i], outCh, endCh).(*signing.LocalParty)
		parties = append(parties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var signature common.SignatureData
	var ended int32
signing:
	for {
		// fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(nil, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					common.Logger.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case sig := <-endCh:
			signature = sig
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				// common.Logger.Debug("Done. Received signature data from %d participants", ended)
				R := parties[0].Temp.BigR
				// r := parties[0].Temp.Rx
				// fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := common.ModInt(tss.S256().Params().N)

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.Temp.Si)
				}
				// fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				ok := ecdsa.Verify(&pk, messageToSign.Bytes(), R.X(), sumS)
				assert.True(nil, ok, "ecdsa verify must pass")
				// fmt.Print("ECDSA signing test done.")
				// END ECDSA verify
				break signing
			}
		}
	}

	return signature, nil
}

// aggregatePublicKeys combines multiple public key shares into a single public key
// Parameters:
//   - keys: array of LocalPartySaveData containing public key shares
//
// Returns the combined ECDSA public key
func aggregatePublicKeys(keys []keygen.LocalPartySaveData) *ecdsa.PublicKey {
	curve := tss.S256()
	combinedX, combinedY := big.NewInt(0), big.NewInt(0)

	for _, key := range keys {
		combinedX, combinedY = curve.Add(combinedX, combinedY, key.ECDSAPub.X(), key.ECDSAPub.Y())
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     combinedX,
		Y:     combinedY,
	}
}

// GenerateNewWallet creates a new TSS wallet with distributed key shares
// Returns the wallet's Ethereum-style address and any errors
func GenerateNewWallet() (string, error) {
	// Generate new TSS key shares
	generatedKeys, signIDs, err := DistibutedKeyGeneration()
	if err != nil {
		return "", fmt.Errorf("key generation failed: %w", err)
	}

	// Aggregate the public key
	combinedPublicKey := aggregatePublicKeys(generatedKeys)

	// Derive the Ethereum-like address
	pubKeyBytes := elliptic.Marshal(combinedPublicKey.Curve, combinedPublicKey.X, combinedPublicKey.Y)

	// Ethereum uses Keccak-256 (SHA3) hash, and the address is the last 20 bytes of the hash
	hasher := sha3.New256()
	hasher.Write(pubKeyBytes[1:]) // Skip the leading byte for uncompressed keys
	pubHash := hasher.Sum(nil)

	address := "0x" + hex.EncodeToString(pubHash[len(pubHash)-20:])

	// Store the wallet data
	walletStore[address] = WalletData{
		GeneratedKeys: generatedKeys,
		SignIDs:       signIDs,
	}

	// Optionally, save to disk for persistence
	if err := saveWalletStoreToDisk(); err != nil {
		return address, fmt.Errorf("wallet generated but failed to save to disk: %w", err)
	}

	return address, nil
}

// GetAllWalletAddresses returns a sorted list of all wallet addresses in the store
func GetAllWalletAddresses() []string {
	addresses := make([]string, 0, len(walletStore))
	for address := range walletStore {
		addresses = append(addresses, address)
	}

	// Sort addresses for consistent output
	sort.Strings(addresses)

	return addresses
}

// saveWalletStoreToDisk persists the wallet store to disk in JSON format
func saveWalletStoreToDisk() error {
	data, err := json.Marshal(walletStore)
	if err != nil {
		return fmt.Errorf("failed to marshal wallet store: %w", err)
	}

	// Save to a file in the same directory as the fixtures
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)
	walletStorePath := filepath.Join(fixtureDirName, "wallet_store.json")

	err = ioutil.WriteFile(walletStorePath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write wallet store to disk: %w", err)
	}

	return nil
}

func main() {

	r := setupRouter()

	// Run the server on port 8080
	if err := r.Run(":8080"); err != nil {
		panic(err)
	}
}
