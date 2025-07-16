package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"sync"
	"os"
	"bufio"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

type Purpose = uint32

const (
	PurposeBIP44 Purpose = 0x8000002C // 44' BIP44
	PurposeBIP49 Purpose = 0x80000031 // 49' BIP49
	PurposeBIP84 Purpose = 0x80000054 // 84' BIP84
	PurposeBIP86 Purpose = 0x80000056 // 86' BIP86 //taprrot
)

type CoinType = uint32

var btcAddresses map[string]int
var ethAddresses map[string]int

const (
	CoinTypeBTC CoinType = 0x80000000
	CoinTypeETH CoinType = 0x8000003c
)

const (
	Apostrophe uint32 = 0x80000000 // 0'
)

type Key struct {
	Path     string
	bip32Key *bip32.Key
}

func (k *Key) Calculate(compress bool) (wif, address, segwitBech32, segwitNested, taproot string, err error) {
	prvKey, _ := btcec.PrivKeyFromBytes(k.bip32Key.Key)
	return CalculateFromPrivateKey(prvKey, compress)
}

type KeyManager struct {
	Mnemonic   string
	Passphrase string
	keys       map[string]*bip32.Key
	mux        sync.Mutex
}

func NewKeyManager(mnemonic, passphrase string) (*KeyManager, error) {
	if mnemonic == "" {
		entropy, err := bip39.NewEntropy(128)
		if err != nil {
			return nil, err
		}
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, err
		}
	}

	km := &KeyManager{
		Mnemonic:   mnemonic,
		Passphrase: passphrase,
		keys:       make(map[string]*bip32.Key, 0),
	}
	return km, nil
}

func (km *KeyManager) GetSeed() []byte {
	return bip39.NewSeed(km.Mnemonic, km.Passphrase)
}

func (km *KeyManager) getKey(path string) (*bip32.Key, bool) {
	km.mux.Lock()
	defer km.mux.Unlock()

	key, ok := km.keys[path]
	return key, ok
}

func (km *KeyManager) setKey(path string, key *bip32.Key) {
	km.mux.Lock()
	defer km.mux.Unlock()

	km.keys[path] = key
}

func (km *KeyManager) GetMasterKey() (*bip32.Key, error) {
	path := "m"

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	key, err := bip32.NewMasterKey(km.GetSeed())
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetPurposeKey(purpose uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'`, purpose-Apostrophe)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetMasterKey()
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(purpose)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetCoinTypeKey(purpose, coinType uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'`, purpose-Apostrophe, coinType-Apostrophe)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetPurposeKey(purpose)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(coinType)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetAccountKey(purpose, coinType, account uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'`, purpose-Apostrophe, coinType-Apostrophe, account)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetCoinTypeKey(purpose, coinType)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(account + Apostrophe)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetChangeKey(purpose, coinType, account, change uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d`, purpose-Apostrophe, coinType-Apostrophe, account, change)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetAccountKey(purpose, coinType, account)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(change)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetKey(purpose, coinType, account, change, index uint32) (*Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d/%d`, purpose-Apostrophe, coinType-Apostrophe, account, change, index)

	key, ok := km.getKey(path)
	if ok {
		return &Key{Path: path, bip32Key: key}, nil
	}

	parent, err := km.GetChangeKey(purpose, coinType, account, change)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(index)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return &Key{Path: path, bip32Key: key}, nil
}

func CalculateFromPrivateKey(prvKey *btcec.PrivateKey, compress bool) (wif, address, segwitBech32, segwitNested, taproot string, err error) {
	btcwif, err := btcutil.NewWIF(prvKey, &chaincfg.MainNetParams, compress)
	if err != nil {
		return "", "", "", "", "", err
	}
	wif = btcwif.String()

	serializedPubKey := btcwif.SerializePubKey()
	addressPubKey, err := btcutil.NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
	if err != nil {
		return "", "", "", "", "", err
	}
	address = addressPubKey.EncodeAddress()

	witnessProg := btcutil.Hash160(serializedPubKey)
	addressWitnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
	if err != nil {
		return "", "", "", "", "", err
	}
	segwitBech32 = addressWitnessPubKeyHash.EncodeAddress()

	serializedScript, err := txscript.PayToAddrScript(addressWitnessPubKeyHash)
	if err != nil {
		return "", "", "", "", "", err
	}
	addressScriptHash, err := btcutil.NewAddressScriptHash(serializedScript, &chaincfg.MainNetParams)
	if err != nil {
		return "", "", "", "", "", err
	}
	segwitNested = addressScriptHash.EncodeAddress()

	tapKey := txscript.ComputeTaprootKeyNoScript(prvKey.PubKey())
	addressTaproot, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), &chaincfg.MainNetParams)
	if err != nil {
		return "", "", "", "", "", err
	}
	taproot = addressTaproot.EncodeAddress()

	return wif, address, segwitBech32, segwitNested, taproot, nil
}

type WalletResult struct {
	Mnemonic     string
	Address      string
	PrivateKey	 string
}

func generateBtcWallet(mnemonic string, index int, results chan<- WalletResult, wg *sync.WaitGroup) {
	defer wg.Done()

	compress := true
	pass := ""

	km, err := NewKeyManager(mnemonic, pass)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; ; i++{
		{
			key, err := km.GetKey(PurposeBIP44, CoinTypeBTC, 0, 0, uint32(i))
			if err != nil {
				log.Fatal(err)
			}
			wif, address, _, _, _, err := key.Calculate(compress)
			if err != nil {
				log.Fatal(err)
			}

			exists := btcAddresses[address]

			if exists == 1 {
				results <- WalletResult{
					Mnemonic:     km.Mnemonic,
					Address:      address,
					PrivateKey:	  wif,
				}
				outFile, err := os.Create(address)
				if err != nil {
					fmt.Println("Error creating file:", err)
					return
				}
				defer outFile.Close()
			
				_, err = outFile.WriteString(km.Mnemonic)
				_, err = outFile.WriteString(wif)
				if err != nil {
					fmt.Println("Error writing to file:", err)
					return
				}
			}
			fmt.Println("Checked wallet:", address)
		}

		{
			key, err := km.GetKey(PurposeBIP49, CoinTypeBTC, 0, 0, uint32(i))
			if err != nil {
				log.Fatal(err)
			}
			wif, _, _, address, _, err := key.Calculate(compress)
			if err != nil {
				log.Fatal(err)
			}

			exists := btcAddresses[address]

			if exists == 1 {
				results <- WalletResult{
					Mnemonic:     km.Mnemonic,
					Address:      address,
					PrivateKey:	  wif,
				}
				outFile, err := os.Create(address)
				if err != nil {
					fmt.Println("Error creating file:", err)
					return
				}
				defer outFile.Close()
			
				_, err = outFile.WriteString(km.Mnemonic)
				_, err = outFile.WriteString(wif)
				if err != nil {
					fmt.Println("Error writing to file:", err)
					return
				}
			}
			fmt.Println("Checked wallet:", address)
		}

		{
			key, err := km.GetKey(PurposeBIP84, CoinTypeBTC, 0, 0, uint32(i))
			if err != nil {
				log.Fatal(err)
			}
			wif, _, address, _, _, err := key.Calculate(compress)
			if err != nil {
				log.Fatal(err)
			}

			exists := btcAddresses[address]

			if exists == 1 {
				results <- WalletResult{
					Mnemonic:     km.Mnemonic,
					Address:      address,
					PrivateKey:	  wif,
				}
				outFile, err := os.Create(address)
				if err != nil {
					fmt.Println("Error creating file:", err)
					return
				}
				defer outFile.Close()
			
				_, err = outFile.WriteString(km.Mnemonic)
				_, err = outFile.WriteString(wif)
				if err != nil {
					fmt.Println("Error writing to file:", err)
					return
				}
			}
			fmt.Println("Checked wallet:", address)
		}

		{
			key, err := km.GetKey(PurposeBIP86, CoinTypeBTC, 0, 0, uint32(i))
			if err != nil {
				log.Fatal(err)
			}
			wif, _, _, _, address, err := key.Calculate(compress)
			if err != nil {
				log.Fatal(err)
			}

			exists := btcAddresses[address]

			if exists == 1 {
				results <- WalletResult{
					Mnemonic:     km.Mnemonic,
					Address:      address,
					PrivateKey:	  wif,
				}
				outFile, err := os.Create(address)
				if err != nil {
					fmt.Println("Error creating file:", err)
					return
				}
				defer outFile.Close()
			
				_, err = outFile.WriteString(km.Mnemonic)
				_, err = outFile.WriteString(wif)
				if err != nil {
					fmt.Println("Error writing to file:", err)
					return
				}
			}
			fmt.Println("Checked wallet:", address)
		}
	}
}

func generateEthWallet(mnemonic string, index int, results chan<- WalletResult, wg *sync.WaitGroup) {
	defer wg.Done()

	pass := ""

	km, err := NewKeyManager(mnemonic, pass)
	if err != nil {
		log.Fatal(err)
	}
	
	for i := 0; ; i++{
		key, err := km.GetKey(PurposeBIP44, CoinTypeETH, 0, 0, uint32(i))
		if err != nil {
			log.Fatal(err)
		}

		address := strings.ToLower(strings.TrimPrefix(ethereumAddress(key.bip32Key.Key), "0x"))
		exists := ethAddresses[address]

		if exists == 1 {
			results <- WalletResult{
				Mnemonic:     km.Mnemonic,
				Address:      address,
				PrivateKey:	  "PK",
			}
			outFile, err := os.Create(address)
			if err != nil {
				fmt.Println("Error creating file:", err)
				return
			}
			defer outFile.Close()
		
			_, err = outFile.WriteString(km.Mnemonic)
			if err != nil {
				fmt.Println("Error writing to file:", err)
				return
			}
		}
		fmt.Println("Checked wallet:", address)
	}
}

func main() {
	var mnemonics string

	numWorkers := flag.Int("workers", 4, "Thread count")
	fileName := flag.String("wallets", "btc.txt", "Name of the file containing the wallet addresses")
	coinType := flag.Int("type", 0, "BTC - 0, Ethereum - 1")
	flag.Parse()

	file, err := os.Open("mnemonics.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		mnemonics = scanner.Text()
		parts := strings.Fields(mnemonics)
		if len(parts) != 12 {
			fmt.Printf("Invalid mnemonics!\n")
			return
		}
		break
	}

	if !bip39.IsMnemonicValid(mnemonics) {
		log.Fatal("Invalid mnemonic")
		return
	}

	//fmt.Println(mnemonicsIn)

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}

	if *coinType == 0 {
		btcAddresses = make(map[string]int)
		file, err := os.Open(*fileName)

		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Fields(line)
			if len(parts) != 2 {
				fmt.Printf("Skipping invalid line: %s\n", line)
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := 1
			btcAddresses[key] = value
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading file:", err)
		}
	} else {
		ethAddresses = make(map[string]int)
		file, err := os.Open(*fileName)

		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			key := strings.TrimSpace(line)
			value := 1
			ethAddresses[key] = value
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading file:", err)
		}
	}

	var wg sync.WaitGroup
	results := make(chan WalletResult, *numWorkers)

	// Start goroutines to generate wallets endlessly
	for i := 0; i < *numWorkers; i++ {
		wg.Add(1)
		if *coinType == 0 {
			go generateBtcWallet(mnemonics, i, results, &wg)
		} else {
			go generateEthWallet(mnemonics, i, results, &wg)
		}
	}

	// Print results as they come in
	go func() {
		for result := range results {
			fmt.Printf("Address: %s\n", result.Address)
		}
	}()

	wg.Wait()
}

func ethereumAddress(privateKeyBytes []byte) (address string) {
	_, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)

	publicKey := pubKey.ToECDSA()
	publicKeyBytes := append(publicKey.X.FillBytes(make([]byte, 32)), publicKey.Y.FillBytes(make([]byte, 32))...)

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes)
	addr := hash.Sum(nil)

	addr = addr[len(addr)-20:]

	return eip55checksum(fmt.Sprintf("0x%x", addr))
}

func eip55checksum(address string) string {
	buf := []byte(strings.ToLower(address))
	sha := sha3.NewLegacyKeccak256()
	sha.Write(buf[2:])
	hash := sha.Sum(nil)
	for i := 2; i < len(buf); i++ {
		hashByte := hash[(i-2)/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if buf[i] > '9' && hashByte > 7 {
			buf[i] -= 32
		}
	}
	return string(buf[:])
}