package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
)

// 派生路径常量
const (
	BTCPath      = "m/44'/0'/0'/0/0"  // BIP44 比特币路径
	BTCBip84Path = "m/84'/0'/0'/0/0"  // BIP84 比特币原生隔离见证路径
	BTCBip86Path = "m/86'/0'/0'/0/0"  // BIP86 比特币Taproot路径
	ETHPath      = "m/44'/60'/0'/0/0" // BIP44 以太坊路径
)

var rootCmd = &cobra.Command{
	Use:   "safewallet",
	Short: "一个多链钱包工具",
	Long:  `一个支持BTC、ETH、SOL的钱包工具，可以生成或导入助记词，并显示对应的私钥和地址。`,
}

var newCmd = &cobra.Command{
	Use:   "new",
	Short: "生成新的助记词",
	Run: func(cmd *cobra.Command, args []string) {
		// 获取助记词长度参数
		wordCount, _ := cmd.Flags().GetInt("words")

		// 根据单词数量确定熵的大小
		var entropySize int
		switch wordCount {
		case 12:
			entropySize = 128
		case 24:
			entropySize = 256
		default:
			log.Printf("助记词长度只能是12或24个单词，如果指定的助记词长度不是这两个数，默认生成12位长度的助记词")
			entropySize = 128
		}

		// 生成新的助记词
		entropy, err := bip39.NewEntropy(entropySize)
		if err != nil {
			log.Fatal(err)
		}
		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			log.Fatal(err)
		}

		// 打印钱包信息
		printWalletInfo(mnemonic)
	},
}

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "导入已有的助记词",
	Run: func(cmd *cobra.Command, args []string) {
		mnemonic, _ := cmd.Flags().GetString("mnemonic")
		if mnemonic == "" {
			fmt.Println("请提供助记词")
			os.Exit(1)
		}

		// 验证助记词
		if !bip39.IsMnemonicValid(mnemonic) {
			fmt.Println("无效的助记词")
			os.Exit(1)
		}

		// 打印钱包信息
		printWalletInfo(mnemonic)
	},
}

func init() {
	// 添加子命令
	rootCmd.AddCommand(newCmd)
	rootCmd.AddCommand(importCmd)

	// 添加 import 命令的 flags
	importCmd.Flags().StringP("mnemonic", "m", "", "指定的助记词")
	importCmd.MarkFlagRequired("mnemonic")

	// 修改 newCmd 的 flags
	newCmd.Flags().IntP("words", "w", 12, "助记词的长度，12或24")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// 打印钱包信息的函数
func printWalletInfo(mnemonic string) {
	fmt.Println("助记词:", mnemonic)

	// 将助记词转换为种子
	seed := bip39.NewSeed(mnemonic, "")
	fmt.Printf("种子: %x\n", seed)

	// 生成 BTC Legacy私钥和地址
	btcPrivateKey, err := generateBTCPrivateKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	// 转换为WIF格式
	wifLegacy, err := btcutil.NewWIF(btcPrivateKey, &chaincfg.MainNetParams, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BTC Legacy私钥(WIF): %s\n", wifLegacy.String())

	btcAddress, err := generateBTCAddress(btcPrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BTC Legacy地址: %s\n", btcAddress)

	// 生成BTC Native SegWit私钥和地址
	btcBip84PrivKey, err := generateBTCBip84PrivateKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	// 转换为WIF格式
	wifSegWit, err := btcutil.NewWIF(btcBip84PrivKey, &chaincfg.MainNetParams, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BTC SegWit私钥(WIF): %s\n", wifSegWit.String())

	bip84Address, err := generateBTCBip84Address(btcBip84PrivKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BTC Native SegWit地址: %s\n", bip84Address)

	// 生成BTC Taproot私钥和地址
	btcBip86PrivKey, err := generateBTCBip86PrivateKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	// 转换为WIF格式
	wifTaproot, err := btcutil.NewWIF(btcBip86PrivKey, &chaincfg.MainNetParams, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BTC Taproot私钥(WIF): %s\n", wifTaproot.String())

	taprootAddress, err := generateBTCTaprootAddress(btcBip86PrivKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("BTC Taproot地址: %s\n", taprootAddress)

	// 生成 ETH 私钥和地址
	ethPrivateKey, err := generateETHPrivateKey(seed)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ETH 私钥: %x\n", ethPrivateKey.D.Bytes())

	ethAddress := crypto.PubkeyToAddress(ethPrivateKey.PublicKey)
	fmt.Printf("ETH 地址: %s\n", ethAddress.Hex())
}

// 生成比特币地址
func generateBTCAddress(privateKey *btcec.PrivateKey) (string, error) {
	publicKey := privateKey.PubKey()
	pubKeyHash := btcutil.Hash160(publicKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// 生成比特币私钥
func generateBTCPrivateKey(seed []byte) (*btcec.PrivateKey, error) {
	// 使用 btcd 的测试网络参数
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	// 手动解析路径并派生
	path := []uint32{
		44 + hdkeychain.HardenedKeyStart, // purpose
		0 + hdkeychain.HardenedKeyStart,  // coin type
		0 + hdkeychain.HardenedKeyStart,  // account
		0,                                // change
		0,                                // address index
	}

	key := masterKey
	for _, n := range path {
		key, err = key.Derive(n)
		if err != nil {
			return nil, err
		}
	}
	return key.ECPrivKey()
}

// 生成以太坊私钥
func generateETHPrivateKey(seed []byte) (*ecdsa.PrivateKey, error) {
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	// 手动解析路径并派生
	path := []uint32{
		44 + hdkeychain.HardenedKeyStart, // purpose
		60 + hdkeychain.HardenedKeyStart, // coin type (60 for ETH)
		0 + hdkeychain.HardenedKeyStart,  // account
		0,                                // change
		0,                                // address index
	}

	key := masterKey
	for _, n := range path {
		key, err = key.Derive(n)
		if err != nil {
			return nil, err
		}
	}

	btcPrivKey, err := key.ECPrivKey()
	if err != nil {
		return nil, err
	}
	return crypto.ToECDSA(btcPrivKey.Serialize())
}

// 生成BIP84比特币私钥
func generateBTCBip84PrivateKey(seed []byte) (*btcec.PrivateKey, error) {
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	path := []uint32{
		84 + hdkeychain.HardenedKeyStart, // purpose
		0 + hdkeychain.HardenedKeyStart,  // coin type
		0 + hdkeychain.HardenedKeyStart,  // account
		0,                                // change
		0,                                // address index
	}

	key := masterKey
	for _, n := range path {
		key, err = key.Derive(n)
		if err != nil {
			return nil, err
		}
	}
	return key.ECPrivKey()
}

// 生成BIP84比特币地址
func generateBTCBip84Address(privateKey *btcec.PrivateKey) (string, error) {
	publicKey := privateKey.PubKey()
	witnessProg := btcutil.Hash160(publicKey.SerializeCompressed())

	// 创建原生隔离见证地址（bc1开头）
	addr, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}

	return addr.EncodeAddress(), nil
}

// 修改生成BIP86私钥的函数
func generateBTCBip86PrivateKey(seed []byte) (*btcec.PrivateKey, error) {
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	// BIP86派生路径: m/86'/0'/0'/0/0
	path := []uint32{
		86 + hdkeychain.HardenedKeyStart, // purpose
		0 + hdkeychain.HardenedKeyStart,  // coin type
		0 + hdkeychain.HardenedKeyStart,  // account
		0,                                // change
		0,                                // address index
	}

	key := masterKey
	for _, n := range path {
		key, err = key.Derive(n)
		if err != nil {
			return nil, err
		}
	}

	return key.ECPrivKey()
}

// 修改生成BIP86比特币地址的函数
func generateBTCTaprootAddress(privateKey *btcec.PrivateKey) (string, error) {
	// 获取内部公钥
	internalKey := privateKey.PubKey()

	// 创建Taproot输出密钥 (使用 ComputeTaprootKeyNoScript 替代)
	tapKey := txscript.ComputeTaprootKeyNoScript(internalKey)

	// 创建Taproot地址
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), &chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}

	return addr.EncodeAddress(), nil
}
