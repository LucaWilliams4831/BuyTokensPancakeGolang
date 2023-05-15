package main

import (
	"buytokenspancakegolang/genericutils"
	"buytokenspancakegolang/models"
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	ierc20 "buytokenspancakegolang/contracts/IERC20"
	pancakeFactory "buytokenspancakegolang/contracts/IPancakeFactory"
	pancakePair "buytokenspancakegolang/contracts/IPancakePair"
	pancakeRouter "buytokenspancakegolang/contracts/IPancakeRouter02"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fatih/color"
	"github.com/hrharder/go-gas"
	"github.com/mattn/go-colorable"
	"github.com/nikola43/web3golanghelper/web3helper"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Create SprintXxx functions to mix strings with other non-colorized strings:
var yellow = color.New(color.FgYellow).SprintFunc()
var red = color.New(color.FgRed).SprintFunc()
var cyan = color.New(color.FgCyan).SprintFunc()
var green = color.New(color.FgGreen).SprintFunc()

type Wallet struct {
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
}
type Reserve struct {
	Reserve0           *big.Int
	Reserve1           *big.Int
	BlockTimestampLast uint32
}

func main() {

	//GenerateWallet()
	fmt.Println(parseDateTime())
	getWallets()

	// Declarations
	web3GolangHelper := initWeb3()
	db := InitDatabase()
	//migrate(db)
	factoryAddress := "0xB7926C0430Afb07AA7DEfDE6DA862aE0Bde767bc"
	factoryAbi, _ := abi.JSON(strings.NewReader(string(pancakeFactory.PancakeABI)))

	// LOGIC -----------------------------------------------------------
	checkTokens(db, web3GolangHelper)
	proccessEvents(db, web3GolangHelper, factoryAddress, factoryAbi)
}

func proccessEvents(db *gorm.DB, web3GolangHelper *web3helper.Web3GolangHelper, contractAddress string, contractAbi abi.ABI) {

	logs := make(chan types.Log)
	sub := BuildContractEventSubscription(web3GolangHelper, contractAddress, logs)

	for {
		select {
		case err := <-sub.Err():
			fmt.Println(err)
			//out <- err.Error()

		case vLog := <-logs:
			fmt.Println("vLog.TxHash: " + vLog.TxHash.Hex())
			res, err := contractAbi.Unpack("PairCreated", vLog.Data)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(res)

			InsertNewEvent(db, res, vLog)
		}
	}
}

func initWeb3() *web3helper.Web3GolangHelper {
	pk := "b366406bc0b4883b9b4b3b41117d6c62839174b7d21ec32a5ad0cc76cb3496bd"
	rpcUrl := "https://speedy-nodes-nyc.moralis.io/84a2745d907034e6d388f8d6/bsc/testnet"
	wsUrl := "wss://speedy-nodes-nyc.moralis.io/84a2745d907034e6d388f8d6/bsc/testnet/ws"
	web3GolangHelper := web3helper.NewWeb3GolangHelper(rpcUrl, wsUrl, pk)

	chainID, err := web3GolangHelper.HttpClient().NetworkID(context.Background())
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Chain Id: " + chainID.String())
	return web3GolangHelper
}

func BuildContractEventSubscription(web3GolangHelper *web3helper.Web3GolangHelper, contractAddress string, logs chan types.Log) ethereum.Subscription {

	query := ethereum.FilterQuery{
		Addresses: []common.Address{common.HexToAddress(contractAddress)},
	}

	sub, err := web3GolangHelper.WebSocketClient().SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		fmt.Println(sub)
	}
	return sub
}

func InitDatabase() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	return db
}

func migrate(db *gorm.DB) {
	db.Migrator().DropTable(&models.EventsCatched{})
	db.Migrator().DropTable(&models.LpPair{})
	db.Migrator().CreateTable(&models.LpPair{})
	db.Migrator().CreateTable(&models.EventsCatched{})
}

func InsertNewEvent(db *gorm.DB, newEvent []interface{}, vLog types.Log) bool {
	wBnbContractAddress := "0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd"

	tokenAddressA := vLog.Topics[0]
	tokenAddressB := vLog.Topics[1]

	event := new(models.EventsCatched)
	lpPairs := make([]*models.LpPair, 0)
	lpPairs = append(lpPairs, &models.LpPair{
		LPAddress:    newEvent[0].(common.Address).Hex(),
		LPPairA:      tokenAddressA.String(),
		LPPairB:      tokenAddressB.String(),
		HasLiquidity: false,
	})

	event.TxHash = vLog.TxHash.Hex()
	event.LPPairs = lpPairs
	if tokenAddressA.Hex() != wBnbContractAddress {
		event.TokenAddress = tokenAddressA.Hex()
	} else {
		event.TokenAddress = tokenAddressB.Hex()
	}

	db.Create(event)

	return true
}

func UpdateLiquidity(db *gorm.DB, eventID uint) bool {
	lpPair := new(models.LpPair)
	db.Where(&lpPair, "events_catched_id = ?", eventID).Update("has_liquidity", 1)

	return true
}

func UpdateName(db *gorm.DB, token string, name string) bool {
	event := new(models.EventsCatched)
	db.Where(&event, "token_address = ?", token).Update("token_name", 1)

	return true
}

func checkTokens(db *gorm.DB, web3GolangHelper *web3helper.Web3GolangHelper) {
	events := make([]*models.EventsCatched, 0)
	db.Find(&events)
	lo.ForEach(events, func(element *models.EventsCatched, _ int) {
		printTokenStatus(element)
		updateTokenStatus(db, web3GolangHelper, element)
	})

}

func Buy(web3GolangHelper *web3helper.Web3GolangHelper, tokenAddress string) {
	// contract addresses
	pancakeContractAddress := common.HexToAddress("0x9Ac64Cc6e4415144C455BD8E4837Fea55603e5c3") // pancake router address
	wBnbContractAddress := "0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd"                         // wbnb token adddress
	tokenContractAddress := common.HexToAddress(tokenAddress)                                   // eth token adddress

	// create pancakeRouter pancakeRouterInstance
	pancakeRouterInstance, instanceErr := pancakeRouter.NewPancake(pancakeContractAddress, web3GolangHelper.HttpClient())
	if instanceErr != nil {
		fmt.Println(instanceErr)
	}
	fmt.Println("pancakeRouterInstance contract is loaded")

	// calculate gas and gas limit
	gasLimit := uint64(2100000) // in units
	gasPrice, gasPriceErr := gas.SuggestGasPrice(gas.GasPriorityAverage)
	if gasPriceErr != nil {
		fmt.Println(gasPriceErr)
	}

	fmt.Println(

		wBnbContractAddress,
		tokenContractAddress,
		pancakeRouterInstance,
		gasLimit,
		gasPrice,
	)

	// calculate fee and final value
	gasFee := web3helper.CalcGasCost(gasLimit, gasPrice)
	ethValue := web3helper.EtherToWei(big.NewFloat(0.1))
	finalValue := big.NewInt(0).Sub(ethValue, gasFee)

	// set transaction data
	transactor := web3GolangHelper.BuildTransactor(finalValue, gasPrice, gasLimit)
	amountOutMin := big.NewInt(1.0)
	deadline := big.NewInt(time.Now().Unix() + 10000)
	path := web3helper.GeneratePath(wBnbContractAddress, tokenContractAddress.Hex())

	swapTx, SwapExactETHForTokensErr := pancakeRouterInstance.SwapExactETHForTokensSupportingFeeOnTransferTokens(
		transactor,
		amountOutMin,
		path,
		*web3GolangHelper.FromAddress,
		deadline)
	if SwapExactETHForTokensErr != nil {
		fmt.Println("SwapExactETHForTokensErr")
		fmt.Println(SwapExactETHForTokensErr)
	}

	fmt.Println(swapTx)

	txHash := swapTx.Hash().Hex()
	fmt.Println(txHash)
	genericutils.OpenBrowser("https://testnet.bscscan.com/tx/" + txHash)

}

/*
   function swapExactETHForTokensSupportingFeeOnTransferTokens(
       uint amountOutMin,
       address[] calldata path,
       address to,
       uint deadline
   ) external payable;
*/

func BuyV2(web3GolangHelper *web3helper.Web3GolangHelper, tokenAddress string, value *big.Int) {
	toAddress := common.HexToAddress("0x9Ac64Cc6e4415144C455BD8E4837Fea55603e5c3")
	wBnbContractAddress := "0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd"

	transferFnSignature := []byte("swapExactETHForTokensSupportingFeeOnTransferTokens(uint,address[],address,uint)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]

	path := web3helper.GeneratePath(wBnbContractAddress, tokenAddress)
	pathString := []string{path[0].Hex(), path[1].Hex()}

	deadline := big.NewInt(time.Now().Unix() + 10000)
	buf := &bytes.Buffer{}
	gob.NewEncoder(buf).Encode(pathString)
	bs := buf.Bytes()
	fmt.Printf("%q", bs)

	paddedAmountOutMin := common.LeftPadBytes(value.Bytes(), 32)
	paddedPathA := common.LeftPadBytes(path[0].Bytes(), 32)
	paddedPathB := common.LeftPadBytes(path[1].Bytes(), 32)
	paddedPath := common.LeftPadBytes(bs, 32)
	paddedTo := common.LeftPadBytes(toAddress.Bytes(), 32)
	paddedDeadline := common.LeftPadBytes(deadline.Bytes(), 32)

	fmt.Println("paddedAmountOutMin", paddedAmountOutMin)
	fmt.Println("paddedPathA", paddedPathA)
	fmt.Println("paddedPathB", paddedPathB)
	fmt.Println("paddedPath", paddedPath)
	fmt.Println("paddedTo", paddedTo)
	fmt.Println("paddedDeadline", paddedDeadline)
	fmt.Println("paddedAmountOutMin", paddedAmountOutMin)
	fmt.Println("paddedAmountOutMin", paddedAmountOutMin)

	txData := web3helper.BuildTxData(methodID, paddedAmountOutMin, paddedPath, paddedTo, paddedDeadline)

	fmt.Println("txData", txData)

	estimateGas := web3GolangHelper.EstimateGas(toAddress.Hex(), txData)

	fmt.Println("estimateGas", estimateGas)

	txId, txNonce, err := web3GolangHelper.SignAndSendTransaction(toAddress.Hex(), web3helper.ToWei(value, 18), txData, web3GolangHelper.PendingNonce(), nil, estimateGas)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(txId)
	fmt.Println(txNonce)
}

/*
	toAddress := common.HexToAddress(toAddressString)

	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]
	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	paddedAmount := common.LeftPadBytes(value.Bytes(), 32)

	txData := BuildTxData(methodID, paddedAddress, paddedAmount)

	estimateGas := w.EstimateGas(tokenAddressString, txData)
	txId, txNonce, err := w.SignAndSendTransaction(toAddressString, ToWei(value, 18), txData, w.PendingNonce(), nil, estimateGas)
	if err != nil {
		return "", big.NewInt(0), err
	}

	return txId, txNonce, nil
*/

func updateTokenStatus(db *gorm.DB, web3GolangHelper *web3helper.Web3GolangHelper, token *models.EventsCatched) {

	// create pancakeRouter pancakeRouterInstance
	tokenContractInstance, instanceErr := ierc20.NewPancake(common.HexToAddress(token.TokenAddress), web3GolangHelper.HttpClient())
	if instanceErr != nil {
		fmt.Println(instanceErr)
	}

	tokenName, getNameErr := tokenContractInstance.Name(nil)
	if getNameErr != nil {
		UpdateName(db, token.TokenAddress, tokenName)
		fmt.Println(getNameErr)
	}

	reserves := getReserves(web3GolangHelper, token.TokenAddress)
	if reserves.Reserve0.Uint64() > web3helper.EtherToWei(big.NewFloat(0)).Uint64() {
		UpdateLiquidity(db, token.ID)
	}

}

func getTokenPairs(web3GolangHelper *web3helper.Web3GolangHelper, token *models.EventsCatched) string {
	//lpPairs := make([]*models.LpPair, 0)

	lpPairAddress := getPair(web3GolangHelper, token.TokenAddress)

	//append(lpPairs, )

	fmt.Println("lpPairAddress", lpPairAddress)
	return lpPairAddress
}

func getReserves(web3GolangHelper *web3helper.Web3GolangHelper, tokenAddress string) Reserve {

	pairInstance, instanceErr := pancakePair.NewPancake(common.HexToAddress("0xB7926C0430Afb07AA7DEfDE6DA862aE0Bde767bc"), web3GolangHelper.HttpClient())
	if instanceErr != nil {
		fmt.Println(instanceErr)
	}

	reserves, getReservesErr := pairInstance.GetReserves(nil)
	if getReservesErr != nil {
		fmt.Println(getReservesErr)
	}

	return reserves
}

func getPair(web3GolangHelper *web3helper.Web3GolangHelper, tokenAddress string) string {

	factoryInstance, instanceErr := pancakeFactory.NewPancake(common.HexToAddress("0xB7926C0430Afb07AA7DEfDE6DA862aE0Bde767bc"), web3GolangHelper.HttpClient())
	if instanceErr != nil {
		fmt.Println(instanceErr)
	}

	wBnbContractAddress := "0xae13d989daC2f0dEbFf460aC112a837C89BAa7cd"

	lpPairAddress, getPairErr := factoryInstance.GetPair(nil, common.HexToAddress(wBnbContractAddress), common.HexToAddress(tokenAddress))
	if getPairErr != nil {
		fmt.Println(getPairErr)
	}

	return lpPairAddress.Hex()

}

func printTokenStatus(token *models.EventsCatched) {
	logrus.SetFormatter(&logrus.TextFormatter{ForceColors: true})
	logrus.SetOutput(colorable.NewColorableStdout())
	logrus.Info("TOKEN INFO")

	fmt.Printf("%s: %s\n", cyan("Token Address"), yellow(token.TokenAddress))
	fmt.Printf("%s:\n", cyan("LP Pairs"))
	lo.ForEach(token.LPPairs, func(element *models.LpPair, _ int) {
		fmt.Printf("\t%s: %s\n", cyan("LP Address"), yellow(element.LPAddress))
		fmt.Printf("\t%s: %s\n", cyan("LP TokenA Address"), yellow(element.LPPairA))
		fmt.Printf("\t%s: %s\n", cyan("LP TokenB Address"), yellow(element.LPPairB))
		fmt.Printf("\t%s: %s\n\n", cyan("LP Has Liquidity"), getPairLiquidityIcon(element))
		fmt.Printf("\t%s: %s\n\n", cyan("Trading Enabled"), getPairTradingIcon(element))
	})
}

func getPairTradingIcon(pair *models.LpPair) string {
	icon := "🔴"
	if pair.TradingEnabled {
		icon = "🟢"
	}
	return icon
}

func getPairLiquidityIcon(pair *models.LpPair) string {
	icon := "🔴"
	if pair.HasLiquidity {
		icon = "🟢"
	}
	return icon
}

func GenerateWallet() {

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Println(hexutil.Encode(privateKeyBytes)[2:]) // fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	fmt.Println(hexutil.Encode(publicKeyBytes)[4:]) // 9a7df67f79246283fdc93af76d4f8cdd62c4886e8cd870944e817dd0b97934fdd7719d0810951e03418205868a5c1b40b192451367f28e0088dd75e15de40c05

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	fmt.Println(address) // 0x96216849c49358B10257cb55b28eA603c874b05E

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])
	fmt.Println(hexutil.Encode(hash.Sum(nil)[12:])) // 0x96216849c49358b10257cb55b28ea603c874b05e

	wallet := Wallet{
		PublicKey:  address,
		PrivateKey: hexutil.Encode(privateKeyBytes)[2:],
	}

	file, _ := json.MarshalIndent(wallet, "", " ")
	_ = ioutil.WriteFile("wallets/"+address+".json", file, 0644)
}

func getWallets() {
	wallets := make([]Wallet, 0)

	wPath := "./wallets"
	files, err := ioutil.ReadDir(wPath)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		fileName := file.Name()
		fmt.Println("fileName", fileName)

		wallet := Wallet{
			PublicKey:  "",
			PrivateKey: "",
		}

		// Open our jsonFile
		jsonFile, _ := os.Open(wPath + "/" + fileName)
		byteValue, _ := ioutil.ReadAll(jsonFile)
		json.Unmarshal(byteValue, &wallet)
		fmt.Println(wallet)
		wallets = append(wallets, wallet)
	}

	fmt.Println(wallets)
}

func parseDateTime() string {
	now := time.Now()
	return strconv.Itoa(now.Year()) + "/" + now.Month().String() + "/" + strconv.Itoa(now.Day()) + " " + strconv.Itoa(now.Hour()) + ":" + strconv.Itoa(now.Minute()) + ":" + strconv.Itoa(now.Second()) + ":" + strconv.Itoa(now.Nanosecond())
}
