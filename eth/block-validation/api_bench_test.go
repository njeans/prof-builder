package blockvalidation

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"testing"
	"time"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/beacon/engine"
	beaconEngine "github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethmath "github.com/ethereum/go-ethereum/common/math"
	beaconConsensus "github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

var (
	wethAddress           = common.HexToAddress("0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512")
	daiAddress            = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	univ2FactoryA_Address = common.HexToAddress("0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0")
	univ2FactoryB_Address = common.HexToAddress("0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")
	atomicSwapAddress     = common.HexToAddress("0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9")

	bigEther = big.NewInt(params.Ether)

	builderTxSigningKey, _ = crypto.GenerateKey()
	etherbase              = crypto.PubkeyToAddress(builderTxSigningKey.PublicKey)

	testValidatorKey1, _ = crypto.HexToECDSA("28c3cd61b687fdd03488e167a5d84f50269df2a4c29a2cfb1390903aa775c5d0")
	testValidatorAddr1   = crypto.PubkeyToAddress(testValidatorKey1.PublicKey)
)

func deployAllContracts(key *ecdsa.PrivateKey, gasPrice *big.Int) []*types.Transaction {
	allContractsData, err := os.ReadFile("testdata/allcontracts.signeddata")
	if err != nil {
		panic(err)
	}
	var signedTxsBytes []hexutil.Bytes
	err = json.Unmarshal(allContractsData, &signedTxsBytes)
	if err != nil {
		panic(err)
	}
	var signedTxs []*types.Transaction
	for _, signedTxBytes := range signedTxsBytes {
		signedTx := types.Transaction{}
		err = signedTx.UnmarshalBinary(signedTxBytes)
		if err != nil {
			panic(err)
		}
		signedTxs = append(signedTxs, &signedTx)
	}

	return signedTxs
}

type TestParticipant struct {
	key           *ecdsa.PrivateKey
	address       common.Address
	tokenBalances []struct {
		tokenABalance *big.Int
		tokenBBalance *big.Int
	}
}

func NewParticipant(numpairs int) *TestParticipant {
	pk, _ := crypto.GenerateKey()
	address := crypto.PubkeyToAddress(pk.PublicKey)
	return &TestParticipant{pk, address, make([]struct {
		tokenABalance *big.Int
		tokenBBalance *big.Int
	}, numpairs)}
}

type TestParticipants struct {
	searchers []*TestParticipant
	users     []*TestParticipant
}

func NewTestParticipants(nSearchers, nUsers, nPairs int) *TestParticipants {
	opa := TestParticipants{}

	for i := 0; i < nSearchers; i++ {
		opa.searchers = append(opa.searchers, NewParticipant(nPairs))
	}

	for i := 0; i < nUsers; i++ {
		opa.users = append(opa.users, NewParticipant(nPairs))
	}

	return &opa
}

func (o *TestParticipants) AppendToGenesisAlloc(genesis types.GenesisAlloc) types.GenesisAlloc {
	for _, searcher := range o.searchers {
		genesis[searcher.address] = types.Account{Balance: new(big.Int).Mul(big.NewInt(10000), bigEther)}
	}

	for _, user := range o.users {
		genesis[user.address] = types.Account{Balance: new(big.Int).Mul(big.NewInt(10000), bigEther)}
	}

	return genesis
}

func parseAbi(filename string) *abi.ABI {
	abiData, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	resAbi := new(abi.ABI)
	err = resAbi.UnmarshalJSON(abiData)
	if err != nil {
		panic(err)
	}
	return resAbi
}

func makeBlock(ethservice *eth.Ethereum, txs []*types.Transaction, requireTx int) *types.Block {
	errs := ethservice.TxPool().Add(txs, true, true, false)
	for _, err := range errs {
		if err != nil {
			panic(err)
		}
	}
	chain := ethservice.BlockChain()
	parent := chain.CurrentBlock()
	args := &miner.BuildPayloadArgs{
		Parent:       parent.Hash(),
		Timestamp:    parent.Time + 12,
		FeeRecipient: testValidatorAddr1,
		BeaconRoot:   &common.Hash{42},
	}
	minerPayload, err := ethservice.Miner().BuildPayload(args)
	if err != nil {
		panic(err)
	}
	payloadEnv := minerPayload.ResolveFull()

	execData := payloadEnv.ExecutionPayload

	versionedHashes := make([]common.Hash, 0)
	block, err := beaconEngine.ExecutableDataToBlock(*execData, versionedHashes, &common.Hash{42})
	if err != nil {
		panic(err)
	}
	if requireTx != len(block.Transactions()) {
		panic(fmt.Errorf("expected %v transactions in block not %v", requireTx, len(block.Transactions())))
	}
	_, err = ethservice.BlockChain().InsertChain([]*types.Block{block})
	if err != nil {
		panic(err)
	}
	return block
}

type tConctract struct {
	simBackend *miner.SimulatedBackend
	abi        *abi.ABI
	address    common.Address
}

func NewTContract(simBackend *miner.SimulatedBackend, abiFile string, address common.Address) tConctract {
	return tConctract{
		simBackend: simBackend,
		abi:        parseAbi(abiFile),
		address:    address,
	}
}

func (c *tConctract) doCall(fromAddress common.Address, method string, args ...interface{}) ([]byte, error) {
	callData, err := c.abi.Pack(method, args...)
	if err != nil {
		return nil, err
	}

	simRes, err := c.simBackend.CallContract(context.Background(), ethereum.CallMsg{
		From:     fromAddress,
		To:       &c.address,
		GasPrice: new(big.Int),
		Data:     callData,
	}, c.simBackend.Blockchain().CurrentHeader().Number)
	if err != nil {
		return nil, err
	}

	return simRes, nil
}

func newTestChain(alloc types.GenesisAlloc) (*eth.Ethereum, ethdb.Database, error) {
	const gasLimit = 1_000_000_000_000_000_000
	chainConfig := *params.AllEthashProtocolChanges
	chainConfig.ChainID = big.NewInt(31337)

	chainConfig.TerminalTotalDifficulty = common.Big0
	chainConfig.TerminalTotalDifficultyPassed = true
	engine := beaconConsensus.NewFaker()

	var gspec = &core.Genesis{
		Config:     &chainConfig,
		GasLimit:   gasLimit,
		Alloc:      alloc,
		ExtraData:  []byte("test genesis"),
		Timestamp:  9000,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(0),
	}
	testNonce := uint64(0)
	generate := func(_ int, g *core.BlockGen) {
		g.OffsetTime(5)
		g.SetExtra([]byte("test"))
		tx, _ := types.SignTx(types.NewTransaction(testNonce, common.HexToAddress("0x9a9070028361F7AAbeB3f2F2Dc07F82C4a98A02a"), big.NewInt(1), params.TxGas, big.NewInt(params.InitialBaseFee*2), nil), types.LatestSigner(&chainConfig), testKey)
		g.AddTx(tx)
		testNonce++
	}
	db, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 10, generate)

	// Set cancun time to last block + 5 seconds
	cTime := blocks[len(blocks)-1].Time() + 5
	gspec.Config.ShanghaiTime = &cTime
	gspec.Config.CancunTime = &cTime

	n, err := node.New(&node.Config{
		P2P: p2p.Config{
			ListenAddr:  "0.0.0.0:0",
			NoDiscovery: true,
			MaxPeers:    25,
		},
	})
	if err != nil {
		return nil, nil, err
	}

	ethcfg := &ethconfig.Config{Genesis: gspec, SyncMode: downloader.FullSync, TrieTimeout: time.Minute, TrieDirtyCache: 256, TrieCleanCache: 256}
	ethservice, err := eth.New(n, ethcfg)
	if err != nil {
		return nil, nil, err
	}
	if err := n.Start(); err != nil {
		return nil, nil, err
	}
	if _, err := ethservice.BlockChain().InsertChain(blocks); err != nil {
		n.Close()
		return nil, nil, err
	}
	time.Sleep(500 * time.Millisecond) // give txpool enough time to consume head event

	ethservice.SetEtherbase(etherbase)
	ethservice.SetSynced()

	ethservice.Merger().ReachTTD()

	return ethservice, db, nil
}

func prepareContractCallTx(ethservice *eth.Ethereum, contract tConctract, signerKey *ecdsa.PrivateKey, nonce uint64, method string, args ...interface{}) *types.Transaction {
	callData, err := contract.abi.Pack(method, args...)
	if err != nil {
		panic(err)
	}
	// nonce := ethservice.TxPool().Nonce(signer) + nonceMod //signer.getNonceMod(ethservice.BlockChain().CurrentHeader().Number)
	baseFee := new(big.Int).Mul(big.NewInt(2), ethservice.BlockChain().CurrentHeader().BaseFee)

	tx, err := types.SignTx(types.NewTransaction(nonce, contract.address, new(big.Int), 9000000, baseFee, callData), types.HomesteadSigner{}, signerKey)
	if err != nil {
		panic(err)
	}
	return tx
}

type pair struct {
	univ2FactoryA      tConctract
	univ2FactoryB      tConctract
	tokenAContract     tConctract
	tokenBContract     tConctract
	atomicSwapContract tConctract
}
type BechmarkEnvironment struct {
	ethservice *eth.Ethereum
	tokenPairs []pair
	users      *TestParticipants
	nonceMod   []uint64
}

func NewBenchmarkEnvironment(numTokenPairs int, numUsers int, numSearcher int) (*BechmarkEnvironment, error) {
	var err error
	rand.New(rand.NewSource(10))
	deployerKey, err := crypto.ToECDSA(hexutil.MustDecode("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"))
	if err != nil {
		return nil, err
	}

	deployerAddress := crypto.PubkeyToAddress(deployerKey.PublicKey)
	deployerTestAddress := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	alloc := types.GenesisAlloc{
		deployerAddress:                  {Balance: new(big.Int).Mul(big.NewInt(10000), bigEther)},
		deployerTestAddress:              {Balance: new(big.Int).Mul(big.NewInt(10000), bigEther)},
		testAddr:                         {Balance: testBalance},
		params.BeaconRootsStorageAddress: {Balance: common.Big0, Code: common.Hex2Bytes("3373fffffffffffffffffffffffffffffffffffffffe14604457602036146024575f5ffd5b620180005f350680545f35146037575f5ffd5b6201800001545f5260205ff35b6201800042064281555f359062018000015500")},
	}

	testParticipants := NewTestParticipants(numSearcher, numUsers, numTokenPairs)
	alloc = testParticipants.AppendToGenesisAlloc(alloc)

	ethservice, db, err := newTestChain(alloc)
	if err != nil {
		return nil, err
	}

	simBackend := miner.NewSimulatedBackendChain(db, ethservice.BlockChain())
	// defer func() {
	// 	require.NoError(t, db.Close())
	// }()

	deploymentTxs := deployAllContracts(deployerKey, ethservice.BlockChain().CurrentHeader().BaseFee)

	getBaseFee := func() *big.Int {
		return new(big.Int).Mul(big.NewInt(2), ethservice.BlockChain().CurrentHeader().BaseFee)
	}

	environment := &BechmarkEnvironment{
		ethservice: ethservice,
		tokenPairs: make([]pair, numTokenPairs),
		users:      testParticipants,
		nonceMod:   make([]uint64, numUsers+numSearcher),
	}
	for i := 0; i < numTokenPairs; i++ {
		univ2FactoryA := NewTContract(simBackend, "testdata/univ2factory.abi", univ2FactoryA_Address)
		univ2FactoryB := NewTContract(simBackend, "testdata/univ2factory.abi", univ2FactoryB_Address)

		wethContract := NewTContract(simBackend, "testdata/weth.abi", wethAddress)
		daiContract := NewTContract(simBackend, "testdata/dai.abi", daiAddress)
		atomicSwapContract := NewTContract(simBackend, "testdata/swap.abi", atomicSwapAddress)

		makeBlock(ethservice, deploymentTxs, len(deploymentTxs))
		deployerNonce := ethservice.TxPool().Nonce(deployerAddress)

		if uint64(18) != ethservice.TxPool().Nonce(deployerAddress) {
			panic(fmt.Errorf("expected %v nonce not %v", 18, ethservice.TxPool().Nonce(deployerAddress)))
		}
		if uint64(3) != ethservice.TxPool().Nonce(deployerTestAddress) {
			panic(fmt.Errorf("expected %v nonce not %v", 3, ethservice.TxPool().Nonce(deployerTestAddress)))
		}

		// Mint tokens
		approveTxs := []*types.Transaction{}
		adminApproveTxWeth := prepareContractCallTx(ethservice, wethContract, deployerKey, deployerNonce, "approve", atomicSwapContract.address, ethmath.MaxBig256)
		deployerNonce += 1
		approveTxs = append(approveTxs, adminApproveTxWeth)
		adminApproveTxDai := prepareContractCallTx(ethservice, daiContract, deployerKey, deployerNonce, "approve", atomicSwapContract.address, ethmath.MaxBig256)
		deployerNonce += 1
		approveTxs = append(approveTxs, adminApproveTxDai)
		for _, spender := range append(testParticipants.users, testParticipants.searchers...) {
			startBalanceA := new(big.Int).Mul(bigEther, big.NewInt(1000))
			startBalanceB := new(big.Int).Mul(bigEther, big.NewInt(50000))
			mintTx := prepareContractCallTx(ethservice, daiContract, deployerKey, deployerNonce, "mint", spender.address, startBalanceB)
			deployerNonce += 1
			approveTxs = append(approveTxs, mintTx)
			spenderNonce := ethservice.TxPool().Nonce(spender.address) //+ spender.getNonceMod(ethservice.BlockChain().CurrentHeader().Number)
			depositTx, err := types.SignTx(types.NewTransaction(spenderNonce, wethContract.address, startBalanceA, 9000000, getBaseFee(), hexutil.MustDecode("0xd0e30db0")), types.HomesteadSigner{}, spender.key)
			if err != nil {
				panic(err)
			}
			spenderNonce += 1
			spender.tokenBalances[i].tokenABalance = startBalanceA
			spender.tokenBalances[i].tokenBBalance = startBalanceB
			approveTxs = append(approveTxs, depositTx)

			spenderApproveTxWeth := prepareContractCallTx(ethservice, wethContract, spender.key, spenderNonce, "approve", atomicSwapContract.address, ethmath.MaxBig256)
			approveTxs = append(approveTxs, spenderApproveTxWeth)
			spenderNonce += 1

			spenderApproveTxDai := prepareContractCallTx(ethservice, daiContract, spender.key, spenderNonce, "approve", atomicSwapContract.address, ethmath.MaxBig256)
			approveTxs = append(approveTxs, spenderApproveTxDai)
		}

		makeBlock(ethservice, approveTxs, len(approveTxs))
		environment.tokenPairs[i] = pair{
			univ2FactoryA:      univ2FactoryA,
			univ2FactoryB:      univ2FactoryB,
			tokenAContract:     wethContract,
			tokenBContract:     daiContract,
			atomicSwapContract: atomicSwapContract,
		}
	}
	return environment, nil

}

func (e *BechmarkEnvironment) getNonceMod(participantId int, isUser bool) uint64 {
	if isUser {
		e.nonceMod[participantId] += 1
		return e.nonceMod[participantId] - 1
	} else {
		e.nonceMod[participantId+len(e.users.users)] += 1
		return e.nonceMod[participantId+len(e.users.users)] - 1
	}
}

func (e *BechmarkEnvironment) resetNonceMod() {
	e.nonceMod = make([]uint64, len(e.users.users)+len(e.users.searchers))
}

func (e *BechmarkEnvironment) randomSwap() *types.Transaction {
	numUsers := len(e.users.users)
	userid := rand.Intn(numUsers)
	user := e.users.users[userid]
	pairId := 0
	pair := e.tokenPairs[pairId]
	var tokenAContract common.Address
	var tokenBContract common.Address
	var factory common.Address
	var userBalance *big.Int
	if userid < numUsers/2 {
		tokenAContract = pair.tokenAContract.address
		tokenBContract = pair.tokenBContract.address
		factory = pair.univ2FactoryA.address
		userBalance = user.tokenBalances[pairId].tokenABalance
	} else {
		tokenBContract = pair.tokenAContract.address
		tokenAContract = pair.tokenBContract.address
		factory = pair.univ2FactoryB.address
		userBalance = user.tokenBalances[pairId].tokenBBalance
	}
	maxAmt := 50
	if userBalance.Cmp(big.NewInt(int64(maxAmt))) == -1 {
		maxAmt = int(userBalance.Div(userBalance, big.NewInt(3)).Int64())
	}
	minAmt := 1
	amtIn := new(big.Int).Mul(bigEther, big.NewInt(int64(rand.Intn(maxAmt)+minAmt)))
	userBalance.Sub(userBalance, amtIn)
	nonce := e.getNonceMod(userid, true) + e.ethservice.TxPool().Nonce(user.address)
	fmt.Printf("%x swap %v nonce %v\n", user.address, amtIn.Int64(), nonce)
	return prepareContractCallTx(e.ethservice, pair.atomicSwapContract, user.key, nonce, "swap", []common.Address{tokenAContract, tokenBContract}, amtIn, factory, user.address, false)
}

func (e *BechmarkEnvironment) setupBuilderSubmission(api *BlockValidationAPI, blockTxs []*types.Transaction) (*BuilderBlockValidationRequestV3, error) {
	nonce := e.ethservice.TxPool().Nonce(testAddr)
	paymentTx, _ := types.SignTx(types.NewTransaction(nonce, testValidatorAddr, big.NewInt(132912184722468), 21000, big.NewInt(2*params.InitialBaseFee), nil), types.LatestSigner(e.ethservice.BlockChain().Config()), testKey)
	blockTxs = append(blockTxs, paymentTx)
	e.ethservice.TxPool().Add(blockTxs, true, true, false)
	parent := e.ethservice.BlockChain().CurrentHeader()
	execData, err := assembleBlock(api, parent.Hash(), &engine.PayloadAttributes{
		Timestamp:             parent.Time + 5,
		SuggestedFeeRecipient: testValidatorAddr,
		BeaconRoot:            &common.Hash{42},
	})
	if err != nil {
		return nil, err
	}
	payload, err := ExecutableDataToExecutionPayloadV3(execData)
	if err != nil {
		return nil, err
	}

	proposerAddr := bellatrix.ExecutionAddress{}
	copy(proposerAddr[:], testValidatorAddr.Bytes())

	blockRequest := &BuilderBlockValidationRequestV3{
		SubmitBlockRequest: builderApiDeneb.SubmitBlockRequest{
			Signature: phase0.BLSSignature{},
			Message: &builderApiV1.BidTrace{
				ParentHash:           phase0.Hash32(execData.ParentHash),
				BlockHash:            phase0.Hash32(execData.BlockHash),
				ProposerFeeRecipient: proposerAddr,
				GasLimit:             execData.GasLimit,
				GasUsed:              execData.GasUsed,
				Value:                uint256.NewInt(132912184722468),
			},
			ExecutionPayload: payload,
			BlobsBundle: &builderApiDeneb.BlobsBundle{
				Commitments: make([]deneb.KZGCommitment, 0),
				Proofs:      make([]deneb.KZGProof, 0),
				Blobs:       make([]deneb.Blob, 0),
			},
		},
		RegisteredGasLimit:    execData.GasLimit,
		ParentBeaconBlockRoot: common.Hash{42},
	}
	err = api.ValidateBuilderSubmissionV3(blockRequest)
	if err != nil {
		return nil, err
	}
	return blockRequest, nil
}

func TestBenchmarkEnvironment(t *testing.T) {
	var err error

	doSwap := func(environ *BechmarkEnvironment, amtIn *big.Int, userid, pairid int, exectedDiffB *big.Int) {
		testUser := environ.users.users[userid]
		pair := environ.tokenPairs[pairid]
		balanceABefore, err := pair.tokenAContract.doCall(testUser.address, "balanceOf", testUser.address)
		require.NoError(t, err)
		balanceBBefore, err := pair.tokenBContract.doCall(testUser.address, "balanceOf", testUser.address)
		require.NoError(t, err)
		nonce := environ.getNonceMod(userid, true) + environ.ethservice.TxPool().Nonce(testUser.address)
		swapTx := prepareContractCallTx(environ.ethservice, pair.atomicSwapContract, testUser.key, nonce, "swap", []common.Address{pair.tokenAContract.address, pair.tokenBContract.address}, amtIn, pair.univ2FactoryA.address, testUser.address, false)
		makeBlock(environ.ethservice, []*types.Transaction{swapTx}, 1)
		balanceAAfter, err := pair.tokenAContract.doCall(testUser.address, "balanceOf", testUser.address)
		require.NoError(t, err)
		balanceBAfter, err := pair.tokenBContract.doCall(testUser.address, "balanceOf", testUser.address)
		require.NoError(t, err)
		aBefore := big.NewInt(0).SetBytes(balanceABefore)
		require.Equal(t, aBefore, testUser.tokenBalances[pairid].tokenABalance)
		bBefore := big.NewInt(0).SetBytes(balanceBBefore)
		require.Equal(t, bBefore, testUser.tokenBalances[pairid].tokenBBalance)

		aAfter := big.NewInt(0).SetBytes(balanceAAfter)
		bAfter := big.NewInt(0).SetBytes(balanceBAfter)
		testUser.tokenBalances[pairid].tokenABalance = aAfter
		testUser.tokenBalances[pairid].tokenBBalance = bAfter

		diffA := aBefore.Sub(aBefore, aAfter)
		diffB := bBefore.Sub(bBefore, bAfter)
		fmt.Printf("Balance of %x token A %v ->  %v = %v\n", testUser.address, aBefore, aAfter, diffA)
		fmt.Printf("Balance of %x token B %v ->  %v = %v\n", testUser.address, bBefore, bAfter, diffB)
		require.NotEqual(t, balanceAAfter, balanceABefore)
		require.NotEqual(t, balanceBAfter, balanceBBefore)
		require.Equal(t, diffA, amtIn)
		require.Equal(t, diffB, exectedDiffB)
	}

	environ1, err := NewBenchmarkEnvironment(1, 5, 5)
	require.NoError(t, err)
	amtOut0, _ := big.NewInt(0).SetString("-61727865885602705148354", 10)
	doSwap(environ1, new(big.Int).Mul(bigEther, big.NewInt(50)), 0, 0, amtOut0)
	environ1.resetNonceMod()

	amtOut1, _ := big.NewInt(0).SetString("-77174302538729393196667", 10)
	doSwap(environ1, new(big.Int).Mul(bigEther, big.NewInt(70)), 1, 0, amtOut1)
	environ1.resetNonceMod()

	// amtOut2, _ := big.NewInt(0).SetString("-1174653512533388870726", 10)
	amtOut2, _ := big.NewInt(0).SetString("-1032665152610525182449", 10)
	doSwap(environ1, new(big.Int).Mul(bigEther, big.NewInt(1)), 0, 0, amtOut2)
	environ1.resetNonceMod()

	// environ2, err := NewBenchmarkEnvironment(2, 5, 5)
	// require.NoError(t, err)

	// // amtOut0, _ := big.NewInt(0).SetString("-61727865885602705148354", 10)
	// doSwap(environ2, new(big.Int).Mul(bigEther, big.NewInt(50)), 0, 0, amtOut0)

	// // amtOut1, _ := big.NewInt(0).SetString("-77174302538729393196667", 10)
	// doSwap(environ1, new(big.Int).Mul(bigEther, big.NewInt(70)), 1, 1, amtOut0)

	// amtOut3, _ := big.NewInt(0).SetString("-1174653512533388870726", 10)
	// doSwap(environ1, new(big.Int).Mul(bigEther, big.NewInt(1)), 0, 1, amtOut3)
}

func TestBenchmarkProf(t *testing.T) {
	environ1, err := NewBenchmarkEnvironment(1, 10, 0)
	require.NoError(t, err)
	api := NewBlockValidationAPI(environ1.ethservice, nil, true, false)
	numBlockTxs := 10
	numProfTxs := 2

	for j := 0; j < 10; j++ {
		blockTxs := make([]*types.Transaction, numBlockTxs)
		for i := 0; i < numBlockTxs; i++ {
			blockTxs[i] = environ1.randomSwap()
		}

		profTxs := make([]string, numProfTxs)
		for i := 0; i < numProfTxs; i++ {
			tx := environ1.randomSwap()
			txBytes, err := tx.MarshalBinary()
			require.NoError(t, err)
			profTxs[i] = fmt.Sprintf("0x%x", txBytes)
		}
		blockRequest, err := environ1.setupBuilderSubmission(api, blockTxs)

		require.NoError(t, err)

		profRequest := &ProfSimReq{
			PbsPayload: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
				ExecutionPayload: blockRequest.ExecutionPayload,
				BlobsBundle:      blockRequest.BlobsBundle,
			},
			ProfBundle: &ProfBundleRequest{
				Transactions: profTxs,
			},
			ParentBeaconBlockRoot: blockRequest.ParentBeaconBlockRoot,
			RegisteredGasLimit:    blockRequest.RegisteredGasLimit,
			ProposerFeeRecipient:  testValidatorAddr,
		}
		_, err = api.AppendProfBundle(profRequest)
		require.NoError(t, err)
		environ1.resetNonceMod()
	}
}

func BenchmarkAppendProfBundle(b *testing.B) {
	numUsers := 100
	environ1, err := NewBenchmarkEnvironment(1, numUsers, 0)
	if err != nil {
		panic(err)
	}
	api := NewBlockValidationAPI(environ1.ethservice, nil, true, false)
	numBlockTxs := 10
	numProfTxs := 2

	for j := 0; j < 10; j++ {
		blockTxs := make([]*types.Transaction, numBlockTxs)
		for i := 0; i < numBlockTxs; i++ {
			blockTxs[i] = environ1.randomSwap()
		}

		profTxs := make([]string, numProfTxs)
		for i := 0; i < numProfTxs; i++ {
			tx := environ1.randomSwap()
			txBytes, err := tx.MarshalBinary()
			if err != nil {
				panic(err)
			}
			profTxs[i] = fmt.Sprintf("0x%x", txBytes)
		}
		blockRequest, err := environ1.setupBuilderSubmission(api, blockTxs)
		if err != nil {
			panic(err)
		}
		profRequest := &ProfSimReq{
			PbsPayload: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
				ExecutionPayload: blockRequest.ExecutionPayload,
				BlobsBundle:      blockRequest.BlobsBundle,
			},
			ProfBundle: &ProfBundleRequest{
				Transactions: profTxs,
			},
			ParentBeaconBlockRoot: blockRequest.ParentBeaconBlockRoot,
			RegisteredGasLimit:    blockRequest.RegisteredGasLimit,
			ProposerFeeRecipient:  testValidatorAddr,
		}
		for i := 0; i < b.N; i++ {
			_, _ = api.AppendProfBundle(profRequest)
		}
		environ1.resetNonceMod()
	}

}
