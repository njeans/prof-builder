package blockvalidation

import (
	"fmt"
	"math/big"
	"testing"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

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

	amtOut2, _ := big.NewInt(0).SetString("-1032665152610525182449", 10)
	doSwap(environ1, new(big.Int).Mul(bigEther, big.NewInt(1)), 0, 0, amtOut2)
	environ1.resetNonceMod()

	// environ2, err := NewBenchmarkEnvironment(2, 5, 5)
	// require.NoError(t, err)

	// amtOut0, _ := big.NewInt(0).SetString("-61727865885602705148354", 10)
	// doSwap(environ2, new(big.Int).Mul(bigEther, big.NewInt(50)), 0, 0, amtOut0)

	// amtOut1, _ := big.NewInt(0).SetString("-77174302538729393196667", 10)
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
	numBlockTxs := 30
	minProfTxs := 2
	maxProfTxs := 20
	environ1, err := NewBenchmarkEnvironment(1, numUsers, 0)
	if err != nil {
		panic(err)
	}
	api := NewBlockValidationAPI(environ1.ethservice, nil, true, false)

	for numProfTxs := minProfTxs; numProfTxs <= maxProfTxs; numProfTxs++ {
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
		b.Run(fmt.Sprintf("numProfTxs %v", numProfTxs), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = api.AppendProfBundle(profRequest)
			}
		})
		environ1.resetNonceMod()
	}

}
