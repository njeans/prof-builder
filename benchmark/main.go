package main

import (
	"fmt"
	"os"
	"time"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	"github.com/ethereum/go-ethereum/core/types"
	blockValidation "github.com/ethereum/go-ethereum/eth/block-validation"
)

func main() {
	numUsers := 100
	numTrails := 1000
	numBlockTxs := 30
	minProfTxs := 2
	maxProfTxs := 20
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	environ1, err := blockValidation.NewBenchmarkEnvironment(1, numUsers, 0, dir+"/../eth/block-validation/testdata")
	if err != nil {
		panic(err)
	}

	for numProfTxs := minProfTxs; numProfTxs <= maxProfTxs; numProfTxs++ {
		for j := 0; j < numTrails; j++ {
			api := blockValidation.NewBlockValidationAPI(environ1.Ethservice, nil, true, false)
			blockTxs := make([]*types.Transaction, numBlockTxs)
			for i := 0; i < numBlockTxs; i++ {
				blockTxs[i] = environ1.RandomSwap()
			}

			profTxs := make([]string, numProfTxs)
			for i := 0; i < numProfTxs; i++ {
				tx := environ1.RandomSwap()
				txBytes, err := tx.MarshalBinary()
				if err != nil {
					panic(err)
				}
				profTxs[i] = fmt.Sprintf("0x%x", txBytes)
			}

			blockRequest, err := environ1.SetupBuilderSubmission(api, blockTxs)
			if err != nil {
				panic(err)
			}
			profRequest := &blockValidation.ProfSimReq{
				PbsPayload: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
					ExecutionPayload: blockRequest.ExecutionPayload,
					BlobsBundle:      blockRequest.BlobsBundle,
				},
				ProfBundle: &blockValidation.ProfBundleRequest{
					Transactions: profTxs,
				},
				ParentBeaconBlockRoot: blockRequest.ParentBeaconBlockRoot,
				RegisteredGasLimit:    blockRequest.RegisteredGasLimit,
				ProposerFeeRecipient:  blockValidation.TestValidatorAddr1,
			}
			start := time.Now()
			resp, err := api.AppendProfBundle(profRequest)
			if err != nil {
				panic(err)
			}
			duration := time.Since(start)
			fmt.Printf("data:%v,%v,%v,%v\n", j, numProfTxs, resp.UsedGas, duration.Nanoseconds())

			environ1.ResetNonceMod()
		}
	}

}
