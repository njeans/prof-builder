package blockvalidation

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	builderApiBellatrix "github.com/attestantio/go-builder-client/api/bellatrix"
	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
)

type BlacklistedAddresses []common.Address

type AccessVerifier struct {
	blacklistedAddresses map[common.Address]struct{}
}

func (a *AccessVerifier) verifyTraces(tracer *logger.AccessListTracer) error {
	log.Trace("x", "tracer.AccessList()", tracer.AccessList())
	for _, accessTuple := range tracer.AccessList() {
		// TODO: should we ignore common.Address{}?
		if _, found := a.blacklistedAddresses[accessTuple.Address]; found {
			log.Info("bundle accesses blacklisted address", "address", accessTuple.Address)
			return fmt.Errorf("blacklisted address %s in execution trace", accessTuple.Address.String())
		}
	}

	return nil
}

func (a *AccessVerifier) isBlacklisted(addr common.Address) error {
	if _, present := a.blacklistedAddresses[addr]; present {
		return fmt.Errorf("transaction from blacklisted address %s", addr.String())
	}
	return nil
}

func (a *AccessVerifier) verifyTransactions(signer types.Signer, txs types.Transactions) error {
	for _, tx := range txs {
		from, err := types.Sender(signer, tx)
		if err == nil {
			if _, present := a.blacklistedAddresses[from]; present {
				return fmt.Errorf("transaction from blacklisted address %s", from.String())
			}
		}
		to := tx.To()
		if to != nil {
			if _, present := a.blacklistedAddresses[*to]; present {
				return fmt.Errorf("transaction to blacklisted address %s", to.String())
			}
		}
	}
	return nil
}

func NewAccessVerifierFromFile(path string) (*AccessVerifier, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ba BlacklistedAddresses
	if err := json.Unmarshal(bytes, &ba); err != nil {
		return nil, err
	}

	blacklistedAddresses := make(map[common.Address]struct{}, len(ba))
	for _, address := range ba {
		blacklistedAddresses[address] = struct{}{}
	}

	return &AccessVerifier{
		blacklistedAddresses: blacklistedAddresses,
	}, nil
}

type BlockValidationConfig struct {
	BlacklistSourceFilePath string
	// If set to true, proposer payment is calculated as a balance difference of the fee recipient.
	UseBalanceDiffProfit bool
	// If set to true, withdrawals to the fee recipient are excluded from the balance difference.
	ExcludeWithdrawals bool
}

// Register adds catalyst APIs to the full node.
func Register(stack *node.Node, backend *eth.Ethereum, cfg BlockValidationConfig) error {
	var accessVerifier *AccessVerifier
	if cfg.BlacklistSourceFilePath != "" {
		var err error
		accessVerifier, err = NewAccessVerifierFromFile(cfg.BlacklistSourceFilePath)
		if err != nil {
			return err
		}
	}

	stack.RegisterAPIs([]rpc.API{
		{
			Namespace: "flashbots",
			Service:   NewBlockValidationAPI(backend, accessVerifier, cfg.UseBalanceDiffProfit, cfg.ExcludeWithdrawals),
		},
	})
	return nil
}

type BlockValidationAPI struct {
	eth            *eth.Ethereum
	accessVerifier *AccessVerifier
	// If set to true, proposer payment is calculated as a balance difference of the fee recipient.
	useBalanceDiffProfit bool
	// If set to true, withdrawals to the fee recipient are excluded from the balance delta.
	excludeWithdrawals bool
	profProcessor      *core.ProfProcessor
	profCache          map[common.Hash]blockValidationCache
}

type blockValidationCache struct {
	receipts *types.Receipts
	state    *state.StateDB
}

// NewConsensusAPI creates a new consensus api for the given backend.
// The underlying blockchain needs to have a valid terminal total difficulty set.
func NewBlockValidationAPI(eth *eth.Ethereum, accessVerifier *AccessVerifier, useBalanceDiffProfit, excludeWithdrawals bool) *BlockValidationAPI {
	bc := eth.BlockChain()
	return &BlockValidationAPI{
		eth:                  eth,
		accessVerifier:       accessVerifier,
		useBalanceDiffProfit: useBalanceDiffProfit,
		excludeWithdrawals:   excludeWithdrawals,
		profProcessor:        core.NewProfProcessor(bc.Config(), bc, bc.Engine()),
		profCache:            make(map[common.Hash]blockValidationCache),
	}
}

type BuilderBlockValidationRequest struct {
	builderApiBellatrix.SubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}

func (api *BlockValidationAPI) ValidateBuilderSubmissionV1(params *BuilderBlockValidationRequest) error {
	// no longer supported endpoint
	if params.ExecutionPayload == nil {
		return errors.New("nil execution payload")
	}
	payload := params.ExecutionPayload
	block, err := engine.ExecutionPayloadV1ToBlock(payload)
	if err != nil {
		return err
	}

	return api.validateBlock(block, params.Message, params.RegisteredGasLimit)
}

type BuilderBlockValidationRequestV2 struct {
	builderApiCapella.SubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}

func (r *BuilderBlockValidationRequestV2) UnmarshalJSON(data []byte) error {
	params := &struct {
		RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
	}{}
	err := json.Unmarshal(data, params)
	if err != nil {
		return err
	}
	r.RegisteredGasLimit = params.RegisteredGasLimit

	blockRequest := new(builderApiCapella.SubmitBlockRequest)
	err = json.Unmarshal(data, &blockRequest)
	if err != nil {
		return err
	}
	r.SubmitBlockRequest = *blockRequest
	return nil
}

func (api *BlockValidationAPI) ValidateBuilderSubmissionV2(params *BuilderBlockValidationRequestV2) error {
	// TODO: fuzztest, make sure the validation is sound
	// TODO: handle context!
	log.Info("json-rpc validation v2 called!")

	if params.ExecutionPayload == nil {
		return errors.New("nil execution payload")
	}
	payload := params.ExecutionPayload
	block, err := engine.ExecutionPayloadV2ToBlock(payload)
	if err != nil {
		return err
	}

	return api.validateBlock(block, params.Message, params.RegisteredGasLimit)
}

type BuilderBlockValidationRequestV3 struct {
	builderApiDeneb.SubmitBlockRequest
	ParentBeaconBlockRoot common.Hash `json:"parent_beacon_block_root"`
	RegisteredGasLimit    uint64      `json:"registered_gas_limit,string"`
}

func (r *BuilderBlockValidationRequestV3) UnmarshalJSON(data []byte) error {
	params := &struct {
		ParentBeaconBlockRoot common.Hash `json:"parent_beacon_block_root"`
		RegisteredGasLimit    uint64      `json:"registered_gas_limit,string"`
	}{}
	err := json.Unmarshal(data, params)
	if err != nil {
		return err
	}
	r.RegisteredGasLimit = params.RegisteredGasLimit
	r.ParentBeaconBlockRoot = params.ParentBeaconBlockRoot

	blockRequest := new(builderApiDeneb.SubmitBlockRequest)
	err = json.Unmarshal(data, &blockRequest)
	if err != nil {
		return err
	}
	r.SubmitBlockRequest = *blockRequest
	return nil
}

type ProfSimReq struct {
	PbsPayload *builderApiDeneb.ExecutionPayloadAndBlobsBundle
	// PbsReceipts           *types.Receipts
	// PbsUsedGas            uint64
	ProfBundle            *ProfBundleRequest
	ParentBeaconBlockRoot common.Hash `json:"parent_beacon_block_root"`
	RegisteredGasLimit    uint64      `json:"registered_gas_limit,string"`
	ProposerFeeRecipient  common.Address
}

type ProfBundleRequest struct {
	slot         uint64
	Transactions []string
	bundleHash   phase0.Hash32
}

type ProfSimResp struct {
	Value            *uint256.Int
	ExecutionPayload *builderApiDeneb.ExecutionPayloadAndBlobsBundle
}

func (api *BlockValidationAPI) AppendProfBundle(params *ProfSimReq) (*ProfSimResp, error) {
	var err error
	log.Info("PROF simulation called!")
	log.Info(params.PbsPayload.String())

	payload := params.PbsPayload.ExecutionPayload
	baseBlockHash := common.Hash(payload.BlockHash)
	blobsBundle := params.PbsPayload.BlobsBundle
	profTransactionString := params.ProfBundle.Transactions
	// convert hex prof transaction to bytes
	profTransactionBytes := make([][]byte, len(profTransactionString))
	for i, tx := range profTransactionString {
		profTransactionBytes[i], _ = hex.DecodeString(tx[2:]) // remove 0x // ignore error as it is prevalidated
	}

	log.Info("blobs bundle", "blobs", len(blobsBundle.Blobs), "commits", len(blobsBundle.Commitments), "proofs", len(blobsBundle.Proofs))
	block, err := engine.ExecutionPayloadV3ToBlockProf(payload, profTransactionBytes, blobsBundle, params.ParentBeaconBlockRoot)
	if err != nil {
		return nil, err
	}
	profValidationResp, err := api.validateProfBlock(baseBlockHash, block, params.ProposerFeeRecipient, params.RegisteredGasLimit)
	if err != nil {
		log.Error("invalid payload", "hash", block.Hash, "number", block.NumberU64(), "parentHash", block.ParentHash, "err", err)
		return nil, err
	}

	return profValidationResp, nil

}

func (api *BlockValidationAPI) ValidateBuilderSubmissionV3(params *BuilderBlockValidationRequestV3) error {
	// TODO: fuzztest, make sure the validation is sound

	log.Info("json-rpc validation v3 called!")

	payload := params.ExecutionPayload
	blobsBundle := params.BlobsBundle
	log.Info("blobs bundle", "blobs", len(blobsBundle.Blobs), "commits", len(blobsBundle.Commitments), "proofs", len(blobsBundle.Proofs))
	block, err := engine.ExecutionPayloadV3ToBlock(payload, blobsBundle, params.ParentBeaconBlockRoot)
	if err != nil {
		return err
	}

	err = api.validateBlock(block, params.Message, params.RegisteredGasLimit)
	if err != nil {
		log.Error("invalid payload", "hash", block.Hash, "number", block.NumberU64(), "parentHash", block.ParentHash, "err", err)
		return err
	}
	err = validateBlobsBundle(block.Transactions(), blobsBundle)
	if err != nil {
		log.Error("invalid blobs bundle", "err", err)
		return err
	}
	return nil
}

// TODO : invalid profTransactions are not being filtered out currently, change the validateProfBlock method to pluck out the invalid transactions, blockhash would also change in that case

func (api *BlockValidationAPI) validateProfBlock(baseblockHash common.Hash, profBlock *types.Block, proposerFeeRecipient common.Address, registeredGasLimit uint64) (*ProfSimResp, error) {
	log.Info("validateProfBlock method called!")

	feeRecipient := common.BytesToAddress(proposerFeeRecipient[:])

	var vmconfig vm.Config

	bc := api.eth.BlockChain()
	baseBlockData := api.profCache[baseblockHash]
	receipts := baseBlockData.receipts
	statedb := baseBlockData.state

	value, header, err := bc.SimulateProfBlock(profBlock, feeRecipient, registeredGasLimit, vmconfig, true /* prof uses balance diff*/, true /* exclude withdrawals */, api.profProcessor, receipts, statedb)

	if err != nil {
		return nil, err
	}
	profBlockFinal := profBlock.WithSeal(header)
	log.Info("validated prof block", "baseblockHash", baseblockHash, "number", profBlockFinal.NumberU64(), "parentHash", profBlockFinal.ParentHash())

	valueBig := value.ToBig()

	executableData := engine.BlockToExecutableData(profBlockFinal, valueBig, []*types.BlobTxSidecar{})

	payload, err := getDenebPayload(executableData)
	if err != nil {
		log.Error("could not format execution payload", "err", err)
		return nil, err
	}

	return &ProfSimResp{value, payload}, nil

	// return &ProfSimResp{uint256.NewInt(0), phase0.Hash32(block.Hash())}, nil

}

func (api *BlockValidationAPI) validateBlock(block *types.Block, msg *builderApiV1.BidTrace, registeredGasLimit uint64) error {
	log.Info("validateBlock method called!")

	if msg.ParentHash != phase0.Hash32(block.ParentHash()) {
		return fmt.Errorf("incorrect ParentHash %s, expected %s", msg.ParentHash.String(), block.ParentHash().String())
	}

	if msg.BlockHash != phase0.Hash32(block.Hash()) {
		return fmt.Errorf("incorrect BlockHash %s, expected %s", msg.BlockHash.String(), block.Hash().String())
	}

	if msg.GasLimit != block.GasLimit() {
		return fmt.Errorf("incorrect GasLimit %d, expected %d", msg.GasLimit, block.GasLimit())
	}

	if msg.GasUsed != block.GasUsed() {
		return fmt.Errorf("incorrect GasUsed %d, expected %d", msg.GasUsed, block.GasUsed())
	}

	feeRecipient := common.BytesToAddress(msg.ProposerFeeRecipient[:])
	expectedProfit := msg.Value.ToBig()

	var vmconfig vm.Config
	var tracer *logger.AccessListTracer = nil
	if api.accessVerifier != nil {
		if err := api.accessVerifier.isBlacklisted(block.Coinbase()); err != nil {
			return err
		}
		if err := api.accessVerifier.isBlacklisted(feeRecipient); err != nil {
			return err
		}
		if err := api.accessVerifier.verifyTransactions(types.LatestSigner(api.eth.BlockChain().Config()), block.Transactions()); err != nil {
			return err
		}
		isPostMerge := true // the call is PoS-native
		precompiles := vm.ActivePrecompiles(api.eth.APIBackend.ChainConfig().Rules(new(big.Int).SetUint64(block.NumberU64()), isPostMerge, block.Time()))
		tracer = logger.NewAccessListTracer(nil, common.Address{}, common.Address{}, precompiles)
		vmconfig = vm.Config{Tracer: tracer}
	}

	err, receipts, statedbObj := api.eth.BlockChain().ValidatePayloadProf(block, feeRecipient, expectedProfit, registeredGasLimit, vmconfig, api.useBalanceDiffProfit, api.excludeWithdrawals)
	if err != nil {
		return err
	}

	if api.accessVerifier != nil && tracer != nil {
		if err := api.accessVerifier.verifyTraces(tracer); err != nil {
			return err
		}
	}
	api.profCache[block.Hash()] = blockValidationCache{receipts: receipts, state: statedbObj}
	fmt.Printf("Validated Block %v adding to cache\n", block.Hash())
	log.Info("validated block", "hash", block.Hash(), "number", block.NumberU64(), "parentHash", block.ParentHash())
	return nil
}

func validateBlobsBundle(txs types.Transactions, blobsBundle *builderApiDeneb.BlobsBundle) error {
	var hashes []common.Hash
	for _, tx := range txs {
		hashes = append(hashes, tx.BlobHashes()...)
	}
	blobs := blobsBundle.Blobs
	commits := blobsBundle.Commitments
	proofs := blobsBundle.Proofs

	if len(blobs) != len(hashes) {
		return fmt.Errorf("invalid number of %d blobs compared to %d blob hashes", len(blobs), len(hashes))
	}
	if len(commits) != len(hashes) {
		return fmt.Errorf("invalid number of %d blob commitments compared to %d blob hashes", len(commits), len(hashes))
	}
	if len(proofs) != len(hashes) {
		return fmt.Errorf("invalid number of %d blob proofs compared to %d blob hashes", len(proofs), len(hashes))
	}

	for i := range blobs {
		if err := kzg4844.VerifyBlobProof(kzg4844.Blob(blobs[i]), kzg4844.Commitment(commits[i]), kzg4844.Proof(proofs[i])); err != nil {
			return fmt.Errorf("invalid blob %d: %v", i, err)
		}
	}
	log.Info("validated blobs bundle", "blobs", len(blobs), "commits", len(commits), "proofs", len(proofs))
	return nil
}

func getDenebPayload(
	data *engine.ExecutionPayloadEnvelope,
) (*builderApiDeneb.ExecutionPayloadAndBlobsBundle, error) {
	payload := data.ExecutionPayload
	blobsBundle := data.BlobsBundle
	baseFeePerGas, overflow := uint256.FromBig(payload.BaseFeePerGas)
	if overflow {
		return nil, fmt.Errorf("base fee per gas overflow")
	}
	transactions := make([]bellatrix.Transaction, len(payload.Transactions))
	for i, tx := range payload.Transactions {
		transactions[i] = bellatrix.Transaction(tx)
	}
	withdrawals := make([]*capella.Withdrawal, len(payload.Withdrawals))
	for i, wd := range payload.Withdrawals {
		withdrawals[i] = &capella.Withdrawal{
			Index:          capella.WithdrawalIndex(wd.Index),
			ValidatorIndex: phase0.ValidatorIndex(wd.Validator),
			Address:        bellatrix.ExecutionAddress(wd.Address),
			Amount:         phase0.Gwei(wd.Amount),
		}
	}
	return &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
		ExecutionPayload: &deneb.ExecutionPayload{
			ParentHash:    [32]byte(payload.ParentHash),
			FeeRecipient:  [20]byte(payload.FeeRecipient),
			StateRoot:     [32]byte(payload.StateRoot),
			ReceiptsRoot:  [32]byte(payload.ReceiptsRoot),
			LogsBloom:     types.BytesToBloom(payload.LogsBloom),
			PrevRandao:    [32]byte(payload.Random),
			BlockNumber:   payload.Number,
			GasLimit:      payload.GasLimit,
			GasUsed:       payload.GasUsed,
			Timestamp:     payload.Timestamp,
			ExtraData:     payload.ExtraData,
			BaseFeePerGas: baseFeePerGas,
			BlockHash:     [32]byte(payload.BlockHash),
			Transactions:  transactions,
			Withdrawals:   withdrawals,
			BlobGasUsed:   *payload.BlobGasUsed,
			ExcessBlobGas: *payload.ExcessBlobGas,
		},
		BlobsBundle: getBlobsBundle(blobsBundle),
	}, nil

}

func getBlobsBundle(blobsBundle *engine.BlobsBundleV1) *builderApiDeneb.BlobsBundle {
	commitments := make([]deneb.KZGCommitment, len(blobsBundle.Commitments))
	proofs := make([]deneb.KZGProof, len(blobsBundle.Proofs))
	blobs := make([]deneb.Blob, len(blobsBundle.Blobs))

	// we assume the lengths for blobs bundle is validated beforehand to be the same
	for i := range blobsBundle.Blobs {
		var commitment deneb.KZGCommitment
		copy(commitment[:], blobsBundle.Commitments[i][:])
		commitments[i] = commitment

		var proof deneb.KZGProof
		copy(proof[:], blobsBundle.Proofs[i][:])
		proofs[i] = proof

		var blob deneb.Blob
		copy(blob[:], blobsBundle.Blobs[i][:])
		blobs[i] = blob
	}
	return &builderApiDeneb.BlobsBundle{
		Commitments: commitments,
		Proofs:      proofs,
		Blobs:       blobs,
	}
}
