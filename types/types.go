// Package types defines the essential types of the Bigfile blockchain.
package types

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"time"

	"lukechampine.com/frand"
)

const (
	v2ResolutionRenewal      = "renewal"
	v2ResolutionStorageProof = "storageProof"
	v2ResolutionExpiration   = "expiration"
)

const (
	// MaxRevisionNumber is used to finalize a FileContract. When a contract's
	// RevisionNumber is set to this value, no further revisions are possible.
	MaxRevisionNumber = math.MaxUint64

	// RenterContractIndex defines the index of the renter's output and public
	// key in a FileContract.
	RenterContractIndex = 0

	// HostContractIndex defines the index of the host's output and public key in
	// a FileContract.
	HostContractIndex = 1

	// UnassignedLeafIndex is a sentinel value used as the LeafIndex of
	// StateElements that have not been added to the accumulator yet. This is
	// necessary for constructing blocks sets where later transactions reference
	// elements created in earlier transactions.
	//
	// Most clients do not need to reference this value directly, and should
	// instead use the EphemeralBigfileElement and EphemeralBigfundElement
	// functions to construct dependent transaction sets.
	UnassignedLeafIndex = 10101010101010101010
)

// Various specifiers.
var (
	SpecifierEd25519       = NewSpecifier("ed25519")
	SpecifierBigfileOutput = NewSpecifier("bigfile output")
	SpecifierBigfundOutput = NewSpecifier("bigfund output")
	SpecifierFileContract  = NewSpecifier("file contract")
	SpecifierStorageProof  = NewSpecifier("storage proof")
	SpecifierFoundation    = NewSpecifier("foundation")
	SpecifierEntropy       = NewSpecifier("entropy")
)

// A Hash256 is a generic 256-bit cryptographic hash.
type Hash256 [32]byte

// A PublicKey is an Ed25519 public key.
type PublicKey [32]byte

// VerifyHash verifies that s is a valid signature of h by pk.
func (pk PublicKey) VerifyHash(h Hash256, s Signature) bool {
	return ed25519.Verify(pk[:], h[:], s[:])
}

// UnlockKey returns pk as an UnlockKey.
func (pk PublicKey) UnlockKey() UnlockKey {
	return UnlockKey{
		Algorithm: SpecifierEd25519,
		Key:       pk[:],
	}
}

// StandardUnlockConditions returns the standard unlock conditions for pk.
func StandardUnlockConditions(pk PublicKey) UnlockConditions {
	return UnlockConditions{
		PublicKeys:         []UnlockKey{pk.UnlockKey()},
		SignaturesRequired: 1,
	}
}

// A PrivateKey is an Ed25519 private key.
type PrivateKey []byte

// PublicKey returns the PublicKey corresponding to priv.
func (priv PrivateKey) PublicKey() (pk PublicKey) {
	copy(pk[:], priv[32:])
	return
}

// SignHash signs h with priv, producing a Signature.
func (priv PrivateKey) SignHash(h Hash256) (s Signature) {
	copy(s[:], ed25519.Sign(ed25519.PrivateKey(priv), h[:]))
	return
}

// NewPrivateKeyFromSeed calculates a private key from a seed.
func NewPrivateKeyFromSeed(seed []byte) PrivateKey {
	return PrivateKey(ed25519.NewKeyFromSeed(seed))
}

// GeneratePrivateKey creates a new private key from a secure entropy source.
func GeneratePrivateKey() PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	frand.Read(seed)
	pk := NewPrivateKeyFromSeed(seed)
	for i := range seed {
		seed[i] = 0
	}
	return pk
}

// A Signature is an Ed25519 signature.
type Signature [64]byte

// A Specifier is a fixed-size, 0-padded identifier.
type Specifier [16]byte

// NewSpecifier returns a specifier containing the provided name.
func NewSpecifier(name string) (s Specifier) {
	if len(name) > len(s) {
		panic(fmt.Sprintf("specifier name too long: len(%q) > 16", name))
	}
	copy(s[:], name)
	return
}

// An UnlockKey can provide one of the signatures required by a set of
// UnlockConditions.
type UnlockKey struct {
	Algorithm Specifier
	Key       []byte
}

// UnlockConditions specify the conditions for spending an output or revising a
// file contract.
type UnlockConditions struct {
	Timelock           uint64      `json:"timelock"`
	PublicKeys         []UnlockKey `json:"publicKeys"`
	SignaturesRequired uint64      `json:"signaturesRequired"`
}

// UnlockHash computes the hash of a set of UnlockConditions. Such hashes are
// most commonly used as addresses, but are also used in file contracts.
func (uc UnlockConditions) UnlockHash() Address {
	// almost all UnlockConditions are standard, so optimize for that case
	if uc.Timelock == 0 &&
		len(uc.PublicKeys) == 1 &&
		uc.PublicKeys[0].Algorithm == SpecifierEd25519 &&
		len(uc.PublicKeys[0].Key) == len(PublicKey{}) &&
		uc.SignaturesRequired == 1 {
		return StandardUnlockHash(*(*PublicKey)(uc.PublicKeys[0].Key))
	}
	return unlockConditionsRoot(uc)
}

// An Address is the hash of a set of UnlockConditions.
type Address Hash256

// VoidAddress is an address whose signing key does not exist. Sending coins to
// this address ensures that they will never be recoverable by anyone.
var VoidAddress Address

// A BlockID uniquely identifies a block.
type BlockID Hash256

// CmpWork compares the work implied by two BlockIDs.
func (bid BlockID) CmpWork(t BlockID) int {
	// work is the inverse of the ID, so reverse the comparison
	return bytes.Compare(t[:], bid[:])
}

// MinerOutputID returns the ID of the block's i'th miner payout.
func (bid BlockID) MinerOutputID(i int) BigfileOutputID {
	return hashAll(bid, i)
}

// FoundationOutputID returns the ID of the block's Foundation subsidy.
func (bid BlockID) FoundationOutputID() BigfileOutputID {
	return hashAll(bid, SpecifierFoundation)
}

// A TransactionID uniquely identifies a transaction.
type TransactionID Hash256

// A ChainIndex pairs a block's height with its ID.
type ChainIndex struct {
	Height uint64  `json:"height"`
	ID     BlockID `json:"id"`
}

// A BigfileOutput is the recipient of some of the bigfiles spent in a
// transaction.
type BigfileOutput struct {
	Value   Currency `json:"value"`
	Address Address  `json:"address"`
}

// A BigfileOutputID uniquely identifies a bigfile output.
type BigfileOutputID Hash256

// A BigfileInput spends an unspent BigfileOutput in the UTXO set by
// revealing and satisfying its unlock conditions.
type BigfileInput struct {
	ParentID         BigfileOutputID  `json:"parentID"`
	UnlockConditions UnlockConditions `json:"unlockConditions"`
}

// MarshalJSON implements json.Marshaler.
//
// For convenience, the input's address is also calculated and included. This field is ignored during unmarshalling.
func (si BigfileInput) MarshalJSON() ([]byte, error) {
	type jsonBigfileInput BigfileInput // prevent recursion
	return json.Marshal(struct {
		jsonBigfileInput
		Address Address `json:"address"`
	}{
		jsonBigfileInput: jsonBigfileInput(si),
		Address:          si.UnlockConditions.UnlockHash(),
	})
}

// A BigfundOutput is the recipient of some of the bigfilefunds spent in a
// transaction.
type BigfundOutput struct {
	Value   uint64  `json:"value"`
	Address Address `json:"address"`
}

// A BigfundOutputID uniquely identifies a bigfund output.
type BigfundOutputID Hash256

// ClaimOutputID returns the ID of the BigfileOutput that is created when
// the bigfund output is spent.
func (bfoid BigfundOutputID) ClaimOutputID() BigfileOutputID {
	return hashAll(bfoid)
}

// V2ClaimOutputID returns the ID of the BigfileOutput that is created when the
// bigfund output is spent.
func (bfoid BigfundOutputID) V2ClaimOutputID() BigfileOutputID {
	return hashAll("id/v2bigfileclaimoutput", bfoid)
}

// A BigfundInput spends an unspent BigfundOutput in the UTXO set by revealing
// and satisfying its unlock conditions. BigfundInputs also include a
// ClaimAddress, specifying the recipient of the bigfiles that were earned by
// the output.
type BigfundInput struct {
	ParentID         BigfundOutputID  `json:"parentID"`
	UnlockConditions UnlockConditions `json:"unlockConditions"`
	ClaimAddress     Address          `json:"claimAddress"`
}

// MarshalJSON implements json.Marshaler.
//
// For convenience, the input's address is also calculated and included. This field is ignored during unmarshalling.
func (si BigfundInput) MarshalJSON() ([]byte, error) {
	type jsonBigfundInput BigfundInput // prevent recursion
	return json.Marshal(struct {
		jsonBigfundInput
		Address Address `json:"address"`
	}{
		jsonBigfundInput: jsonBigfundInput(si),
		Address:          si.UnlockConditions.UnlockHash(),
	})
}

// A FileContract is a storage agreement between a renter and a host. It
// contains a bidirectional payment channel that resolves as either "valid" or
// "missed" depending on whether a valid StorageProof is submitted for the
// contract.
type FileContract struct {
	Filesize           uint64          `json:"filesize"`
	FileMerkleRoot     Hash256         `json:"fileMerkleRoot"`
	WindowStart        uint64          `json:"windowStart"`
	WindowEnd          uint64          `json:"windowEnd"`
	Payout             Currency        `json:"payout"`
	ValidProofOutputs  []BigfileOutput `json:"validProofOutputs"`
	MissedProofOutputs []BigfileOutput `json:"missedProofOutputs"`
	UnlockHash         Address         `json:"unlockHash"`
	RevisionNumber     uint64          `json:"revisionNumber"`
}

// EndHeight returns the height at which the contract's host is no longer
// obligated to store the contract data.
func (fc *FileContract) EndHeight() uint64 { return fc.WindowStart }

// ValidRenterOutput returns the output that will be created for the renter if
// the contract resolves valid.
func (fc *FileContract) ValidRenterOutput() BigfileOutput {
	return fc.ValidProofOutputs[RenterContractIndex]
}

// ValidRenterPayout returns the amount of bigfiles that the renter will receive
// if the contract resolves valid.
func (fc *FileContract) ValidRenterPayout() Currency { return fc.ValidRenterOutput().Value }

// MissedRenterOutput returns the output that will be created for the renter if
// the contract resolves missed.
func (fc *FileContract) MissedRenterOutput() BigfileOutput {
	return fc.MissedProofOutputs[RenterContractIndex]
}

// MissedRenterPayout returns the amount of bigfiles that the renter will receive
// if the contract resolves missed.
func (fc *FileContract) MissedRenterPayout() Currency { return fc.MissedRenterOutput().Value }

// ValidHostOutput returns the output that will be created for the host if
// the contract resolves valid.
func (fc *FileContract) ValidHostOutput() BigfileOutput {
	return fc.ValidProofOutputs[HostContractIndex]
}

// ValidHostPayout returns the amount of bigfiles that the host will receive
// if the contract resolves valid.
func (fc *FileContract) ValidHostPayout() Currency { return fc.ValidHostOutput().Value }

// MissedHostOutput returns the output that will be created for the host if
// the contract resolves missed.
func (fc *FileContract) MissedHostOutput() BigfileOutput {
	return fc.MissedProofOutputs[HostContractIndex]
}

// MissedHostPayout returns the amount of bigfiles that the host will receive
// if the contract resolves missed.
func (fc *FileContract) MissedHostPayout() Currency { return fc.MissedHostOutput().Value }

// A FileContractID uniquely identifies a file contract.
type FileContractID Hash256

// ValidOutputID returns the ID of the valid proof output at index i.
func (fcid FileContractID) ValidOutputID(i int) BigfileOutputID {
	return hashAll(SpecifierStorageProof, fcid, true, i)
}

// MissedOutputID returns the ID of the missed proof output at index i.
func (fcid FileContractID) MissedOutputID(i int) BigfileOutputID {
	return hashAll(SpecifierStorageProof, fcid, false, i)
}

// V2RenterOutputID returns the ID of the renter output for a v2 contract.
func (fcid FileContractID) V2RenterOutputID() BigfileOutputID {
	return hashAll("id/v2filecontractoutput", fcid, 0)
}

// V2HostOutputID returns the ID of the host output for a v2 contract.
func (fcid FileContractID) V2HostOutputID() BigfileOutputID {
	return hashAll("id/v2filecontractoutput", fcid, 1)
}

// V2RenewalID returns the ID of the renewal of a v2 contract.
func (fcid FileContractID) V2RenewalID() FileContractID {
	return hashAll("id/v2filecontractrenewal", fcid)
}

// A FileContractRevision updates the state of an existing file contract.
type FileContractRevision struct {
	ParentID         FileContractID   `json:"parentID"`
	UnlockConditions UnlockConditions `json:"unlockConditions"`
	// NOTE: the Payout field of the contract is not "really" part of a
	// revision. A revision cannot change the total payout, so the original siad
	// code defines FileContractRevision as an entirely separate struct without
	// a Payout field. Here, we instead reuse the FileContract type, which means
	// we must treat its Payout field as invalid. To guard against developer
	// error, we set it to a sentinel value when decoding it.
	FileContract
}

// A StorageProof asserts the presence of a randomly-selected leaf within the
// Merkle tree of a FileContract's data.
type StorageProof struct {
	ParentID FileContractID
	Leaf     [64]byte
	Proof    []Hash256
}

// A FoundationAddressUpdate updates the primary and failsafe Foundation subsidy
// addresses.
type FoundationAddressUpdate struct {
	NewPrimary  Address `json:"newPrimary"`
	NewFailsafe Address `json:"newFailsafe"`
}

// CoveredFields indicates which fields of a transaction are covered by a
// signature.
type CoveredFields struct {
	WholeTransaction      bool     `json:"wholeTransaction,omitempty"`
	BigfileInputs         []uint64 `json:"bigfileInputs,omitempty"`
	BigfileOutputs        []uint64 `json:"bigfileOutputs,omitempty"`
	FileContracts         []uint64 `json:"fileContracts,omitempty"`
	FileContractRevisions []uint64 `json:"fileContractRevisions,omitempty"`
	StorageProofs         []uint64 `json:"storageProofs,omitempty"`
	BigfundInputs         []uint64 `json:"bigfundInputs,omitempty"`
	BigfundOutputs        []uint64 `json:"bigfundOutputs,omitempty"`
	MinerFees             []uint64 `json:"minerFees,omitempty"`
	ArbitraryData         []uint64 `json:"arbitraryData,omitempty"`
	Signatures            []uint64 `json:"signatures,omitempty"`
}

// A TransactionSignature signs transaction data.
type TransactionSignature struct {
	ParentID       Hash256       `json:"parentID"`
	PublicKeyIndex uint64        `json:"publicKeyIndex"`
	Timelock       uint64        `json:"timelock,omitempty"`
	CoveredFields  CoveredFields `json:"coveredFields"`
	Signature      []byte        `json:"signature"`
}

// A Transaction effects a change of blockchain state.
type Transaction struct {
	BigfileInputs         []BigfileInput         `json:"bigfileInputs,omitempty"`
	BigfileOutputs        []BigfileOutput        `json:"bigfileOutputs,omitempty"`
	FileContracts         []FileContract         `json:"fileContracts,omitempty"`
	FileContractRevisions []FileContractRevision `json:"fileContractRevisions,omitempty"`
	StorageProofs         []StorageProof         `json:"storageProofs,omitempty"`
	BigfundInputs         []BigfundInput         `json:"bigfundInputs,omitempty"`
	BigfundOutputs        []BigfundOutput        `json:"bigfundOutputs,omitempty"`
	MinerFees             []Currency             `json:"minerFees,omitempty"`
	ArbitraryData         [][]byte               `json:"arbitraryData,omitempty"`
	Signatures            []TransactionSignature `json:"signatures,omitempty"`
}

// MarshalJSON implements json.Marshaler.
//
// The transaction and UTXO IDs are calculated and included for convenience.
// These fields are ignored during unmarshalling.
func (txn Transaction) MarshalJSON() ([]byte, error) {
	type jsonTxn Transaction
	type jsonBigfileOutput struct {
		ID BigfileOutputID `json:"id"`
		BigfileOutput
	}
	type jsonBigfundOutput struct {
		ID BigfundOutputID `json:"id"`
		BigfundOutput
	}
	obj := struct {
		ID             TransactionID       `json:"id"`
		BigfileOutputs []jsonBigfileOutput `json:"bigfileOutputs,omitempty"`
		BigfundOutputs []jsonBigfundOutput `json:"bigfundOutputs,omitempty"`
		jsonTxn
	}{
		ID:             txn.ID(),
		jsonTxn:        jsonTxn(txn),
		BigfileOutputs: make([]jsonBigfileOutput, 0, len(txn.BigfileOutputs)),
		BigfundOutputs: make([]jsonBigfundOutput, 0, len(txn.BigfundOutputs)),
	}
	for i := range txn.BigfileOutputs {
		obj.BigfileOutputs = append(obj.BigfileOutputs, jsonBigfileOutput{
			ID:            txn.BigfileOutputID(i),
			BigfileOutput: txn.BigfileOutputs[i],
		})
	}
	for i := range txn.BigfundOutputs {
		obj.BigfundOutputs = append(obj.BigfundOutputs, jsonBigfundOutput{
			ID:            txn.BigfundOutputID(i),
			BigfundOutput: txn.BigfundOutputs[i],
		})
	}
	return json.Marshal(obj)
}

// ID returns the "semantic hash" of the transaction, covering all of the
// transaction's effects, but not incidental data such as signatures. This
// ensures that the ID will remain stable (i.e. non-malleable).
//
// To hash all of the data in a transaction, use the FullHash method.
func (txn *Transaction) ID() TransactionID {
	return hashAll((*txnSansSigs)(txn))
}

// FullHash returns the hash of the transaction's binary encoding. This hash is
// only used in specific circumstances; generally, ID should be used instead.
func (txn *Transaction) FullHash() Hash256 {
	return hashAll(txn)
}

// BigfileOutputID returns the ID of the bigfile output at index i.
func (txn *Transaction) BigfileOutputID(i int) BigfileOutputID {
	return hashAll(SpecifierBigfileOutput, (*txnSansSigs)(txn), i)
}

// BigfundOutputID returns the ID of the bigfund output at index i.
func (txn *Transaction) BigfundOutputID(i int) BigfundOutputID {
	return hashAll(SpecifierBigfundOutput, (*txnSansSigs)(txn), i)
}

// BigfundClaimOutputID returns the ID of the bigfile claim output for the
// bigfund input at index i.
func (txn *Transaction) BigfundClaimOutputID(i int) BigfileOutputID {
	return hashAll(txn.BigfundOutputID(i))
}

// FileContractID returns the ID of the file contract at index i.
func (txn *Transaction) FileContractID(i int) FileContractID {
	return hashAll(SpecifierFileContract, (*txnSansSigs)(txn), i)
}

// TotalFees returns the sum of the transaction's miner fees. If the sum would
// overflow, TotalFees returns ZeroCurrency.
func (txn *Transaction) TotalFees() Currency {
	var sum Currency
	var overflow bool
	for _, fee := range txn.MinerFees {
		sum, overflow = sum.AddWithOverflow(fee)
		if overflow {
			return ZeroCurrency
		}
	}
	return sum
}

// A V2FileContract is a storage agreement between a renter and a host. It
// consists of a bidirectional payment channel that resolves as either "valid"
// or "missed" depending on whether a valid StorageProof is submitted for the
// contract.
type V2FileContract struct {
	Capacity         uint64        `json:"capacity"`
	Filesize         uint64        `json:"filesize"`
	FileMerkleRoot   Hash256       `json:"fileMerkleRoot"`
	ProofHeight      uint64        `json:"proofHeight"`
	ExpirationHeight uint64        `json:"expirationHeight"`
	RenterOutput     BigfileOutput `json:"renterOutput"`
	HostOutput       BigfileOutput `json:"hostOutput"`
	MissedHostValue  Currency      `json:"missedHostValue"`
	TotalCollateral  Currency      `json:"totalCollateral"`
	RenterPublicKey  PublicKey     `json:"renterPublicKey"`
	HostPublicKey    PublicKey     `json:"hostPublicKey"`
	RevisionNumber   uint64        `json:"revisionNumber"`

	// signatures cover above fields
	RenterSignature Signature `json:"renterSignature"`
	HostSignature   Signature `json:"hostSignature"`
}

// MissedHostOutput returns the host output that will be created if the contract
// resolves missed.
func (fc V2FileContract) MissedHostOutput() BigfileOutput {
	return BigfileOutput{
		Value:   fc.MissedHostValue,
		Address: fc.HostOutput.Address,
	}
}

// A V2BigfileInput spends an unspent BigfileElement in the state accumulator by
// revealing its public key and signing the transaction.
type V2BigfileInput struct {
	Parent          BigfileElement  `json:"parent"`
	SatisfiedPolicy SatisfiedPolicy `json:"satisfiedPolicy"`
}

// A V2BigfundInput spends an unspent BigfundElement in the state accumulator by
// revealing its public key and signing the transaction. Inputs also include a
// ClaimAddress, specifying the recipient of the bigfiles that were earned by
// the BigfundElement.
type V2BigfundInput struct {
	Parent          BigfundElement  `json:"parent"`
	ClaimAddress    Address         `json:"claimAddress"`
	SatisfiedPolicy SatisfiedPolicy `json:"satisfiedPolicy"`
}

// A V2FileContractRevision updates the state of an existing file contract.
type V2FileContractRevision struct {
	Parent   V2FileContractElement `json:"parent"`
	Revision V2FileContract        `json:"revision"`
}

// A V2FileContractResolution closes a v2 file contract's payment channel. There
// are three ways a contract can be resolved:
//
// 1) The renter and host can jointly renew the contract. The old contract is
// finalized, and a portion of its funds are "rolled over" into a new contract.
// Renewals must be submitted prior to the contract's ProofHeight.
//
// 2) If the renter is unwilling or unable to sign a renewal, the host can
// submit a storage proof, asserting that it has faithfully stored the contract
// data for the agreed-upon duration. Storage proofs must be submitted after the
// contract's ProofHeight and prior to its ExpirationHeight.
//
// 3) Lastly, anyone can submit a contract expiration. An expiration can only be
// submitted after the contract's ExpirationHeight.
//
// Once a contract has been resolved, it cannot be altered or resolved again.
// When a contract is resolved, its RenterOutput and HostOutput are created
// immediately (though they will not be spendable until their timelock expires).
// However, if the contract is resolved via an expiration, the HostOutput will
// have value equal to MissedHostValue; in other words, the host forfeits its
// collateral. This is considered a "missed" resolution; all other resolution
// types are "valid." As a special case, the expiration of an empty contract is
// considered valid, reflecting the fact that the host has not failed to perform
// any duty.
type V2FileContractResolution struct {
	Parent     V2FileContractElement        `json:"parent"`
	Resolution V2FileContractResolutionType `json:"resolution"`
}

// V2FileContractResolutionType enumerates the types of file contract resolution.
type V2FileContractResolutionType interface {
	isV2FileContractResolution()
}

func (*V2FileContractRenewal) isV2FileContractResolution()    {}
func (*V2StorageProof) isV2FileContractResolution()           {}
func (*V2FileContractExpiration) isV2FileContractResolution() {}

// A V2FileContractRenewal renews a file contract.
type V2FileContractRenewal struct {
	FinalRenterOutput BigfileOutput  `json:"finalRenterOutput"`
	FinalHostOutput   BigfileOutput  `json:"finalHostOutput"`
	RenterRollover    Currency       `json:"renterRollover"`
	HostRollover      Currency       `json:"hostRollover"`
	NewContract       V2FileContract `json:"newContract"`

	// signatures cover above fields
	RenterSignature Signature `json:"renterSignature"`
	HostSignature   Signature `json:"hostSignature"`
}

// A V2StorageProof asserts the presence of a randomly-selected leaf within the
// Merkle tree of a V2FileContract's data.
type V2StorageProof struct {
	// Selecting the leaf requires a source of unpredictable entropy; we use the
	// ID of the block at the contract's ProofHeight. The storage proof thus
	// includes a proof that this ID is the correct ancestor.
	//
	// During validation, it is imperative to check that ProofIndex.Height
	// matches the ProofHeight field of the contract's final revision;
	// otherwise, the prover could use any ProofIndex, giving them control over
	// the leaf index.
	ProofIndex ChainIndexElement

	// The leaf is always 64 bytes, extended with zeros if necessary.
	Leaf  [64]byte
	Proof []Hash256
}

// A V2FileContractExpiration resolves an expired contract. A contract is
// considered expired when its proof window has elapsed. If the contract is not
// storing any data, it will resolve as valid; otherwise, it resolves as missed.
type V2FileContractExpiration struct{}

// An Attestation associates a key-value pair with an identity. For example,
// hosts attest to their network address by setting Key to "HostAnnouncement"
// and Value to their address, thereby allowing renters to discover them.
// Generally, an attestation for a particular key is considered to overwrite any
// previous attestations with the same key. (This allows hosts to announce a new
// network address, for example.)
type Attestation struct {
	PublicKey PublicKey `json:"publicKey"`
	Key       string    `json:"key"`
	Value     []byte    `json:"value"`
	Signature Signature `json:"signature"`
}

// An AttestationID uniquely identifies an attestation.
type AttestationID Hash256

// An ElementID identifies a generic element within the state accumulator. In
// practice, it may be a BlockID, BigfileOutputID, BigfundOutputID,
// FileContractID, or AttestationID.
type ElementID = [32]byte

// A StateElement is a generic element within the state accumulator.
type StateElement struct {
	LeafIndex   uint64    `json:"leafIndex"`
	MerkleProof []Hash256 `json:"merkleProof,omitempty"`

	shared bool // if true, mutation is illegal
}

// A ChainIndexElement is a record of a ChainIndex within the state accumulator.
type ChainIndexElement struct {
	ID           BlockID      `json:"id"`
	StateElement StateElement `json:"stateElement"`
	ChainIndex   ChainIndex   `json:"chainIndex"`
}

// A BigfileElement is a record of a BigfileOutput within the state accumulator.
type BigfileElement struct {
	ID             BigfileOutputID `json:"id"`
	StateElement   StateElement    `json:"stateElement"`
	BigfileOutput  BigfileOutput   `json:"bigfileOutput"`
	MaturityHeight uint64          `json:"maturityHeight"`
}

// A BigfundElement is a record of a BigfundOutput within the state accumulator.
type BigfundElement struct {
	ID            BigfundOutputID `json:"id"`
	StateElement  StateElement    `json:"stateElement"`
	BigfundOutput BigfundOutput   `json:"bigfundOutput"`
	ClaimStart    Currency        `json:"claimStart"` // value of BigfundTaxRevenue when element was created
}

// A FileContractElement is a record of a FileContract within the state
// accumulator.
type FileContractElement struct {
	ID           FileContractID `json:"id"`
	StateElement StateElement   `json:"stateElement"`
	FileContract FileContract   `json:"fileContract"`
}

// A V2FileContractElement is a record of a V2FileContract within the state
// accumulator.
type V2FileContractElement struct {
	ID             FileContractID `json:"id"`
	StateElement   StateElement   `json:"stateElement"`
	V2FileContract V2FileContract `json:"v2FileContract"`
}

// An AttestationElement is a record of an Attestation within the state
// accumulator.
type AttestationElement struct {
	ID           AttestationID `json:"id"`
	StateElement StateElement  `json:"stateElement"`
	Attestation  Attestation   `json:"attestation"`
}

// A V2Transaction effects a change of blockchain state.
type V2Transaction struct {
	BigfileInputs           []V2BigfileInput           `json:"bigfileInputs,omitempty"`
	BigfileOutputs          []BigfileOutput            `json:"bigfileOutputs,omitempty"`
	BigfundInputs           []V2BigfundInput           `json:"bigfundInputs,omitempty"`
	BigfundOutputs          []BigfundOutput            `json:"bigfundOutputs,omitempty"`
	FileContracts           []V2FileContract           `json:"fileContracts,omitempty"`
	FileContractRevisions   []V2FileContractRevision   `json:"fileContractRevisions,omitempty"`
	FileContractResolutions []V2FileContractResolution `json:"fileContractResolutions,omitempty"`
	Attestations            []Attestation              `json:"attestations,omitempty"`
	ArbitraryData           []byte                     `json:"arbitraryData,omitempty"`
	NewFoundationAddress    *Address                   `json:"newFoundationAddress,omitempty"`
	MinerFee                Currency                   `json:"minerFee"`
}

// ID returns the "semantic hash" of the transaction, covering all of the
// transaction's effects, but not incidental data such as signatures or Merkle
// proofs. This ensures that the ID will remain stable (i.e. non-malleable).
//
// To hash all of the data in a transaction, use the FullHash method.
func (txn *V2Transaction) ID() TransactionID {
	return hashAll("id/transaction", (*V2TransactionSemantics)(txn))
}

// FullHash returns the hash of the transaction's binary encoding. This hash is
// only used in specific circumstances; generally, ID should be used instead.
func (txn *V2Transaction) FullHash() Hash256 {
	return hashAll(txn)
}

// BigfileOutputID returns the ID for the bigfile output at index i.
func (*V2Transaction) BigfileOutputID(txid TransactionID, i int) BigfileOutputID {
	return hashAll("id/bigfileoutput", txid, i)
}

// BigfundOutputID returns the ID for the bigfund output at index i.
func (*V2Transaction) BigfundOutputID(txid TransactionID, i int) BigfundOutputID {
	return hashAll("id/bigfundoutput", txid, i)
}

// V2FileContractID returns the ID for the v2 file contract at index i.
func (*V2Transaction) V2FileContractID(txid TransactionID, i int) FileContractID {
	return hashAll("id/filecontract", txid, i)
}

// AttestationID returns the ID for the attestation at index i.
func (*V2Transaction) AttestationID(txid TransactionID, i int) AttestationID {
	return hashAll("id/attestation", txid, i)
}

// EphemeralBigfileOutput returns a BigfileElement for the bigfile output at
// index i.
func (txn *V2Transaction) EphemeralBigfileOutput(i int) BigfileElement {
	return BigfileElement{
		StateElement: StateElement{
			LeafIndex: UnassignedLeafIndex,
		},
		ID:            txn.BigfileOutputID(txn.ID(), i),
		BigfileOutput: txn.BigfileOutputs[i],
	}
}

// EphemeralBigfundOutput returns a BigfundElement for the bigfund output at
// index i.
func (txn *V2Transaction) EphemeralBigfundOutput(i int) BigfundElement {
	return BigfundElement{
		StateElement: StateElement{
			LeafIndex: UnassignedLeafIndex,
		},
		ID:            txn.BigfundOutputID(txn.ID(), i),
		BigfundOutput: txn.BigfundOutputs[i],
	}
}

// DeepCopy returns a copy of txn that does not alias any of its memory.
func (txn *V2Transaction) DeepCopy() V2Transaction {
	c := *txn
	c.BigfileInputs = slices.Clone(c.BigfileInputs)
	for i := range c.BigfileInputs {
		c.BigfileInputs[i].Parent = c.BigfileInputs[i].Parent.Copy()
		c.BigfileInputs[i].SatisfiedPolicy.Signatures = slices.Clone(c.BigfileInputs[i].SatisfiedPolicy.Signatures)
		c.BigfileInputs[i].SatisfiedPolicy.Preimages = slices.Clone(c.BigfileInputs[i].SatisfiedPolicy.Preimages)
	}
	c.BigfileOutputs = slices.Clone(c.BigfileOutputs)
	c.BigfundInputs = slices.Clone(c.BigfundInputs)
	for i := range c.BigfundInputs {
		c.BigfundInputs[i].Parent = c.BigfundInputs[i].Parent.Copy()
		c.BigfundInputs[i].SatisfiedPolicy.Signatures = slices.Clone(c.BigfundInputs[i].SatisfiedPolicy.Signatures)
		c.BigfundInputs[i].SatisfiedPolicy.Preimages = slices.Clone(c.BigfundInputs[i].SatisfiedPolicy.Preimages)
	}
	c.BigfundOutputs = slices.Clone(c.BigfundOutputs)
	c.FileContracts = slices.Clone(c.FileContracts)
	c.FileContractRevisions = slices.Clone(c.FileContractRevisions)
	for i := range c.FileContractRevisions {
		c.FileContractRevisions[i].Parent = c.FileContractRevisions[i].Parent.Copy()
	}
	c.FileContractResolutions = slices.Clone(c.FileContractResolutions)
	for i := range c.FileContractResolutions {
		c.FileContractResolutions[i].Parent = c.FileContractResolutions[i].Parent.Copy()
		if res, ok := c.FileContractResolutions[i].Resolution.(*V2StorageProof); ok {
			sp := *res
			sp.ProofIndex = sp.ProofIndex.Copy()
			sp.Proof = slices.Clone(sp.Proof)
			c.FileContractResolutions[i].Resolution = &sp
		}
	}
	c.Attestations = slices.Clone(c.Attestations)
	for i := range c.Attestations {
		c.Attestations[i].Value = slices.Clone(c.Attestations[i].Value)
	}
	c.ArbitraryData = slices.Clone(c.ArbitraryData)
	return c
}

// CurrentTimestamp returns the current time, rounded to the nearest second. The
// time zone is set to UTC.
func CurrentTimestamp() time.Time { return time.Now().Round(time.Second).UTC() }

// V2BlockData contains additional fields not present in v1 blocks.
type V2BlockData struct {
	Height       uint64          `json:"height"`
	Commitment   Hash256         `json:"commitment"`
	Transactions []V2Transaction `json:"transactions"`
}

// A BlockHeader is the preimage of a Block's ID.
type BlockHeader struct {
	ParentID   BlockID   `json:"parentID"`
	Nonce      uint64    `json:"nonce"`
	Timestamp  time.Time `json:"timestamp"`
	Commitment Hash256   `json:"commitment"`
}

// ID returns the hash of the header data.
func (bh BlockHeader) ID() BlockID {
	buf := make([]byte, 32+8+8+32)
	copy(buf[:32], bh.ParentID[:])
	binary.LittleEndian.PutUint64(buf[32:], bh.Nonce)
	binary.LittleEndian.PutUint64(buf[40:], uint64(bh.Timestamp.Unix()))
	copy(buf[48:], bh.Commitment[:])
	return BlockID(HashBytes(buf))
}

// A Block is a timestamped set of transactions, immutably linked to a previous
// block, secured by proof-of-work.
type Block struct {
	ParentID     BlockID         `json:"parentID"`
	Nonce        uint64          `json:"nonce"`
	Timestamp    time.Time       `json:"timestamp"`
	MinerPayouts []BigfileOutput `json:"minerPayouts"`
	Transactions []Transaction   `json:"transactions"`

	V2 *V2BlockData `json:"v2,omitempty"`
}

// V2Transactions returns the block's v2 transactions, if present.
func (b *Block) V2Transactions() []V2Transaction {
	if b.V2 != nil {
		return b.V2.Transactions
	}
	return nil
}

// Header returns the block's header.
func (b *Block) Header() BlockHeader {
	var commitment Hash256
	if b.V2 == nil {
		// NOTE: expensive!
		commitment = blockMerkleRoot(b.MinerPayouts, b.Transactions)
	} else {
		commitment = b.V2.Commitment
	}
	return BlockHeader{
		ParentID:   b.ParentID,
		Nonce:      b.Nonce,
		Timestamp:  b.Timestamp,
		Commitment: commitment,
	}
}

// ID returns a hash that uniquely identifies a block.
func (b *Block) ID() BlockID {
	return b.Header().ID()
}

func unmarshalHex(dst []byte, data []byte) error {
	if len(data) > len(dst)*2 {
		return errors.New("input too long")
	}
	n, err := hex.Decode(dst, data)
	if err == nil && n < len(dst) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return fmt.Errorf("decoding %q failed: %w", data, err)
	}
	return nil
}

// String implements fmt.Stringer.
func (h Hash256) String() string { return hex.EncodeToString(h[:]) }

// MarshalText implements encoding.TextMarshaler.
func (h Hash256) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(h[:])), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *Hash256) UnmarshalText(b []byte) error { return unmarshalHex(h[:], b) }

// String implements fmt.Stringer.
func (ci ChainIndex) String() string {
	// use the 4 least-significant bytes of ID -- in a mature chain, the
	// most-significant bytes will be zeros
	return fmt.Sprintf("%d::%x", ci.Height, ci.ID[len(ci.ID)-4:])
}

// MarshalText implements encoding.TextMarshaler.
func (ci ChainIndex) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("%d::%x", ci.Height, ci.ID[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (ci *ChainIndex) UnmarshalText(b []byte) (err error) {
	parts := bytes.Split(b, []byte("::"))
	if len(parts) != 2 {
		return errors.New("decoding <height>::<id> failed: wrong number of separators")
	} else if ci.Height, err = strconv.ParseUint(string(parts[0]), 10, 64); err != nil {
		return fmt.Errorf("decoding <height>::<id> failed: %w", err)
	} else if n, err := hex.Decode(ci.ID[:], parts[1]); err != nil {
		return fmt.Errorf("decoding <height>::<id> failed: %w", err)
	} else if n < len(ci.ID) {
		return fmt.Errorf("decoding <height>::<id> failed: %w", io.ErrUnexpectedEOF)
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (ci ChainIndex) MarshalJSON() ([]byte, error) {
	type jsonCI ChainIndex // hide MarshalText method
	return json.Marshal(jsonCI(ci))
}

// UnmarshalJSON implements json.Unmarshaler.
func (ci *ChainIndex) UnmarshalJSON(b []byte) error {
	type jsonCI ChainIndex // hide UnmarshalText method
	return json.Unmarshal(b, (*jsonCI)(ci))
}

// ParseChainIndex parses a chain index from a string.
func ParseChainIndex(s string) (ci ChainIndex, err error) {
	err = ci.UnmarshalText([]byte(s))
	return
}

// String implements fmt.Stringer.
func (s Specifier) String() string {
	b := string(bytes.TrimRight(s[:], "\x00"))
	for _, c := range b {
		if !(('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9')) {
			return strconv.Quote(b)
		}
	}
	return b
}

// MarshalText implements encoding.TextMarshaler.
func (s Specifier) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Specifier) UnmarshalText(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		uq, err := strconv.Unquote(string(b))
		if err != nil {
			return err
		}
		b = []byte(uq)
	}
	if len(b) > len(s) {
		return fmt.Errorf("specifier %v too long (%v > 16)", b, len(b))
	}
	copy(s[:], b)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (uk UnlockKey) MarshalText() ([]byte, error) {
	return []byte(uk.Algorithm.String() + ":" + hex.EncodeToString(uk.Key)), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (uk *UnlockKey) UnmarshalText(b []byte) error {
	if i := bytes.LastIndexByte(b, ':'); i < 0 {
		return errors.New("decoding <algorithm>:<key> failed: no separator")
	} else if err := uk.Algorithm.UnmarshalText(b[:i]); err != nil {
		return fmt.Errorf("decoding <algorithm>:<key> failed: %w", err)
	} else if uk.Key, err = hex.DecodeString(string(b[i+1:])); err != nil {
		return fmt.Errorf("decoding <algorithm>:<key> failed: %w", err)
	}
	return nil
}

// String implements fmt.Stringer.
func (a Address) String() string {
	checksum := HashBytes(a[:])
	return hex.EncodeToString(append(a[:], checksum[:6]...))
}

// MarshalText implements encoding.TextMarshaler.
func (a Address) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Address) UnmarshalText(b []byte) error {
	withChecksum := make([]byte, 32+6)
	if len(b) != len(withChecksum)*2 {
		return fmt.Errorf("address must be %d characters", len(withChecksum)*2)
	}
	n, err := hex.Decode(withChecksum, b)
	if err != nil {
		return fmt.Errorf("decoding %q failed: %w", b, err)
	} else if n != len(withChecksum) {
		return fmt.Errorf("decoding %q failed: %w", b, io.ErrUnexpectedEOF)
	} else if checksum := HashBytes(withChecksum[:32]); !bytes.Equal(checksum[:6], withChecksum[32:]) {
		return errors.New("bad checksum")
	}
	copy(a[:], withChecksum[:32])
	return nil
}

// ParseAddress parses an address from a prefixed hex encoded string.
func ParseAddress(s string) (a Address, err error) {
	err = a.UnmarshalText([]byte(s))
	return
}

// String implements fmt.Stringer.
func (bid BlockID) String() string { return hex.EncodeToString(bid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (bid BlockID) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(bid[:])), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (bid *BlockID) UnmarshalText(b []byte) error { return unmarshalHex(bid[:], b) }

// String implements fmt.Stringer.
func (pk PublicKey) String() string { return "ed25519:" + hex.EncodeToString(pk[:]) }

// MarshalText implements encoding.TextMarshaler.
func (pk PublicKey) MarshalText() ([]byte, error) { return []byte(pk.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (pk *PublicKey) UnmarshalText(b []byte) error {
	i := bytes.IndexByte(b, ':')
	if i < 0 {
		return errors.New("missing separator")
	} else if string(b[:i]) != "ed25519" {
		return fmt.Errorf("unknown algorithm %q", b[:i])
	}
	return unmarshalHex(pk[:], b[i+1:])
}

// String implements fmt.Stringer.
func (tid TransactionID) String() string { return hex.EncodeToString(tid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (tid TransactionID) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(tid[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (tid *TransactionID) UnmarshalText(b []byte) error { return unmarshalHex(tid[:], b) }

// String implements fmt.Stringer.
func (aid AttestationID) String() string { return hex.EncodeToString(aid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (aid AttestationID) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(aid[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (aid *AttestationID) UnmarshalText(b []byte) error {
	return unmarshalHex(aid[:], b)
}

// String implements fmt.Stringer.
func (bigoid BigfileOutputID) String() string { return hex.EncodeToString(bigoid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (bigoid BigfileOutputID) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(bigoid[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (bigoid *BigfileOutputID) UnmarshalText(b []byte) error {
	return unmarshalHex(bigoid[:], b)
}

// String implements fmt.Stringer.
func (bfoid BigfundOutputID) String() string { return hex.EncodeToString(bfoid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (bfoid BigfundOutputID) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(bfoid[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (bfoid *BigfundOutputID) UnmarshalText(b []byte) error {
	return unmarshalHex(bfoid[:], b)
}

// String implements fmt.Stringer.
func (fcid FileContractID) String() string { return hex.EncodeToString(fcid[:]) }

// MarshalText implements encoding.TextMarshaler.
func (fcid FileContractID) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(fcid[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (fcid *FileContractID) UnmarshalText(b []byte) error { return unmarshalHex(fcid[:], b) }

// String implements fmt.Stringer.
func (sig Signature) String() string { return hex.EncodeToString(sig[:]) }

// MarshalText implements encoding.TextMarshaler.
func (sig Signature) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(sig[:])), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (sig *Signature) UnmarshalText(b []byte) error { return unmarshalHex(sig[:], b) }

// MarshalJSON implements json.Marshaler.
func (fcr FileContractRevision) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ParentID         FileContractID   `json:"parentID"`
		UnlockConditions UnlockConditions `json:"unlockConditions"`
		Filesize         uint64           `json:"filesize"`
		FileMerkleRoot   Hash256          `json:"fileMerkleRoot"`
		WindowStart      uint64           `json:"windowStart"`
		WindowEnd        uint64           `json:"windowEnd"`
		// Payout omitted; see FileContractRevision docstring
		ValidProofOutputs  []BigfileOutput `json:"validProofOutputs"`
		MissedProofOutputs []BigfileOutput `json:"missedProofOutputs"`
		UnlockHash         Address         `json:"unlockHash"`
		RevisionNumber     uint64          `json:"revisionNumber"`
	}{
		fcr.ParentID,
		fcr.UnlockConditions,
		fcr.Filesize,
		fcr.FileMerkleRoot,
		fcr.WindowStart,
		fcr.WindowEnd,
		fcr.ValidProofOutputs,
		fcr.MissedProofOutputs,
		fcr.UnlockHash,
		fcr.RevisionNumber,
	})
}

// UnmarshalJSON implements json.Unmarshaler.
func (fcr *FileContractRevision) UnmarshalJSON(b []byte) error {
	type alias FileContractRevision
	if err := json.Unmarshal(b, (*alias)(fcr)); err != nil {
		return err
	}
	// see FileContractRevision docstring
	fcr.Payout = NewCurrency(math.MaxUint64, math.MaxUint64)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (sp StorageProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ParentID FileContractID `json:"parentID"`
		Leaf     string         `json:"leaf"`
		Proof    []Hash256      `json:"proof"`
	}{sp.ParentID, hex.EncodeToString(sp.Leaf[:]), sp.Proof})
}

// UnmarshalJSON implements json.Unmarshaler.
func (sp *StorageProof) UnmarshalJSON(b []byte) error {
	var leaf string
	err := json.Unmarshal(b, &struct {
		ParentID *FileContractID
		Leaf     *string
		Proof    *[]Hash256
	}{&sp.ParentID, &leaf, &sp.Proof})
	if err != nil {
		return err
	} else if len(leaf) != len(sp.Leaf)*2 {
		return errors.New("invalid storage proof leaf length")
	} else if _, err = hex.Decode(sp.Leaf[:], []byte(leaf)); err != nil {
		return err
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (sp V2StorageProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ProofIndex ChainIndexElement `json:"proofIndex"`
		Leaf       string            `json:"leaf"`
		Proof      []Hash256         `json:"proof"`
	}{sp.ProofIndex, hex.EncodeToString(sp.Leaf[:]), sp.Proof})
}

// UnmarshalJSON implements json.Unmarshaler.
func (sp *V2StorageProof) UnmarshalJSON(b []byte) error {
	var leaf string
	err := json.Unmarshal(b, &struct {
		ProofIndex *ChainIndexElement
		Leaf       *string
		Proof      *[]Hash256
	}{&sp.ProofIndex, &leaf, &sp.Proof})
	if err != nil {
		return err
	} else if len(leaf) != len(sp.Leaf)*2 {
		return errors.New("invalid storage proof leaf length")
	} else if _, err = hex.Decode(sp.Leaf[:], []byte(leaf)); err != nil {
		return err
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (res V2FileContractResolution) MarshalJSON() ([]byte, error) {
	var typ string
	switch res.Resolution.(type) {
	case *V2FileContractRenewal:
		typ = v2ResolutionRenewal
	case *V2StorageProof:
		typ = v2ResolutionStorageProof
	case *V2FileContractExpiration:
		typ = v2ResolutionExpiration
	default:
		panic(fmt.Sprintf("unhandled file contract resolution type %T", res.Resolution))
	}
	return json.Marshal(struct {
		Parent     V2FileContractElement        `json:"parent"`
		Type       string                       `json:"type"`
		Resolution V2FileContractResolutionType `json:"resolution"`
	}{res.Parent, typ, res.Resolution})
}

// UnmarshalJSON implements json.Marshaler.
func (res *V2FileContractResolution) UnmarshalJSON(b []byte) error {
	var p struct {
		Parent     V2FileContractElement
		Type       string
		Resolution json.RawMessage
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	switch p.Type {
	case v2ResolutionRenewal:
		res.Resolution = new(V2FileContractRenewal)
	case v2ResolutionStorageProof:
		res.Resolution = new(V2StorageProof)
	case v2ResolutionExpiration:
		res.Resolution = new(V2FileContractExpiration)
	default:
		return fmt.Errorf("unknown file contract resolution type %q", p.Type)
	}
	if err := json.Unmarshal(p.Resolution, res.Resolution); err != nil {
		return err
	}
	res.Parent = p.Parent.Move()
	return nil
}

// MarshalJSON implements json.Marshaler.
//
// For convenience, the transaction's ID is also calculated and included. This
// field is ignored during unmarshalling.
func (txn V2Transaction) MarshalJSON() ([]byte, error) {
	type jsonTxn V2Transaction // prevent recursion
	type jsonBigfileOutput struct {
		ID BigfileOutputID `json:"id"`
		BigfileOutput
	}
	type jsonBigfundOutput struct {
		ID BigfundOutputID `json:"id"`
		BigfundOutput
	}
	txnID := txn.ID()
	obj := struct {
		ID             TransactionID       `json:"id"`
		BigfileOutputs []jsonBigfileOutput `json:"bigfileOutputs"`
		BigfundOutputs []jsonBigfundOutput `json:"bigfundOutputs"`
		jsonTxn
	}{
		ID:             txnID,
		jsonTxn:        jsonTxn(txn),
		BigfileOutputs: make([]jsonBigfileOutput, 0, len(txn.BigfileOutputs)),
		BigfundOutputs: make([]jsonBigfundOutput, 0, len(txn.BigfundOutputs)),
	}
	for i := range txn.BigfileOutputs {
		obj.BigfileOutputs = append(obj.BigfileOutputs, jsonBigfileOutput{
			ID:            txn.BigfileOutputID(txnID, i),
			BigfileOutput: txn.BigfileOutputs[i],
		})
	}
	for i := range txn.BigfundOutputs {
		obj.BigfundOutputs = append(obj.BigfundOutputs, jsonBigfundOutput{
			ID:            txn.BigfundOutputID(txnID, i),
			BigfundOutput: txn.BigfundOutputs[i],
		})
	}
	return json.Marshal(obj)
}

// To guard against memory ownership bugs, all Element types have Move, Share,
// and Copy methods. This enables a linter to flag any instances where Element
// memory is not explicitly managed.

// Move returns a shallow copy of the element. It must only be used when the
// element's memory is not shared.
func (se StateElement) Move() StateElement {
	if se.shared {
		panic("Move called on shared StateElement")
	}
	return se
}

// Move returns a shallow copy of the element. It must only be used when the
// element's memory is not shared.
func (cie ChainIndexElement) Move() ChainIndexElement {
	cie.StateElement = cie.StateElement.Move()
	return cie
}

// Move returns a shallow copy of the element. It must only be used when the
// element's memory is not shared.
func (bige BigfileElement) Move() BigfileElement {
	bige.StateElement = bige.StateElement.Move()
	return bige
}

// Move returns a shallow copy of the element. It must only be used when the
// element's memory is not shared.
func (bfe BigfundElement) Move() BigfundElement {
	bfe.StateElement = bfe.StateElement.Move()
	return bfe
}

// Move returns a shallow copy of the element. It must only be used when the
// element's memory is not shared.
func (fce FileContractElement) Move() FileContractElement {
	fce.StateElement = fce.StateElement.Move()
	return fce
}

// Move returns a shallow copy of the element. It must only be used when the
// element's memory is not shared.
func (v2fce V2FileContractElement) Move() V2FileContractElement {
	v2fce.StateElement = v2fce.StateElement.Move()
	return v2fce
}

// Move returns a shallow copy of the element. It must only be used when the
// element's memory is not shared.
func (ae AttestationElement) Move() AttestationElement {
	ae.StateElement = ae.StateElement.Move()
	return ae
}

// Share returns a shallow copy of the element. It must be used whenever the
// element's memory is intentionally aliased.
func (se StateElement) Share() StateElement {
	se.shared = true
	return se
}

// Share returns a shallow copy of the element. It must be used whenever the
// element's memory is intentionally aliased.
func (cie ChainIndexElement) Share() ChainIndexElement {
	cie.StateElement = cie.StateElement.Share()
	return cie
}

// Share returns a shallow copy of the element. It must be used whenever the
// element's memory is intentionally aliased.
func (bige BigfileElement) Share() BigfileElement {
	bige.StateElement = bige.StateElement.Share()
	return bige
}

// Share returns a shallow copy of the element. It must be used whenever the
// element's memory is intentionally aliased.
func (bfe BigfundElement) Share() BigfundElement {
	bfe.StateElement = bfe.StateElement.Share()
	return bfe
}

// Share returns a shallow copy of the element. It must be used whenever the
// element's memory is intentionally aliased.
func (fce FileContractElement) Share() FileContractElement {
	fce.StateElement = fce.StateElement.Share()
	return fce
}

// Share returns a shallow copy of the element. It must be used whenever the
// element's memory is intentionally aliased.
func (v2fce V2FileContractElement) Share() V2FileContractElement {
	v2fce.StateElement = v2fce.StateElement.Share()
	return v2fce
}

// Share returns a shallow copy of the element. It must be used whenever the
// element's memory is intentionally aliased.
func (ae AttestationElement) Share() AttestationElement {
	ae.StateElement = ae.StateElement.Share()
	return ae
}

// Copy returns a deep copy of the element. It must be used whenever the
// element's memory is copied.
func (se StateElement) Copy() StateElement {
	se.MerkleProof = slices.Clone(se.MerkleProof)
	se.shared = false
	return se
}

// Copy returns a deep copy of the element. It must be used whenever the
// element's memory is copied.
func (cie ChainIndexElement) Copy() ChainIndexElement {
	cie.StateElement = cie.StateElement.Copy()
	return cie
}

// Copy returns a deep copy of the element. It must be used whenever the
// element's memory is copied.
func (bige BigfileElement) Copy() BigfileElement {
	bige.StateElement = bige.StateElement.Copy()
	return bige
}

// Copy returns a deep copy of the element. It must be used whenever the
// element's memory is copied.
func (bfe BigfundElement) Copy() BigfundElement {
	bfe.StateElement = bfe.StateElement.Copy()
	return bfe
}

// Copy returns a deep copy of the element. It must be used whenever the
// element's memory is copied.
func (fce FileContractElement) Copy() FileContractElement {
	fce.StateElement = fce.StateElement.Copy()
	return fce
}

// Copy returns a deep copy of the element. It must be used whenever the
// element's memory is copied.
func (v2fce V2FileContractElement) Copy() V2FileContractElement {
	v2fce.StateElement = v2fce.StateElement.Copy()
	return v2fce
}

// Copy returns a deep copy of the element. It must be used whenever the
// element's memory is copied.
func (ae AttestationElement) Copy() AttestationElement {
	ae.StateElement = ae.StateElement.Copy()
	return ae
}
