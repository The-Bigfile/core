package types_test

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"go.thebigfile.com/core/consensus"
	"go.thebigfile.com/core/types"
	"lukechampine.com/frand"
)

// Multiproof encoding only works with "real" transactions -- we can't generate
// fake Merkle proofs randomly, because they won't share nodes with each other
// the way they should. This is annoying.
func multiproofTxns(numTxns int, numElems int) []types.V2Transaction {
	// fake accumulator state
	cs := (&consensus.Network{InitialTarget: types.BlockID{0: 1}, BlockInterval: time.Second}).GenesisState()
	cs.Elements.NumLeaves = 19527 // arbitrary
	for i := range cs.Elements.Trees {
		cs.Elements.Trees[i] = frand.Entropy256()
	}
	// create a bunch of elements in a fake block
	b := types.Block{
		V2: &types.V2BlockData{
			Transactions: []types.V2Transaction{{
				// NOTE: this creates more elements than necessary, but that's
				// desirable; otherwise they'll be contiguous and we'll end up
				// with an uncharacteristically-small multiproof
				BigFileOutputs: make([]types.BigFileOutput, numTxns*numElems),
				BigfundOutputs: make([]types.BigfundOutput, numTxns*numElems),
				FileContracts:  make([]types.V2FileContract, numTxns*numElems),
			}},
		},
	}
	// apply the block and extract the created elements
	cs, cau := consensus.ApplyBlock(cs, b, consensus.V1BlockSupplement{}, time.Time{})
	biges := make([]types.BigFileElement, len(cau.BigFileElementDiffs()))
	for i := range biges {
		biges[i] = cau.BigFileElementDiffs()[i].BigFileElement.Copy()
	}
	bfes := make([]types.BigfundElement, len(cau.BigfundElementDiffs()))
	for i := range bfes {
		bfes[i] = cau.BigfundElementDiffs()[i].BigfundElement.Copy()
	}
	fces := make([]types.V2FileContractElement, len(cau.V2FileContractElementDiffs()))
	for i := range fces {
		fces[i] = cau.V2FileContractElementDiffs()[i].V2FileContractElement.Copy()
	}

	// select randomly
	rng := frand.NewCustom(make([]byte, 32), 1024, 12)
	rng.Shuffle(len(biges), reflect.Swapper(biges))
	rng.Shuffle(len(bfes), reflect.Swapper(bfes))
	rng.Shuffle(len(fces), reflect.Swapper(fces))

	// use the elements in fake txns
	sp := types.SatisfiedPolicy{Policy: types.AnyoneCanSpend()}
	txns := make([]types.V2Transaction, numTxns)
	for i := range txns {
		txn := &txns[i]
		for j := 0; j < numElems; j++ {
			switch j % 4 {
			case 0:
				txn.BigFileInputs, biges = append(txn.BigFileInputs, types.V2BigFileInput{
					Parent:          biges[0].Copy(),
					SatisfiedPolicy: sp,
				}), biges[1:]
			case 1:
				txn.BigfundInputs, bfes = append(txn.BigfundInputs, types.V2BigfundInput{
					Parent:          bfes[0].Copy(),
					SatisfiedPolicy: sp,
				}), bfes[1:]
			case 2:
				txn.FileContractRevisions, fces = append(txn.FileContractRevisions, types.V2FileContractRevision{
					Parent: fces[0].Copy(),
				}), fces[1:]
			case 3:
				txn.FileContractResolutions, fces = append(txn.FileContractResolutions, types.V2FileContractResolution{
					Parent:     fces[0].Copy(),
					Resolution: &types.V2FileContractExpiration{},
				}), fces[1:]
			}
		}
	}
	// make every 5th bigfile input ephemeral
	n := 0
	for i := range txns {
		for j := range txns[i].BigFileInputs {
			if (n+1)%5 == 0 {
				txns[i].BigFileInputs[j].Parent.StateElement = types.StateElement{LeafIndex: types.UnassignedLeafIndex}
			}
			n++
		}
	}
	return txns
}

func TestMultiproofEncoding(t *testing.T) {
	for _, n := range []int{0, 1, 2, 10} {
		b := types.V2BlockData{Transactions: multiproofTxns(n, n)}
		// placate reflect.DeepEqual
		for i := range b.Transactions {
			var buf bytes.Buffer
			e := types.NewEncoder(&buf)
			b.Transactions[i].EncodeTo(e)
			e.Flush()
			b.Transactions[i].DecodeFrom(types.NewBufDecoder(buf.Bytes()))
		}

		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		b.EncodeTo(e)
		e.Flush()
		d := types.NewBufDecoder(buf.Bytes())
		var b2 types.V2BlockData
		b2.DecodeFrom(d)
		if err := d.Err(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(b, b2) {
			t.Fatalf("multiproof encoding of %v txns did not survive roundtrip: expected %v, got %v", n, b, b2)
		}
	}
}

type uncompressedBlock types.Block

func (b uncompressedBlock) EncodeTo(e *types.Encoder) {
	types.V1Block(b).EncodeTo(e)
	e.WriteBool(b.V2 != nil)
	if b.V2 != nil {
		e.WriteUint64(b.V2.Height)
		b.V2.Commitment.EncodeTo(e)
		types.EncodeSlice(e, b.V2.Transactions)
	}
}

func TestBlockCompression(t *testing.T) {
	encSize := func(v types.EncoderTo) int {
		var buf bytes.Buffer
		e := types.NewEncoder(&buf)
		v.EncodeTo(e)
		e.Flush()
		return buf.Len()
	}
	ratio := func(txns []types.V2Transaction) float64 {
		b := types.Block{V2: &types.V2BlockData{Transactions: txns}}
		return float64(encSize(types.V2Block(b))) / float64(encSize(uncompressedBlock(b)))
	}

	tests := []struct {
		desc string
		txns []types.V2Transaction
		exp  float64
	}{
		{"nil", nil, 1.071},
		{"0 elements", make([]types.V2Transaction, 10), 1.04},
		{"1 element", multiproofTxns(1, 1), 1.025},
		{"4 elements", multiproofTxns(2, 2), 0.90},
		{"10 elements", multiproofTxns(2, 5), 0.85},
		{"25 elements", multiproofTxns(5, 5), 0.75},
		{"100 elements", multiproofTxns(10, 10), 0.71},
	}
	for _, test := range tests {
		if r := ratio(test.txns); r >= test.exp {
			t.Errorf("%s compression ratio: expected <%g, got %g", test.desc, test.exp, r)
		}
	}
}
