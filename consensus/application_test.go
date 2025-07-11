package consensus

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.thebigfile.com/core/blake2b"
	"go.thebigfile.com/core/types"
	"lukechampine.com/frand"
)

func checkApplyUpdate(t *testing.T, cs State, au ApplyUpdate) {
	t.Helper()

	for _, bige := range au.biges {
		if !cs.Elements.containsLeaf(bigfileLeaf(&bige.BigfileElement, bige.Spent)) {
			t.Fatalf("consensus: bigfile element %v %v not found in accumulator after apply", bige.Spent, bige.BigfileElement.ID)
		}
	}
	for _, bfe := range au.bfes {
		if !cs.Elements.containsLeaf(bigfundLeaf(&bfe.BigfundElement, bfe.Spent)) {
			t.Fatalf("consensus: bigfund element %v not found in accumulator after apply", bfe.BigfundElement.ID)
		}
	}
	for _, fce := range au.fces {
		if !cs.Elements.containsLeaf(fileContractLeaf(&fce.FileContractElement, fce.Revision, fce.Resolved)) {
			t.Fatal("consensus: file contract element leaf not found in accumulator after apply")
		}
	}
	for _, fce := range au.v2fces {
		if !cs.Elements.containsLeaf(v2FileContractLeaf(&fce.V2FileContractElement, fce.Revision, fce.Resolution != nil)) {
			t.Fatal("consensus: v2 file contract element leaf not found in accumulator after apply")
		}
	}
	for _, ae := range au.aes {
		if !cs.Elements.containsLeaf(attestationLeaf(&ae)) {
			t.Fatal("consensus: attestation element leaf not found in accumulator after apply")
		}
	}
}

func checkRevertUpdate(t *testing.T, cs State, ru RevertUpdate) {
	t.Helper()

	for _, bige := range ru.biges {
		if cs.Elements.containsLeaf(bigfileLeaf(&bige.BigfileElement, bige.Spent)) {
			t.Fatal("consensus: bigfile element found in accumulator after revert")
		}
	}
	for _, bfe := range ru.bfes {
		if cs.Elements.containsLeaf(bigfundLeaf(&bfe.BigfundElement, bfe.Spent)) {
			t.Fatal("consensus: bigfund element found in accumulator after revert")
		}
	}
	for _, fce := range ru.fces {
		if cs.Elements.containsLeaf(fileContractLeaf(&fce.FileContractElement, fce.Revision, fce.Resolved)) {
			t.Fatal("consensus: file contract element leaf found in accumulator after revert")
		}
	}
	for _, fce := range ru.v2fces {
		if cs.Elements.containsLeaf(v2FileContractLeaf(&fce.V2FileContractElement, fce.Revision, fce.Resolution != nil)) {
			t.Fatal("consensus: v2 file contract element leaf found in accumulator after revert")
		}
	}
	for _, ae := range ru.aes {
		if cs.Elements.containsLeaf(attestationLeaf(&ae)) {
			t.Fatal("consensus: attestation element leaf found in accumulator after revert")
		}
	}
}
func checkUpdateElements(t *testing.T, au ApplyUpdate, addedBIGEs, spentBIGEs []types.BigfileElement, addedBFEs, spentBFEs []types.BigfundElement) {
	for _, biged := range au.BigfileElementDiffs() {
		biges := &addedBIGEs
		if biged.Spent {
			biges = &spentBIGEs
		}
		if len(*biges) == 0 {
			t.Fatal("unexpected spent bigfile element")
		}
		bige := biged.BigfileElement.Move()
		bige.StateElement = types.StateElement{}
		bige.ID = types.BigfileOutputID{}
		if !reflect.DeepEqual(bige.Move(), (*biges)[0].Copy()) {
			t.Fatalf("bigfile element doesn't match:\n%v\nvs\n%v\n", bige.Move(), (*biges)[0].Copy())
		}
		*biges = (*biges)[1:]
	}
	for _, bfed := range au.BigfundElementDiffs() {
		bfes := &addedBFEs
		if bfed.Spent {
			bfes = &spentBFEs
		}
		if len(*bfes) == 0 {
			t.Fatal("unexpected spent bigfund element")
		}
		bfe := bfed.BigfundElement.Move()
		bfe.StateElement = types.StateElement{}
		bfe.ID = types.BigfundOutputID{}
		if !reflect.DeepEqual(bfe.Move(), (*bfes)[0].Copy()) {
			t.Fatalf("bigfund element doesn't match:\n%v\nvs\n%v\n", bfe.Move(), (*bfes)[0].Copy())
		}
		*bfes = (*bfes)[1:]
	}
	if len(addedBIGEs)+len(spentBIGEs)+len(addedBFEs)+len(spentBFEs) > 0 {
		t.Fatal("extraneous elements")
	}
}

func checkRevertElements(t *testing.T, ru RevertUpdate, addedBIGEs, spentBIGEs []types.BigfileElement, addedBFEs, spentBFEs []types.BigfundElement) {
	for _, biged := range ru.BigfileElementDiffs() {
		biges := &addedBIGEs
		if biged.Spent {
			biges = &spentBIGEs
		}
		if len(*biges) == 0 {
			t.Fatal("unexpected spent bigfile element")
		}
		bige := biged.BigfileElement.Move()
		bige.StateElement = types.StateElement{}
		bige.ID = types.BigfileOutputID{}
		if !reflect.DeepEqual(bige.Move(), (*biges)[len(*biges)-1].Copy()) {
			t.Fatalf("bigfile element doesn't match:\n%v\nvs\n%v\n", bige.Move(), (*biges)[len(*biges)-1].Copy())
		}
		*biges = (*biges)[:len(*biges)-1]
	}
	for _, bfed := range ru.BigfundElementDiffs() {
		bfes := &addedBFEs
		if bfed.Spent {
			bfes = &spentBFEs
		}
		if len(*bfes) == 0 {
			t.Fatal("unexpected spent bigfund element")
		}
		bfe := bfed.BigfundElement.Move()
		bfe.StateElement = types.StateElement{}
		bfe.ID = types.BigfundOutputID{}
		if !reflect.DeepEqual(bfe.Move(), (*bfes)[len(*bfes)-1].Copy()) {
			t.Fatalf("bigfund element doesn't match:\n%v\nvs\n%v\n", bfe.Move(), (*bfes)[len(*bfes)-1].Copy())
		}
		*bfes = (*bfes)[:len(*bfes)-1]
	}
	if len(addedBIGEs)+len(spentBIGEs)+len(addedBFEs)+len(spentBFEs) > 0 {
		t.Fatal("extraneous elements")
	}
}

func TestApplyBlock(t *testing.T) {
	n, genesisBlock := testnet()

	giftPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()
	giftAddress := types.StandardUnlockHash(giftPublicKey)
	giftAmountBIG := types.Bigfiles(100)
	giftAmountBF := uint64(100)
	giftTxn := types.Transaction{
		BigfileOutputs: []types.BigfileOutput{
			{Address: giftAddress, Value: giftAmountBIG},
		},
		BigfundOutputs: []types.BigfundOutput{
			{Address: giftAddress, Value: giftAmountBF},
		},
	}
	genesisBlock.Transactions = []types.Transaction{giftTxn}
	db, cs := newConsensusDB(n, genesisBlock)

	signTxn := func(txn *types.Transaction) {
		appendSig := func(parentID types.Hash256) {
			sig := giftPrivateKey.SignHash(cs.WholeSigHash(*txn, parentID, 0, 0, nil))
			txn.Signatures = append(txn.Signatures, types.TransactionSignature{
				ParentID:       parentID,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
				PublicKeyIndex: 0,
				Signature:      sig[:],
			})
		}
		for i := range txn.BigfileInputs {
			appendSig(types.Hash256(txn.BigfileInputs[i].ParentID))
		}
		for i := range txn.BigfundInputs {
			appendSig(types.Hash256(txn.BigfundInputs[i].ParentID))
		}
		for i := range txn.FileContractRevisions {
			appendSig(types.Hash256(txn.FileContractRevisions[i].ParentID))
		}
	}
	addBlock := func(b *types.Block) (au ApplyUpdate, err error) {
		bs := db.supplementTipBlock(*b)
		findBlockNonce(cs, b)
		if err = ValidateBlock(cs, *b, bs); err != nil {
			return
		}
		cs, au = ApplyBlock(cs, *b, bs, db.ancestorTimestamp(b.ParentID))
		// test update marshalling while we're at it
		{
			js, _ := au.MarshalJSON()
			var au2 ApplyUpdate
			if err = au2.UnmarshalJSON(js); err != nil {
				panic(err)
			}
			au = au2
		}
		db.applyBlock(au)
		return
	}

	// block with nothing except block reward
	b1 := types.Block{
		ParentID:     genesisBlock.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
	}
	addedBIGEs := []types.BigfileElement{
		{BigfileOutput: b1.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs := []types.BigfileElement{}
	addedBFEs := []types.BigfundElement{}
	spentBFEs := []types.BigfundElement{}
	if au, err := addBlock(&b1); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// block that spends part of the gift transaction
	txnB2 := types.Transaction{
		BigfileInputs: []types.BigfileInput{{
			ParentID:         giftTxn.BigfileOutputID(0),
			UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
		}},
		BigfundInputs: []types.BigfundInput{{
			ParentID:         giftTxn.BigfundOutputID(0),
			ClaimAddress:     types.VoidAddress,
			UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Value: giftAmountBIG.Div64(2), Address: giftAddress},
			{Value: giftAmountBIG.Div64(2), Address: types.VoidAddress},
		},
		BigfundOutputs: []types.BigfundOutput{
			{Value: giftAmountBF / 2, Address: giftAddress},
			{Value: giftAmountBF / 2, Address: types.VoidAddress},
		},
	}
	signTxn(&txnB2)
	b2 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		Transactions: []types.Transaction{txnB2},
	}
	addedBIGEs = []types.BigfileElement{
		{BigfileOutput: txnB2.BigfileOutputs[0]},
		{BigfileOutput: txnB2.BigfileOutputs[1]},
		{BigfileOutput: types.BigfileOutput{Value: types.ZeroCurrency, Address: txnB2.BigfundInputs[0].ClaimAddress}, MaturityHeight: cs.MaturityHeight()},
		{BigfileOutput: b2.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs = []types.BigfileElement{
		{BigfileOutput: giftTxn.BigfileOutputs[0]},
	}
	addedBFEs = []types.BigfundElement{
		{BigfundOutput: txnB2.BigfundOutputs[0]},
		{BigfundOutput: txnB2.BigfundOutputs[1]},
	}
	spentBFEs = []types.BigfundElement{
		{BigfundOutput: giftTxn.BigfundOutputs[0]},
	}

	prev := cs
	bs := db.supplementTipBlock(b2)
	if au, err := addBlock(&b2); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	ru := RevertBlock(prev, b2, bs)
	// test update marshalling while we're at it
	{
		js, _ := ru.MarshalJSON()
		var ru2 RevertUpdate
		if err := ru2.UnmarshalJSON(js); err != nil {
			panic(err)
		}
		ru = ru2
	}

	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)

	// reverting a non-child block should trigger a panic
	func() {
		defer func() { recover() }()
		RevertBlock(cs, b2, bs)
		t.Error("did not panic on reverting non-child block")
	}()
}

func TestWorkEncoding(t *testing.T) {
	for _, test := range []struct {
		val       string
		err       bool
		roundtrip string
	}{
		{val: "0"},
		{val: "12345"},
		{val: "115792089237316195423570985008687907853269984665640564039457584007913129639935"}, // 1<<256 - 1
		{val: "01", roundtrip: "1"},
		{val: "-0", roundtrip: "0"},
		{err: true, val: ""},
		{err: true, val: "-1"},
		{err: true, val: " 1"},
		{err: true, val: "1 "},
		{err: true, val: "1157920892373161954235709850086879078532699846656405640394575840079131296399366"},
		{err: true, val: "not a number"},
	} {
		for _, codec := range []struct {
			name string
			enc  func(Work) (string, error)
			dec  func(string) (Work, error)
		}{
			{
				name: "String",
				enc: func(w Work) (string, error) {
					return w.String(), nil
				},
				dec: func(s string) (w Work, err error) {
					err = w.UnmarshalText([]byte(s))
					return
				},
			},
			{
				name: "MarshalText",
				enc: func(w Work) (string, error) {
					v, err := w.MarshalText()
					return string(v), err
				},
				dec: func(s string) (w Work, err error) {
					err = w.UnmarshalText([]byte(s))
					return
				},
			},
			{
				name: "MarshalJSON",
				enc: func(w Work) (string, error) {
					v, err := w.MarshalJSON()
					return strings.Trim(string(v), `"`), err
				},
				dec: func(s string) (w Work, err error) {
					err = w.UnmarshalJSON([]byte(strings.Trim(s, `"`)))
					return
				},
			},
		} {
			w, err := codec.dec(test.val)
			if err != nil {
				if !test.err {
					t.Errorf("%v: unexpected error for %v: %v", codec.name, test.val, err)
				}
				continue
			} else if test.err {
				t.Errorf("%v: expected error for %v, got nil", codec.name, test.val)
				continue
			}
			exp := test.roundtrip
			if exp == "" {
				exp = test.val
			}
			got, err := codec.enc(w)
			if err != nil {
				t.Fatal(err)
			} else if string(got) != exp {
				t.Errorf("%v: %q failed roundtrip (got %q)", codec.name, test.val, got)
				continue
			}
		}
	}
}

func TestRevertedRevisionLeaf(t *testing.T) {
	// Regression test for a1a2c3fd (consensus: Add (*MidState).forEachRevertedElement)
	//
	// NOTE: this is a tricky bug to reproduce. We can't directly observe it by
	// looking at the contract element itself; instead, we have to look at the
	// leaf *adjacent* to it in the accumulator (in this case, the chain index
	// element).

	n, genesisBlock := testnet()
	genesisBlock.Transactions = []types.Transaction{{
		FileContracts: []types.FileContract{{
			Filesize:       123,
			Payout:         types.Bigfiles(1),
			WindowStart:    1000,
			WindowEnd:      1001,
			RevisionNumber: 0,
		}},
	}}
	bs := V1BlockSupplement{Transactions: make([]V1TransactionSupplement, len(genesisBlock.Transactions))}
	cs, cau := ApplyBlock(n.GenesisState(), genesisBlock, bs, time.Time{})
	cie := cau.ChainIndexElement()
	fced := cau.FileContractElementDiffs()[0]
	if !cs.Elements.containsChainIndex(cie.Share()) {
		t.Error("chain index element should be present in accumulator")
	}
	if !cs.Elements.containsUnresolvedFileContractElement(fced.FileContractElement.Share()) {
		t.Error("unrevised contract should be present in accumulator")
	}

	// revise the contract
	b := types.Block{
		ParentID: cs.Index.ID,
		Transactions: []types.Transaction{{
			FileContractRevisions: []types.FileContractRevision{{
				ParentID: fced.FileContractElement.ID,
				FileContract: types.FileContract{
					Filesize:       456,
					Payout:         types.Bigfiles(2),
					WindowStart:    1000,
					WindowEnd:      1001,
					RevisionNumber: 1,
				},
			}},
		}},
	}
	bs = V1BlockSupplement{
		Transactions: []V1TransactionSupplement{{
			RevisedFileContracts: []types.FileContractElement{fced.FileContractElement},
		}},
	}
	prev := cs
	cs, cau = ApplyBlock(cs, b, bs, time.Time{})

	cau.UpdateElementProof(&cie.StateElement)
	if !cs.Elements.containsChainIndex(cie.Share()) {
		t.Fatal("chain index element should be present in accumulator")
	}
	revFCE := cau.FileContractElementDiffs()[0].FileContractElement.Copy()
	revFCE.FileContract = *cau.FileContractElementDiffs()[0].Revision
	if !cs.Elements.containsUnresolvedFileContractElement(revFCE.Share()) {
		t.Error("revised contract should be present in accumulator")
	}
	cau.UpdateElementProof(&fced.FileContractElement.StateElement)
	if cs.Elements.containsUnresolvedFileContractElement(fced.FileContractElement.Share()) {
		t.Error("unrevised contract should not be present in accumulator")
	}

	// revert the block
	cru := RevertBlock(prev, b, bs)
	cs = prev

	cru.UpdateElementProof(&cie.StateElement)
	if !cs.Elements.containsChainIndex(cie.Share()) {
		t.Error("chain index element should be present in accumulator")
	}
	cru.UpdateElementProof(&revFCE.StateElement)
	if cs.Elements.containsUnresolvedFileContractElement(revFCE.Share()) {
		t.Error("revised contract should not be present in accumulator")
	}
	cru.UpdateElementProof(&fced.FileContractElement.StateElement)
	if !cs.Elements.containsUnresolvedFileContractElement(fced.FileContractElement.Share()) {
		t.Error("unrevised contract should be present in accumulator")
	}
}

func TestApplyRevertBlockV1(t *testing.T) {
	n, genesisBlock := testnet()

	giftPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	giftAddress := types.StandardUnlockHash(giftPublicKey)
	giftAmountBIG := types.Bigfiles(100)
	giftAmountBF := uint64(100)
	giftTxn := types.Transaction{
		BigfileOutputs: []types.BigfileOutput{
			{Address: giftAddress, Value: giftAmountBIG},
		},
		BigfundOutputs: []types.BigfundOutput{
			{Address: giftAddress, Value: giftAmountBF},
		},
	}
	genesisBlock.Transactions = []types.Transaction{giftTxn}
	db, cs := newConsensusDB(n, genesisBlock)

	signTxn := func(txn *types.Transaction) {
		appendSig := func(key types.PrivateKey, pubkeyIndex uint64, parentID types.Hash256) {
			sig := key.SignHash(cs.WholeSigHash(*txn, parentID, pubkeyIndex, 0, nil))
			txn.Signatures = append(txn.Signatures, types.TransactionSignature{
				ParentID:       parentID,
				CoveredFields:  types.CoveredFields{WholeTransaction: true},
				PublicKeyIndex: pubkeyIndex,
				Signature:      sig[:],
			})
		}
		for i := range txn.BigfileInputs {
			appendSig(giftPrivateKey, 0, types.Hash256(txn.BigfileInputs[i].ParentID))
		}
		for i := range txn.BigfundInputs {
			appendSig(giftPrivateKey, 0, types.Hash256(txn.BigfundInputs[i].ParentID))
		}
		for i := range txn.FileContractRevisions {
			appendSig(renterPrivateKey, 0, types.Hash256(txn.FileContractRevisions[i].ParentID))
			appendSig(hostPrivateKey, 1, types.Hash256(txn.FileContractRevisions[i].ParentID))
		}
	}
	addBlock := func(b *types.Block, bs V1BlockSupplement) (au ApplyUpdate, err error) {
		findBlockNonce(cs, b)
		if err = ValidateBlock(cs, *b, bs); err != nil {
			return
		}
		cs, au = ApplyBlock(cs, *b, bs, db.ancestorTimestamp(b.ParentID))
		db.applyBlock(au)
		return
	}

	// block with nothing except block reward
	b1 := types.Block{
		ParentID:     genesisBlock.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
	}
	addedBIGEs := []types.BigfileElement{
		{BigfileOutput: b1.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs := []types.BigfileElement{}
	addedBFEs := []types.BigfundElement{}
	spentBFEs := []types.BigfundElement{}
	if au, err := addBlock(&b1, db.supplementTipBlock(b1)); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// block that spends part of the gift transaction
	txnB2 := types.Transaction{
		BigfileInputs: []types.BigfileInput{{
			ParentID:         giftTxn.BigfileOutputID(0),
			UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
		}},
		BigfundInputs: []types.BigfundInput{{
			ParentID:         giftTxn.BigfundOutputID(0),
			ClaimAddress:     types.VoidAddress,
			UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Value: giftAmountBIG.Div64(2), Address: giftAddress},
			{Value: giftAmountBIG.Div64(2), Address: types.VoidAddress},
		},
		BigfundOutputs: []types.BigfundOutput{
			{Value: giftAmountBF / 2, Address: giftAddress},
			{Value: giftAmountBF / 2, Address: types.VoidAddress},
		},
	}
	signTxn(&txnB2)
	b2 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		Transactions: []types.Transaction{txnB2},
	}
	addedBIGEs = []types.BigfileElement{
		{BigfileOutput: txnB2.BigfileOutputs[0]},
		{BigfileOutput: txnB2.BigfileOutputs[1]},
		{BigfileOutput: types.BigfileOutput{Value: types.ZeroCurrency, Address: txnB2.BigfundInputs[0].ClaimAddress}, MaturityHeight: cs.MaturityHeight()},
		{BigfileOutput: b2.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs = []types.BigfileElement{
		{BigfileOutput: giftTxn.BigfileOutputs[0]},
	}
	addedBFEs = []types.BigfundElement{
		{BigfundOutput: txnB2.BigfundOutputs[0]},
		{BigfundOutput: txnB2.BigfundOutputs[1]},
	}
	spentBFEs = []types.BigfundElement{
		{BigfundOutput: giftTxn.BigfundOutputs[0]},
	}

	prev := cs
	bs := db.supplementTipBlock(b2)
	if au, err := addBlock(&b2, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// revert block spending big and bf
	ru := RevertBlock(prev, b2, bs)
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	db.revertBlock(ru)

	// block that creates a file contract
	fc := prepareContractFormation(renterPublicKey, hostPublicKey, types.Bigfiles(1), types.Bigfiles(1), 100, 105, types.VoidAddress)
	txnB3 := types.Transaction{
		BigfileInputs: []types.BigfileInput{{
			ParentID:         giftTxn.BigfileOutputID(0),
			UnlockConditions: types.StandardUnlockConditions(giftPublicKey),
		}},
		BigfileOutputs: []types.BigfileOutput{{
			Address: giftAddress,
			Value:   giftAmountBIG.Sub(fc.Payout),
		}},
		FileContracts: []types.FileContract{fc},
	}
	signTxn(&txnB3)

	b3 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		Transactions: []types.Transaction{txnB3},
	}
	addedBIGEs = []types.BigfileElement{
		{BigfileOutput: txnB3.BigfileOutputs[0]},
		{BigfileOutput: b3.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs = []types.BigfileElement{
		{BigfileOutput: giftTxn.BigfileOutputs[0]},
	}
	addedBFEs = nil
	spentBFEs = nil

	// add block creating fc
	bs = db.supplementTipBlock(b3)
	if au, err := addBlock(&b3, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// revert block creating fc
	ru = RevertBlock(prev, b3, bs)
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	db.revertBlock(ru)

	// readd block creating fc
	if au, err := addBlock(&b3, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// block creating file contract revision
	fcr := fc
	fcr.RevisionNumber++
	fcr.Filesize = 65
	fcr.WindowStart = 4
	fcr.WindowEnd = 20
	fcr.FileMerkleRoot = blake2b.SumPair((State{}).StorageProofLeafHash([]byte{1}), (State{}).StorageProofLeafHash([]byte{2}))

	uc := types.UnlockConditions{
		PublicKeys: []types.UnlockKey{
			{Algorithm: types.SpecifierEd25519, Key: renterPublicKey[:]},
			{Algorithm: types.SpecifierEd25519, Key: hostPublicKey[:]},
		},
		SignaturesRequired: 2,
	}
	txnB4 := types.Transaction{
		FileContractRevisions: []types.FileContractRevision{{
			ParentID:         txnB3.FileContractID(0),
			UnlockConditions: uc,
			FileContract:     fcr,
		}},
	}
	signTxn(&txnB4)
	b4 := types.Block{
		ParentID:     b3.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		Transactions: []types.Transaction{txnB4},
	}
	addedBIGEs = []types.BigfileElement{
		{BigfileOutput: b4.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs = []types.BigfileElement{}
	addedBFEs = nil
	spentBFEs = nil

	prev = cs
	bs = db.supplementTipBlock(b4)
	if au, err := addBlock(&b4, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// revert block revising fc
	ru = RevertBlock(prev, b4, bs)
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	db.revertBlock(ru)

	// readd block revising fc
	if au, err := addBlock(&b4, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// block with storage proof
	txnB5 := types.Transaction{
		StorageProofs: []types.StorageProof{{
			ParentID: txnB3.FileContractID(0),
			Leaf:     [64]byte{1},
			Proof:    []types.Hash256{cs.StorageProofLeafHash([]byte{2})},
		}},
	}
	signTxn(&txnB5)
	b5 := types.Block{
		ParentID:     b4.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		Transactions: []types.Transaction{txnB5},
	}
	if cs.StorageProofLeafIndex(fcr.Filesize, b3.ID(), types.FileContractID(txnB3.FileContractID(0))) == 1 {
		b5.Transactions[0].StorageProofs[0] = types.StorageProof{
			ParentID: txnB3.FileContractID(0),
			Leaf:     [64]byte{2},
			Proof:    []types.Hash256{cs.StorageProofLeafHash([]byte{1})},
		}
	}
	addedBIGEs = []types.BigfileElement{
		{BigfileOutput: txnB3.FileContracts[0].ValidProofOutputs[1], MaturityHeight: cs.MaturityHeight()},
		{BigfileOutput: txnB3.FileContracts[0].ValidProofOutputs[0], MaturityHeight: cs.MaturityHeight()},
		{BigfileOutput: b5.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs = nil
	addedBFEs = nil
	spentBFEs = nil

	// add block with storage proof
	bs = db.supplementTipBlock(b5)
	bs.Transactions[0].StorageProofs = append(bs.Transactions[0].StorageProofs, V1StorageProofSupplement{
		FileContract: db.fces[txnB5.StorageProofs[0].ParentID].Copy(),
		WindowID:     b3.ID(),
	})
	prev = cs
	if au, err := addBlock(&b5, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// revert block with storage proof
	ru = RevertBlock(prev, b5, bs)
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	db.revertBlock(ru)

	// readd block with storage proof
	if au, err := addBlock(&b5, bs); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}
}

func TestApplyRevertBlockV2(t *testing.T) {
	n, genesisBlock := testnet()
	n.HardforkV2.AllowHeight = 1
	n.HardforkV2.RequireHeight = 2

	giftPrivateKey := types.GeneratePrivateKey()
	giftPublicKey := giftPrivateKey.PublicKey()

	renterPrivateKey := types.GeneratePrivateKey()
	renterPublicKey := renterPrivateKey.PublicKey()

	hostPrivateKey := types.GeneratePrivateKey()
	hostPublicKey := hostPrivateKey.PublicKey()

	giftAddress := types.StandardUnlockHash(giftPublicKey)
	giftAmountBIG := types.Bigfiles(100)
	giftAmountBF := uint64(100)
	giftTxn := types.Transaction{
		BigfileOutputs: []types.BigfileOutput{
			{Address: giftAddress, Value: giftAmountBIG},
		},
		BigfundOutputs: []types.BigfundOutput{
			{Address: giftAddress, Value: giftAmountBF},
		},
	}
	genesisBlock.Transactions = []types.Transaction{giftTxn}
	db, cs := newConsensusDB(n, genesisBlock)

	signTxn := func(cs State, txn *types.V2Transaction) {
		for i := range txn.Attestations {
			txn.Attestations[i].Signature = giftPrivateKey.SignHash(cs.AttestationSigHash(txn.Attestations[i]))
		}
		for i := range txn.BigfileInputs {
			txn.BigfileInputs[i].SatisfiedPolicy.Signatures = []types.Signature{giftPrivateKey.SignHash(cs.InputSigHash(*txn))}
		}
		for i := range txn.BigfundInputs {
			txn.BigfundInputs[i].SatisfiedPolicy.Signatures = []types.Signature{giftPrivateKey.SignHash(cs.InputSigHash(*txn))}
		}
		for i := range txn.FileContracts {
			txn.FileContracts[i].RenterSignature = renterPrivateKey.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
			txn.FileContracts[i].HostSignature = hostPrivateKey.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
		}
		for i := range txn.FileContractRevisions {
			txn.FileContractRevisions[i].Revision.RenterSignature = renterPrivateKey.SignHash(cs.ContractSigHash(txn.FileContractRevisions[i].Revision))
			txn.FileContractRevisions[i].Revision.HostSignature = hostPrivateKey.SignHash(cs.ContractSigHash(txn.FileContractRevisions[i].Revision))
		}
		for i := range txn.FileContractResolutions {
			r, ok := txn.FileContractResolutions[i].Resolution.(*types.V2FileContractRenewal)
			if !ok {
				continue
			}
			r.RenterSignature = renterPrivateKey.SignHash(cs.RenewalSigHash(*r))
			r.HostSignature = hostPrivateKey.SignHash(cs.RenewalSigHash(*r))
		}
	}
	addBlock := func(b *types.Block) (au ApplyUpdate, err error) {
		if b.V2 != nil {
			b.V2.Commitment = cs.Commitment(b.MinerPayouts[0].Address, b.Transactions, b.V2Transactions())
		}
		findBlockNonce(cs, b)
		if err = ValidateBlock(cs, *b, V1BlockSupplement{}); err != nil {
			return
		}
		cs, au = ApplyBlock(cs, *b, V1BlockSupplement{}, db.ancestorTimestamp(b.ParentID))
		db.applyBlock(au)
		return
	}
	satisfiedPolicy := func(uc types.UnlockConditions) types.SatisfiedPolicy {
		return types.SatisfiedPolicy{
			Policy: types.SpendPolicy{Type: types.PolicyTypeUnlockConditions(uc)},
		}
	}

	// block with nothing except block reward
	b1 := types.Block{
		ParentID:     genesisBlock.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
	}
	addedBIGEs := []types.BigfileElement{
		{BigfileOutput: b1.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs := []types.BigfileElement{}
	addedBFEs := []types.BigfundElement{}
	spentBFEs := []types.BigfundElement{}
	if au, err := addBlock(&b1); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}
	// block that spends part of the gift transaction
	txnB2 := types.V2Transaction{
		Attestations: []types.Attestation{
			{
				PublicKey: giftPublicKey,
				Key:       hex.EncodeToString(frand.Bytes(16)),
				Value:     frand.Bytes(16),
			},
		},
		BigfileInputs: []types.V2BigfileInput{{
			Parent:          db.biges[giftTxn.BigfileOutputID(0)].Copy(),
			SatisfiedPolicy: satisfiedPolicy(types.StandardUnlockConditions(giftPublicKey)),
		}},
		BigfundInputs: []types.V2BigfundInput{{
			Parent:          db.bfes[giftTxn.BigfundOutputID(0)].Copy(),
			ClaimAddress:    types.VoidAddress,
			SatisfiedPolicy: satisfiedPolicy(types.StandardUnlockConditions(giftPublicKey)),
		}},
		BigfileOutputs: []types.BigfileOutput{
			{Value: giftAmountBIG.Div64(2), Address: giftAddress},
			{Value: giftAmountBIG.Div64(2), Address: types.VoidAddress},
		},
		BigfundOutputs: []types.BigfundOutput{
			{Value: giftAmountBF / 2, Address: giftAddress},
			{Value: giftAmountBF / 2, Address: types.VoidAddress},
		},
	}
	signTxn(cs, &txnB2)
	b2 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		V2: &types.V2BlockData{
			Height:       2,
			Transactions: []types.V2Transaction{txnB2},
		},
	}
	addedBIGEs = []types.BigfileElement{
		{BigfileOutput: txnB2.BigfileOutputs[0]},
		{BigfileOutput: txnB2.BigfileOutputs[1]},
		{BigfileOutput: types.BigfileOutput{Value: types.ZeroCurrency, Address: txnB2.BigfundInputs[0].ClaimAddress}, MaturityHeight: cs.MaturityHeight()},
		{BigfileOutput: b2.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs = []types.BigfileElement{
		{BigfileOutput: giftTxn.BigfileOutputs[0]},
	}
	addedBFEs = []types.BigfundElement{
		{BigfundOutput: txnB2.BigfundOutputs[0]},
		{BigfundOutput: txnB2.BigfundOutputs[1]},
	}
	spentBFEs = []types.BigfundElement{
		{BigfundOutput: giftTxn.BigfundOutputs[0]},
	}

	prev := cs
	if au, err := addBlock(&b2); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// revert block spending sc and sf
	ru := RevertBlock(prev, b2, V1BlockSupplement{})
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	db.revertBlock(ru)

	// block that creates a file contract
	v1FC := prepareContractFormation(renterPublicKey, hostPublicKey, types.Bigfiles(1), types.Bigfiles(1), 100, 105, types.VoidAddress)
	v1FC.Filesize = 65
	v1FC.FileMerkleRoot = blake2b.SumPair((State{}).StorageProofLeafHash([]byte{1}), (State{}).StorageProofLeafHash([]byte{2}))
	v2FC := types.V2FileContract{
		Capacity:         v1FC.Filesize,
		Filesize:         v1FC.Filesize,
		FileMerkleRoot:   v1FC.FileMerkleRoot,
		ProofHeight:      20,
		ExpirationHeight: 30,
		RenterOutput:     v1FC.ValidProofOutputs[0],
		HostOutput:       v1FC.ValidProofOutputs[1],
		MissedHostValue:  v1FC.MissedProofOutputs[1].Value,
		TotalCollateral:  v1FC.ValidProofOutputs[0].Value,
		RenterPublicKey:  renterPublicKey,
		HostPublicKey:    hostPublicKey,
	}
	fcOut := v2FC.RenterOutput.Value.Add(v2FC.HostOutput.Value).Add(cs.V2FileContractTax(v2FC))

	txnB3 := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{{
			Parent:          db.biges[giftTxn.BigfileOutputID(0)].Copy(),
			SatisfiedPolicy: satisfiedPolicy(types.StandardUnlockConditions(giftPublicKey)),
		}},
		BigfileOutputs: []types.BigfileOutput{{
			Address: giftAddress,
			Value:   giftAmountBIG.Sub(fcOut),
		}},
		FileContracts: []types.V2FileContract{v2FC},
	}
	signTxn(cs, &txnB3)

	b3 := types.Block{
		ParentID:     b1.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		V2: &types.V2BlockData{
			Height:       2,
			Transactions: []types.V2Transaction{txnB3},
		},
	}
	addedBIGEs = []types.BigfileElement{
		{BigfileOutput: txnB3.BigfileOutputs[0]},
		{BigfileOutput: b3.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs = []types.BigfileElement{
		{BigfileOutput: giftTxn.BigfileOutputs[0]},
	}
	addedBFEs = nil
	spentBFEs = nil

	// add block creating fc
	if au, err := addBlock(&b3); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// revert block creating fc
	ru = RevertBlock(prev, b3, V1BlockSupplement{})
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	db.revertBlock(ru)

	// readd block creating fc
	if au, err := addBlock(&b3); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// block creating file contract revision
	fcr := v2FC
	fcr.RevisionNumber++
	fcr.Filesize = 65
	fcr.ProofHeight = 3
	fcr.ExpirationHeight = 20
	fcr.FileMerkleRoot = blake2b.SumPair((State{}).StorageProofLeafHash([]byte{1}), (State{}).StorageProofLeafHash([]byte{2}))

	txnB4 := types.V2Transaction{
		FileContractRevisions: []types.V2FileContractRevision{{
			Parent:   db.v2fces[txnB3.V2FileContractID(txnB3.ID(), 0)].Copy(),
			Revision: fcr,
		}},
	}
	signTxn(cs, &txnB4)
	b4 := types.Block{
		ParentID:     b3.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		V2: &types.V2BlockData{
			Height:       3,
			Transactions: []types.V2Transaction{txnB4},
		},
	}
	addedBIGEs = []types.BigfileElement{
		{BigfileOutput: b4.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs = []types.BigfileElement{
		// {BigfileOutput: giftTxn.BigfileOutputs[0]},
	}
	addedBFEs = nil
	spentBFEs = nil

	var cie types.ChainIndexElement
	prev = cs
	if au, err := addBlock(&b4); err != nil {
		t.Fatal(err)
	} else {
		cie = au.ChainIndexElement()
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// revert block revising fc
	ru = RevertBlock(prev, b4, V1BlockSupplement{})
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	db.revertBlock(ru)

	// readd block revising fc
	if au, err := addBlock(&b4); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// block with storage proof
	fce := db.v2fces[txnB3.V2FileContractID(txnB3.ID(), 0)].Copy()
	txnB5 := types.V2Transaction{
		FileContractResolutions: []types.V2FileContractResolution{{
			Parent: fce.Copy(),
			Resolution: &types.V2StorageProof{
				ProofIndex: cie.Copy(),
				Leaf:       [64]byte{1},
				Proof:      []types.Hash256{cs.StorageProofLeafHash([]byte{2})},
			},
		}},
	}
	signTxn(cs, &txnB5)
	b5 := types.Block{
		ParentID:     b4.ID(),
		Timestamp:    types.CurrentTimestamp(),
		MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
		V2: &types.V2BlockData{
			Height:       4,
			Transactions: []types.V2Transaction{txnB5},
		},
	}
	if cs.StorageProofLeafIndex(fce.V2FileContract.Filesize, cie.ChainIndex.ID, types.FileContractID(fce.ID)) == 1 {
		b5.V2.Transactions[0].FileContractResolutions[0].Resolution = &types.V2StorageProof{
			ProofIndex: cie.Copy(),
			Leaf:       [64]byte{2},
			Proof:      []types.Hash256{cs.StorageProofLeafHash([]byte{1})},
		}
	}

	addedBIGEs = []types.BigfileElement{
		{BigfileOutput: txnB3.FileContracts[0].RenterOutput, MaturityHeight: cs.MaturityHeight()},
		{BigfileOutput: txnB3.FileContracts[0].HostOutput, MaturityHeight: cs.MaturityHeight()},
		{BigfileOutput: b5.MinerPayouts[0], MaturityHeight: cs.MaturityHeight()},
	}
	spentBIGEs = nil
	addedBFEs = nil
	spentBFEs = nil

	// add block with storage proof
	prev = cs
	if au, err := addBlock(&b5); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}

	// revert block with storage proof
	ru = RevertBlock(prev, b5, V1BlockSupplement{})
	cs = prev
	checkRevertUpdate(t, cs, ru)
	checkRevertElements(t, ru, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	db.revertBlock(ru)

	// readd block with storage proof
	if au, err := addBlock(&b5); err != nil {
		t.Fatal(err)
	} else {
		checkApplyUpdate(t, cs, au)
		checkUpdateElements(t, au, addedBIGEs, spentBIGEs, addedBFEs, spentBFEs)
	}
}

func TestBigfunds(t *testing.T) {
	n, genesisBlock := testnet()
	n.HardforkV2.AllowHeight = 1
	n.HardforkV2.RequireHeight = 2

	key := types.GeneratePrivateKey()

	giftAddress := types.StandardAddress(key.PublicKey())
	giftAmountBIG := types.Bigfiles(100e3)
	giftAmountBF := uint64(1000)
	giftTxn := types.Transaction{
		BigfileOutputs: []types.BigfileOutput{
			{Address: giftAddress, Value: giftAmountBIG},
		},
		BigfundOutputs: []types.BigfundOutput{
			{Address: giftAddress, Value: giftAmountBF},
		},
	}
	genesisBlock.Transactions = []types.Transaction{giftTxn}
	genesisBlock.V2 = &types.V2BlockData{
		Transactions: []types.V2Transaction{{
			FileContracts: []types.V2FileContract{{
				RenterOutput: types.BigfileOutput{
					Value: types.Bigfiles(1000), // ensure initial BigfundTaxRevenue is not 0
				},
			}},
		}},
	}
	db, cs := newConsensusDB(n, genesisBlock)

	signTxn := func(cs State, txn *types.V2Transaction) {
		for i := range txn.BigfileInputs {
			txn.BigfileInputs[i].SatisfiedPolicy = types.SatisfiedPolicy{
				Policy:     types.PolicyPublicKey(key.PublicKey()),
				Signatures: []types.Signature{key.SignHash(cs.InputSigHash(*txn))},
			}
		}
		for i := range txn.BigfundInputs {
			txn.BigfundInputs[i].SatisfiedPolicy = types.SatisfiedPolicy{
				Policy:     types.PolicyPublicKey(key.PublicKey()),
				Signatures: []types.Signature{key.SignHash(cs.InputSigHash(*txn))},
			}
		}
		for i := range txn.FileContracts {
			txn.FileContracts[i].RenterSignature = key.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
			txn.FileContracts[i].HostSignature = key.SignHash(cs.ContractSigHash(txn.FileContracts[i]))
		}
	}
	mineTxns := func(txns []types.Transaction, v2txns []types.V2Transaction) (au ApplyUpdate, err error) {
		b := types.Block{
			ParentID:     cs.Index.ID,
			Timestamp:    types.CurrentTimestamp(),
			MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
			Transactions: txns,
		}
		if len(v2txns) > 0 {
			b.V2 = &types.V2BlockData{
				Height:       cs.Index.Height + 1,
				Commitment:   cs.Commitment(b.MinerPayouts[0].Address, txns, v2txns),
				Transactions: v2txns,
			}
		}
		findBlockNonce(cs, &b)
		if err = ValidateBlock(cs, b, V1BlockSupplement{}); err != nil {
			return
		}
		cs, au = ApplyBlock(cs, b, V1BlockSupplement{}, db.ancestorTimestamp(b.ParentID))
		db.applyBlock(au)
		return
	}

	// roundtrip BF output, to reset its ClaimStart
	bfoid := giftTxn.BigfundOutputID(0)
	txn := types.V2Transaction{
		BigfundInputs: []types.V2BigfundInput{{
			Parent:       db.bfes[bfoid].Copy(),
			ClaimAddress: giftAddress,
		}},
		BigfundOutputs: []types.BigfundOutput{{
			Address: giftAddress,
			Value:   giftAmountBF,
		}},
	}
	signTxn(cs, &txn)
	if _, err := mineTxns(nil, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	bfoid = txn.BigfundOutputID(txn.ID(), 0)

	fc := types.V2FileContract{
		ProofHeight:      20,
		ExpirationHeight: 30,
		RenterOutput:     types.BigfileOutput{Value: types.Bigfiles(5000)},
		HostOutput:       types.BigfileOutput{Value: types.Bigfiles(5000)},
		RenterPublicKey:  key.PublicKey(),
		HostPublicKey:    key.PublicKey(),
	}
	fcValue := fc.RenterOutput.Value.Add(fc.HostOutput.Value).Add(cs.V2FileContractTax(fc))

	txn = types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{{
			Parent: db.biges[giftTxn.BigfileOutputID(0)].Copy(),
		}},
		BigfileOutputs: []types.BigfileOutput{{
			Address: giftAddress,
			Value:   giftAmountBIG.Sub(fcValue),
		}},
		FileContracts: []types.V2FileContract{fc},
	}
	signTxn(cs, &txn)
	prev := cs
	if _, err := mineTxns(nil, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	}
	// bigfund revenue should have increased
	if cs.BigfundTaxRevenue != prev.BigfundTaxRevenue.Add(cs.V2FileContractTax(fc)) {
		t.Fatalf("expected %v bigfund revenue, got %v", prev.BigfundTaxRevenue.Add(cs.V2FileContractTax(fc)), cs.BigfundTaxRevenue)
	}

	// make a bigfund claim
	txn = types.V2Transaction{
		BigfundInputs: []types.V2BigfundInput{{
			Parent:       db.bfes[bfoid].Copy(),
			ClaimAddress: giftAddress,
		}},
		BigfundOutputs: []types.BigfundOutput{{
			Address: giftAddress,
			Value:   giftAmountBF,
		}},
	}
	signTxn(cs, &txn)
	prev = cs
	if au, err := mineTxns(nil, []types.V2Transaction{txn}); err != nil {
		t.Fatal(err)
	} else {
		// bigfund revenue should be unchanged
		if cs.BigfundTaxRevenue != prev.BigfundTaxRevenue {
			t.Fatalf("expected %v bigfund revenue, got %v", prev.BigfundTaxRevenue, cs.BigfundTaxRevenue)
		}
		// should have received a timelocked bigfund claim output
		var claimOutput *types.BigfileElement
		for _, bige := range au.BigfileElementDiffs() {
			if bige.BigfileElement.ID == txn.BigfundInputs[0].Parent.ID.V2ClaimOutputID() {
				claimOutput = &bige.BigfileElement
				break
			}
		}
		if claimOutput == nil {
			t.Fatal("expected bigfund claim output")
		} else if claimOutput.MaturityHeight != cs.MaturityHeight()-1 {
			t.Fatalf("expected bigfund claim output to mature at height %v, got %v", cs.MaturityHeight()-1, claimOutput.MaturityHeight)
		} else if exp := cs.V2FileContractTax(fc).Div64(cs.BigfundCount() / giftAmountBF); claimOutput.BigfileOutput.Value != exp {
			t.Fatalf("expected bigfund claim output value %v, got %v", exp, claimOutput.BigfileOutput.Value)
		}
	}
}

func TestFoundationSubsidy(t *testing.T) {
	key := types.GeneratePrivateKey()
	addr := types.StandardAddress(key.PublicKey())
	n, genesisBlock := testnet()
	n.HardforkFoundation.Height = 1
	n.HardforkFoundation.PrimaryAddress = addr
	n.HardforkFoundation.FailsafeAddress = addr
	n.HardforkV2.AllowHeight = 1
	n.HardforkV2.RequireHeight = 1
	n.BlockInterval = 10 * time.Hour // subsidies every 10 blocks
	subsidyInterval := uint64(365 * 24 * time.Hour / n.BlockInterval / 12)
	genesisBlock.Transactions = []types.Transaction{{
		BigfileOutputs: []types.BigfileOutput{{
			Address: addr,
			Value:   types.Bigfiles(1), // funds for changing address later
		}},
	}}
	bigoid := genesisBlock.Transactions[0].BigfileOutputID(0)

	db, cs := newConsensusDB(n, genesisBlock)
	mineBlock := func(txns []types.V2Transaction) (subsidy types.BigfileElement, exists bool) {
		b := types.Block{
			ParentID:     cs.Index.ID,
			Timestamp:    types.CurrentTimestamp(),
			MinerPayouts: []types.BigfileOutput{{Address: types.VoidAddress, Value: cs.BlockReward()}},
			V2: &types.V2BlockData{
				Height:       cs.Index.Height + 1,
				Commitment:   cs.Commitment(types.VoidAddress, nil, txns),
				Transactions: txns,
			},
		}
		bs := db.supplementTipBlock(b)
		findBlockNonce(cs, &b)
		if err := ValidateBlock(cs, b, bs); err != nil {
			t.Fatal(err)
			return
		}
		var au ApplyUpdate
		cs, au = ApplyBlock(cs, b, bs, db.ancestorTimestamp(b.ParentID))
		db.applyBlock(au)
		for _, bige := range au.BigfileElementDiffs() {
			if bige.Created && bige.BigfileElement.BigfileOutput.Address == addr {
				subsidy = bige.BigfileElement.Copy()
				exists = true
			}
		}
		return
	}

	// receive initial subsidy
	initialSubsidy, ok := mineBlock(nil)
	if !ok {
		t.Fatal("expected subsidy")
	}

	// mine until we receive a normal subsidy
	for range subsidyInterval - 1 {
		if _, ok := mineBlock(nil); ok {
			t.Fatal("unexpected subsidy")
		}
	}
	subsidy, ok := mineBlock(nil)
	if !ok {
		t.Fatal("expected subsidy")
	} else if subsidy.BigfileOutput.Value != initialSubsidy.BigfileOutput.Value.Div64(12) {
		t.Fatal("expected subsidy to be 1/12 of initial subsidy")
	}
	// disable subsidy
	txn := types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{{
			Parent: db.biges[bigoid].Copy(),
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.PolicyPublicKey(key.PublicKey()),
			},
		}},
		BigfileOutputs: []types.BigfileOutput{{
			Address: addr,
			Value:   db.biges[bigoid].BigfileOutput.Value,
		}},
		NewFoundationAddress: &types.VoidAddress,
	}
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{key.SignHash(cs.InputSigHash(txn))}
	bigoid = txn.BigfileOutputID(txn.ID(), 0)
	mineBlock([]types.V2Transaction{txn})

	// mine until we would receive another subsidy
	for range subsidyInterval {
		if _, ok := mineBlock(nil); ok {
			t.Fatal("unexpected subsidy")
		}
	}

	// re-enable subsidy
	txn = types.V2Transaction{
		BigfileInputs: []types.V2BigfileInput{{
			Parent: db.biges[bigoid].Copy(),
			SatisfiedPolicy: types.SatisfiedPolicy{
				Policy: types.PolicyPublicKey(key.PublicKey()),
			},
		}},
		BigfileOutputs: []types.BigfileOutput{{
			Address: addr,
			Value:   db.biges[bigoid].BigfileOutput.Value,
		}},
		NewFoundationAddress: &addr,
	}
	txn.BigfileInputs[0].SatisfiedPolicy.Signatures = []types.Signature{key.SignHash(cs.InputSigHash(txn))}
	mineBlock([]types.V2Transaction{txn})

	// mine until we would receive another subsidy
	for range subsidyInterval - 3 {
		if _, ok := mineBlock(nil); ok {
			t.Fatal("unexpected subsidy")
		}
	}
	if _, ok := mineBlock(nil); !ok {
		t.Fatal("expected subsidy")
	}
}
