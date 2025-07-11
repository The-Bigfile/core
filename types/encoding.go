package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
	"unsafe"
)

// An Encoder writes Bigfile objects to an underlying stream.
type Encoder struct {
	w   io.Writer
	buf [1024]byte
	n   int
	err error
}

// Flush writes any pending data to the underlying stream. It returns the first
// error encountered by the Encoder.
func (e *Encoder) Flush() error {
	if e.err == nil && e.n > 0 {
		_, e.err = e.w.Write(e.buf[:e.n])
		e.n = 0
	}
	return e.err
}

// Write implements io.Writer.
func (e *Encoder) Write(p []byte) (int, error) {
	lenp := len(p)
	for e.err == nil && len(p) > 0 {
		if e.n == len(e.buf) {
			e.Flush()
		}
		c := copy(e.buf[e.n:], p)
		e.n += c
		p = p[c:]
	}
	return lenp, e.err
}

// WriteBool writes a bool value to the underlying stream.
func (e *Encoder) WriteBool(b bool) {
	var buf [1]byte
	if b {
		buf[0] = 1
	}
	e.Write(buf[:])
}

// WriteUint8 writes a uint8 value to the underlying stream.
func (e *Encoder) WriteUint8(u uint8) {
	e.Write([]byte{u})
}

// WriteUint64 writes a uint64 value to the underlying stream.
func (e *Encoder) WriteUint64(u uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], u)
	e.Write(buf[:])
}

// WriteTime writes a time.Time value to the underlying stream.
func (e *Encoder) WriteTime(t time.Time) {
	e.WriteUint64(uint64(t.Unix()))
}

// WriteBytes writes a length-prefixed []byte to the underlying stream.
func (e *Encoder) WriteBytes(b []byte) {
	e.WriteUint64(uint64(len(b)))
	e.Write(b)
}

// WriteString writes a length-prefixed string to the underlying stream.
func (e *Encoder) WriteString(s string) {
	e.WriteBytes([]byte(s))
}

// Reset resets the Encoder to write to w. Any unflushed data, along with any
// error previously encountered, is discarded.
func (e *Encoder) Reset(w io.Writer) {
	e.w = w
	e.n = 0
	e.err = nil
}

// NewEncoder returns an Encoder that wraps the provided stream.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{
		w: w,
	}
}

// An EncoderTo can encode itself to a stream via an Encoder.
type EncoderTo interface {
	EncodeTo(e *Encoder)
}

// EncoderFunc implements types.EncoderTo with a function.
type EncoderFunc func(*Encoder)

// EncodeTo implements types.EncoderTo.
func (fn EncoderFunc) EncodeTo(e *Encoder) { fn(e) }

// EncodePtr encodes a pointer to an object that implements EncoderTo.
func EncodePtr[T any, P interface {
	*T
	EncoderTo
}](e *Encoder, p P) {
	e.WriteBool(p != nil)
	if p != nil {
		p.EncodeTo(e)
	}
}

// EncodePtrCast encodes a pointer to an object by casting it to V.
func EncodePtrCast[V interface {
	Cast() T
	EncoderTo
}, T any](e *Encoder, p *T) {
	e.WriteBool(p != nil)
	if p != nil {
		vp := *(*V)(unsafe.Pointer(p))
		vp.EncodeTo(e)
	}
}

// EncodeSlice encodes a slice of objects that implement EncoderTo.
func EncodeSlice[T EncoderTo](e *Encoder, s []T) {
	e.WriteUint64(uint64(len(s)))
	for i := range s {
		s[i].EncodeTo(e)
	}
}

// EncodeSliceCast encodes a slice of objects by casting them to V.
func EncodeSliceCast[V interface {
	Cast() T
	EncoderTo
}, T any](e *Encoder, s []T) {
	EncodeSlice(e, unsafe.Slice((*V)(unsafe.Pointer(unsafe.SliceData(s))), len(s)))
}

// EncodeSliceFn encodes a slice of objects by calling an explicit function to
// encode each element.
func EncodeSliceFn[T any](e *Encoder, s []T, fn func(*Encoder, T)) {
	e.WriteUint64(uint64(len(s)))
	for i := range s {
		fn(e, s[i])
	}
}

// A Decoder reads values from an underlying stream. Callers MUST check
// (*Decoder).Err before using any decoded values.
type Decoder struct {
	lr  io.LimitedReader
	buf [64]byte
	err error
}

// SetErr sets the Decoder's error if it has not already been set. SetErr should
// only be called from DecodeFrom methods.
func (d *Decoder) SetErr(err error) {
	if err != nil && d.err == nil {
		d.err = err
		// clear d.buf so that future reads always return zero
		d.buf = [len(d.buf)]byte{}
	}
}

// Err returns the first error encountered during decoding.
func (d *Decoder) Err() error { return d.err }

// Read implements the io.Reader interface. It always returns an error if fewer
// than len(p) bytes were read.
func (d *Decoder) Read(p []byte) (int, error) {
	n := 0
	for len(p[n:]) > 0 && d.err == nil {
		read, err := io.ReadFull(&d.lr, d.buf[:min(len(p[n:]), len(d.buf))])
		n += copy(p[n:], d.buf[:read])
		d.SetErr(err)
	}
	return n, d.err
}

// ReadBool reads a bool value from the underlying stream.
func (d *Decoder) ReadBool() bool {
	d.Read(d.buf[:1])
	switch d.buf[0] {
	case 0:
		return false
	case 1:
		return true
	default:
		d.SetErr(fmt.Errorf("invalid bool value (%v)", d.buf[0]))
		return false
	}
}

// ReadUint8 reads a uint8 value from the underlying stream.
func (d *Decoder) ReadUint8() uint8 {
	d.Read(d.buf[:1])
	return d.buf[0]
}

// ReadUint64 reads a uint64 value from the underlying stream.
func (d *Decoder) ReadUint64() uint64 {
	d.Read(d.buf[:8])
	return binary.LittleEndian.Uint64(d.buf[:8])
}

// ReadTime reads a time.Time from the underlying stream.
func (d *Decoder) ReadTime() time.Time {
	return time.Unix(int64(d.ReadUint64()), 0)
}

// ReadBytes reads a length-prefixed []byte from the underlying stream.
func (d *Decoder) ReadBytes() []byte {
	n := d.ReadUint64()
	if n > uint64(d.lr.N) {
		d.SetErr(fmt.Errorf("encoded object contains invalid length prefix (%v elems > %v bytes left in stream)", n, d.lr.N))
		return nil
	}
	b := make([]byte, n)
	d.Read(b)
	return b
}

// ReadString reads a length-prefixed string from the underlying stream.
func (d *Decoder) ReadString() string {
	return string(d.ReadBytes())
}

// NewDecoder returns a Decoder that wraps the provided stream.
func NewDecoder(lr io.LimitedReader) *Decoder {
	return &Decoder{
		lr: lr,
	}
}

// A DecoderFrom can decode itself from a stream via a Decoder.
type DecoderFrom interface {
	DecodeFrom(d *Decoder)
}

// DecoderFunc implements types.DecoderTo with a function.
type DecoderFunc func(*Decoder)

// DecodeFrom implements types.DecoderTo.
func (fn DecoderFunc) DecodeFrom(d *Decoder) { fn(d) }

// DecodePtr decodes a pointer to an object that implements DecoderFrom.
func DecodePtr[T any, TP interface {
	*T
	DecoderFrom
}](d *Decoder, v **T) {
	if d.ReadBool() {
		*v = new(T)
		TP(*v).DecodeFrom(d)
	} else {
		*v = nil
	}
}

// DecodePtrCast decodes a pointer to an object by casting it to V.
func DecodePtrCast[T interface {
	Cast() V
}, TP interface {
	*T
	DecoderFrom
}, V any](d *Decoder, p **V) {
	tp := (**T)(unsafe.Pointer(p))
	if d.ReadBool() {
		*tp = new(T)
		TP(*tp).DecodeFrom(d)
	} else {
		*tp = nil
	}
}

// DecodeSlice decodes a length-prefixed slice of type T, containing values read
// from the decoder.
func DecodeSlice[T any, DF interface {
	*T
	DecoderFrom
}](d *Decoder, s *[]T) {
	n := d.ReadUint64()
	if n > uint64(d.lr.N) {
		d.SetErr(fmt.Errorf("encoded object contains invalid length prefix (%v elems > %v bytes left in stream)", n, d.lr.N))
		return
	}
	*s = make([]T, n)
	for i := range *s {
		DF(&(*s)[i]).DecodeFrom(d)
		if d.Err() != nil {
			break
		}
	}
}

// DecodeSliceCast decodes a length-prefixed slice of type T, casting through
// type V.
func DecodeSliceCast[V any, T any, VF interface {
	*V
	Cast() T
	DecoderFrom
}](d *Decoder, s *[]T) {
	DecodeSlice[V, VF](d, (*[]V)(unsafe.Pointer(s)))
}

// DecodeSliceFn decodes a length-prefixed slice of type T, calling an explicit
// function to decode each element.
func DecodeSliceFn[T any](d *Decoder, s *[]T, fn func(*Decoder) T) {
	n := d.ReadUint64()
	if n > uint64(d.lr.N) {
		d.SetErr(fmt.Errorf("encoded object contains invalid length prefix (%v elems > %v bytes left in stream)", n, d.lr.N))
		return
	}
	*s = make([]T, n)
	for i := range *s {
		(*s)[i] = fn(d)
		if d.Err() != nil {
			break
		}
	}
}

// NewBufDecoder returns a Decoder for the provided byte slice.
func NewBufDecoder(buf []byte) *Decoder {
	return NewDecoder(io.LimitedReader{
		R: bytes.NewReader(buf),
		N: int64(len(buf)),
	})
}

// implementations of EncoderTo and DecoderFrom for core types

// EncodeTo implements types.EncoderTo.
func (h Hash256) EncodeTo(e *Encoder) { e.Write(h[:]) }

// EncodeTo implements types.EncoderTo.
func (id BlockID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// EncodeTo implements types.EncoderTo.
func (id TransactionID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// EncodeTo implements types.EncoderTo.
func (a Address) EncodeTo(e *Encoder) { e.Write(a[:]) }

// EncodeTo implements types.EncoderTo.
func (pk PublicKey) EncodeTo(e *Encoder) { e.Write(pk[:]) }

// EncodeTo implements types.EncoderTo.
func (s Signature) EncodeTo(e *Encoder) { e.Write(s[:]) }

// EncodeTo implements types.EncoderTo.
func (s Specifier) EncodeTo(e *Encoder) { e.Write(s[:]) }

// EncodeTo implements types.EncoderTo.
func (uk UnlockKey) EncodeTo(e *Encoder) {
	uk.Algorithm.EncodeTo(e)
	e.WriteBytes(uk.Key)
}

// EncodeTo implements types.EncoderTo.
func (uc UnlockConditions) EncodeTo(e *Encoder) {
	e.WriteUint64(uc.Timelock)
	EncodeSlice(e, uc.PublicKeys)
	e.WriteUint64(uc.SignaturesRequired)
}

// V1Currency provides v1 encoding for Currency.
type V1Currency Currency

// V2Currency provides v2 encoding for Currency.
type V2Currency Currency

// Cast provides type safety for DecodeSliceCast.
func (c V1Currency) Cast() Currency { return Currency(c) }

// Cast provides type safety for DecodeSliceCast.
func (c V2Currency) Cast() Currency { return Currency(c) }

// EncodeTo implements types.EncoderTo.
func (c V1Currency) EncodeTo(e *Encoder) {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], c.Hi)
	binary.BigEndian.PutUint64(buf[8:], c.Lo)
	e.WriteBytes(bytes.TrimLeft(buf[:], "\x00"))
}

// EncodeTo implements types.EncoderTo.
func (c V2Currency) EncodeTo(e *Encoder) {
	e.WriteUint64(c.Lo)
	e.WriteUint64(c.Hi)
}

// EncodeTo implements types.EncoderTo.
func (index ChainIndex) EncodeTo(e *Encoder) {
	e.WriteUint64(index.Height)
	index.ID.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (id AttestationID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// V1BigfileOutput provides v1 encoding for BigfileOutput.
type V1BigfileOutput BigfileOutput

// V2BigfileOutput provides v2 encoding for BigfileOutput.
type V2BigfileOutput BigfileOutput

// Cast provides type safety for DecodeSliceCast.
func (bigo V1BigfileOutput) Cast() BigfileOutput { return BigfileOutput(bigo) }

// Cast provides type safety for DecodeSliceCast.
func (bigo V2BigfileOutput) Cast() BigfileOutput { return BigfileOutput(bigo) }

// EncodeTo implements types.EncoderTo.
func (bigo V1BigfileOutput) EncodeTo(e *Encoder) {
	V1Currency(bigo.Value).EncodeTo(e)
	bigo.Address.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (bigo V2BigfileOutput) EncodeTo(e *Encoder) {
	V2Currency(bigo.Value).EncodeTo(e)
	bigo.Address.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (id BigfileOutputID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// V1BigfundOutput provides v1 encoding for BigfundOutput.
type V1BigfundOutput BigfundOutput

// V2BigfundOutput provides v2 encoding for BigfundOutput.
type V2BigfundOutput BigfundOutput

// Cast provides type safety for DecodeSliceCast.
func (bfo V1BigfundOutput) Cast() BigfundOutput { return BigfundOutput(bfo) }

// Cast provides type safety for DecodeSliceCast.
func (bfo V2BigfundOutput) Cast() BigfundOutput { return BigfundOutput(bfo) }

// EncodeTo implements types.EncoderTo.
func (bfo V1BigfundOutput) EncodeTo(e *Encoder) {
	V1Currency(NewCurrency64(bfo.Value)).EncodeTo(e)
	bfo.Address.EncodeTo(e)
	(V1Currency{}).EncodeTo(e) // siad expects a "ClaimStart" value
}

// EncodeTo implements types.EncoderTo.
func (bfo V2BigfundOutput) EncodeTo(e *Encoder) {
	e.WriteUint64(bfo.Value)
	bfo.Address.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (id BigfundOutputID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// EncodeTo implements types.EncoderTo.
func (in BigfileInput) EncodeTo(e *Encoder) {
	in.ParentID.EncodeTo(e)
	in.UnlockConditions.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (in BigfundInput) EncodeTo(e *Encoder) {
	in.ParentID.EncodeTo(e)
	in.UnlockConditions.EncodeTo(e)
	in.ClaimAddress.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (fc FileContract) EncodeTo(e *Encoder) {
	e.WriteUint64(fc.Filesize)
	fc.FileMerkleRoot.EncodeTo(e)
	e.WriteUint64(fc.WindowStart)
	e.WriteUint64(fc.WindowEnd)
	V1Currency(fc.Payout).EncodeTo(e)
	EncodeSliceCast[V1BigfileOutput](e, fc.ValidProofOutputs)
	EncodeSliceCast[V1BigfileOutput](e, fc.MissedProofOutputs)
	fc.UnlockHash.EncodeTo(e)
	e.WriteUint64(fc.RevisionNumber)
}

// EncodeTo implements types.EncoderTo.
func (id FileContractID) EncodeTo(e *Encoder) { e.Write(id[:]) }

// EncodeTo implements types.EncoderTo.
func (rev FileContractRevision) EncodeTo(e *Encoder) {
	rev.ParentID.EncodeTo(e)
	rev.UnlockConditions.EncodeTo(e)
	e.WriteUint64(rev.FileContract.RevisionNumber)
	e.WriteUint64(rev.FileContract.Filesize)
	rev.FileContract.FileMerkleRoot.EncodeTo(e)
	e.WriteUint64(rev.FileContract.WindowStart)
	e.WriteUint64(rev.FileContract.WindowEnd)
	EncodeSliceCast[V1BigfileOutput](e, rev.FileContract.ValidProofOutputs)
	EncodeSliceCast[V1BigfileOutput](e, rev.FileContract.MissedProofOutputs)
	rev.FileContract.UnlockHash.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (sp StorageProof) EncodeTo(e *Encoder) {
	sp.ParentID.EncodeTo(e)
	e.Write(sp.Leaf[:])
	EncodeSlice(e, sp.Proof)
}

// EncodeTo implements types.EncoderTo.
func (fau FoundationAddressUpdate) EncodeTo(e *Encoder) {
	fau.NewPrimary.EncodeTo(e)
	fau.NewFailsafe.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (cf CoveredFields) EncodeTo(e *Encoder) {
	e.WriteBool(cf.WholeTransaction)
	EncodeSliceFn(e, cf.BigfileInputs, (*Encoder).WriteUint64)
	EncodeSliceFn(e, cf.BigfileOutputs, (*Encoder).WriteUint64)
	EncodeSliceFn(e, cf.FileContracts, (*Encoder).WriteUint64)
	EncodeSliceFn(e, cf.FileContractRevisions, (*Encoder).WriteUint64)
	EncodeSliceFn(e, cf.StorageProofs, (*Encoder).WriteUint64)
	EncodeSliceFn(e, cf.BigfundInputs, (*Encoder).WriteUint64)
	EncodeSliceFn(e, cf.BigfundOutputs, (*Encoder).WriteUint64)
	EncodeSliceFn(e, cf.MinerFees, (*Encoder).WriteUint64)
	EncodeSliceFn(e, cf.ArbitraryData, (*Encoder).WriteUint64)
	EncodeSliceFn(e, cf.Signatures, (*Encoder).WriteUint64)
}

// EncodeTo implements types.EncoderTo.
func (ts TransactionSignature) EncodeTo(e *Encoder) {
	ts.ParentID.EncodeTo(e)
	e.WriteUint64(ts.PublicKeyIndex)
	e.WriteUint64(ts.Timelock)
	ts.CoveredFields.EncodeTo(e)
	e.WriteBytes(ts.Signature)
}

type txnSansSigs Transaction

func (txn txnSansSigs) EncodeTo(e *Encoder) {
	EncodeSlice(e, txn.BigfileInputs)
	EncodeSliceCast[V1BigfileOutput](e, txn.BigfileOutputs)
	EncodeSlice(e, txn.FileContracts)
	EncodeSlice(e, txn.FileContractRevisions)
	EncodeSlice(e, txn.StorageProofs)
	EncodeSlice(e, txn.BigfundInputs)
	EncodeSliceCast[V1BigfundOutput](e, txn.BigfundOutputs)
	EncodeSliceCast[V1Currency](e, txn.MinerFees)
	EncodeSliceFn(e, txn.ArbitraryData, (*Encoder).WriteBytes)
}

// EncodeTo implements types.EncoderTo.
func (txn Transaction) EncodeTo(e *Encoder) {
	txnSansSigs(txn).EncodeTo(e)
	EncodeSlice(e, txn.Signatures)
}

func (p SpendPolicy) encodePolicy(e *Encoder) {
	const (
		opInvalid = iota
		opAbove
		opAfter
		opPublicKey
		opHash
		opThreshold
		opOpaque
		opUnlockConditions
	)
	switch p := p.Type.(type) {
	case PolicyTypeAbove:
		e.WriteUint8(opAbove)
		e.WriteUint64(uint64(p))
	case PolicyTypeAfter:
		e.WriteUint8(opAfter)
		e.WriteTime(time.Time(p))
	case PolicyTypePublicKey:
		e.WriteUint8(opPublicKey)
		PublicKey(p).EncodeTo(e)
	case PolicyTypeHash:
		e.WriteUint8(opHash)
		Hash256(p).EncodeTo(e)
	case PolicyTypeThreshold:
		e.WriteUint8(opThreshold)
		e.WriteUint8(p.N)
		e.WriteUint8(uint8(len(p.Of)))
		for i := range p.Of {
			p.Of[i].encodePolicy(e)
		}
	case PolicyTypeOpaque:
		e.WriteUint8(opOpaque)
		Hash256(p).EncodeTo(e)
	case PolicyTypeUnlockConditions:
		e.WriteUint8(opUnlockConditions)
		UnlockConditions(p).EncodeTo(e)
	default:
		panic(fmt.Sprintf("unhandled policy type %T", p))
	}
}

// EncodeTo implements types.EncoderTo.
func (p SpendPolicy) EncodeTo(e *Encoder) {
	const version = 1
	e.WriteUint8(version)
	p.encodePolicy(e)
}

// EncodeTo implements types.EncoderTo.
func (sp SatisfiedPolicy) EncodeTo(e *Encoder) {
	sp.Policy.EncodeTo(e)
	EncodeSlice(e, sp.Signatures)
	EncodeSliceFn(e, sp.Preimages, func(e *Encoder, pre [32]byte) {
		Hash256(pre).EncodeTo(e)
	})
}

// EncodeTo implements types.EncoderTo.
func (se StateElement) EncodeTo(e *Encoder) {
	e.WriteUint64(se.LeafIndex)
	EncodeSlice(e, se.MerkleProof)
}

// EncodeTo implements types.EncoderTo.
func (in V2BigfileInput) EncodeTo(e *Encoder) {
	in.Parent.EncodeTo(e)
	in.SatisfiedPolicy.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (cie ChainIndexElement) EncodeTo(e *Encoder) {
	cie.StateElement.EncodeTo(e)
	cie.ID.EncodeTo(e)
	cie.ChainIndex.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (bige BigfileElement) EncodeTo(e *Encoder) {
	bige.StateElement.EncodeTo(e)
	bige.ID.EncodeTo(e)
	V2BigfileOutput(bige.BigfileOutput).EncodeTo(e)
	e.WriteUint64(bige.MaturityHeight)
}

// EncodeTo implements types.EncoderTo.
func (in V2BigfundInput) EncodeTo(e *Encoder) {
	in.Parent.EncodeTo(e)
	in.ClaimAddress.EncodeTo(e)
	in.SatisfiedPolicy.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (bfe BigfundElement) EncodeTo(e *Encoder) {
	bfe.StateElement.EncodeTo(e)
	bfe.ID.EncodeTo(e)
	V2BigfundOutput(bfe.BigfundOutput).EncodeTo(e)
	V2Currency(bfe.ClaimStart).EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (fc V2FileContract) EncodeTo(e *Encoder) {
	e.WriteUint64(fc.Capacity)
	e.WriteUint64(fc.Filesize)
	fc.FileMerkleRoot.EncodeTo(e)
	e.WriteUint64(fc.ProofHeight)
	e.WriteUint64(fc.ExpirationHeight)
	V2BigfileOutput(fc.RenterOutput).EncodeTo(e)
	V2BigfileOutput(fc.HostOutput).EncodeTo(e)
	V2Currency(fc.MissedHostValue).EncodeTo(e)
	V2Currency(fc.TotalCollateral).EncodeTo(e)
	fc.RenterPublicKey.EncodeTo(e)
	fc.HostPublicKey.EncodeTo(e)
	e.WriteUint64(fc.RevisionNumber)
	fc.RenterSignature.EncodeTo(e)
	fc.HostSignature.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (fce FileContractElement) EncodeTo(e *Encoder) {
	fce.StateElement.EncodeTo(e)
	fce.ID.EncodeTo(e)
	fce.FileContract.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (fce V2FileContractElement) EncodeTo(e *Encoder) {
	fce.StateElement.EncodeTo(e)
	fce.ID.EncodeTo(e)
	fce.V2FileContract.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (rev V2FileContractRevision) EncodeTo(e *Encoder) {
	rev.Parent.EncodeTo(e)
	rev.Revision.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (ren V2FileContractRenewal) EncodeTo(e *Encoder) {
	V2BigfileOutput(ren.FinalRenterOutput).EncodeTo(e)
	V2BigfileOutput(ren.FinalHostOutput).EncodeTo(e)
	V2Currency(ren.RenterRollover).EncodeTo(e)
	V2Currency(ren.HostRollover).EncodeTo(e)
	ren.NewContract.EncodeTo(e)
	ren.RenterSignature.EncodeTo(e)
	ren.HostSignature.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (sp V2StorageProof) EncodeTo(e *Encoder) {
	sp.ProofIndex.EncodeTo(e)
	e.Write(sp.Leaf[:])
	EncodeSlice(e, sp.Proof)
}

// EncodeTo implements types.EncoderTo.
func (V2FileContractExpiration) EncodeTo(e *Encoder) {}

// EncodeTo implements types.EncoderTo.
func (res V2FileContractResolution) EncodeTo(e *Encoder) {
	res.Parent.EncodeTo(e)
	switch r := res.Resolution.(type) {
	case *V2FileContractRenewal:
		e.WriteUint8(0)
	case *V2StorageProof:
		e.WriteUint8(1)
	case *V2FileContractExpiration:
		e.WriteUint8(2)
	default:
		panic(fmt.Sprintf("unhandled resolution type %T", r))
	}
	res.Resolution.(EncoderTo).EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (a Attestation) EncodeTo(e *Encoder) {
	a.PublicKey.EncodeTo(e)
	e.WriteString(a.Key)
	e.WriteBytes(a.Value)
	a.Signature.EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (txn V2Transaction) EncodeTo(e *Encoder) {
	const version = 2
	e.WriteUint8(version)

	var fields uint64
	for i, b := range [...]bool{
		len(txn.BigfileInputs) != 0,
		len(txn.BigfileOutputs) != 0,
		len(txn.BigfundInputs) != 0,
		len(txn.BigfundOutputs) != 0,
		len(txn.FileContracts) != 0,
		len(txn.FileContractRevisions) != 0,
		len(txn.FileContractResolutions) != 0,
		len(txn.Attestations) != 0,
		len(txn.ArbitraryData) != 0,
		txn.NewFoundationAddress != nil,
		!txn.MinerFee.IsZero(),
	} {
		if b {
			fields |= 1 << i
		}
	}
	e.WriteUint64(fields)

	if fields&(1<<0) != 0 {
		EncodeSlice(e, txn.BigfileInputs)
	}
	if fields&(1<<1) != 0 {
		EncodeSliceCast[V2BigfileOutput](e, txn.BigfileOutputs)
	}
	if fields&(1<<2) != 0 {
		EncodeSlice(e, txn.BigfundInputs)
	}
	if fields&(1<<3) != 0 {
		EncodeSliceCast[V2BigfundOutput](e, txn.BigfundOutputs)
	}
	if fields&(1<<4) != 0 {
		EncodeSlice(e, txn.FileContracts)
	}
	if fields&(1<<5) != 0 {
		EncodeSlice(e, txn.FileContractRevisions)
	}
	if fields&(1<<6) != 0 {
		EncodeSlice(e, txn.FileContractResolutions)
	}
	if fields&(1<<7) != 0 {
		EncodeSlice(e, txn.Attestations)
	}
	if fields&(1<<8) != 0 {
		e.WriteBytes(txn.ArbitraryData)
	}
	if fields&(1<<9) != 0 {
		txn.NewFoundationAddress.EncodeTo(e)
	}
	if fields&(1<<10) != 0 {
		V2Currency(txn.MinerFee).EncodeTo(e)
	}
}

// V2TransactionSemantics is a helper type that provides a "semantic encoding"
// of a v2 transaction, for use in computing IDs and signature hashes.
type V2TransactionSemantics V2Transaction

// EncodeTo implements types.EncoderTo.
func (txn V2TransactionSemantics) EncodeTo(e *Encoder) {
	nilSigs := func(sigs ...*Signature) {
		for i := range sigs {
			*sigs[i] = Signature{}
		}
	}

	e.WriteUint64(uint64(len(txn.BigfileInputs)))
	for _, in := range txn.BigfileInputs {
		in.Parent.ID.EncodeTo(e)
	}
	e.WriteUint64(uint64(len(txn.BigfileOutputs)))
	for _, out := range txn.BigfileOutputs {
		V2BigfileOutput(out).EncodeTo(e)
	}
	e.WriteUint64(uint64(len(txn.BigfundInputs)))
	for _, in := range txn.BigfundInputs {
		in.Parent.ID.EncodeTo(e)
	}
	e.WriteUint64(uint64(len(txn.BigfundOutputs)))
	for _, out := range txn.BigfundOutputs {
		V2BigfundOutput(out).EncodeTo(e)
	}
	e.WriteUint64(uint64(len(txn.FileContracts)))
	for _, fc := range txn.FileContracts {
		nilSigs(&fc.RenterSignature, &fc.HostSignature)
		fc.EncodeTo(e)
	}
	e.WriteUint64(uint64(len(txn.FileContractRevisions)))
	for _, fcr := range txn.FileContractRevisions {
		fcr.Parent.ID.EncodeTo(e)
		nilSigs(&fcr.Revision.RenterSignature, &fcr.Revision.HostSignature)
		fcr.Revision.EncodeTo(e)
	}
	e.WriteUint64(uint64(len(txn.FileContractResolutions)))
	for _, fcr := range txn.FileContractResolutions {
		fcr.Parent.ID.EncodeTo(e)
		// normalize (being careful not to modify the original)
		switch res := fcr.Resolution.(type) {
		case *V2FileContractRenewal:
			renewal := *res
			nilSigs(
				&renewal.NewContract.RenterSignature, &renewal.NewContract.HostSignature,
				&renewal.RenterSignature, &renewal.HostSignature,
			)
			fcr.Resolution = &renewal
		case *V2StorageProof:
			sp := *res
			sp.ProofIndex.StateElement.MerkleProof = nil
			fcr.Resolution = &sp
		}
		fcr.Resolution.(EncoderTo).EncodeTo(e)
	}
	e.WriteUint64(uint64(len(txn.Attestations)))
	for _, a := range txn.Attestations {
		a.EncodeTo(e)
	}
	e.WriteBytes(txn.ArbitraryData)
	EncodePtr(e, txn.NewFoundationAddress)
	V2Currency(txn.MinerFee).EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (b V2BlockData) EncodeTo(e *Encoder) {
	e.WriteUint64(b.Height)
	b.Commitment.EncodeTo(e)
	V2TransactionsMultiproof(b.Transactions).EncodeTo(e)
}

// EncodeTo implements types.EncoderTo.
func (h BlockHeader) EncodeTo(e *Encoder) {
	h.ParentID.EncodeTo(e)
	e.WriteUint64(h.Nonce)
	e.WriteTime(h.Timestamp)
	h.Commitment.EncodeTo(e)
}

// V1Block provides v1 encoding for Block.
type V1Block Block

// V2Block provides v2 encoding for Block.
type V2Block Block

// Cast provides type safety for DecodeSliceCast.
func (b V1Block) Cast() Block { return Block(b) }

// Cast provides type safety for DecodeSliceCast.
func (b V2Block) Cast() Block { return Block(b) }

// EncodeTo implements types.EncoderTo.
func (b V1Block) EncodeTo(e *Encoder) {
	b.ParentID.EncodeTo(e)
	e.WriteUint64(b.Nonce)
	e.WriteTime(b.Timestamp)
	EncodeSliceCast[V1BigfileOutput](e, b.MinerPayouts)
	EncodeSlice(e, b.Transactions)
}

// EncodeTo implements types.EncoderTo.
func (b V2Block) EncodeTo(e *Encoder) {
	V1Block(b).EncodeTo(e)
	EncodePtr(e, b.V2)
}

// DecodeFrom implements types.DecoderFrom.
func (h *Hash256) DecodeFrom(d *Decoder) { d.Read(h[:]) }

// DecodeFrom implements types.DecoderFrom.
func (id *BlockID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (id *TransactionID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (id *AttestationID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (a *Address) DecodeFrom(d *Decoder) { d.Read(a[:]) }

// DecodeFrom implements types.DecoderFrom.
func (pk *PublicKey) DecodeFrom(d *Decoder) { d.Read(pk[:]) }

// DecodeFrom implements types.DecoderFrom.
func (s *Signature) DecodeFrom(d *Decoder) { d.Read(s[:]) }

// DecodeFrom implements types.DecoderFrom.
func (s *Specifier) DecodeFrom(d *Decoder) { d.Read(s[:]) }

// DecodeFrom implements types.DecoderFrom.
func (uk *UnlockKey) DecodeFrom(d *Decoder) {
	uk.Algorithm.DecodeFrom(d)
	uk.Key = d.ReadBytes()
}

// DecodeFrom implements types.DecoderFrom.
func (uc *UnlockConditions) DecodeFrom(d *Decoder) {
	uc.Timelock = d.ReadUint64()
	DecodeSlice(d, &uc.PublicKeys)
	uc.SignaturesRequired = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (c *V1Currency) DecodeFrom(d *Decoder) {
	var buf [16]byte
	n := d.ReadUint64()
	if n > 16 {
		d.SetErr(fmt.Errorf("Currency too large: %v bytes", n))
		return
	}
	d.Read(buf[16-n:])
	c.Hi = binary.BigEndian.Uint64(buf[:8])
	c.Lo = binary.BigEndian.Uint64(buf[8:])
}

// DecodeFrom implements types.DecoderFrom.
func (c *V2Currency) DecodeFrom(d *Decoder) {
	c.Lo = d.ReadUint64()
	c.Hi = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (index *ChainIndex) DecodeFrom(d *Decoder) {
	index.Height = d.ReadUint64()
	index.ID.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (bigo *V1BigfileOutput) DecodeFrom(d *Decoder) {
	(*V1Currency)(&bigo.Value).DecodeFrom(d)
	bigo.Address.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (bigo *V2BigfileOutput) DecodeFrom(d *Decoder) {
	(*V2Currency)(&bigo.Value).DecodeFrom(d)
	bigo.Address.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (id *BigfileOutputID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (bfo *V1BigfundOutput) DecodeFrom(d *Decoder) {
	var val V1Currency
	val.DecodeFrom(d)
	if val.Hi != 0 {
		d.SetErr(errors.New("value overflows bigfund representation"))
		return
	}
	bfo.Value = val.Lo
	bfo.Address.DecodeFrom(d)
	(&V1Currency{}).DecodeFrom(d) // siad expects a "ClaimStart" value
}

// DecodeFrom implements types.DecoderFrom.
func (bfo *V2BigfundOutput) DecodeFrom(d *Decoder) {
	bfo.Value = d.ReadUint64()
	bfo.Address.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (id *BigfundOutputID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (in *BigfileInput) DecodeFrom(d *Decoder) {
	in.ParentID.DecodeFrom(d)
	in.UnlockConditions.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (in *BigfundInput) DecodeFrom(d *Decoder) {
	in.ParentID.DecodeFrom(d)
	in.UnlockConditions.DecodeFrom(d)
	in.ClaimAddress.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (fc *FileContract) DecodeFrom(d *Decoder) {
	fc.Filesize = d.ReadUint64()
	fc.FileMerkleRoot.DecodeFrom(d)
	fc.WindowStart = d.ReadUint64()
	fc.WindowEnd = d.ReadUint64()
	(*V1Currency)(&fc.Payout).DecodeFrom(d)
	DecodeSliceCast[V1BigfileOutput](d, &fc.ValidProofOutputs)
	DecodeSliceCast[V1BigfileOutput](d, &fc.MissedProofOutputs)
	fc.UnlockHash.DecodeFrom(d)
	fc.RevisionNumber = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (id *FileContractID) DecodeFrom(d *Decoder) { d.Read(id[:]) }

// DecodeFrom implements types.DecoderFrom.
func (rev *FileContractRevision) DecodeFrom(d *Decoder) {
	rev.ParentID.DecodeFrom(d)
	rev.UnlockConditions.DecodeFrom(d)
	rev.FileContract.RevisionNumber = d.ReadUint64()
	rev.FileContract.Filesize = d.ReadUint64()
	rev.FileContract.FileMerkleRoot.DecodeFrom(d)
	rev.FileContract.WindowStart = d.ReadUint64()
	rev.FileContract.WindowEnd = d.ReadUint64()
	DecodeSliceCast[V1BigfileOutput](d, &rev.FileContract.ValidProofOutputs)
	DecodeSliceCast[V1BigfileOutput](d, &rev.FileContract.MissedProofOutputs)
	rev.FileContract.UnlockHash.DecodeFrom(d)

	// see FileContractRevision docstring
	rev.FileContract.Payout = NewCurrency(math.MaxUint64, math.MaxUint64)
}

// DecodeFrom implements types.DecoderFrom.
func (sp *StorageProof) DecodeFrom(d *Decoder) {
	sp.ParentID.DecodeFrom(d)
	d.Read(sp.Leaf[:])
	DecodeSlice(d, &sp.Proof)
}

// DecodeFrom implements types.DecoderFrom.
func (fau *FoundationAddressUpdate) DecodeFrom(d *Decoder) {
	fau.NewPrimary.DecodeFrom(d)
	fau.NewFailsafe.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (cf *CoveredFields) DecodeFrom(d *Decoder) {
	cf.WholeTransaction = d.ReadBool()
	DecodeSliceFn(d, &cf.BigfileInputs, (*Decoder).ReadUint64)
	DecodeSliceFn(d, &cf.BigfileOutputs, (*Decoder).ReadUint64)
	DecodeSliceFn(d, &cf.FileContracts, (*Decoder).ReadUint64)
	DecodeSliceFn(d, &cf.FileContractRevisions, (*Decoder).ReadUint64)
	DecodeSliceFn(d, &cf.StorageProofs, (*Decoder).ReadUint64)
	DecodeSliceFn(d, &cf.BigfundInputs, (*Decoder).ReadUint64)
	DecodeSliceFn(d, &cf.BigfundOutputs, (*Decoder).ReadUint64)
	DecodeSliceFn(d, &cf.MinerFees, (*Decoder).ReadUint64)
	DecodeSliceFn(d, &cf.ArbitraryData, (*Decoder).ReadUint64)
	DecodeSliceFn(d, &cf.Signatures, (*Decoder).ReadUint64)
}

// DecodeFrom implements types.DecoderFrom.
func (ts *TransactionSignature) DecodeFrom(d *Decoder) {
	ts.ParentID.DecodeFrom(d)
	ts.PublicKeyIndex = d.ReadUint64()
	ts.Timelock = d.ReadUint64()
	ts.CoveredFields.DecodeFrom(d)
	ts.Signature = d.ReadBytes()
}

// DecodeFrom implements types.DecoderFrom.
func (txn *Transaction) DecodeFrom(d *Decoder) {
	DecodeSlice(d, &txn.BigfileInputs)
	DecodeSliceCast[V1BigfileOutput](d, &txn.BigfileOutputs)
	DecodeSlice(d, &txn.FileContracts)
	DecodeSlice(d, &txn.FileContractRevisions)
	DecodeSlice(d, &txn.StorageProofs)
	DecodeSlice(d, &txn.BigfundInputs)
	DecodeSliceCast[V1BigfundOutput](d, &txn.BigfundOutputs)
	DecodeSliceCast[V1Currency](d, &txn.MinerFees)
	DecodeSliceFn(d, &txn.ArbitraryData, (*Decoder).ReadBytes)
	DecodeSlice(d, &txn.Signatures)
}

// DecodeFrom implements types.DecoderFrom.
func (p *SpendPolicy) DecodeFrom(d *Decoder) {
	const version = 1
	const (
		opInvalid = iota
		opAbove
		opAfter
		opPublicKey
		opHash
		opThreshold
		opOpaque
		opUnlockConditions
	)

	var readPolicy func() (SpendPolicy, error)
	readPolicy = func() (SpendPolicy, error) {
		switch op := d.ReadUint8(); op {
		case opAbove:
			return PolicyAbove(d.ReadUint64()), nil
		case opAfter:
			return PolicyAfter(d.ReadTime()), nil
		case opPublicKey:
			var pk PublicKey
			pk.DecodeFrom(d)
			return PolicyPublicKey(pk), nil
		case opHash:
			var h Hash256
			h.DecodeFrom(d)
			return PolicyHash(h), nil
		case opThreshold:
			n := d.ReadUint8()
			of := make([]SpendPolicy, d.ReadUint8())
			var err error
			for i := range of {
				if of[i], err = readPolicy(); err != nil {
					return SpendPolicy{}, err
				}
			}
			return PolicyThreshold(n, of), nil
		case opOpaque:
			var p PolicyTypeOpaque
			(*Address)(&p).DecodeFrom(d)
			return SpendPolicy{p}, nil
		case opUnlockConditions:
			var uc UnlockConditions
			uc.DecodeFrom(d)
			return SpendPolicy{PolicyTypeUnlockConditions(uc)}, nil
		default:
			return SpendPolicy{}, fmt.Errorf("unknown policy (opcode %d)", op)
		}
	}

	if v := d.ReadUint8(); v != version {
		d.SetErr(fmt.Errorf("unsupported policy version (%v)", version))
		return
	}
	var err error
	*p, err = readPolicy()
	d.SetErr(err)
}

// DecodeFrom implements types.DecoderFrom.
func (sp *SatisfiedPolicy) DecodeFrom(d *Decoder) {
	sp.Policy.DecodeFrom(d)
	DecodeSlice(d, &sp.Signatures)
	DecodeSliceFn(d, &sp.Preimages, func(d *Decoder) (pre [32]byte) {
		(*Hash256)(&pre).DecodeFrom(d)
		return
	})
}

// DecodeFrom implements types.DecoderFrom.
func (se *StateElement) DecodeFrom(d *Decoder) {
	se.LeafIndex = d.ReadUint64()
	DecodeSlice(d, &se.MerkleProof)
}

// DecodeFrom implements types.DecoderFrom.
func (in *V2BigfileInput) DecodeFrom(d *Decoder) {
	in.Parent.DecodeFrom(d)
	in.SatisfiedPolicy.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (cie *ChainIndexElement) DecodeFrom(d *Decoder) {
	cie.StateElement.DecodeFrom(d)
	cie.ID.DecodeFrom(d)
	cie.ChainIndex.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (bige *BigfileElement) DecodeFrom(d *Decoder) {
	bige.StateElement.DecodeFrom(d)
	bige.ID.DecodeFrom(d)
	(*V2BigfileOutput)(&bige.BigfileOutput).DecodeFrom(d)
	bige.MaturityHeight = d.ReadUint64()
}

// DecodeFrom implements types.DecoderFrom.
func (in *V2BigfundInput) DecodeFrom(d *Decoder) {
	in.Parent.DecodeFrom(d)
	in.ClaimAddress.DecodeFrom(d)
	in.SatisfiedPolicy.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (bfe *BigfundElement) DecodeFrom(d *Decoder) {
	bfe.StateElement.DecodeFrom(d)
	bfe.ID.DecodeFrom(d)
	(*V2BigfundOutput)(&bfe.BigfundOutput).DecodeFrom(d)
	(*V2Currency)(&bfe.ClaimStart).DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (fc *V2FileContract) DecodeFrom(d *Decoder) {
	fc.Capacity = d.ReadUint64()
	fc.Filesize = d.ReadUint64()
	fc.FileMerkleRoot.DecodeFrom(d)
	fc.ProofHeight = d.ReadUint64()
	fc.ExpirationHeight = d.ReadUint64()
	(*V2BigfileOutput)(&fc.RenterOutput).DecodeFrom(d)
	(*V2BigfileOutput)(&fc.HostOutput).DecodeFrom(d)
	(*V2Currency)(&fc.MissedHostValue).DecodeFrom(d)
	(*V2Currency)(&fc.TotalCollateral).DecodeFrom(d)
	fc.RenterPublicKey.DecodeFrom(d)
	fc.HostPublicKey.DecodeFrom(d)
	fc.RevisionNumber = d.ReadUint64()
	fc.RenterSignature.DecodeFrom(d)
	fc.HostSignature.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (fce *FileContractElement) DecodeFrom(d *Decoder) {
	fce.StateElement.DecodeFrom(d)
	fce.ID.DecodeFrom(d)
	fce.FileContract.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (fce *V2FileContractElement) DecodeFrom(d *Decoder) {
	fce.StateElement.DecodeFrom(d)
	fce.ID.DecodeFrom(d)
	fce.V2FileContract.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (rev *V2FileContractRevision) DecodeFrom(d *Decoder) {
	rev.Parent.DecodeFrom(d)
	rev.Revision.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (ren *V2FileContractRenewal) DecodeFrom(d *Decoder) {
	(*V2BigfileOutput)(&ren.FinalRenterOutput).DecodeFrom(d)
	(*V2BigfileOutput)(&ren.FinalHostOutput).DecodeFrom(d)
	(*V2Currency)(&ren.RenterRollover).DecodeFrom(d)
	(*V2Currency)(&ren.HostRollover).DecodeFrom(d)
	ren.NewContract.DecodeFrom(d)
	ren.RenterSignature.DecodeFrom(d)
	ren.HostSignature.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (sp *V2StorageProof) DecodeFrom(d *Decoder) {
	sp.ProofIndex.DecodeFrom(d)
	d.Read(sp.Leaf[:])
	DecodeSlice(d, &sp.Proof)
}

// DecodeFrom implements types.DecoderFrom.
func (*V2FileContractExpiration) DecodeFrom(d *Decoder) {}

// DecodeFrom implements types.DecoderFrom.
func (res *V2FileContractResolution) DecodeFrom(d *Decoder) {
	res.Parent.DecodeFrom(d)
	switch t := d.ReadUint8(); t {
	case 0:
		res.Resolution = new(V2FileContractRenewal)
	case 1:
		res.Resolution = new(V2StorageProof)
	case 2:
		res.Resolution = new(V2FileContractExpiration)
	default:
		d.SetErr(fmt.Errorf("unknown resolution type %d", t))
	}
	res.Resolution.(DecoderFrom).DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (a *Attestation) DecodeFrom(d *Decoder) {
	a.PublicKey.DecodeFrom(d)
	a.Key = d.ReadString()
	a.Value = d.ReadBytes()
	a.Signature.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (txn *V2Transaction) DecodeFrom(d *Decoder) {
	if version := d.ReadUint8(); version != 2 {
		d.SetErr(fmt.Errorf("unsupported transaction version (%v)", version))
		return
	}

	fields := d.ReadUint64()

	if fields&(1<<0) != 0 {
		DecodeSlice(d, &txn.BigfileInputs)
	}
	if fields&(1<<1) != 0 {
		DecodeSliceCast[V2BigfileOutput](d, &txn.BigfileOutputs)
	}
	if fields&(1<<2) != 0 {
		DecodeSlice(d, &txn.BigfundInputs)
	}
	if fields&(1<<3) != 0 {
		DecodeSliceCast[V2BigfundOutput](d, &txn.BigfundOutputs)
	}
	if fields&(1<<4) != 0 {
		DecodeSlice(d, &txn.FileContracts)
	}
	if fields&(1<<5) != 0 {
		DecodeSlice(d, &txn.FileContractRevisions)
	}
	if fields&(1<<6) != 0 {
		DecodeSlice(d, &txn.FileContractResolutions)
	}
	if fields&(1<<7) != 0 {
		DecodeSlice(d, &txn.Attestations)
	}
	if fields&(1<<8) != 0 {
		txn.ArbitraryData = d.ReadBytes()
	}
	if fields&(1<<9) != 0 {
		txn.NewFoundationAddress = new(Address)
		txn.NewFoundationAddress.DecodeFrom(d)
	}
	if fields&(1<<10) != 0 {
		(*V2Currency)(&txn.MinerFee).DecodeFrom(d)
	}
}

// DecodeFrom implements types.DecoderFrom.
func (b *V2BlockData) DecodeFrom(d *Decoder) {
	b.Height = d.ReadUint64()
	b.Commitment.DecodeFrom(d)
	(*V2TransactionsMultiproof)(&b.Transactions).DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (h *BlockHeader) DecodeFrom(d *Decoder) {
	h.ParentID.DecodeFrom(d)
	h.Nonce = d.ReadUint64()
	h.Timestamp = d.ReadTime()
	h.Commitment.DecodeFrom(d)
}

// DecodeFrom implements types.DecoderFrom.
func (b *V1Block) DecodeFrom(d *Decoder) {
	b.ParentID.DecodeFrom(d)
	b.Nonce = d.ReadUint64()
	b.Timestamp = d.ReadTime()
	DecodeSliceCast[V1BigfileOutput](d, &b.MinerPayouts)
	DecodeSlice(d, &b.Transactions)
}

// DecodeFrom implements types.DecoderFrom.
func (b *V2Block) DecodeFrom(d *Decoder) {
	(*V1Block)(b).DecodeFrom(d)
	DecodePtr(d, &b.V2)
}
