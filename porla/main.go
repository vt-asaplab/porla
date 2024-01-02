package main

import (
	"C"
	"fmt"
	// "time"
	"bytes"
	"math/big"
	// "math/bits"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	// "github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
)

var (
	g1GenAff bn254.G1Affine
)

var kzg_SRS 	*kzg.SRS
var tau_key_bi  *big.Int
var tau_key 	fr.Element
var alpha_bi 	*big.Int
var alpha		fr.Element 
var tau_alpha   fr.Element 
var n_samples   int
var h_MAC 		bn254.G1Affine

//export init_key
func init_key(tau_key_in *[]byte, alpha_key_in *[]byte) {
	// Initialize tau key
	tau_key.SetBytes(*tau_key_in)
	tau_key_bi = new(big.Int).SetBytes(*tau_key_in)

	alpha.SetBytes(*alpha_key_in)
	alpha_bi   = new(big.Int).SetBytes(*alpha_key_in)
	tau_alpha.Mul(&tau_key, &alpha)
}

//export init_SRS
func init_SRS(SRS_size int, out *[]byte, out_len *int64) {
	// Initialize generators
	n_samples   = SRS_size
	kzg_SRS, _  = kzg.NewSRS(uint64(SRS_size), tau_key_bi)
	var buf bytes.Buffer 
	*out_len, _ = kzg_SRS.WriteTo(&buf)
	copy(*out, buf.Bytes())

	// Initialize MAC hiding h
	var random_value fr.Element
	random_value.SetRandom()

	var random_value_bi big.Int
	random_value.ToBigIntRegular(&random_value_bi)

	h_MAC.Set(&kzg_SRS.G1[0])
	h_MAC.ScalarMultiplication(&h_MAC, &random_value_bi)
}

//export init_SRS_from_data
func init_SRS_from_data(SRS_size int, in *[]byte) {
	n_samples  = SRS_size
	buf 	  := bytes.NewBuffer(*in)
	kzg_SRS, _ = kzg.NewSRS(uint64(SRS_size), new(big.Int).SetInt64(0))
	kzg_SRS.ReadFrom(buf)
}

//export compute_digest
func compute_digest(data_in *[]byte, data_out *[]byte) {

	f := make(polynomial.Polynomial, n_samples)
	k := 0

	for i := 0; i < n_samples; i++ {
		f[i].SetBytes((*data_in)[k:k+32])
		k += 32
	}

	fx := f.Eval(&tau_key)
	fx.Mul(&fx, &alpha)
	var fxbi big.Int
	fx.ToBigIntRegular(&fxbi)
	var commitment bn254.G1Affine
	commitment.Set(&kzg_SRS.G1[0])
	commitment.ScalarMultiplication(&commitment, &fxbi)
	copy(*data_out, commitment.Marshal())
}

//export compute_digest_complement
func compute_digest_complement(data_in *[]byte, data_out *[]byte) {
	var secret_value fr.Element
	secret_value.SetBytes(*data_in)
	var secret_value_bi big.Int
	secret_value.ToBigIntRegular(&secret_value_bi)
	var complement bn254.G1Affine
	complement.Set(&h_MAC)
	complement.ScalarMultiplication(&complement, &secret_value_bi)
	copy(*data_out, complement.Marshal())
}

//export compute_digest_from_srs
func compute_digest_from_srs(data_in *[]byte, data_out *[]byte) {

	f := make(polynomial.Polynomial, n_samples)
	k := 0

	for i := 0; i < n_samples; i++ {
		f[i].SetBytes((*data_in)[k:k+32])
		k += 32
	}

	commitment, _ := kzg.Commit(f, kzg_SRS)
	copy(*data_out, commitment.Marshal())
}

//export compute_multi_exp
func compute_multi_exp(scalars *[]byte, points *[]byte, length int, result_out *[]byte) {
	sc := make([]fr.Element, length)
	pt := make([]bn254.G1Affine, length)

	k1 := 0
	k2 := 0
	for i := 0; i < length; i++ {
		// Assign scalars[i]
		sc[i].SetBytes((*scalars)[k1:k1+32])
		k1 += 32
		// Assign points[i]
		pt[i].Unmarshal((*points)[k2:k2+64])
		k2 += 64
	}

	config := ecc.MultiExpConfig{ScalarsMont: true}
	var res bn254.G1Affine
	res.MultiExp(pt, sc, config)
	copy(*result_out, res.Marshal())
}

//export compare_commitment
func compare_commitment(commitment_a *[]byte, commitment_b *[]byte) bool {
	// return true 
	var cm_a, cm_b bn254.G1Affine
	cm_a.Unmarshal(*commitment_a)
	cm_b.Unmarshal(*commitment_b)
	if !cm_a.Equal(&cm_b) {
		fmt.Println("error KZG commitment")
		return false
	} 
	return true 
}

//export create_proof
func create_proof(random_point uint64, data_in *[]byte, commitment_out *[]byte, proof_H *[]byte, proof_point *[]byte, proof_claim *[]byte) {
	
	f := make(polynomial.Polynomial, n_samples)
	k := 0

	for i := 0; i < n_samples; i++ {
		f[i].SetBytes((*data_in)[k:k+32])
		k += 32
	}

	commitment, _ := kzg.Commit(f, kzg_SRS)
	copy(*commitment_out, commitment.Marshal())

	var point fr.Element
	point.SetUint64(random_point)

	proof, _ := kzg.Open(f, &point, nil, kzg_SRS)

	copy(*proof_H, proof.H.Marshal())
	copy(*proof_point, proof.Point.Marshal())
	copy(*proof_claim, proof.ClaimedValue.Marshal())
}

//export verify_proof
func verify_proof(commitment_in *[]byte, proof_H *[]byte, proof_point *[]byte, proof_claim *[]byte) bool {
	var proof kzg.OpeningProof
	proof.H.Unmarshal(*proof_H)
	proof.Point.SetBytes(*proof_point)
	proof.ClaimedValue.SetBytes(*proof_claim)

	var commitment bn254.G1Affine
	commitment.Unmarshal(*commitment_in)

	err := kzg.Verify(&commitment, &proof, kzg_SRS)
	if err != nil {
		fmt.Println("Verifying is wrong")
		return false 
	} 
	return true
}

//export add_point
func add_point(point_a *[]byte, point_b *[]byte) {
	var a, b bn254.G1Affine
	a.Unmarshal(*point_a)
	b.Unmarshal(*point_b)
	a.Add(&a, &b)
	copy(*point_a, a.Marshal())
}

//export mult_point
func mult_point(point_a *[]byte, scalar *[]byte) {
	var p bn254.G1Affine
	var s fr.Element
	p.Unmarshal(*point_a)
	s.SetBytes(*scalar)
	var sbi big.Int
	s.ToBigIntRegular(&sbi)
	p.ScalarMultiplication(&p, &sbi)
	copy(*point_a, p.Marshal())
}

//export neg_point
func neg_point(point *[]byte) {
	var p bn254.G1Affine
	p.Unmarshal(*point)
	p.Neg(&p)
	copy(*point, p.Marshal())
}

//export set_inf_point
func set_inf_point(point *[]byte) {
	var p bn254.G1Affine
	p.X.SetZero()
	p.Y.SetZero()
	copy(*point, p.Marshal())
}

func main() {
	
}

