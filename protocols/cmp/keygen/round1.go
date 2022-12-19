package keygen

import (
	"crypto/rand"
	"errors"
	"log"

	"github.com/capsule-org/multi-party-sig/internal/round"
	"github.com/capsule-org/multi-party-sig/internal/types"
	"github.com/capsule-org/multi-party-sig/pkg/hash"
	"github.com/capsule-org/multi-party-sig/pkg/math/curve"
	"github.com/capsule-org/multi-party-sig/pkg/math/polynomial"
	"github.com/capsule-org/multi-party-sig/pkg/math/sample"
	"github.com/capsule-org/multi-party-sig/pkg/paillier"
	"github.com/capsule-org/multi-party-sig/pkg/party"
	zksch "github.com/capsule-org/multi-party-sig/pkg/zk/sch"
	"github.com/cronokirby/safenum"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper

	// PreviousSecretECDSA = sk'ᵢ
	// Contains the previous secret ECDSA key share which is being refreshed
	// Keygen:  sk'ᵢ = nil
	// Refresh: sk'ᵢ = sk'ᵢ
	PreviousSecretECDSA curve.Scalar

	// PreviousPublicSharesECDSA[j] = pk'ⱼ
	// Keygen:  pk'ⱼ = nil
	// Refresh: pk'ⱼ = pk'ⱼ
	PreviousPublicSharesECDSA map[party.ID]curve.Point

	// PreviousChainKey contains the chain key, if we're refreshing
	//
	// In that case, we will simply use the previous chain key at the very end.
	PreviousChainKey types.RID

	// VSSSecret = fᵢ(X)
	// Polynomial from which the new secret shares are computed.
	// Keygen:  fᵢ(0) = xⁱ
	// Refresh: fᵢ(0) = 0
	VSSSecret *polynomial.Polynomial
}

// VerifyMessage implements round.Round.
func (r *round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (r *round1) StoreMessage(round.Message) error { return nil }

// 
ze implements round.Round
//
// - sample Paillier (pᵢ, qᵢ)
// - sample Pedersen Nᵢ, sᵢ, tᵢ
// - sample aᵢ  <- 𝔽
// - set Aᵢ = aᵢ⋅G
// - compute Fᵢ(X) = fᵢ(X)⋅G
// - sample ridᵢ <- {0,1}ᵏ
// - sample cᵢ <- {0,1}ᵏ
// - commit to message.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// generate Paillier and Pedersen
	log.Println("oooooo1")
	PaillierSecret := paillier.NewSecretKey(nil)
	log.Println("oooooo2")
	SelfPaillierPublic := PaillierSecret.PublicKey
	SelfPedersenPublic, PedersenSecret := PaillierSecret.GeneratePedersen()

	ElGamalSecret, ElGamalPublic := sample.ScalarPointPair(rand.Reader, r.Group())
	log.Println("oooooo3")

	// save our own share already so we are consistent with what we receive from others
	SelfShare := r.VSSSecret.Evaluate(r.SelfID().Scalar(r.Group()))

	log.Println("oooooo4")
	// set Fᵢ(X) = fᵢ(X)•G
	SelfVSSPolynomial := polynomial.NewPolynomialExponent(r.VSSSecret)
	log.Println("oooooo5")

	// generate Schnorr randomness
	SchnorrRand := zksch.NewRandomness(rand.Reader, r.Group(), nil)
	log.Println("oooooo6")
	

	// Sample RIDᵢ
	SelfRID, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, errors.New("failed to sample Rho")
	}
	chainKey, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, errors.New("failed to sample c")
	}
	log.Println("oooooo7")
	

	// commit to data in message 2
	SelfCommitment, Decommitment, err := r.HashForID(r.SelfID()).Commit(
		SelfRID, chainKey, SelfVSSPolynomial, SchnorrRand.Commitment(), ElGamalPublic,
		SelfPedersenPublic.N(), SelfPedersenPublic.S(), SelfPedersenPublic.T())
	log.Println("oooooo8", err)
	
	if err != nil {
		return r, errors.New("failed to commit")
	}

	// should be broadcast but we don't need that here
	msg := &broadcast2{Commitment: SelfCommitment}
	err = r.BroadcastMessage(out, msg)
	if err != nil {
		return r, err
	}
	log.Println("oooooo9", err)
	

	nextRound := &round2{
		round1:         r,
		VSSPolynomials: map[party.ID]*polynomial.Exponent{r.SelfID(): SelfVSSPolynomial},
		Commitments:    map[party.ID]hash.Commitment{r.SelfID(): SelfCommitment},
		RIDs:           map[party.ID]types.RID{r.SelfID(): SelfRID},
		ChainKeys:      map[party.ID]types.RID{r.SelfID(): chainKey},
		ShareReceived:  map[party.ID]curve.Scalar{r.SelfID(): SelfShare},
		ElGamalPublic:  map[party.ID]curve.Point{r.SelfID(): ElGamalPublic},
		PaillierPublic: map[party.ID]*paillier.PublicKey{r.SelfID(): SelfPaillierPublic},
		NModulus:       map[party.ID]*safenum.Modulus{r.SelfID(): SelfPedersenPublic.N()},
		S:              map[party.ID]*safenum.Nat{r.SelfID(): SelfPedersenPublic.S()},
		T:              map[party.ID]*safenum.Nat{r.SelfID(): SelfPedersenPublic.T()},
		ElGamalSecret:  ElGamalSecret,
		PaillierSecret: PaillierSecret,
		PedersenSecret: PedersenSecret,
		SchnorrRand:    SchnorrRand,
		Decommitment:   Decommitment,
	}
	log.Println("oooooo10", err)
	
	return nextRound, nil
}

// PreviousRound implements round.Round.
func (round1) PreviousRound() round.Round { return nil }

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }
