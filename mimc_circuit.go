package main

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

const numHashes = 140 * 1024

//const numHashes = 10

type MiMcCircuit struct {
	curveID     tedwards.ID
	Message     []frontend.Variable `gnark:",public"`
	HashOutputs []frontend.Variable `gnark:",public"`
}

func (circuit *MiMcCircuit) Define(api frontend.API) error {
	mimcHash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	for i := 0; i < numHashes; i++ {
		mimcHash.Write(circuit.Message[i])
		temp := mimcHash.Sum()
		api.AssertIsEqual(temp, circuit.HashOutputs[i])
		mimcHash.Reset()
	}

	return err
}

// GetMiMcAssign generate a test assignment of circuit for Testing!
func GetMiMcAssign() *MiMcCircuit {
	bn264MiMCHash := hash.MIMC_BN254.New()

	msg := make([]byte, 32)
	msg[0] = 0x0d
	bn264MiMCHash.Write(msg)
	var assignment MiMcCircuit
	hashOut := bn264MiMCHash.Sum(nil)
	// assign message value
	assignment.Message = make([]frontend.Variable, numHashes)
	assignment.HashOutputs = make([]frontend.Variable, numHashes)
	// assign public key values
	for i := 0; i < numHashes; i++ {
		assignment.Message[i] = msg
		assignment.HashOutputs[i] = hashOut
	}

	return &assignment
}

func GetEmptyMiMcAssign() *MiMcCircuit {
	mimcHash := hash.MIMC_BN254.New()

	msg := make([]byte, 32)
	msg[0] = 0x0d
	mimcHash.Write(msg)
	var assignment MiMcCircuit
	hashOut := mimcHash.Sum(nil)
	// assign message value
	assignment.Message = make([]frontend.Variable, numHashes)
	assignment.HashOutputs = make([]frontend.Variable, numHashes)
	// assign public key values
	for i := 0; i < numHashes; i++ {
		assignment.Message[i] = msg
		assignment.HashOutputs[i] = hashOut
	}

	return &assignment
}
