package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"time"
)

const trail = 10

func referenceCircuit(curve ecc.ID) (constraint.ConstraintSystem, frontend.Circuit, kzg.SRS) {
	circuit := GetEmptyMiMcAssign()
	ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}

	assignedCircuit := GetMiMcAssign()

	srs, err := test.NewKZGSRS(ccs)
	if err != nil {
		panic(err)
	}

	return ccs, assignedCircuit, srs
}

func main() {
	// Plonk zkSNARK: Setup
	ccs, assigned, srs := referenceCircuit(ecc.BN254)
	fullWitness, err := frontend.NewWitness(assigned, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("Error = ", err)
	}

	pk, vk, err := plonk.Setup(ccs, srs)
	if err != nil {
		fmt.Println("Error = ", err)
	}

	for i := 0; i < trail; i++ {
		startingTime := time.Now().UTC()
		proof, err := plonk.Prove(ccs, pk, fullWitness)
		if err != nil {
			fmt.Println("Error = ", err)
		}
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("PlonK MiMC Hash, Num:[%d], took [%.3f] Seconds.\n", numHashes, duration.Seconds())

		publicWitness, err := fullWitness.Public()
		if err != nil {
			fmt.Println("Error = ", err)
		}

		err = plonk.Verify(proof, vk, publicWitness)
		if err != nil {
			fmt.Println("Error = ", err)
		}
	}
}
