// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	keyBitSize     = 4096
	rsaKeyType     = "RSA PRIVATE KEY"
	ecdsaKeyType   = "EC PRIVATE KEY"
	ed25519KeyType = "PRIVATE KEY"
	publicKeyType  = "PUBLIC KEY"
	publicKeyFile  = "public.pem"
	privateKeyFile = "private.pem"
	ECDSA          = "ecdsa"
	ED25519        = "ed25519"
)

var KeyType string

func (cli *CLI) NewKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keys",
		Short: "Generate a new public/private key pair",
		Long: "Generates a new public/private key pair using an algorithm of the users choice.\n" +
			"Supported algorithms are RSA, ecdsa, and ed25519.",
		Example: "./build/cocos-cli keys -k rsa",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch KeyType {
			case ECDSA:
				privEcdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return printError(cmd, "Error generating keys: %v ❌ ", err)
				}

				pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privEcdsaKey.PublicKey)
				if err != nil {
					return printError(cmd, "Error marshalling public key: %v ❌ ", err)
				}

				if err := generateAndWriteKeys(privEcdsaKey, pubKeyBytes, ecdsaKeyType); err != nil {
					return printError(cmd, "Error generating and writing keys: %v ❌ ", err)
				}

			case ED25519:
				pubEd25519Key, privEd25519Key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					return printError(cmd, "Error generating keys: %v ❌ ", err)
				}
				pubKey, err := x509.MarshalPKIXPublicKey(pubEd25519Key)
				if err != nil {
					return printError(cmd, "Error marshalling public key: %v ❌ ", err)
				}
				if err := generateAndWriteKeys(privEd25519Key, pubKey, ed25519KeyType); err != nil {
					return printError(cmd, "Error generating and writing keys: %v ❌ ", err)
				}

			default:
				privKey, err := rsa.GenerateKey(rand.Reader, keyBitSize)
				if err != nil {
					return printError(cmd, "Error generating keys: %v ❌ ", err)
				}

				pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
				if err != nil {
					return printError(cmd, "Error marshalling public key: %v ❌ ", err)
				}
				if err := generateAndWriteKeys(privKey, pubKeyBytes, rsaKeyType); err != nil {
					return printError(cmd, "Error generating and writing keys: %v ❌ ", err)
				}
			}

			cmd.Printf("Successfully generated public/private key pair of type: %s", KeyType)
			return nil
		},
	}
}

func generateAndWriteKeys(privKey any, pubKeyBytes []byte, keyType string) error {
	var b []byte
	var err error
	switch privKey := privKey.(type) {
	case *rsa.PrivateKey:
		b = x509.MarshalPKCS1PrivateKey(privKey)
	case *ecdsa.PrivateKey:
		b, err = x509.MarshalECPrivateKey(privKey)
	case ed25519.PrivateKey:
		b, err = x509.MarshalPKCS8PrivateKey(privKey)
	default:
		return fmt.Errorf("unsupported private key type")
	}
	if err != nil {
		return err
	}

	privFile, err := os.OpenFile(privateKeyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = privFile.Close()
		if !complete {
			_ = os.Remove(privateKeyFile)
		}
	}()
	if err := pem.Encode(privFile, &pem.Block{Type: keyType, Bytes: b}); err != nil {
		return err
	}
	if err := privFile.Close(); err != nil {
		return err
	}

	pubFile, err := os.OpenFile(publicKeyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		_ = pubFile.Close()
		if !complete {
			_ = os.Remove(publicKeyFile)
		}
	}()
	if err := pem.Encode(pubFile, &pem.Block{Type: publicKeyType, Bytes: pubKeyBytes}); err != nil {
		return err
	}
	if err := pubFile.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}
