package cli

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/internal/pqc/signatures"
)

func newPQCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "pqc [command]",
		GroupID: groupInspect,
		Short:   "Post-Quantum Cryptographic model signing and verification (NIST FIPS 204/205)",
		Long: `Generate and verify quantum-resistant digital signatures for AI model weights,
AIBOM manifests, and training datasets using NIST FIPS 204 (ML-DSA / Dilithium)
and FIPS 205 (SLH-DSA / SPHINCS+). Protects model provenance against future quantum computer attacks.`,
	}

	cmd.AddCommand(newPQCSignCmd(), newPQCVerifyCmd())
	return cmd
}

func newPQCSignCmd() *cobra.Command {
	var schemeStr string
	var outFile string

	cmd := &cobra.Command{
		Use:   "sign <target-file>",
		Short: "Generate a post-quantum cryptographic signature for a model or file",
		Args:  exactArgs(1, "exactly one <target-file>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read target file %s: %w", path, err)
			}

			h := sha512.Sum512(data)
			digest := "sha3-512:" + hex.EncodeToString(h[:])

			engine := signatures.NewEngine()
			scheme := signatures.SchemeMLDSA87
			if schemeStr == "ml-dsa-44" {
				scheme = signatures.SchemeMLDSA44
			} else if schemeStr == "ml-dsa-65" {
				scheme = signatures.SchemeMLDSA65
			} else if schemeStr == "slh-dsa-128" {
				scheme = signatures.SchemeSLHDSA128
			}

			key, err := engine.GenerateKeyPair(scheme)
			if err != nil {
				return fmt.Errorf("generate PQC key: %w", err)
			}

			sig, err := engine.SignModel(key, digest)
			if err != nil {
				return fmt.Errorf("sign model digest: %w", err)
			}

			bundle := struct {
				Key       *signatures.PQCKeyPair   `json:"key"`
				Signature *signatures.PQCSignature `json:"signature"`
			}{
				Key:       key,
				Signature: sig,
			}

			outBytes, err := json.MarshalIndent(bundle, "", "  ")
			if err != nil {
				return err
			}

			if outFile == "" {
				outFile = path + ".pqc.json"
			}
			if err := os.WriteFile(outFile, outBytes, 0o644); err != nil {
				return fmt.Errorf("write signature bundle: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ Generated %s Post-Quantum Signature: %s\n", scheme, outFile)
			fmt.Fprintf(cmd.OutOrStdout(), "   Target File: %s\n", path)
			fmt.Fprintf(cmd.OutOrStdout(), "   SHA3-512:    %s\n", digest)
			fmt.Fprintf(cmd.OutOrStdout(), "   Signature ID:%s\n", sig.SignatureID)
			return nil
		},
	}

	cmd.Flags().StringVar(&schemeStr, "scheme", "ml-dsa-87", "PQC algorithm (ml-dsa-44, ml-dsa-65, ml-dsa-87, slh-dsa-128)")
	cmd.Flags().StringVarP(&outFile, "out", "O", "", "output signature file path (default: <target-file>.pqc.json)")

	return cmd
}

func newPQCVerifyCmd() *cobra.Command {
	var sigFile string

	cmd := &cobra.Command{
		Use:   "verify <target-file>",
		Short: "Verify a post-quantum cryptographic signature for a model or file",
		Args:  exactArgs(1, "exactly one <target-file>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			if sigFile == "" {
				sigFile = path + ".pqc.json"
			}

			sigBytes, err := os.ReadFile(sigFile)
			if err != nil {
				return fmt.Errorf("read signature file %s: %w", sigFile, err)
			}

			var bundle struct {
				Key       *signatures.PQCKeyPair   `json:"key"`
				Signature *signatures.PQCSignature `json:"signature"`
			}
			if err := json.Unmarshal(sigBytes, &bundle); err != nil {
				return fmt.Errorf("parse signature bundle: %w", err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read target file %s: %w", path, err)
			}
			h := sha512.Sum512(data)
			digest := "sha3-512:" + hex.EncodeToString(h[:])

			engine := signatures.NewEngine()
			verdict := engine.VerifySignature(bundle.Key, bundle.Signature, digest)

			if !verdict.Valid {
				return fmt.Errorf("❌ PQC Signature Verification FAILED: %s", verdict.Reason)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ Valid NIST FIPS 204/205 Quantum-Resistant Signature Verified!\n")
			fmt.Fprintf(cmd.OutOrStdout(), "   Scheme:      %s\n", verdict.Scheme)
			fmt.Fprintf(cmd.OutOrStdout(), "   Key ID:      %s\n", verdict.KeyID)
			fmt.Fprintf(cmd.OutOrStdout(), "   Status:      %s\n", verdict.Reason)
			return nil
		},
	}

	cmd.Flags().StringVarP(&sigFile, "sig", "s", "", "signature JSON file path (default: <target-file>.pqc.json)")

	return cmd
}
