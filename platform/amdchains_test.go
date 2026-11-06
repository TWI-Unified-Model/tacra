package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-sev-guest/verify/trust"
	"github.com/stretchr/testify/require"
)

// TestShippedAMDChains checks that the copies this Workload ships are the
// bundles go-sev-guest embeds, byte for byte, one per product line and key
// type, indexed by the issuer of the VCEK or VLEK.
func TestShippedAMDChains(t *testing.T) {
	chains, err := loadAMDChains("")
	require.NoError(t, err)
	for issuer, bundle := range map[string][]byte{
		"SEV-Milan": trust.AskArkMilanVcekBytes, "SEV-VLEK-Milan": trust.AskArkMilanVlekBytes,
		"SEV-Genoa": trust.AskArkGenoaVcekBytes, "SEV-VLEK-Genoa": trust.AskArkGenoaVlekBytes,
		"SEV-Turin": trust.AskArkTurinVcekBytes, "SEV-VLEK-Turin": trust.AskArkTurinVlekBytes,
	} {
		ch, ok := chains.chain(issuer)
		require.True(t, ok, issuer)
		raw, err := shippedAMDChains.ReadFile("amdchains/" + ch.file)
		require.NoError(t, err)
		require.Equal(t, bundle, raw, "%s differs from the bundle go-sev-guest embeds", ch.file)
		require.NotEmpty(t, ch.ask)
		require.NotEmpty(t, ch.ark)
	}
	require.Len(t, chains.byIssuer, 6)
	_, ok := chains.chain("SEV-Venice")
	require.False(t, ok)
}

// TestAMDChainsDirectory checks that a directory replaces the copies this
// Workload ships, and that a bad directory is refused with its reason.
func TestAMDChainsDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "turin.pem"), trust.AskArkTurinVlekBytes, 0o600))
	chains, err := loadAMDChains(dir)
	require.NoError(t, err)
	require.Len(t, chains.byIssuer, 1)
	_, ok := chains.chain("SEV-VLEK-Turin")
	require.True(t, ok)
	_, ok = chains.chain("SEV-Milan")
	require.False(t, ok, "the directory replaces the copies this Workload ships")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "again.pem"), trust.AskArkTurinVlekBytes, 0o600))
	_, err = loadAMDChains(dir)
	require.ErrorContains(t, err, `both hold the chain of "SEV-VLEK-Turin"`)

	bad := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bad, "x.pem"), []byte("not a chain"), 0o600))
	_, err = loadAMDChains(bad)
	require.ErrorContains(t, err, "x.pem")
	_, err = loadAMDChains(t.TempDir())
	require.ErrorContains(t, err, "no PEM file")
	_, err = loadAMDChains(filepath.Join(bad, "missing"))
	require.Error(t, err)
}
