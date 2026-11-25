package container

import (
	"crypto/hpke"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSealThenOpen(t *testing.T) {
	notExportable := false
	content := Content{
		CredentialItems: []Item{{
			Type:       "jwt",
			Format:     "compact",
			Value:      base64.RawURLEncoding.EncodeToString([]byte("header.payload.signature")),
			Kid:        "0123456789abcdef",
			Purpose:    []string{"authenticate"},
			Algorithm:  "ES256",
			Exportable: &notExportable,
		}},
		Metadata: map[string]any{"validity_seconds": 3600},
	}
	aad := AAD{GroupID: "group", Target: B64("https://server.example"), Handle: B64("0123456789abcdef0123456789abcdef"), CredentialHint: "hint"}

	mlkem, mlkemPub, err := GenerateCEK()
	require.NoError(t, err)
	p256, p256Pub, err := GenerateCEKP256()
	require.NoError(t, err)
	p256CEK, err := DHKEMPrivateKey(p256)
	require.NoError(t, err)

	for _, tt := range []struct {
		name   string
		cek    hpke.PrivateKey
		cekPub []byte
		suite  Suite
	}{
		{name: "MLKEM768-P256", cek: mlkem, cekPub: mlkemPub, suite: SuiteMLKEM768P256},
		{name: "DHKEM(P-256, HKDF-SHA256)", cek: p256CEK, cekPub: p256Pub, suite: SuiteDHKEMP256},
	} {
		t.Run(tt.name, func(t *testing.T) {
			suite, err := SuiteOfCEKPub(tt.cekPub)
			require.NoError(t, err)
			require.Equal(t, tt.suite, suite)

			sealed, err := Seal(tt.cekPub, aad, content)
			require.NoError(t, err)
			require.Equal(t, ContainerBase, sealed.Container)
			require.Equal(t, tt.suite, sealed.Suite)
			require.Nil(t, sealed.Origin)

			expect := Expect{Target: "https://server.example", Handle: aad.Handle, CredentialHint: "hint", CEK: tt.cek, CEKPub: tt.cekPub}
			opened, err := Open(sealed, expect)
			require.NoError(t, err)
			require.NoError(t, CheckItems(opened, false, 3600))
			require.Len(t, opened.CredentialItems, 1)
			octets, err := ItemOctets(opened.CredentialItems[0])
			require.NoError(t, err)
			require.Equal(t, "header.payload.signature", string(octets))

			// A container for another Target, another freshness element or another Credential Hint does not open.
			for _, other := range []Expect{
				{Target: "https://other.example", Handle: aad.Handle, CredentialHint: "hint", CEK: tt.cek},
				{Target: "https://server.example", Handle: []byte("another freshness element......."), CredentialHint: "hint", CEK: tt.cek},
				{Target: "https://server.example", Handle: aad.Handle, CredentialHint: "other", CEK: tt.cek},
			} {
				_, err := Open(sealed, other)
				require.ErrorIs(t, err, ErrAAD)
			}

			// A container whose associated data was changed after sealing does not open.
			changed := *sealed
			changed.AAD.GroupID = "another group"
			_, err = Open(&changed, expect)
			require.Error(t, err)

			// A Workload that requires origin authentication refuses this container.
			expect.RequireOrigin = true
			_, err = Open(sealed, expect)
			require.ErrorIs(t, err, ErrOriginRequired)
		})
	}
}

func TestSealRefusesOtherKeys(t *testing.T) {
	_, err := Seal([]byte("not a key"), AAD{Target: B64("t")}, Content{})
	require.ErrorIs(t, err, ErrCEKPub)
	_, err = SuiteOfCEKPub([]byte("not a key"))
	require.ErrorIs(t, err, ErrCEKPub)
}
