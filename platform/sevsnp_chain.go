package platform

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/trust"
)

// AMD's public product chains (ASK or ASVK, and ARK), as embedded in go-sev-guest, by product line and by the key
// that signs the report. The plug-in needs no network to supply them.
var amdChains = map[string][]byte{
	"Milan/VCEK": trust.AskArkMilanVcekBytes,
	"Milan/VLEK": trust.AskArkMilanVlekBytes,
	"Genoa/VCEK": trust.AskArkGenoaVcekBytes,
	"Genoa/VLEK": trust.AskArkGenoaVlekBytes,
	"Turin/VCEK": trust.AskArkTurinVcekBytes,
	"Turin/VLEK": trust.AskArkTurinVlekBytes,
}

// Certificate table GUIDs as the host writes them: go-sev-guest's abi
// constants, in hex without the dashes (see snpCertGUIDs).
var (
	guidVCEK = strings.ReplaceAll(abi.VcekGUID, "-", "")
	guidVLEK = strings.ReplaceAll(abi.VlekGUID, "-", "")
	guidASK  = strings.ReplaceAll(abi.AskGUID, "-", "") // also carries the ASVK of a VLEK chain
	guidARK  = strings.ReplaceAll(abi.ArkGUID, "-", "")
)

type certEntry struct {
	guid []byte
	cert []byte
}

// completeCertTable returns the host's certificate table with AMD's ASK (or ASVK) and ARK appended when the host
// left them out, as AWS does. The table is not covered by the report signature; the Verifier checks the chain up to
// the ARK it holds as trust anchor, so a wrong certificate here can only make the Evidence fail. added reports
// whether anything was appended. A table that already has both, or whose VCEK or VLEK is missing, unreadable or
// issued for a product line without an embedded chain, is returned unchanged for the Verifier to judge.
func completeCertTable(table []byte) (out []byte, added bool, err error) {
	entries, err := certTableEntries(table)
	if err != nil {
		return nil, false, err
	}
	have := map[string][]byte{}
	for _, e := range entries {
		have[hex.EncodeToString(e.guid)] = e.cert
	}
	if have[guidASK] != nil && have[guidARK] != nil {
		return table, false, nil
	}
	signer, kind := have[guidVCEK], "VCEK"
	if signer == nil {
		signer, kind = have[guidVLEK], "VLEK"
	}
	if signer == nil {
		return table, false, nil
	}
	leaf, err := trust.ParseCert(signer) // hosts write DER or PEM
	if err != nil {
		return table, false, nil
	}
	// The VCEK is issued by "SEV-<product>", the VLEK by "SEV-VLEK-<product>".
	cn := leaf.Issuer.CommonName
	if !strings.HasPrefix(cn, "SEV-") {
		return table, false, nil
	}
	chain, ok := amdChains[cn[strings.LastIndex(cn, "-")+1:]+"/"+kind]
	if !ok {
		return table, false, nil
	}
	ask, ark, err := kds.ParseProductCertChain(chain)
	if err != nil {
		return nil, false, err
	}
	for _, add := range []struct {
		guid string
		der  []byte
	}{{guidASK, ask}, {guidARK, ark}} {
		if have[add.guid] == nil {
			g, _ := hex.DecodeString(add.guid)
			entries = append(entries, certEntry{g, add.der})
			added = true
		}
	}
	return encodeCertTable(entries), added, nil
}

func certTableEntries(table []byte) ([]certEntry, error) {
	var entries []certEntry
	for i := 0; i+24 <= len(table); i += 24 {
		g := table[i : i+16]
		if bytes.Equal(g, make([]byte, 16)) {
			return entries, nil
		}
		off, n := binary.LittleEndian.Uint32(table[i+16:]), binary.LittleEndian.Uint32(table[i+20:])
		if uint64(off)+uint64(n) > uint64(len(table)) {
			return nil, fmt.Errorf("platform: certificate table entry %d out of range", i/24)
		}
		entries = append(entries, certEntry{append([]byte(nil), g...), append([]byte(nil), table[off:off+n]...)})
	}
	return nil, errors.New("platform: certificate table without terminator")
}

func encodeCertTable(entries []certEntry) []byte {
	off := uint32(24 * (len(entries) + 1))
	var head, body []byte
	for _, e := range entries {
		head = append(head, e.guid...)
		head = binary.LittleEndian.AppendUint32(head, off+uint32(len(body)))
		head = binary.LittleEndian.AppendUint32(head, uint32(len(e.cert)))
		body = append(body, e.cert...)
	}
	head = append(head, make([]byte, 24)...)
	return append(head, body...)
}
