// Command mmdb-trim rebuilds a GeoLite2-ASN database that only contains the
// networks of the ASNs listed in an allowlist file.
//
// The record layout (uint32 autonomous_system_number + string
// autonomous_system_organization) is preserved, so readers such as mihomo's
// IP-ASN rule keep working. The output is not deduplicated; run mmdbshrink
// afterwards to restore the size the original MaxMind file has.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/maxminddb-golang"
)

type asnRecord struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// loadAllowlist reads one ASN per line. "IP-ASN,13335", "AS13335" and
// "13335" are all accepted, so a mihomo/Clash rule list can be pasted as is.
// Blank lines and everything after '#' are ignored.
func loadAllowlist(path string) (map[uint]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	list := make(map[uint]bool)
	scanner := bufio.NewScanner(f)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// "IP-ASN,13335" and friends: keep whatever follows the last comma.
		if i := strings.LastIndexByte(line, ','); i >= 0 {
			line = strings.TrimSpace(line[i+1:])
		}
		line = strings.TrimPrefix(strings.ToUpper(line), "AS")
		n, err := strconv.ParseUint(line, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid ASN %q", path, lineNo, line)
		}
		list[uint(n)] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%s: allowlist is empty; refusing to emit a database without networks", path)
	}
	return list, nil
}

func main() {
	src := flag.String("src", "", "source GeoLite2-ASN.mmdb")
	dst := flag.String("dst", "", "output mmdb")
	allowlist := flag.String("allowlist", "", "file with the ASNs to keep, one per line")
	flag.Parse()

	if *src == "" || *dst == "" || *allowlist == "" {
		flag.Usage()
		log.Fatal("-src, -dst and -allowlist are required")
	}

	allow, err := loadAllowlist(*allowlist)
	if err != nil {
		log.Fatal(err)
	}

	db, err := maxminddb.Open(*src)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "GeoLite2-ASN",
		RecordSize:              24,
		IPVersion:               6,
		IncludeReservedNetworks: true,
		Languages:               []string{"en"},
		Description:             map[string]string{"en": "GeoLite2-ASN trimmed"},
	})
	if err != nil {
		log.Fatal(err)
	}

	var seenNetworks, keptNetworks int
	found := make(map[uint]bool)
	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var rec asnRecord
		network, err := networks.Network(&rec)
		if err != nil {
			log.Fatalf("decoding network: %v", err)
		}
		seenNetworks++
		if !allow[rec.Number] {
			continue
		}

		prefix, err := netip.ParsePrefix(network.String())
		if err != nil {
			log.Fatalf("parsing network %s: %v", network, err)
		}
		ipnet := &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		}
		value := mmdbtype.Map{
			"autonomous_system_number":       mmdbtype.Uint32(rec.Number),
			"autonomous_system_organization": mmdbtype.String(rec.Org),
		}
		if err := w.Insert(ipnet, value); err != nil {
			log.Fatalf("inserting %s: %v", network, err)
		}
		keptNetworks++
		found[rec.Number] = true
	}
	if err := networks.Err(); err != nil {
		log.Fatal(err)
	}

	if keptNetworks == 0 {
		log.Fatal("no network matched the allowlist; check the ASN numbers")
	}

	f, err := os.Create(*dst)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := w.WriteTo(f); err != nil {
		f.Close()
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}

	var missing []string
	for asn := range allow {
		if !found[asn] {
			missing = append(missing, fmt.Sprintf("AS%d", asn))
		}
	}
	fmt.Printf("source networks: %d\n", seenNetworks)
	fmt.Printf("kept networks:   %d (%d ASNs)\n", keptNetworks, len(found))
	if len(missing) > 0 {
		fmt.Printf("WARNING: allowlisted ASNs not present in source: %s\n", strings.Join(missing, ", "))
	}
	fmt.Printf("output: %s\n", *dst)
}
