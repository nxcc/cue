package source

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/decrypt"
)

// decryptSopsEncryptedData tries to transparently decrypt SOPS encrypted data
func decryptSopsEncryptedData(filenamne string, src io.Reader) (io.ReadCloser, error) {
	buffer := bytes.Buffer{}
	if _, err := io.Copy(&buffer, src); err != nil {
		return nil, fmt.Errorf("decryptSopsEncryptedData: copy: %w", err)
	}
	format, found := knownSopsFormats[filepath.Ext(filenamne)]
	if !found {
		format = formats.Binary
	}
	contents := buffer.Bytes()
	if !looksLikeSopsEncrypted(contents, format) {
		return io.NopCloser(bytes.NewReader(contents)), nil
	}
	cleartext, err := decrypt.DataWithFormat(contents, format)
	if err != nil && errors.Is(err, sops.MetadataNotFound) {
		return io.NopCloser(bytes.NewReader(contents)), nil
	}
	if err != nil {
		return nil, fmt.Errorf("decryptSopsEncryptedData: DataWithFormat: %w", err)
	}
	return io.NopCloser(bytes.NewReader(cleartext)), nil
}

var knownSopsFormats = map[string]formats.Format{
	".env":  formats.Dotenv,
	".json": formats.Json,
	".sops": formats.Binary,
	".yaml": formats.Yaml,
	".yml":  formats.Yaml,
}

var probeStringsJsonOrYamlOrBinary = []string{
	"sops", "version", "unencrypted_suffix", "lastmodified", "mac",
}

var probeStringsEnv = []string{
	"sops_version", "sops_unencrypted_suffix", "sops_lastmodified", "sops_mac",
}

func looksLikeSopsEncrypted(contents []byte, format formats.Format) bool {
	probes := probeStringsJsonOrYamlOrBinary
	if format == formats.Dotenv {
		probes = probeStringsEnv
	}
	allMatched := true
	for _, probe := range probes {
		allMatched = allMatched && bytes.Contains(contents, []byte(probe))
	}
	return allMatched
}
