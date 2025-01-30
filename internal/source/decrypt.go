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
	format, found := knownSopsFormats[filepath.Ext(filenamne)]
	if !found {
		return io.NopCloser(src), nil
	}
	buffer := bytes.Buffer{}
	if _, err := io.Copy(&buffer, src); err != nil {
		return nil, fmt.Errorf("decryptSopsEncryptedData: copy: %w", err)
	}
	cleartext, err := decrypt.DataWithFormat(buffer.Bytes(), format)
	if err != nil && errors.Is(err, sops.MetadataNotFound) {
		return io.NopCloser(bytes.NewReader(buffer.Bytes())), nil
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
