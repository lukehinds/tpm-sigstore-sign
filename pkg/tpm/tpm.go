package tpm

import (
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
)

// type realTPM struct {
// 	rwc io.ReadWriteCloser
// }

func TPMConn(tpmName string) (io.ReadWriteCloser, error) {
	rw, err := tpm2.OpenTPM(tpmName)
	if err != nil {
		return nil, fmt.Errorf("tpm2.OpenTPM(): %v", err)
	}
	return rw, nil
}