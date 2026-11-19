//go:build !unix

package client

import "errors"

func lockFile(string) (func(), error) {
	return nil, errors.New("parent credential files need a unix host (advisory locks)")
}
