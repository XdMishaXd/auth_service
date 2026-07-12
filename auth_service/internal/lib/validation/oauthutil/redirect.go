package oauthutil

import (
	"errors"
	"net/url"
)

var (
	ErrRedirectURIRequired = errors.New("redirect_uri is required")
	ErrRedirectURIInvalid  = errors.New("redirect_uri is not a valid URL")
	ErrRedirectURIScheme   = errors.New("redirect_uri must use https")
	ErrRedirectURIHost     = errors.New("redirect_uri host is not allowed")
)

func ValidateRedirectURI(raw string, allowedHosts map[string]bool) (string, error) {
	if raw == "" {
		return "", ErrRedirectURIRequired
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", ErrRedirectURIInvalid
	}

	if u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost") {
		return "", ErrRedirectURIScheme
	}

	if !allowedHosts[u.Hostname()] {
		return "", ErrRedirectURIHost
	}

	return raw, nil
}
