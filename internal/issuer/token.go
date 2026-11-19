package issuer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Actor is one link of the RFC 8693 actor chain: who is acting for the subject. Act nests the actor's own
// actor (session -> agent -> launcher).
type Actor struct {
	Sub  string `json:"sub"`
	Kind string `json:"kind,omitempty"`
	Act  *Actor `json:"act,omitempty"`
}

// Depth is the length of the chain starting at a.
func (a *Actor) Depth() int {
	n := 0
	for ; a != nil; a = a.Act {
		n++
	}
	return n
}

// Claims is a Warden access token's payload. The names iss, sub, aud, scope, exp, nbf, jti, kind, sid and
// par are the ones libs/security/auth's JWTVerifier reads, so every resource server that already verifies
// Tether or Substrate identity tokens verifies Warden tokens unchanged. act and grant are new: resource
// servers that do not know them ignore them.
type Claims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aud"` // always one audience (RFC 8707 resource)
	Scope string `json:"scope"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Nbf   int64  `json:"nbf"`
	JTI   string `json:"jti"`
	Kind  string `json:"kind"`
	SID   string `json:"sid,omitempty"`
	// Par is the parent credential family the token was minted from (not a secret).
	Par   string `json:"par,omitempty"`
	Grant string `json:"grant,omitempty"`
	Act   *Actor `json:"act,omitempty"`
}

// Scopes splits the scope claim.
func (c Claims) Scopes() []string { return strings.Fields(c.Scope) }

// Sign signs c with the active key and returns the compact JWS and the key id.
func (ks *KeyStore) Sign(c Claims) (token, kid string, err error) {
	kid, priv := ks.Active()
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	pl, err := json.Marshal(c)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(pl)
	return signing + "." + enc.EncodeToString(ed25519.Sign(priv, []byte(signing))), kid, nil
}

// ErrInvalid is any token that does not verify. The reason is never shown to callers.
var ErrInvalid = errors.New("issuer: invalid token")

// Leeway is the clock skew allowed on exp and nbf.
const Leeway = 30 * time.Second

// Verify checks a token Warden issued: EdDSA, a published kid, the signature, the issuer and the time
// window. It does not check the audience or the deny-list; callers do (they know which audience they
// accept and hold the deny-list).
func (ks *KeyStore) Verify(token, iss string, now time.Time) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalid
	}
	enc := base64.RawURLEncoding
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "EdDSA" || hdr.Kid == "" {
		return Claims{}, ErrInvalid
	}
	pub, ok := ks.Public(hdr.Kid)
	if !ok {
		return Claims{}, ErrInvalid
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, ErrInvalid
	}
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalid
	}
	var c Claims
	if json.Unmarshal(pb, &c) != nil {
		return Claims{}, ErrInvalid
	}
	switch {
	case c.Iss != iss, c.Sub == "", c.JTI == "", c.Aud == "":
		return Claims{}, ErrInvalid
	case now.After(time.Unix(c.Exp, 0).Add(Leeway)):
		return Claims{}, ErrInvalid
	case c.Nbf != 0 && now.Add(Leeway).Before(time.Unix(c.Nbf, 0)):
		return Claims{}, ErrInvalid
	}
	return c, nil
}
