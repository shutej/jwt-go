package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// TimeFunc provides the current time when parsing token to validate "exp"
// claim (expiration time).  You can override it to use another time value.
// This is useful for testing or if your server uses a different time zone than
// your tokens.
var TimeFunc = time.Now

// Parse methods use this callback function to supply the key for verification.
// The function receives the parsed, but unverified Token.  This allows you to
// use propries in the Header of the token (such as `kid`) to identify which
// key to use.
type Keyfunc func(*Token) ([]byte, error)

type Header interface {
	Alg() (string, bool)
	Kid() (kid string, ok bool)
}

type Claims interface {
	Exp() (float64, bool)
	Nbf() (float64, bool)
}

// A JWT Token.  Different fields will be used depending on whether you're
// creating or parsing/verifying a token.
type Token struct {
	Raw       string        // The raw token.  Populated when you Parse a token
	Method    SigningMethod // The signing method used or to be used
	Header    Header        // The first segment of the token
	Claims    Claims        // The second segment of the token
	Signature string        // The third segment of the token.  Populated when you Parse a token
	Valid     bool          // Is the token valid?  Populated when you Parse/Verify a token
}

type HeaderMap map[string]interface{}

func (self *HeaderMap) Alg() (string, bool) {
	alg, ok := (*self)["alg"]
	if !ok {
		return "", false
	}
	switch retval := alg.(type) {
	case string:
		return retval, true
	default:
		return "", false
	}
}

func (self *HeaderMap) Kid() (string, bool) {
	kid, ok := (*self)["kid"]
	if !ok {
		return "", false
	}
	switch retval := kid.(type) {
	case string:
		return retval, true
	default:
		return "", false
	}
}

type ClaimsMap map[string]interface{}

func (self *ClaimsMap) Exp() (float64, bool) {
	exp, ok := (*self)["exp"]
	if !ok {
		return 0., false
	}
	switch retval := exp.(type) {
	case float64:
		return retval, true
	default:
		return 0., false
	}
}

func (self *ClaimsMap) Nbf() (float64, bool) {
	nbf, ok := (*self)["nbf"]
	if !ok {
		return 0., false
	}
	switch retval := nbf.(type) {
	case float64:
		return retval, true
	default:
		return 0., false
	}
}

func NewHeaderMap(method SigningMethod) *HeaderMap {
	return &HeaderMap{
		"typ": "JWT",
		"alg": method.Alg(),
	}
}

func New() *Token {
	return &Token{
		Header: &HeaderMap{},
		Claims: &ClaimsMap{},
	}
}

// Create a new Token.  Takes a signing method.
func NewWithSigningMethod(method SigningMethod) *Token {
	return &Token{
		Header: NewHeaderMap(method),
		Claims: &ClaimsMap{},
		Method: method,
	}
}

// Create a new Token.  Takes a signing method.
func NewWithClaims(method SigningMethod, claims Claims) *Token {
	return &Token{
		Header: NewHeaderMap(method),
		Claims: claims,
		Method: method,
	}
}

// Get the complete, signed token.
func (t *Token) SignedString(key []byte) (string, error) {
	var sig, sstr string
	var err error
	if sstr, err = t.SigningString(); err != nil {
		return "", err
	}
	if sig, err = t.Method.Sign(sstr, key); err != nil {
		return "", err
	}
	return strings.Join([]string{sstr, sig}, "."), nil
}

// Generate the signing string.  This is the most expensive part of the whole
// deal.  Unless you need this for something special, just go straight for the
// SignedString.
func (t *Token) SigningString() (string, error) {
	var err error
	parts := make([]string, 2)
	for i, _ := range parts {
		var source interface{}
		if i == 0 {
			source = t.Header
		} else {
			source = t.Claims
		}

		var jsonValue []byte
		if jsonValue, err = json.Marshal(source); err != nil {
			return "", err
		}

		parts[i] = EncodeSegment(jsonValue)
	}
	return strings.Join(parts, "."), nil
}

// Parse, validate, and return a token.  keyFunc will receive the parsed token
// and should return the key for validating.  If everything is kosher, err will
// be nil.
func (t *Token) Parse(tokenString string, keyFunc Keyfunc) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return &ValidationError{err: "Token contains an invalid number of segments", Errors: ValidationErrorMalformed}
	}

	var err error
	t.Raw = tokenString
	// parse Header
	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		return &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}
	if err = json.Unmarshal(headerBytes, t.Header); err != nil {
		return &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}

	// parse Claims
	var claimBytes []byte
	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}
	if err = json.Unmarshal(claimBytes, t.Claims); err != nil {
		return &ValidationError{err: err.Error(), Errors: ValidationErrorMalformed}
	}

	// Lookup signature method
	if method, ok := t.Header.Alg(); ok {
		if t.Method = GetSigningMethod(method); t.Method == nil {
			return &ValidationError{err: "Signing method (alg) is unavailable.", Errors: ValidationErrorUnverifiable}
		}
	} else {
		return &ValidationError{err: "Signing method (alg) is unspecified.", Errors: ValidationErrorUnverifiable}
	}

	// Lookup key
	var key []byte
	if key, err = keyFunc(t); err != nil {
		return &ValidationError{err: err.Error(), Errors: ValidationErrorUnverifiable}
	}

	// Check expiration times
	vErr := &ValidationError{}
	now := TimeFunc().Unix()
	if exp, ok := t.Claims.Exp(); ok {
		if now > int64(exp) {
			vErr.err = "Token is expired"
			vErr.Errors |= ValidationErrorExpired
		}
	}
	if nbf, ok := t.Claims.Nbf(); ok {
		if now < int64(nbf) {
			vErr.err = "Token is not valid yet"
			vErr.Errors |= ValidationErrorNotValidYet
		}
	}

	// Perform validation
	if err = t.Method.Verify(strings.Join(parts[0:2], "."), parts[2], key); err != nil {
		vErr.err = err.Error()
		vErr.Errors |= ValidationErrorSignatureInvalid
	}

	if vErr.valid() {
		t.Valid = true
		return nil
	}

	return vErr
}

// The errors that might occur when parsing and validating a token
const (
	ValidationErrorMalformed        uint32 = 1 << iota // Token is malformed
	ValidationErrorUnverifiable                        // Token could not be verified because of signing problems
	ValidationErrorSignatureInvalid                    // Signature validation failed
	ValidationErrorExpired                             // Exp validation failed
	ValidationErrorNotValidYet                         // NBF validation failed
)

// The error from Parse if token is not valid
type ValidationError struct {
	err    string
	Errors uint32 // bitfield.  see ValidationError... constants
}

// Validation error is an error type
func (e ValidationError) Error() string {
	if e.err == "" {
		return "Token is invalid"
	}
	return e.err
}

// No errors
func (e *ValidationError) valid() bool {
	if e.Errors > 0 {
		return false
	}
	return true
}

const jwtPrefix = "JWT "

// Try to find the token in an http.Request.
// This method will call ParseMultipartForm if there's no token in the header.
// Currently, it looks in the Authorization header as well as
// looking for an 'access_token' request parameter in req.Form.
func (t *Token) ParseFromRequest(req *http.Request, keyFunc Keyfunc) (err error) {

	// Look for an Authorization header
	if ah := req.Header.Get("Authorization"); ah != "" {
		// Should be a JWT token
		if len(ah) > len(jwtPrefix) && strings.ToUpper(ah[0:len(jwtPrefix)]) == jwtPrefix {
			return t.Parse(ah[len(jwtPrefix):], keyFunc)
		}
	}

	return errors.New("No token present in request.")
}

// Encode JWT specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// Decode JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
