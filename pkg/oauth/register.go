// Dynamic Client Registration (RFC 7591): the fallback when no client_id is
// configured and the authorization server lets clients register themselves.
// A static clientID stays first-class — Keycloak and authentik usually have
// DCR disabled (04-oauth.md).

package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/vmkteam/mcpurl/pkg/redact"
)

const (
	clientName     = "mcpurl" // what the authorization server shows on its consent/login page
	authMethodNone = "none"   // public client: no secret, PKCE protects the code exchange

	// clientLockPrefix keeps the registration lock apart from the token locks
	// sharing LockDir.
	clientLockPrefix = "client-"
)

var (
	// errNoClient: neither a configured client_id nor a stored registration.
	errNoClient = errors.New("no client_id")
	// errClientGone: the dynamic registration was dropped — Token runs one
	// more round, which registers anew.
	errClientGone = errors.New("client registration dropped")
	// errCorruptRegistration: the stored record is unreadable — logout drops it.
	errCorruptRegistration = errors.New("corrupt client registration")
)

// Registration is a client_id obtained by dynamic registration. It is not a
// secret — mcpurl registers public clients only — so it lives in a plain
// file, keyed by endpoint + redirect URI: the callback port is part of what
// the server registered.
type Registration struct {
	ClientID     string    `json:"client_id"`
	Issuer       string    `json:"issuer"`
	RedirectURI  string    `json:"redirect_uri"`
	RegisteredAt time.Time `json:"registered_at"`
}

// ClientStore keeps registrations as 0600 JSON files with atomic writes.
type ClientStore struct {
	Dir string // e.g. ~/.config/mcpurl/clients
}

func (s *ClientStore) path(key string) string { return filepath.Join(s.Dir, key+".json") }

func (s *ClientStore) Load(key string) (*Registration, error) {
	data, err := os.ReadFile(s.path(key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var r Registration
	if err := json.Unmarshal(data, &r); err != nil || r.ClientID == "" {
		return nil, fmt.Errorf("%w %s (`mcpurl logout` drops it)", errCorruptRegistration, s.path(key))
	}
	return &r, nil
}

func (s *ClientStore) Save(key string, r *Registration) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.Dir, key+".json", data)
}

func (s *ClientStore) Delete(key string) error {
	if err := os.Remove(s.path(key)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ClientsDir holds dynamic client registrations.
func ClientsDir() string { return filepath.Join(BaseDir(), "clients") }

func (f *Flow) clients() *ClientStore {
	if f.Clients != nil {
		return f.Clients
	}
	return &ClientStore{Dir: ClientsDir()}
}

// clientKey is the registration key: what the server registered is the
// redirect URI, so a different callback port is a different client.
func (f *Flow) clientKey(canonical string) string { return Key(canonical, f.redirectURI()) }

// clientID is the client_id in use: the configured one, else the dynamic
// registration resolved by resourceKey. Caller holds f.mu.
func (f *Flow) clientID() string {
	if f.ClientID != "" || f.reg == nil {
		return f.ClientID
	}
	return f.reg.ClientID
}

// ensureClient is resourceKey that registers the client first when no
// client_id is configured and none is stored yet. Caller holds f.mu.
func (f *Flow) ensureClient(ctx context.Context, challenge string) (canonical, key string, err error) {
	canonical, key, err = f.resourceKey()
	if !errors.Is(err, errNoClient) {
		return canonical, key, err
	}
	d, err := f.discover(ctx, challenge)
	if err != nil {
		return "", "", err
	}
	if d.AS.RegistrationEndpoint == "" {
		return "", "", fmt.Errorf("no client_id: set clientID in the profile — %s offers no dynamic client registration", d.AS.Issuer)
	}

	ck := f.clientKey(canonical)
	err = WithLock(ctx, f.lockDir(), clientLockPrefix+ck, func() error {
		// Another process may have registered while we waited for the lock.
		if reg, lerr := f.clients().Load(ck); lerr == nil && reg.Issuer == d.AS.Issuer {
			f.reg = reg
			return nil
		}
		reg, rerr := f.register(ctx, d)
		if rerr != nil {
			return rerr
		}
		if serr := f.clients().Save(ck, reg); serr != nil {
			return fmt.Errorf("persisting client registration: %w", serr)
		}
		f.reg = reg
		f.printf("Registered with %s as client %s.", d.AS.Issuer, reg.ClientID)
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return canonical, Key(canonical, f.clientID()), nil
}

// register obtains a client_id from the authorization server: a public
// client bound to the loopback redirect URI browserLogin listens on.
func (f *Flow) register(ctx context.Context, d *discovery) (*Registration, error) {
	endpoint := d.AS.RegistrationEndpoint
	if err := requireHTTPS(endpoint); err != nil {
		return nil, err
	}
	redirectURI := f.redirectURI()
	body, err := json.Marshal(map[string]any{
		"client_name":                clientName,
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", grantRefreshToken},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": authMethodNone,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := f.httpc().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var out struct {
		ClientID         string   `json:"client_id"`
		ClientSecret     string   `json:"client_secret"`
		RedirectURIs     []string `json:"redirect_uris"`
		Error            string   `json:"error"`
		ErrorDescription string   `json:"error_description"`
	}
	jerr := json.Unmarshal(data, &out)
	switch {
	case resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK:
		msg := fmt.Sprintf("client registration at %s: HTTP %d", endpoint, resp.StatusCode)
		if out.Error != "" {
			// error_description is free text from the server, like a challenge's.
			msg += " (" + redact.Tokens(out.Error+": "+out.ErrorDescription) + ")"
		}
		return nil, errors.New(msg)
	case jerr != nil:
		return nil, fmt.Errorf("client registration at %s: bad response: %w", endpoint, jerr)
	case out.ClientID == "":
		return nil, fmt.Errorf("client registration at %s: response has no client_id", endpoint)
	case out.ClientSecret != "":
		return nil, fmt.Errorf("client registration at %s issued a confidential client (client_secret): mcpurl registers public clients only — set clientID in the profile", endpoint)
	case len(out.RedirectURIs) > 0 && !slices.Contains(out.RedirectURIs, redirectURI):
		return nil, fmt.Errorf("client registration at %s: server registered redirect_uris %v instead of %s", endpoint, out.RedirectURIs, redirectURI)
	}
	f.debugf("registered client %s at %s", out.ClientID, endpoint)
	return &Registration{ClientID: out.ClientID, Issuer: d.AS.Issuer, RedirectURI: redirectURI, RegisteredAt: time.Now()}, nil
}

// foreignClient reports a dynamic registration made at another authorization
// server than the one discovery found: its client_id means nothing here.
func (f *Flow) foreignClient(d *discovery) bool {
	return f.ClientID == "" && f.reg != nil && f.reg.Issuer != d.AS.Issuer
}

// dropClient forgets a dynamic registration the authorization server does
// not accept, with the token issued to it, and answers errClientGone so that
// Token runs one more round — with a new registration. The stored record is
// deleted only while it is still the one this process used: another process
// may have replaced it already, and that one is good.
func (f *Flow) dropClient(ctx context.Context, canonical, key, why string) error {
	gone := f.reg
	f.warnf("dropping client registration %s (%s); registering anew", gone.ClientID, why)
	if err := f.Store.Delete(key); err != nil {
		f.debugf("deleting token of the dropped client: %v", err)
	}
	f.leaveClient()
	ck := f.clientKey(canonical)
	err := WithLock(ctx, f.lockDir(), clientLockPrefix+ck, func() error {
		if reg, lerr := f.clients().Load(ck); lerr == nil && reg.ClientID == gone.ClientID {
			return f.clients().Delete(ck)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return errClientGone
}

// clientReplaced reports that another process has dropped or replaced the
// dynamic registration this one holds — typically while this one waited for
// the token lock. Logging in with it would open the browser on a client_id
// the server no longer knows.
func (f *Flow) clientReplaced(canonical string) bool {
	if f.ClientID != "" || f.reg == nil {
		return false
	}
	reg, err := f.clients().Load(f.clientKey(canonical))
	return err != nil || reg.ClientID != f.reg.ClientID
}

// leaveClient forgets the dynamic registration in use with everything this
// process got from it. The tokens it issued say nothing about the next
// client: kept, they would read as "the server rejects even fresh tokens"
// and stop the login the next round owes.
func (f *Flow) leaveClient() {
	f.reg, f.cached = nil, nil
	f.lastRefreshed, f.lastLoggedIn = "", ""
}

// Registration returns the dynamic registration in use for the endpoint; nil
// when the client_id is configured or nothing is registered yet.
func (f *Flow) Registration() (*Registration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, _, err := f.resourceKey(); err != nil && !errors.Is(err, errNoClient) {
		return nil, err
	}
	if f.ClientID != "" {
		return nil, nil
	}
	return f.reg, nil
}

// Forget drops what is stored for the endpoint: the token and, for a dynamic
// client, the registration — the next login registers anew. That is also the
// way out when the server has forgotten the client: its authorization page
// then fails in the browser, out of mcpurl's sight. The token deletion is
// unconditional (an unreadable leftover must go too); the results report what
// there was to drop.
func (f *Flow) Forget() (token, registration bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	canonical, key, err := f.resourceKey()
	switch {
	case errors.Is(err, errNoClient):
		return false, false, nil // no client_id, so nothing was ever stored
	case errors.Is(err, errCorruptRegistration):
		// Without its client_id the token is out of reach, but the record is
		// what blocks every run — and logout is the way out the error names.
		return false, true, f.clients().Delete(f.clientKey(canonical))
	case err != nil:
		return false, false, err
	}
	// Load first only to decide what to report: Delete stays a no-op for an
	// empty store either way.
	_, loadErr := f.Store.Load(key)
	if err := f.Store.Delete(key); err != nil {
		return false, false, err
	}
	token = !errors.Is(loadErr, ErrNotFound)
	if f.reg != nil {
		if err := f.clients().Delete(f.clientKey(canonical)); err != nil {
			return token, false, err
		}
		f.leaveClient()
		registration = true
	}
	return token, registration, nil
}
