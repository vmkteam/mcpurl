package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRedirectURI = "http://127.0.0.1:18075/callback"

// register is the fake AS side of RFC 7591: public clients only, every
// registration a new client_id — or the canned answer when one is set.
func (f *fakeAS) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RedirectURIs []string `json:"redirect_uris"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case f.registerBody != "":
		w.WriteHeader(f.registerStatus)
		w.Write([]byte(f.registerBody))
		return
	case r.Method != http.MethodPost, json.NewDecoder(r.Body).Decode(&in) != nil, len(in.RedirectURIs) == 0, in.AuthMethod != "none":
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_client_metadata"}`))
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	id := fmt.Sprintf("dyn-%d", f.registrations.Add(1))
	f.clients[id] = true
	f.redirectURIs = in.RedirectURIs
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"client_id": id, "redirect_uris": in.RedirectURIs, "token_endpoint_auth_method": "none"})
}

// answer makes the fake AS offer registration and reply to it verbatim.
func answer(status int, body string) func(*fakeAS) {
	return func(as *fakeAS) { as.dcr, as.registerStatus, as.registerBody = true, status, body }
}

// forgetClients is the server losing its registrations (a reset base).
func (f *fakeAS) forgetClients() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clients = map[string]bool{}
}

// newDCRFlow is a Flow with no client_id: it has to register.
func newDCRFlow(t *testing.T, as *fakeAS, dir string, logins *atomic.Int32) *Flow {
	f := newTestFlow(t, as, dir)
	f.ClientID = ""
	f.loginFn = func(context.Context, *discovery, []string) (*Token, error) {
		n := logins.Add(1)
		return &Token{AccessToken: fmt.Sprintf("login-access-%d", n), RefreshToken: "refresh-0",
			Expiry: time.Now().Add(time.Hour)}, nil
	}
	return f
}

func loadRegistration(t *testing.T, dir, endpoint string) *Registration {
	t.Helper()
	canonical, err := Canonicalize(endpoint)
	require.NoError(t, err)
	reg, err := (&ClientStore{Dir: dir + "/clients"}).Load(Key(canonical, testRedirectURI))
	if err != nil {
		require.ErrorIs(t, err, ErrNotFound)
		return nil
	}
	return reg
}

// The first run registers once and persists it; a second process reuses the
// registration and the token issued to it — no new client, no new login.
func TestDynamicRegistration(t *testing.T) {
	as := newFakeAS(t)
	as.dcr = true
	dir := t.TempDir()
	var logins atomic.Int32
	f1 := newDCRFlow(t, as, dir, &logins)

	tok, err := f1.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "login-access-1", tok)
	assert.EqualValues(t, 1, as.registrations.Load())
	assert.Equal(t, []string{testRedirectURI}, as.redirectURIs, "the loopback callback is what gets registered")

	reg := loadRegistration(t, dir, f1.Endpoint)
	require.NotNil(t, reg)
	assert.Equal(t, "dyn-1", reg.ClientID)
	assert.Equal(t, as.srv.URL, reg.Issuer)
	assert.Equal(t, testRedirectURI, reg.RedirectURI)

	canonical, _ := Canonicalize(f1.Endpoint)
	stored, err := f1.Store.Load(Key(canonical, "dyn-1"))
	require.NoError(t, err, "the token is keyed by the registered client_id")
	assert.Equal(t, "dyn-1", stored.ClientID)

	f2 := newDCRFlow(t, as, dir, &logins)
	tok, err = f2.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "login-access-1", tok)
	assert.EqualValues(t, 1, as.registrations.Load(), "the registration is reused")
	assert.EqualValues(t, 1, logins.Load(), "and so is the token")

	// Another callback port is another redirect URI — another client.
	f3 := newDCRFlow(t, as, dir, &logins)
	f3.CallbackPort = 19000
	_, err = f3.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.EqualValues(t, 2, as.registrations.Load())
	assert.Equal(t, []string{"http://127.0.0.1:19000/callback"}, as.redirectURIs)
}

// Two processes starting together (Claude Desktop + Cursor) register once
// and log in once: the registration lock and the token lock serialize them.
func TestDynamicRegistrationRace(t *testing.T) {
	as := newFakeAS(t)
	as.dcr = true
	dir := t.TempDir()
	var logins atomic.Int32
	flows := []*Flow{newDCRFlow(t, as, dir, &logins), newDCRFlow(t, as, dir, &logins)}

	var wg sync.WaitGroup
	errs := make(chan error, len(flows))
	for _, f := range flows {
		wg.Go(func() {
			if _, err := f.Token(context.Background(), "", ""); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.EqualValues(t, 1, as.registrations.Load())
	assert.EqualValues(t, 1, logins.Load())
}

// A server that forgot the client answers the refresh with invalid_client:
// mcpurl drops the registration with its token, registers anew and logs in
// once — instead of failing until someone deletes files by hand.
func TestReRegisterWhenClientForgotten(t *testing.T) {
	as := newFakeAS(t)
	as.dcr = true
	dir := t.TempDir()
	var logins atomic.Int32
	_, err := newDCRFlow(t, as, dir, &logins).Token(context.Background(), "", "")
	require.NoError(t, err)

	// Expire the stored token so the next process has to refresh it.
	canonical, _ := Canonicalize(newTestFlow(t, as, dir).Endpoint)
	oldKey := Key(canonical, "dyn-1")
	store := &FileStore{Dir: dir + "/tokens"}
	require.NoError(t, store.Save(oldKey, &Token{AccessToken: "access-0", RefreshToken: "refresh-0",
		Expiry: time.Now().Add(-time.Minute), ClientID: "dyn-1"}))
	as.forgetClients()

	var warnings []string
	f := newDCRFlow(t, as, dir, &logins)
	f.Warnf = func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }
	tok, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "login-access-2", tok)
	assert.EqualValues(t, 2, as.registrations.Load())
	assert.Equal(t, "dyn-2", loadRegistration(t, dir, f.Endpoint).ClientID)
	_, err = store.Load(oldKey)
	require.ErrorIs(t, err, ErrNotFound, "the dropped client's token goes with it")
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "invalid_client", "the operator learns why")
}

// The same in a bridge that logged in itself: its login token, rejected as
// expired once the server forgot the client, belongs to the dropped client —
// it must not read as "the server rejects fresh tokens" and stop the one
// login the new registration needs.
func TestReRegisterAfterOwnLogin(t *testing.T) {
	as := newFakeAS(t)
	as.dcr = true
	var logins atomic.Int32
	f := newDCRFlow(t, as, t.TempDir(), &logins)
	tok, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)
	as.forgetClients()

	tok, err = f.Token(context.Background(), tok, `Bearer error="invalid_token", error_description="token expired"`)
	require.NoError(t, err)
	assert.Equal(t, "login-access-2", tok)
	assert.EqualValues(t, 2, as.registrations.Load())
	assert.EqualValues(t, 2, logins.Load())
}

// Two bridges share a registration the server forgot. The one that drops it
// registers anew and logs in; the other, waiting on the same token lock,
// must follow the new registration — not open a second browser window on a
// client_id the server no longer knows.
func TestReRegisterFollowedByOtherProcess(t *testing.T) {
	as := newFakeAS(t)
	as.dcr = true
	dir := t.TempDir()
	var logins atomic.Int32
	first, second := newDCRFlow(t, as, dir, &logins), newDCRFlow(t, as, dir, &logins)
	tok, err := first.Token(context.Background(), "", "")
	require.NoError(t, err)
	_, err = second.Token(context.Background(), "", "")
	require.NoError(t, err, "the second bridge picks up dyn-1 and its token")

	canonical, _ := Canonicalize(first.Endpoint)
	require.NoError(t, first.Store.Save(Key(canonical, "dyn-1"), &Token{AccessToken: tok, RefreshToken: "refresh-0",
		Expiry: time.Now().Add(-time.Minute)}))
	as.forgetClients()
	const expired = `Bearer error="invalid_token", error_description="token expired"`

	tok1, err := first.Token(context.Background(), tok, expired)
	require.NoError(t, err)
	tok2, err := second.Token(context.Background(), tok, expired)
	require.NoError(t, err)
	assert.Equal(t, "login-access-2", tok1)
	assert.Equal(t, tok1, tok2, "the second bridge reuses the first one's login")
	assert.EqualValues(t, 2, logins.Load())
	assert.EqualValues(t, 2, as.registrations.Load())
	assert.Equal(t, "dyn-2", second.clientID())
}

// invalid_client for a configured client_id is the operator's to fix: no
// substitute gets registered, the refusal is reported as it came.
func TestInvalidStaticClient(t *testing.T) {
	as := newFakeAS(t)
	as.dcr = true // its token endpoint knows no "test-client"
	dir := t.TempDir()
	var logins atomic.Int32
	f := newDCRFlow(t, as, dir, &logins)
	f.ClientID = "test-client"
	seedToken(t, f)

	_, err := f.Token(context.Background(), "", "")
	require.ErrorContains(t, err, "token refresh: token endpoint HTTP 401 (invalid_client)")
	assert.Zero(t, as.registrations.Load())
	assert.Nil(t, loadRegistration(t, dir, f.Endpoint))
	assert.Zero(t, logins.Load())
}

// A registration made at another authorization server (the endpoint moved
// to a new AS) is replaced, not presented to the new one.
func TestForeignRegistrationReplaced(t *testing.T) {
	as := newFakeAS(t)
	as.dcr = true
	dir := t.TempDir()
	var logins atomic.Int32
	f := newDCRFlow(t, as, dir, &logins)
	canonical, _ := Canonicalize(f.Endpoint)
	require.NoError(t, f.clients().Save(Key(canonical, testRedirectURI),
		&Registration{ClientID: "old-client", Issuer: "https://old.example.com", RedirectURI: testRedirectURI}))
	oldKey := Key(canonical, "old-client")
	require.NoError(t, f.Store.Save(oldKey, &Token{AccessToken: "old-access", RefreshToken: "old-refresh",
		Expiry: time.Now().Add(-time.Minute)}))

	tok, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "login-access-1", tok)
	assert.Zero(t, as.refreshCalls.Load(), "the old client's refresh token never reaches the new AS")
	reg := loadRegistration(t, dir, f.Endpoint)
	assert.Equal(t, "dyn-1", reg.ClientID)
	assert.Equal(t, as.srv.URL, reg.Issuer)
	_, err = f.Store.Load(oldKey)
	require.ErrorIs(t, err, ErrNotFound)
}

// `mcpurl login` takes the same path: register when needed, replace a
// foreign registration.
func TestLoginRegisters(t *testing.T) {
	as := newFakeAS(t)
	as.dcr = true
	dir := t.TempDir()
	var logins atomic.Int32
	f := newDCRFlow(t, as, dir, &logins)
	f.Endpoint = as.srv.URL + "/mcp" // the challenge probe stays local
	canonical, _ := Canonicalize(f.Endpoint)
	require.NoError(t, f.clients().Save(Key(canonical, testRedirectURI),
		&Registration{ClientID: "old-client", Issuer: "https://old.example.com", RedirectURI: testRedirectURI}))

	tok, err := f.Login(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "dyn-1", tok.ClientID)
	assert.Equal(t, "dyn-1", loadRegistration(t, dir, f.Endpoint).ClientID)
	assert.EqualValues(t, 1, logins.Load())
}

// Every registration answer mcpurl cannot use is refused with its reason,
// before anything is persisted or a browser opens.
func TestRegistrationRefusals(t *testing.T) {
	const jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0"
	tests := []struct {
		name  string
		setup func(as *fakeAS)
		want  []string // in the error
		hide  string   // never in the error
	}{
		{name: "no registration endpoint", setup: func(*fakeAS) {},
			want: []string{"clientID", "no dynamic client registration"}},
		{name: "plain http endpoint", setup: func(as *fakeAS) { as.registrationURL = "http://dcr.example.com/register" },
			want: []string{"is not https"}},
		{name: "confidential client", setup: answer(http.StatusCreated, `{"client_id":"c-1","client_secret":"s3cret"}`),
			want: []string{"client_secret", "clientID"}, hide: "s3cret"},
		{name: "other redirect_uris", setup: answer(http.StatusCreated, `{"client_id":"c-1","redirect_uris":["https://evil.example/cb"]}`),
			want: []string{"https://evil.example/cb", "instead of " + testRedirectURI}},
		{name: "no client_id", setup: answer(http.StatusCreated, `{"redirect_uris":["`+testRedirectURI+`"]}`),
			want: []string{"no client_id"}},
		{name: "not JSON", setup: answer(http.StatusCreated, `<html>`),
			want: []string{"bad response"}},
		{name: "OAuth error", setup: answer(http.StatusBadRequest, `{"error":"invalid_redirect_uri","error_description":"loopback not allowed"}`),
			want: []string{"HTTP 400", "invalid_redirect_uri: loopback not allowed"}},
		{name: "OAuth error quoting a token", setup: answer(http.StatusUnauthorized, `{"error":"invalid_token","error_description":"initial access token `+jwt+` expired"}`),
			want: []string{"HTTP 401", "invalid_token: initial access token"}, hide: jwt},
		{name: "error page", setup: answer(http.StatusNotFound, `<html>Not Found</html>`),
			want: []string{"HTTP 404"}, hide: "<html>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := newFakeAS(t)
			tt.setup(as)
			dir := t.TempDir()
			var logins atomic.Int32
			f := newDCRFlow(t, as, dir, &logins)

			_, err := f.Token(context.Background(), "", "")
			require.Error(t, err)
			for _, w := range tt.want {
				assert.Contains(t, err.Error(), w)
			}
			if tt.hide != "" {
				assert.NotContains(t, err.Error(), tt.hide)
			}
			assert.Nil(t, loadRegistration(t, dir, f.Endpoint), "nothing is persisted")
			assert.Zero(t, logins.Load(), "no browser without a client")
		})
	}
}

// Lenient where it costs nothing: 200 in place of 201, and an answer that
// skips the metadata echo RFC 7591 §3.2.1 asks for.
func TestRegistrationLenientAnswers(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"200 OK", http.StatusOK, `{"client_id":"c-ok","redirect_uris":["` + testRedirectURI + `"]}`},
		{"no redirect_uris echo", http.StatusCreated, `{"client_id":"c-ok"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as := newFakeAS(t)
			answer(tt.status, tt.body)(as)
			dir := t.TempDir()
			var logins atomic.Int32
			f := newDCRFlow(t, as, dir, &logins)

			_, err := f.Token(context.Background(), "", "")
			require.NoError(t, err)
			reg := loadRegistration(t, dir, f.Endpoint)
			require.NotNil(t, reg)
			assert.Equal(t, "c-ok", reg.ClientID)
			assert.Equal(t, testRedirectURI, reg.RedirectURI)
			assert.EqualValues(t, 1, logins.Load())
		})
	}
}

// Forget (logout) drops the token and the registration of a dynamic client;
// a static client's leftovers in the registration store are not its to drop.
func TestForget(t *testing.T) {
	as := newFakeAS(t)
	as.dcr = true
	dir := t.TempDir()
	var logins atomic.Int32
	f := newDCRFlow(t, as, dir, &logins)
	_, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)

	reg, err := newDCRFlow(t, as, dir, &logins).Registration()
	require.NoError(t, err)
	require.NotNil(t, reg)
	assert.Equal(t, "dyn-1", reg.ClientID)

	token, registration, err := newDCRFlow(t, as, dir, &logins).Forget()
	require.NoError(t, err)
	assert.True(t, token)
	assert.True(t, registration)
	assert.Nil(t, loadRegistration(t, dir, f.Endpoint))
	reg, err = newDCRFlow(t, as, dir, &logins).Registration()
	require.NoError(t, err)
	assert.Nil(t, reg)

	token, registration, err = newDCRFlow(t, as, dir, &logins).Forget()
	require.NoError(t, err)
	assert.False(t, token, "nothing left to report")
	assert.False(t, registration)

	// Static client: its token goes, the registration file stays.
	static := newTestFlow(t, as, dir)
	seedToken(t, static)
	canonical, _ := Canonicalize(static.Endpoint)
	require.NoError(t, static.clients().Save(Key(canonical, testRedirectURI),
		&Registration{ClientID: "dyn-9", Issuer: as.srv.URL, RedirectURI: testRedirectURI}))
	reg, err = static.Registration()
	require.NoError(t, err)
	assert.Nil(t, reg, "a configured client_id wins")
	token, registration, err = static.Forget()
	require.NoError(t, err)
	assert.True(t, token)
	assert.False(t, registration)
	assert.NotNil(t, loadRegistration(t, dir, static.Endpoint))
}

// An unreadable registration stops every run with a pointer to logout, and
// logout drops it: the next run registers anew.
func TestForgetCorruptRegistration(t *testing.T) {
	for _, body := range []string{"", "{", "{}", `{"client_id":""}`} {
		t.Run(fmt.Sprintf("%q", body), func(t *testing.T) {
			as := newFakeAS(t)
			as.dcr = true
			dir := t.TempDir()
			var logins atomic.Int32
			f := newDCRFlow(t, as, dir, &logins)
			canonical, _ := Canonicalize(f.Endpoint)
			require.NoError(t, os.MkdirAll(dir+"/clients", 0o700))
			require.NoError(t, os.WriteFile(f.clients().path(Key(canonical, testRedirectURI)), []byte(body), 0o600))

			_, err := f.Token(context.Background(), "", "")
			require.ErrorContains(t, err, "`mcpurl logout` drops it")

			token, registration, err := newDCRFlow(t, as, dir, &logins).Forget()
			require.NoError(t, err)
			assert.False(t, token, "its token is out of reach without the client_id")
			assert.True(t, registration)

			tok, err := newDCRFlow(t, as, dir, &logins).Token(context.Background(), "", "")
			require.NoError(t, err)
			assert.Equal(t, "login-access-1", tok)
			assert.EqualValues(t, 1, as.registrations.Load())
		})
	}
}
