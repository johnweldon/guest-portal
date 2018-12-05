package portal

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"time"
)

func NewGuestHandler(username, password, unifiBaseURL string, tmpl *template.Template) http.Handler {
	base, err := url.Parse(unifiBaseURL)
	if err != nil {
		panic(err)
	}

	cl, err := newClient()
	if err != nil {
		panic(err)
	}
	return &guestHandler{
		cl:       cl,
		username: username,
		password: password,
		unifiURL: base,
		tmpl:     tmpl,
		nonces:   nonceCache{},
	}
}

type guestHandler struct {
	cl       *http.Client
	tmpl     *template.Template
	username string
	password string
	unifiURL *url.URL
	nonces   nonceCache
}

func (h *guestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %s %q %s", r.RemoteAddr, r.Method, r.URL.String())
	switch r.Method {
	case "GET":
		h.handleGet(w, r)
	case "POST":
		h.handlePost(w, r)
	default:
		h.handleDefault(w, r)
	}
}

func (h *guestHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	login, err := parseForm(r)
	if err != nil {
		log.Printf("Error extracting form data: %v", err)
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	h.nonces.Set(login.Key(), login.Nonce)

	tmpl := h.tmpl.Lookup("default.html")
	if tmpl == nil {
		log.Printf("couldn't find template %q", "default.html")
		http.Error(w, "unexpected error", http.StatusInternalServerError)
		return
	}

	if err = tmpl.Execute(w, login); err != nil {
		log.Printf("Error rendering form: %v", err)
		http.Error(w, "unexpected error", http.StatusInternalServerError)
		return
	}
}

func (h *guestHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	login, err := parseForm(r)
	if err != nil {
		log.Printf("Error extracting form data: %v", err)
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	if !h.nonces.Valid(login.Key(), login.Nonce) {
		log.Println("Missing valid nonce, possible bypass attempt")
		http.Error(w, "suspicious login attempt", http.StatusUnauthorized)
		return
	}

	if err := h.loginUnifi(); err != nil {
		log.Printf("Error logging in to UniFi: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := h.authorizeGuest(login); err != nil {
		log.Printf("Error authorizing with UniFi: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer delete(h.nonces, login.Key())

	log.Printf("SUCCESSFUL login: redirect %q", login.Redirect)
	http.Redirect(w, r, login.Redirect.String(), http.StatusSeeOther)
}

func (h *guestHandler) handleDefault(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
}

func (h *guestHandler) loginUnifi() error {
	frm := loginForm{Username: h.username, Password: h.password, Strict: true}
	data, err := json.Marshal(frm)
	if err != nil {
		return err
	}

	loginURL, err := h.unifiURL.Parse("/api/login")
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", loginURL.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}

	resp, err := h.cl.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("not ok response: %v", resp.Status))
	}
	return nil
}

func (h *guestHandler) authorizeGuest(login *guestLogin) error {
	payload := cmd{Cmd: "authorize-guest", MAC: login.MAC, Minutes: 7 * 24 * 60}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	authURL, err := h.unifiURL.Parse("/api/s/default/cmd/stamgr")
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", authURL.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Add("content-type", "application/json;charset=UTF-8")

	for _, cookie := range h.cl.Jar.Cookies(authURL) {
		if cookie.Name == "csrf_token" {
			req.Header.Add("x-csrf-token", cookie.Value)
		}
	}

	resp, err := h.cl.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("login: unexpected response: %v", resp.Status))
	}
	return nil
}

func (h *guestHandler) listGuests() ([]guest, error) {
	staURL, err := h.unifiURL.Parse("/api/s/default/stat/sta")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", staURL.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.cl.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("listGuests: unexpected response: %v", resp.Status))
	}
	defer resp.Body.Close()
	packet := &guestPacket{}
	if err = json.NewDecoder(resp.Body).Decode(packet); err != nil {
		return nil, err
	}
	return packet.Data, nil
}

type loginForm struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
	Strict   bool   `json:"strict"`
}

type guestLogin struct {
	MAC      string
	AP       string
	SSID     string
	When     time.Time
	Redirect *url.URL
	Nonce    string
}

func (l guestLogin) Key() string {
	return fmt.Sprintf("%s:%s:%s:%d", l.MAC, l.AP, l.SSID, l.When.Unix())
}

func parseForm(r *http.Request) (*guestLogin, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	redir, err := url.Parse(r.Form.Get("url"))
	if err != nil {
		return nil, err
	}

	when, err := strconv.ParseInt(r.Form.Get("t"), 10, 64)
	if err != nil {
		return nil, err
	}

	nonce := r.Form.Get("nonce")
	if nonce == "" {
		data := [128]byte{}
		if _, err := rand.Read(data[:]); err != nil {
			return nil, err
		}
		nonce = base64.StdEncoding.EncodeToString(data[:])
	}

	return &guestLogin{
		MAC:      r.Form.Get("id"),
		AP:       r.Form.Get("ap"),
		SSID:     r.Form.Get("ssid"),
		When:     time.Unix(when, 0),
		Redirect: redir,
		Nonce:    nonce,
	}, nil
}

type guest struct {
	MAC       string `json:"mac"`
	Hostname  string `json:"hostname"`
	IP        string `json:"ip"`
	IsGuest   bool   `json:"is_guest"`
	IsWired   bool   `json:"is_wired"`
	ESSID     string `json:"essid"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

type guestPacket struct {
	Data []guest `json:"data"`
}

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &http.Client{Jar: jar}, nil
}

func noCache(w http.ResponseWriter) {
	w.Header().Set("Expires", Clock.HTTP(-1000*time.Hour))
	w.Header().Set("Last-Modified", Clock.HTTP(0))
	w.Header().Set("Cache-Control", "max-age=0, no-cache, must-revalidate, proxy-revalidate")
}

type cmd struct {
	Cmd     string `json:"cmd"`
	MAC     string `json:"mac"`
	Minutes int    `json:"minutes"`
}

type expireNonce struct {
	nonce string
	until int64
}

func newNonce(nonce string) expireNonce {
	until := Clock.Unix(10 * time.Minute)
	return expireNonce{nonce: nonce, until: until}
}

type nonceCache map[string][]expireNonce

func (c nonceCache) Valid(key, val string) bool {
	for _, n := range c.Get(key) {
		if n == val {
			return true
		}
	}
	return false
}

func (c nonceCache) Get(key string) []string {
	var nonces []string
	var fresh []expireNonce
	now := Clock.Unix(0)
	if l, ok := c[key]; ok {
		for _, n := range l {
			if n.until > now {
				nonces = append(nonces, n.nonce)
				fresh = append(fresh, n)
			}
		}
		c[key] = fresh
	}
	return nonces
}

func (c nonceCache) Set(key string, val string) {
	nonce := newNonce(val)
	c[key] = append(c[key], nonce)
}

func (c nonceCache) Purge() {
	for k := range c {
		c.Get(k)
	}
}
