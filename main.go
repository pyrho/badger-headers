package badgerheaders

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Config struct {
	APIBaseUrl                  string `json:"apiBaseUrl"`
	UserSessionCookieName       string `json:"userSessionCookieName"`
	ResourceSessionRequestParam string `json:"resourceSessionRequestParam"`
}

type Badger struct {
	next                        http.Handler
	name                        string
	apiBaseUrl                  string
	userSessionCookieName       string
	resourceSessionRequestParam string
}

type VerifyBody struct {
	Sessions           map[string]string `json:"sessions"`
	OriginalRequestURL string            `json:"originalRequestURL"`
	RequestScheme      *string           `json:"scheme"`
	RequestHost        *string           `json:"host"`
	RequestPath        *string           `json:"path"`
	RequestMethod      *string           `json:"method"`
	TLS                bool              `json:"tls"`
	RequestIP          *string           `json:"requestIp,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	Query              map[string]string `json:"query,omitempty"`
}

type VerifyResponse struct {
	Data struct {
		Valid           bool              `json:"valid"`
		RedirectURL     *string           `json:"redirectUrl"`
		Username        *string           `json:"username,omitempty"`
		Email           *string           `json:"email,omitempty"`
		Name            *string           `json:"name,omitempty"`
		ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
	} `json:"data"`
}

type ExchangeSessionBody struct {
	RequestToken *string `json:"requestToken"`
	RequestHost  *string `json:"host"`
	RequestIP    *string `json:"requestIp,omitempty"`
}

type ExchangeSessionResponse struct {
	Data struct {
		Valid           bool              `json:"valid"`
		Cookie          *string           `json:"cookie"`
		ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
	} `json:"data"`
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Badger{
		next:                        next,
		name:                        name,
		apiBaseUrl:                  config.APIBaseUrl,
		userSessionCookieName:       config.UserSessionCookieName,
		resourceSessionRequestParam: config.ResourceSessionRequestParam,
	}, nil
}

func (p *Badger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cookies := p.extractCookies(req)

	queryValues := req.URL.Query()

	if sessionRequestValue := queryValues.Get(p.resourceSessionRequestParam); sessionRequestValue != "" {
		body := ExchangeSessionBody{
			RequestToken: &sessionRequestValue,
			RequestHost:  &req.Host,
			RequestIP:    &req.RemoteAddr,
		}

		jsonData, err := json.Marshal(body)
		if err != nil {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		verifyURL := fmt.Sprintf("%s/badger/exchange-session", p.apiBaseUrl)
		resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		var result ExchangeSessionResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if result.Data.Cookie != nil && *result.Data.Cookie != "" {
			rw.Header().Add("Set-Cookie", *result.Data.Cookie)

			queryValues.Del(p.resourceSessionRequestParam)
			cleanedQuery := queryValues.Encode()
			originalRequestURL := fmt.Sprintf("%s://%s%s", p.getScheme(req), req.Host, req.URL.Path)
			if cleanedQuery != "" {
				originalRequestURL = fmt.Sprintf("%s?%s", originalRequestURL, cleanedQuery)
			}

			if result.Data.ResponseHeaders != nil {
				for key, value := range result.Data.ResponseHeaders {
					rw.Header().Add(key, value)
				}
			}

			fmt.Println("Got exchange token, redirecting to", originalRequestURL)
			http.Redirect(rw, req, originalRequestURL, http.StatusFound)
			return
		}
	}

	cleanedQuery := queryValues.Encode()
	originalRequestURL := fmt.Sprintf("%s://%s%s", p.getScheme(req), req.Host, req.URL.Path)
	if cleanedQuery != "" {
		originalRequestURL = fmt.Sprintf("%s?%s", originalRequestURL, cleanedQuery)
	}

	verifyURL := fmt.Sprintf("%s/badger/verify-session", p.apiBaseUrl)

	headers := make(map[string]string)
	for name, values := range req.Header {
		if len(values) > 0 {
			headers[name] = values[0] // Send only the first value for simplicity
		}
	}

	queryParams := make(map[string]string)
	for key, values := range queryValues {
		if len(values) > 0 {
			queryParams[key] = values[0]
		}
	}

	cookieData := VerifyBody{
		Sessions:           cookies,
		OriginalRequestURL: originalRequestURL,
		RequestScheme:      &req.URL.Scheme,
		RequestHost:        &req.Host,
		RequestPath:        &req.URL.Path,
		RequestMethod:      &req.Method,
		TLS:                req.TLS != nil,
		RequestIP:          &req.RemoteAddr,
		Headers:            headers,
		Query:              queryParams,
	}

	jsonData, err := json.Marshal(cookieData)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError) // TODO: redirect to error page
		return
	}

	resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for _, setCookie := range resp.Header["Set-Cookie"] {
		rw.Header().Add("Set-Cookie", setCookie)
	}

	if resp.StatusCode != http.StatusOK {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var result VerifyResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if result.Data.ResponseHeaders != nil {
		for key, value := range result.Data.ResponseHeaders {
			rw.Header().Add(key, value)
		}
	}

	if result.Data.RedirectURL != nil && *result.Data.RedirectURL != "" {
		fmt.Println("Badger: Redirecting to", *result.Data.RedirectURL)
		http.Redirect(rw, req, *result.Data.RedirectURL, http.StatusFound)
		return
	}

	if result.Data.Valid {

		if result.Data.Username != nil {
			req.Header.Add("Remote-User", *result.Data.Username)
		}

		if result.Data.Email != nil {
			req.Header.Add("Remote-Email", *result.Data.Email)
		}

		if result.Data.Name != nil {
			req.Header.Add("Remote-Name", *result.Data.Name)
		}

		fmt.Println("Badger: Valid session")
		req.Header.Add("X-BadgerHeaders-Version", "0.0.12")
		p.next.ServeHTTP(rw, req)
		return
	}

	http.Error(rw, "Unauthorized", http.StatusUnauthorized)
}

func (p *Badger) extractCookies(req *http.Request) map[string]string {
	cookies := make(map[string]string)
	isSecureRequest := req.TLS != nil

	for _, cookie := range req.Cookies() {
		if strings.HasPrefix(cookie.Name, p.userSessionCookieName) {
			if cookie.Secure && !isSecureRequest {
				continue
			}
			cookies[cookie.Name] = cookie.Value
		}
	}

	return cookies
}

func (p *Badger) getScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	return "http"
}
