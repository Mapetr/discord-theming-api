package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
)

// pendingAuth stores tokens keyed by the client-generated state parameter.
// Entries are created by the OAuth callback and consumed by the polling endpoint.
type pendingAuth struct {
	mu      sync.Mutex
	tokens  map[string]string    // state -> JWT
	created map[string]time.Time // state -> creation time (for cleanup)
}

func newPendingAuth() *pendingAuth {
	pa := &pendingAuth{
		tokens:  make(map[string]string),
		created: make(map[string]time.Time),
	}
	go pa.cleanup()
	return pa
}

func (pa *pendingAuth) set(state, token string) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	pa.tokens[state] = token
	pa.created[state] = time.Now()
	log.Printf("[auth] stored token for state %s", state)
}

func (pa *pendingAuth) get(state string) (string, bool) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	token, ok := pa.tokens[state]
	if ok {
		// consume the token so it can only be retrieved once
		delete(pa.tokens, state)
		delete(pa.created, state)
		log.Printf("[auth] consumed token for state %s", state)
	}
	return token, ok
}

// cleanup removes stale pending tokens every minute (tokens older than 5 minutes).
func (pa *pendingAuth) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		pa.mu.Lock()
		now := time.Now()
		for state, created := range pa.created {
			if now.Sub(created) > 5*time.Minute {
				delete(pa.tokens, state)
				delete(pa.created, state)
				log.Printf("[auth] cleaned up expired state %s", state)
			}
		}
		pa.mu.Unlock()
	}
}

// exchangeCode exchanges an OAuth2 authorization code for a Discord access token.
func exchangeCode(code, clientID, clientSecret, redirectURI string) (string, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	log.Printf("[auth] exchanging code for token (redirect_uri: %s)", redirectURI)
	resp, err := http.PostForm("https://discord.com/api/oauth2/token", data)
	if err != nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[auth] token exchange failed: status %d, body: %s", resp.StatusCode, string(body))
		return "", fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	log.Println("[auth] token exchange successful")
	return tokenResp.AccessToken, nil
}

// fetchDiscordUser fetches the authenticated user's info from Discord.
func fetchDiscordUser(accessToken string) (string, error) {
	req, err := http.NewRequest("GET", "https://discord.com/api/users/@me", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	log.Println("[auth] fetching Discord user info")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[auth] user fetch failed: status %d, body: %s", resp.StatusCode, string(body))
		return "", fmt.Errorf("user fetch failed with status %d", resp.StatusCode)
	}

	var user struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("failed to decode user response: %w", err)
	}

	log.Printf("[auth] fetched Discord user: %s", user.ID)
	return user.ID, nil
}

// createJWT creates a signed JWT with the Discord user ID as the subject.
func createJWT(userID, secret string) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	log.Printf("[auth] created JWT for user %s", userID)
	return signed, nil
}

// verifyJWT parses and validates a JWT, returning the subject (Discord user ID).
func verifyJWT(tokenString, secret string) (string, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", err
	}

	sub, err := token.Claims.GetSubject()
	if err != nil {
		return "", fmt.Errorf("missing subject in token: %w", err)
	}

	return sub, nil
}

// handleAuthRedirect redirects to Discord OAuth2 authorize page.
// GET /auth/discord?state=<state>
func (s *server) handleAuthRedirect(c fiber.Ctx) error {
	state := c.Query("state")
	if state == "" {
		log.Println("[auth] /auth/discord called without state param")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "state parameter is required",
		})
	}

	params := url.Values{
		"client_id":     {s.discordClientID},
		"redirect_uri":  {s.discordRedirectURI},
		"response_type": {"code"},
		"scope":         {"identify"},
		"state":         {state},
	}

	redirectURL := "https://discord.com/api/oauth2/authorize?" + params.Encode()
	log.Printf("[auth] redirecting to Discord OAuth (state: %s)", state)
	return c.Redirect().To(redirectURL)
}

// handleAuthCallback handles OAuth2 callback from Discord.
// Exchanges the code, fetches user identity, creates a JWT, and stores it
// in the pending map keyed by state for the client to poll.
// GET /auth/discord/callback
func (s *server) handleAuthCallback(c fiber.Ctx) error {
	code := c.Query("code")
	state := c.Query("state")

	log.Printf("[auth] callback received (state: %s)", state)

	if state == "" {
		log.Println("[auth] callback missing state")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "missing state parameter",
		})
	}

	if code == "" {
		log.Println("[auth] callback missing code")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "missing authorization code",
		})
	}

	accessToken, err := exchangeCode(code, s.discordClientID, s.discordClientSecret, s.discordRedirectURI)
	if err != nil {
		log.Printf("[auth] code exchange failed: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to exchange code",
		})
	}

	userID, err := fetchDiscordUser(accessToken)
	if err != nil {
		log.Printf("[auth] user fetch failed: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to fetch user",
		})
	}

	token, err := createJWT(userID, s.jwtSecret)
	if err != nil {
		log.Printf("[auth] JWT creation failed: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to create token",
		})
	}

	// store the token for the client to pick up via polling
	s.pending.set(state, token)

	log.Printf("[auth] auth complete for user %s (state: %s), token stored for polling", userID, state)
	c.Set("Content-Type", "text/html")
	return c.SendString(`<!DOCTYPE html>
<html><body>
<p>Login successful! You can close this tab and return to Discord.</p>
</body></html>`)
}

// handleAuthToken is the polling endpoint for the client.
// Returns { "token": "..." } once auth is complete, or 404 while pending.
// GET /auth/token?state=<state>
func (s *server) handleAuthToken(c fiber.Ctx) error {
	state := c.Query("state")
	if state == "" {
		log.Println("[auth] /auth/token called without state param")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "state parameter is required",
		})
	}

	token, ok := s.pending.get(state)
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "pending",
		})
	}

	log.Printf("[auth] token retrieved for state %s", state)
	return c.JSON(fiber.Map{
		"token": token,
	})
}
