package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cache"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/utils/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
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

// avatarCache tracks which user IDs have uploaded avatars.
// true = avatar exists, false = checked R2 and not found.
// Unknown IDs are checked against R2 on demand and cached.
type avatarCache struct {
	mu    sync.RWMutex
	known map[string]bool // userId -> exists
}

func newAvatarCache() *avatarCache {
	return &avatarCache{
		known: make(map[string]bool),
	}
}

// markExists marks a user as having an avatar (called after successful upload).
func (ac *avatarCache) markExists(userID string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.known[userID] = true
	log.Printf("[avatar-cache] marked %s as exists", userID)
}

// lookup returns (exists, cached). If cached is false, the caller should check R2.
func (ac *avatarCache) lookup(userID string) (exists bool, cached bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	exists, cached = ac.known[userID]
	return
}

// setChecked caches the result of an R2 check for a user ID.
func (ac *avatarCache) setChecked(userID string, exists bool) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.known[userID] = exists
}

// checkR2 does a HeadObject to see if an avatar exists in R2 for the given user ID.
func checkR2(r2 *s3.Client, bucket, userID string) bool {
	_, err := r2.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String("avatars/" + userID),
	})
	return err == nil
}

// convertToAVIF writes the input to a temp file, converts it to AVIF via ImageMagick, and returns the result.
// Uses temp files so ImageMagick can properly handle animated WebP and other formats.
// Animated images (WebP, GIF) are preserved as animated AVIF (AVIS).
func convertToAVIF(input io.Reader, inputExt string) ([]byte, error) {
	log.Printf("[magick] starting AVIF conversion (input ext: %s)", inputExt)
	start := time.Now()

	// write input to a temp file so ImageMagick can read it properly
	tmpIn, err := os.CreateTemp("", "avatar-in-*"+inputExt)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp input file: %w", err)
	}
	defer os.Remove(tmpIn.Name())
	defer tmpIn.Close()

	written, err := io.Copy(tmpIn, input)
	if err != nil {
		return nil, fmt.Errorf("failed to write temp input file: %w", err)
	}
	tmpIn.Close()
	log.Printf("[magick] wrote %d bytes to temp input %s", written, tmpIn.Name())

	tmpOut, err := os.CreateTemp("", "avatar-out-*.avif")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp output file: %w", err)
	}
	defer os.Remove(tmpOut.Name())
	tmpOut.Close()

	// -coalesce expands animated frames so each is a full image (needed for proper animation conversion)
	// all frames are kept so the output AVIF is animated
	cmd := exec.Command("magick",
		tmpIn.Name(),
		"-coalesce",
		"-quality", "50",
		tmpOut.Name(),
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Printf("[magick] conversion failed: %v\n%s", err, stderr.String())
		return nil, fmt.Errorf("magick: %w: %s", err, stderr.String())
	}

	avifData, err := os.ReadFile(tmpOut.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read converted file: %w", err)
	}

	log.Printf("[magick] conversion complete in %s, output size: %d bytes", time.Since(start), len(avifData))
	return avifData, nil
}

func newR2Client() *s3.Client {
	accountID := os.Getenv("R2_ACCOUNT_ID")
	accessKey := os.Getenv("R2_ACCESS_KEY_ID")
	secretKey := os.Getenv("R2_SECRET_ACCESS_KEY")

	endpoint := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)
	log.Printf("[r2] initializing client, endpoint: %s", endpoint)

	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(endpoint),
		Region:       "auto",
		Credentials:  credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
	})

	log.Println("[r2] client initialized")
	return client
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

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("[config] no .env file found, using system environment")
	} else {
		log.Println("[config] loaded .env file")
	}

	bucket := os.Getenv("R2_BUCKET_NAME")
	if bucket == "" {
		log.Fatal("[config] R2_BUCKET_NAME is required")
	}
	log.Printf("[config] using bucket: %s", bucket)

	discordClientID := os.Getenv("DISCORD_CLIENT_ID")
	discordClientSecret := os.Getenv("DISCORD_CLIENT_SECRET")
	discordRedirectURI := os.Getenv("DISCORD_REDIRECT_URI")
	jwtSecret := os.Getenv("JWT_SECRET")

	if discordClientID == "" || discordClientSecret == "" || discordRedirectURI == "" || jwtSecret == "" {
		log.Fatal("[config] DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI, and JWT_SECRET are all required")
	}
	log.Printf("[config] Discord OAuth configured, redirect URI: %s", discordRedirectURI)

	pending := newPendingAuth()
	avatars := newAvatarCache()
	r2 := newR2Client()
	app := fiber.New()

	app.Use(func(c fiber.Ctx) error {
		start := time.Now()
		log.Printf("[http] --> %s %s | Origin: %s | Content-Type: %s | Authorization: %s | User-Agent: %s",
			c.Method(), c.OriginalURL(),
			c.Get("Origin"), c.Get("Content-Type"), c.Get("Authorization"), c.Get("User-Agent"))
		err := c.Next()
		log.Printf("[http] <-- %s %s %d %s", c.Method(), c.OriginalURL(), c.Response().StatusCode(), time.Since(start))
		return err
	})

	app.Use(cors.New(cors.Config{
		AllowOrigins: []string{"https://discord.com"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization"},
	}))

	app.Use(cache.New(cache.Config{
		ExpirationGenerator: func(c fiber.Ctx, cfg *cache.Config) time.Duration {
			newCacheTime, _ := strconv.Atoi(c.GetRespHeader("Cache-Time", "600"))
			return time.Second * time.Duration(newCacheTime)
		},
		KeyGenerator: func(c fiber.Ctx) string {
			return utils.CopyString(c.Path() + "?" + string(c.Request().URI().QueryString()))
		},
		Next: func(c fiber.Ctx) bool {
			// skip cache for auth routes and POST requests
			return strings.HasPrefix(c.Path(), "/auth") || c.Method() == "POST"
		},
	}))

	// GET /auth/discord?state=<state> — redirect to Discord OAuth2 authorize page.
	// The state param is generated by the client and passed through the entire flow.
	app.Get("/auth/discord", func(c fiber.Ctx) error {
		state := c.Query("state")
		if state == "" {
			log.Println("[auth] /auth/discord called without state param")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "state parameter is required",
			})
		}

		params := url.Values{
			"client_id":     {discordClientID},
			"redirect_uri":  {discordRedirectURI},
			"response_type": {"code"},
			"scope":         {"identify"},
			"state":         {state},
		}

		redirectURL := "https://discord.com/api/oauth2/authorize?" + params.Encode()
		log.Printf("[auth] redirecting to Discord OAuth (state: %s)", state)
		return c.Redirect().To(redirectURL)
	})

	// GET /auth/discord/callback — handle OAuth2 callback from Discord.
	// Exchanges the code, fetches user identity, creates a JWT, and stores it
	// in the pending map keyed by state for the client to poll.
	app.Get("/auth/discord/callback", func(c fiber.Ctx) error {
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

		accessToken, err := exchangeCode(code, discordClientID, discordClientSecret, discordRedirectURI)
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

		token, err := createJWT(userID, jwtSecret)
		if err != nil {
			log.Printf("[auth] JWT creation failed: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to create token",
			})
		}

		// store the token for the client to pick up via polling
		pending.set(state, token)

		log.Printf("[auth] auth complete for user %s (state: %s), token stored for polling", userID, state)
		c.Set("Content-Type", "text/html")
		return c.SendString(`<!DOCTYPE html>
<html><body>
<p>Login successful! You can close this tab and return to Discord.</p>
</body></html>`)
	})

	// GET /auth/token?state=<state> — polling endpoint for the client.
	// Returns { "token": "..." } once auth is complete, or 404 while pending.
	app.Get("/auth/token", func(c fiber.Ctx) error {
		state := c.Query("state")
		if state == "" {
			log.Println("[auth] /auth/token called without state param")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "state parameter is required",
			})
		}

		token, ok := pending.get(state)
		if !ok {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "pending",
			})
		}

		log.Printf("[auth] token retrieved for state %s", state)
		return c.JSON(fiber.Map{
			"token": token,
		})
	})

	// POST /avatars/check — batch check which user IDs have avatars.
	// Request body: { "ids": ["123", "456", "789"] }
	// Response: { "available": ["123", "789"] }
	app.Post("/avatars/check", func(c fiber.Ctx) error {
		var body struct {
			IDs []string `json:"ids"`
		}
		if err := c.Bind().JSON(&body); err != nil {
			log.Printf("[check] failed to parse request body: %v", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body, expected { \"ids\": [\"...\"] }",
			})
		}

		log.Printf("[check] checking %d user IDs", len(body.IDs))

		available := make([]string, 0)
		for _, id := range body.IDs {
			exists, cached := avatars.lookup(id)
			if !cached {
				// not in cache yet, check R2
				exists = checkR2(r2, bucket, id)
				avatars.setChecked(id, exists)
				log.Printf("[check] R2 lookup for %s: exists=%v", id, exists)
			}
			if exists {
				available = append(available, id)
			}
		}

		log.Printf("[check] %d/%d IDs have avatars", len(available), len(body.IDs))
		return c.JSON(fiber.Map{
			"available": available,
		})
	})

	app.Post("/avatars/:userId", func(c fiber.Ctx) error {
		userId := c.Params("userId")
		log.Printf("[upload] POST /avatars/%s - request received", userId)

		// verify JWT auth
		authHeader := c.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			log.Printf("[upload] user %s: missing or invalid Authorization header", userId)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authorization required",
			})
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		tokenUserID, err := verifyJWT(tokenString, jwtSecret)
		if err != nil {
			log.Printf("[upload] user %s: invalid token: %v", userId, err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired token",
			})
		}

		if tokenUserID != userId {
			log.Printf("[upload] user %s: token belongs to %s, rejecting", userId, tokenUserID)
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "you can only upload to your own profile",
			})
		}

		log.Printf("[upload] user %s: authenticated successfully", userId)

		file, err := c.FormFile("avatar")
		if err != nil {
			log.Printf("[upload] user %s: no avatar field in form: %v", userId, err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "avatar file is required",
			})
		}

		log.Printf("[upload] user %s: received file %q, size: %d bytes, content-type: %s",
			userId, file.Filename, file.Size, file.Header.Get("Content-Type"))

		key := "avatars/" + userId

		src, err := file.Open()
		if err != nil {
			log.Printf("[upload] user %s: failed to open multipart file: %v", userId, err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to read uploaded file",
			})
		}
		defer src.Close()

		//avifData, err := convertToAVIF(src, ext)
		//if err != nil {
		//	log.Printf("[upload] user %s: AVIF conversion failed: %v", userId, err)
		//	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		//		"error": "failed to convert image to AVIF",
		//	})
		//}

		log.Printf("[upload] user %s: uploading to R2 key %q", userId, key)
		_, err = r2.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket:      aws.String(bucket),
			Key:         aws.String(key),
			Body:        src,
			ContentType: aws.String("image/avif"),
		})
		if err != nil {
			log.Printf("[upload] user %s: R2 upload failed: %v", userId, err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to upload avatar to storage",
			})
		}

		// update the avatar cache so /avatars/check reflects this immediately
		avatars.markExists(userId)

		log.Printf("[upload] user %s: avatar uploaded successfully", userId)
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message": fmt.Sprintf("avatar uploaded for user %s", userId),
		})
	})

	log.Println("[server] starting on :3000")
	if err := app.Listen(":3000"); err != nil {
		panic(err)
	}
}
