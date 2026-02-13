package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	"github.com/gofiber/fiber/v3/middleware/limiter"
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
// Positive entries (avatar exists) are persisted to a file and loaded on startup.
// Negative entries (checked R2, not found) are in-memory only.
type avatarCache struct {
	mu       sync.RWMutex
	known    map[string]bool // userId -> exists
	filePath string
}

func newAvatarCache(filePath string) *avatarCache {
	ac := &avatarCache{
		known:    make(map[string]bool),
		filePath: filePath,
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[avatar-cache] no cache file at %s, starting empty", filePath)
		} else {
			log.Printf("[avatar-cache] failed to read cache file %s: %v", filePath, err)
		}
		return ac
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		id := strings.TrimSpace(line)
		if id != "" {
			ac.known[id] = true
		}
	}
	log.Printf("[avatar-cache] loaded %d user IDs from %s", len(ac.known), filePath)

	return ac
}

// markExists marks a user as having an avatar (called after successful upload).
// Persists the ID to disk if it wasn't already cached.
func (ac *avatarCache) markExists(userID string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if ac.known[userID] {
		return
	}

	ac.known[userID] = true

	f, err := os.OpenFile(ac.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[avatar-cache] failed to open cache file for append: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(userID + "\n"); err != nil {
		log.Printf("[avatar-cache] failed to write user ID to cache file: %v", err)
		return
	}

	log.Printf("[avatar-cache] marked %s as exists (persisted)", userID)
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

// detectFormat identifies the image/video format from magic bytes.
// Returns "png", "jpg", "gif", "webp", "webp-anim", "avif", "mp4", or error.
func detectFormat(data []byte) (string, error) {
	if len(data) < 32 {
		return "", fmt.Errorf("data too short for format detection (%d bytes)", len(data))
	}

	// PNG: \x89PNG\r\n\x1a\n
	if data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G' &&
		data[4] == 0x0D && data[5] == 0x0A && data[6] == 0x1A && data[7] == 0x0A {
		return "png", nil
	}

	// JPEG: \xFF\xD8\xFF
	if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return "jpg", nil
	}

	// GIF: "GIF87a" or "GIF89a"
	if string(data[0:3]) == "GIF" && (string(data[3:6]) == "87a" || string(data[3:6]) == "89a") {
		return "gif", nil
	}

	// WebP: RIFF at 0, WEBP at 8
	if string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP" {
		// check for animation: VP8X chunk at offset 12, animation flag at byte 20 bit 1
		if string(data[12:16]) == "VP8X" && len(data) > 20 {
			if data[20]&0x02 != 0 {
				return "webp-anim", nil
			}
		}
		return "webp", nil
	}

	// ISOBMFF container (AVIF and MP4): "ftyp" at offset 4
	if string(data[4:8]) == "ftyp" {
		brand := string(data[8:12])
		switch brand {
		case "avif", "avis", "mif1":
			return "avif", nil
		case "isom", "mp41", "mp42", "M4V ", "M4A ", "f4v ", "kddi", "mp71":
			return "mp4", nil
		default:
			// some MP4 files use other brands
			if strings.HasPrefix(brand, "mp4") {
				return "mp4", nil
			}
		}
	}

	return "", fmt.Errorf("unsupported format (magic bytes: %x)", data[:16])
}

// convertToAVIF routes the input data to the appropriate converter based on format.
func convertToAVIF(input []byte, format string) ([]byte, error) {
	log.Printf("[convert] converting %d bytes, format=%s", len(input), format)
	start := time.Now()

	var result []byte
	var err error

	switch format {
	case "avif":
		log.Printf("[convert] AVIF passthrough, no conversion needed")
		return input, nil
	case "png", "jpg", "webp":
		result, err = convertStaticToAVIF(input, format)
	case "gif":
		result, err = convertGIFToAVIF(input)
	case "webp-anim":
		result, err = convertAnimatedWebPToAVIF(input)
	case "mp4":
		result, err = convertMP4ToAVIF(input)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		return nil, err
	}

	log.Printf("[convert] done in %s, output=%d bytes", time.Since(start), len(result))
	return result, nil
}

// convertStaticToAVIF converts a static image (PNG, JPG, static WebP) to a still AVIF.
func convertStaticToAVIF(input []byte, ext string) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "avif-static-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	inPath := filepath.Join(tmpDir, "input."+ext)
	outPath := filepath.Join(tmpDir, "output.avif")

	if err := os.WriteFile(inPath, input, 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp input: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ffmpeg", "-y",
		"-i", inPath,
		"-c:v", "libaom-av1",
		"-crf", "30",
		"-still-picture", "1",
		outPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	log.Printf("[ffmpeg] running: ffmpeg -y -i input.%s -c:v libaom-av1 -crf 30 -still-picture 1 output.avif", ext)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg static conversion failed: %w: %s", err, stderr.String())
	}

	return os.ReadFile(outPath)
}

// convertGIFToAVIF converts a GIF (static or animated) to AVIF using ffmpeg.
// Uses -vsync vfr to preserve original per-frame timing and yuva420p for transparency.
func convertGIFToAVIF(input []byte) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "avif-gif-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	inPath := filepath.Join(tmpDir, "input.gif")
	outPath := filepath.Join(tmpDir, "output.avif")

	if err := os.WriteFile(inPath, input, 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp input: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// GIF uses pal8 with 1-bit transparency. We need to:
	// 1. Decode to rgba to get proper alpha channel
	// 2. Use yuva420p to preserve alpha in output
	// 3. Use vfr to preserve per-frame timing
	cmd := exec.CommandContext(ctx, "ffmpeg", "-y",
		"-i", inPath,
		"-vf", "format=rgba",
		"-c:v", "libaom-av1",
		"-crf", "30",
		"-pix_fmt", "yuva420p",
		"-vsync", "vfr",
		outPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	log.Printf("[ffmpeg] converting GIF to AVIF (rgba→yuva420p + vfr)")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg GIF conversion failed: %w: %s", err, stderr.String())
	}

	return os.ReadFile(outPath)
}

// parseWebPFrameDurations parses the animated WebP binary format and extracts
// per-frame durations from ANMF chunks. Returns one duration per frame.
func parseWebPFrameDurations(data []byte) ([]time.Duration, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("data too short for WebP")
	}

	var durations []time.Duration
	// skip RIFF header (12 bytes: "RIFF" + size + "WEBP")
	pos := 12

	for pos+8 <= len(data) {
		tag := string(data[pos : pos+4])
		chunkSize := int(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		chunkDataStart := pos + 8

		if tag == "ANMF" {
			// ANMF chunk data layout:
			// bytes 0-2: X offset (3 bytes LE)
			// bytes 3-5: Y offset (3 bytes LE)
			// bytes 6-8: width-1  (3 bytes LE)
			// bytes 9-11: height-1 (3 bytes LE)
			// bytes 12-14: duration in ms (3 bytes LE, 24-bit uint)
			// byte 15: flags
			if chunkSize >= 16 && chunkDataStart+15 <= len(data) {
				durMs := uint32(data[chunkDataStart+12]) |
					uint32(data[chunkDataStart+13])<<8 |
					uint32(data[chunkDataStart+14])<<16
				dur := time.Duration(durMs) * time.Millisecond
				// clamp 0ms to 100ms (same convention as GIF)
				if dur == 0 {
					dur = 100 * time.Millisecond
				}
				durations = append(durations, dur)
			}
		}

		// advance to next chunk (chunks are padded to even size)
		advance := 8 + chunkSize
		if chunkSize%2 != 0 {
			advance++
		}
		pos += advance
	}

	if len(durations) == 0 {
		return nil, fmt.Errorf("no ANMF chunks found in WebP")
	}

	log.Printf("[webp-parse] found %d frames, durations: %v", len(durations), durations)
	return durations, nil
}

// writeFFmpegConcatFile creates an ffmpeg concat demuxer file with per-frame durations.
func writeFFmpegConcatFile(concatPath string, frameFiles []string, durations []time.Duration) error {
	var buf bytes.Buffer
	buf.WriteString("ffconcat version 1.0\n")

	for i, name := range frameFiles {
		buf.WriteString(fmt.Sprintf("file '%s'\n", name))
		if i < len(durations) {
			// duration in seconds as a decimal
			buf.WriteString(fmt.Sprintf("duration %.3f\n", durations[i].Seconds()))
		}
	}

	return os.WriteFile(concatPath, buf.Bytes(), 0644)
}

// convertAnimatedWebPToAVIF converts an animated WebP to animated AVIF using anim_dump + ffmpeg.
func convertAnimatedWebPToAVIF(input []byte) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "avif-anim-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	inPath := filepath.Join(tmpDir, "input.webp")
	framesDir := filepath.Join(tmpDir, "frames")
	outPath := filepath.Join(tmpDir, "output.avif")

	if err := os.Mkdir(framesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create frames dir: %w", err)
	}

	if err := os.WriteFile(inPath, input, 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp input: %w", err)
	}

	// Step 1: extract frames with anim_dump
	ctx1, cancel1 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel1()

	dumpCmd := exec.CommandContext(ctx1, "anim_dump", "-folder", framesDir, "-prefix", "frame", inPath)
	var dumpStdout, dumpStderr bytes.Buffer
	dumpCmd.Stdout = &dumpStdout
	dumpCmd.Stderr = &dumpStderr

	log.Printf("[anim_dump] extracting frames from animated WebP")
	if err := dumpCmd.Run(); err != nil {
		return nil, fmt.Errorf("anim_dump failed: %w: %s", err, dumpStderr.String())
	}
	log.Printf("[anim_dump] output: %s", dumpStdout.String())

	// list extracted frames to determine the pattern
	entries, err := os.ReadDir(framesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read frames dir: %w", err)
	}

	var frameFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".png") {
			frameFiles = append(frameFiles, e.Name())
		}
	}

	if len(frameFiles) == 0 {
		return nil, fmt.Errorf("anim_dump produced no frames")
	}

	sort.Strings(frameFiles)
	log.Printf("[anim_dump] extracted %d frames, first=%s last=%s", len(frameFiles), frameFiles[0], frameFiles[len(frameFiles)-1])

	// rename frames to sequential numbering for ffmpeg
	for i, name := range frameFiles {
		oldPath := filepath.Join(framesDir, name)
		newPath := filepath.Join(framesDir, fmt.Sprintf("frame_%04d.png", i+1))
		if oldPath != newPath {
			if err := os.Rename(oldPath, newPath); err != nil {
				return nil, fmt.Errorf("failed to rename frame %s: %w", name, err)
			}
		}
	}

	// parse per-frame durations from the WebP binary
	durations, durErr := parseWebPFrameDurations(input)
	if durErr != nil {
		log.Printf("[anim_dump] could not parse frame durations: %v, falling back to 100ms/frame", durErr)
		durations = make([]time.Duration, len(frameFiles))
		for i := range durations {
			durations[i] = 100 * time.Millisecond
		}
	}

	// if frame count mismatch, distribute total duration evenly
	if len(durations) != len(frameFiles) {
		log.Printf("[anim_dump] duration count (%d) != frame count (%d), redistributing evenly", len(durations), len(frameFiles))
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		perFrame := total / time.Duration(len(frameFiles))
		if perFrame < 10*time.Millisecond {
			perFrame = 100 * time.Millisecond
		}
		durations = make([]time.Duration, len(frameFiles))
		for i := range durations {
			durations[i] = perFrame
		}
	}

	// build renamed frame file list for the concat file
	renamedFrames := make([]string, len(frameFiles))
	for i := range frameFiles {
		renamedFrames[i] = fmt.Sprintf("frame_%04d.png", i+1)
	}

	// Step 2: write concat demuxer file with per-frame durations
	concatPath := filepath.Join(framesDir, "concat.txt")
	if err := writeFFmpegConcatFile(concatPath, renamedFrames, durations); err != nil {
		return nil, fmt.Errorf("failed to write concat file: %w", err)
	}

	// Step 3: encode frames to animated AVIF with ffmpeg using concat demuxer
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()

	cmd := exec.CommandContext(ctx2, "ffmpeg", "-y",
		"-f", "concat",
		"-safe", "0",
		"-i", concatPath,
		"-c:v", "libaom-av1",
		"-crf", "30",
		"-pix_fmt", "yuv420p",
		"-vsync", "vfr",
		outPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	log.Printf("[ffmpeg] encoding %d frames to animated AVIF with per-frame timing", len(frameFiles))
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg animated conversion failed: %w: %s", err, stderr.String())
	}

	return os.ReadFile(outPath)
}

// convertMP4ToAVIF converts an MP4 video to animated AVIF.
func convertMP4ToAVIF(input []byte) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "avif-mp4-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	inPath := filepath.Join(tmpDir, "input.mp4")
	outPath := filepath.Join(tmpDir, "output.avif")

	if err := os.WriteFile(inPath, input, 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp input: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ffmpeg", "-y",
		"-i", inPath,
		"-c:v", "libaom-av1",
		"-crf", "30",
		"-pix_fmt", "yuv420p",
		"-an",
		outPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	log.Printf("[ffmpeg] converting MP4 to animated AVIF")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg MP4 conversion failed: %w: %s", err, stderr.String())
	}

	return os.ReadFile(outPath)
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

	// verify required CLI tools are available
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		log.Fatal("[config] ffmpeg not found on PATH — required for AVIF conversion")
	}
	log.Println("[config] ffmpeg found")

	if _, err := exec.LookPath("anim_dump"); err != nil {
		log.Fatal("[config] anim_dump not found on PATH — required for animated WebP conversion (install libwebp-tools)")
	}
	log.Println("[config] anim_dump found")

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
	avatars := newAvatarCache("avatars.txt")
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

	app.Use(limiter.New(limiter.Config{
		Next: func(c fiber.Ctx) bool {
			return c.IP() == "127.0.0.1"
		},
		Max:        30,
		Expiration: 5 * time.Minute,
	}))

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

		data, err := io.ReadAll(src)
		if err != nil {
			log.Printf("[upload] user %s: failed to read file bytes: %v", userId, err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to read uploaded file",
			})
		}
		log.Printf("[upload] user %s: read %d bytes from upload", userId, len(data))

		format, err := detectFormat(data)
		if err != nil {
			log.Printf("[upload] user %s: unsupported format: %v", userId, err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "unsupported file format — accepted: PNG, JPG, GIF, WebP, AVIF, MP4",
			})
		}
		log.Printf("[upload] user %s: detected format=%s", userId, format)

		avifData, err := convertToAVIF(data, format)
		if err != nil {
			log.Printf("[upload] user %s: AVIF conversion failed: %v", userId, err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to convert image to AVIF",
			})
		}

		log.Printf("[upload] user %s: uploading %d bytes to R2 key %q", userId, len(avifData), key)
		_, err = r2.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket:      aws.String(bucket),
			Key:         aws.String(key),
			Body:        bytes.NewReader(avifData),
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
