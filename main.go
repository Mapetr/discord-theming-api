package main

import (
	"log"
	"os"
	"os/exec"

	"github.com/gofiber/fiber/v3"
	"github.com/joho/godotenv"
)

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

	r2 := newR2Client()
	s := newServer(r2, bucket, jwtSecret, discordClientID, discordClientSecret, discordRedirectURI)

	app := fiber.New()
	s.setupRoutes(app)

	log.Println("[server] starting on :3000")
	if err := app.Listen(":3000"); err != nil {
		panic(err)
	}
}
