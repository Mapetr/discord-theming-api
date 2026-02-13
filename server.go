package main

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/contrib/v3/websocket"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cache"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/utils/v2"
)

type server struct {
	r2                  *s3.Client
	bucket              string
	jwtSecret           string
	discordClientID     string
	discordClientSecret string
	discordRedirectURI  string
	pending             *pendingAuth
	avatars             *avatarCache
	banners             *avatarCache
	hub                 *wsHub
}

func newServer(r2 *s3.Client, bucket, jwtSecret, discordClientID, discordClientSecret, discordRedirectURI string) *server {
	pending := newPendingAuth()
	avatars := newAvatarCache("avatars.txt")
	banners := newAvatarCache("banners.txt")
	hub := newWSHub()

	s := &server{
		r2:                  r2,
		bucket:              bucket,
		jwtSecret:           jwtSecret,
		discordClientID:     discordClientID,
		discordClientSecret: discordClientSecret,
		discordRedirectURI:  discordRedirectURI,
		pending:             pending,
		avatars:             avatars,
		banners:             banners,
		hub:                 hub,
	}

	// wire avatar cache mutations to broadcast via WebSocket
	avatars.broadcastFn = func(version uint64, userID, hash string) {
		msg, _ := json.Marshal(fiber.Map{
			"type":    "update",
			"asset":   "avatar",
			"version": version,
			"userId":  userID,
			"hash":    hash,
		})
		hub.broadcast(msg)
	}

	// wire banner cache mutations to broadcast via WebSocket
	banners.broadcastFn = func(version uint64, userID, hash string) {
		msg, _ := json.Marshal(fiber.Map{
			"type":    "update",
			"asset":   "banner",
			"version": version,
			"userId":  userID,
			"hash":    hash,
		})
		hub.broadcast(msg)
	}

	return s
}

func (s *server) setupRoutes(app *fiber.App) {
	// request logging
	app.Use(func(c fiber.Ctx) error {
		start := time.Now()
		log.Printf("[http] --> %s %s | Origin: %s | Content-Type: %s | Authorization: %s | User-Agent: %s",
			c.Method(), c.OriginalURL(),
			c.Get("Origin"), c.Get("Content-Type"), c.Get("Authorization"), c.Get("User-Agent"))
		err := c.Next()
		log.Printf("[http] <-- %s %s %d %s", c.Method(), c.OriginalURL(), c.Response().StatusCode(), time.Since(start))
		return err
	})

	// rate limiter
	app.Use(limiter.New(limiter.Config{
		Next: func(c fiber.Ctx) bool {
			return c.IP() == "127.0.0.1"
		},
		Max:        30,
		Expiration: 5 * time.Minute,
	}))

	// CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins: []string{"https://discord.com"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization"},
	}))

	// HTTP cache
	app.Use(cache.New(cache.Config{
		ExpirationGenerator: func(c fiber.Ctx, cfg *cache.Config) time.Duration {
			newCacheTime, _ := strconv.Atoi(c.GetRespHeader("Cache-Time", "600"))
			return time.Second * time.Duration(newCacheTime)
		},
		KeyGenerator: func(c fiber.Ctx) string {
			return utils.CopyString(c.Path() + "?" + string(c.Request().URI().QueryString()))
		},
		Next: func(c fiber.Ctx) bool {
			// skip cache for auth routes, POST requests, and websocket
			return strings.HasPrefix(c.Path(), "/auth") || c.Method() == "POST" || c.Path() == "/avatars/ws"
		},
	}))

	// auth routes
	app.Get("/auth/discord", s.handleAuthRedirect)
	app.Get("/auth/discord/callback", s.handleAuthCallback)
	app.Get("/auth/token", s.handleAuthToken)

	// websocket
	app.Get("/avatars/ws", websocket.New(s.handleWebSocket))

	// asset routes (parameterized for avatar and banner)
	avatarKind := assetKind{name: "avatar", prefix: "avatars", formField: "avatar", cache: s.avatars}
	bannerKind := assetKind{name: "banner", prefix: "banners", formField: "banner", cache: s.banners}

	app.Post("/avatars/:userId", s.handleUpload(avatarKind))
	app.Delete("/avatars/:userId", s.handleDelete(avatarKind))
	app.Post("/banners/:userId", s.handleUpload(bannerKind))
	app.Delete("/banners/:userId", s.handleDelete(bannerKind))
}
