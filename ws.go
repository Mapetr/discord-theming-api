package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/gofiber/contrib/v3/websocket"
	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
)

// wsHub manages WebSocket client connections and broadcasts avatar changes.
type wsHub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]bool
}

func newWSHub() *wsHub {
	return &wsHub{
		clients: make(map[*websocket.Conn]bool),
	}
}

func (h *wsHub) register(conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[conn] = true
	log.Printf("[ws] client connected (%d total)", len(h.clients))
}

func (h *wsHub) unregister(conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, conn)
	log.Printf("[ws] client disconnected (%d remaining)", len(h.clients))
}

// broadcast sends a JSON message to all connected WebSocket clients.
// Failed sends cause the client to be removed.
func (h *wsHub) broadcast(msg []byte) {
	h.mu.RLock()
	clients := make([]*websocket.Conn, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	var failed []*websocket.Conn
	for _, c := range clients {
		if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
			log.Printf("[ws] write failed, removing client: %v", err)
			failed = append(failed, c)
		}
	}

	if len(failed) > 0 {
		h.mu.Lock()
		for _, c := range failed {
			delete(h.clients, c)
			c.Close()
		}
		h.mu.Unlock()
	}
}

type syncChange struct {
	UserID string `json:"userId"`
	Hash   string `json:"hash"`
}

type assetSync struct {
	Version uint64       `json:"version"`
	Changes []syncChange `json:"changes"`
}

func buildSync(ac *avatarCache) assetSync {
	version, changes, _ := ac.sync(0)
	sc := make([]syncChange, len(changes))
	for i, ch := range changes {
		sc[i] = syncChange{UserID: ch.UserID, Hash: ch.Hash}
	}
	return assetSync{Version: version, Changes: sc}
}

// handleWebSocket handles WebSocket connections for real-time avatar and banner updates.
// No authentication required. Sends initial full state on connect, then pushes incremental changes.
//
// Messages from server (push):
//
//	Initial: { "type": "sync", "avatars": { "version": N, "changes": [...] }, "banners": { "version": N, "changes": [...] } }
//	Update:  { "type": "update", "asset": "avatar"|"banner", "version": N, "userId": "...", "hash": "..." }
//	Error:   { "type": "error", "error": "..." }
//
// Client can send:
//
//	Ping:    { "type": "ping" }  -> { "type": "pong" }
//	Check:   { "type": "check", "asset": "avatar"|"banner", "ids": ["123", "456"] }
//	         -> { "type": "check", "asset": "avatar"|"banner", "available": { "123": "hash" } }
//	Verify:  { "type": "verify", "token": "<jwt>" }
//	         -> { "type": "verify", "valid": true, "expired": false, "userId": "...", "expiresAt": "..." }
func (s *server) handleWebSocket(c *websocket.Conn) {
	// register this client
	s.hub.register(c)
	defer s.hub.unregister(c)

	// send initial full snapshot of both avatars and banners
	initMsg, _ := json.Marshal(fiber.Map{
		"type":    "sync",
		"avatars": buildSync(s.avatars),
		"banners": buildSync(s.banners),
	})
	if err := c.WriteMessage(websocket.TextMessage, initMsg); err != nil {
		log.Printf("[ws] failed to send initial sync: %v", err)
		return
	}

	// read loop — keeps connection alive and handles client messages
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			break
		}

		var clientMsg struct {
			Type  string   `json:"type"`
			Asset string   `json:"asset,omitempty"` // "avatar" or "banner", defaults to "avatar"
			IDs   []string `json:"ids,omitempty"`
			Token string   `json:"token,omitempty"`
		}
		if json.Unmarshal(msg, &clientMsg) != nil {
			continue
		}

		var reply []byte

		switch clientMsg.Type {
		case "ping":
			reply, _ = json.Marshal(fiber.Map{"type": "pong"})

		case "check":
			// pick the right cache and R2 prefix based on asset type
			assetType := clientMsg.Asset
			if assetType == "" {
				assetType = "avatar"
			}
			var ac *avatarCache
			var prefix string
			switch assetType {
			case "banner":
				ac = s.banners
				prefix = "banners"
			default:
				ac = s.avatars
				prefix = "avatars"
				assetType = "avatar"
			}

			available := make(map[string]string)
			for _, id := range clientMsg.IDs {
				hash, cached := ac.lookup(id)
				if !cached {
					exists := checkR2(s.r2, s.bucket, prefix, id)
					if exists {
						hash = "unknown"
					}
					ac.setChecked(id, hash)
				}
				if hash != "" {
					available[id] = hash
				}
			}
			reply, _ = json.Marshal(fiber.Map{
				"type":      "check",
				"asset":     assetType,
				"available": available,
			})

		case "verify":
			if clientMsg.Token == "" {
				reply, _ = json.Marshal(fiber.Map{
					"type":  "verify",
					"valid": false,
					"error": "token field is required",
				})
			} else {
				keyFunc := func(t *jwt.Token) (any, error) {
					if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
					}
					return []byte(s.jwtSecret), nil
				}

				tok, err := jwt.Parse(clientMsg.Token, keyFunc)
				if err == nil {
					sub, _ := tok.Claims.GetSubject()
					exp, _ := tok.Claims.GetExpirationTime()
					reply, _ = json.Marshal(fiber.Map{
						"type":      "verify",
						"valid":     true,
						"expired":   false,
						"userId":    sub,
						"expiresAt": exp.Time,
					})
				} else {
					// check if signature is valid but expired
					tok, err2 := jwt.Parse(clientMsg.Token, keyFunc, jwt.WithoutClaimsValidation())
					if err2 != nil {
						reply, _ = json.Marshal(fiber.Map{
							"type":  "verify",
							"valid": false,
							"error": "invalid token",
						})
					} else {
						sub, _ := tok.Claims.GetSubject()
						exp, _ := tok.Claims.GetExpirationTime()
						reply, _ = json.Marshal(fiber.Map{
							"type":      "verify",
							"valid":     true,
							"expired":   true,
							"userId":    sub,
							"expiresAt": exp.Time,
						})
					}
				}
			}

		default:
			continue
		}

		if err := c.WriteMessage(websocket.TextMessage, reply); err != nil {
			break
		}
	}
}

