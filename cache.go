package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

const maxChangelogEntries = 1000

// changeEntry represents a single mutation in the avatar cache changelog.
type changeEntry struct {
	Version uint64
	UserID  string
	Hash    string
}

// avatarCache tracks which user IDs have uploaded avatars and their content hashes.
// Positive entries (hash != "") are persisted to a versioned file and loaded on startup.
// Negative entries (hash == "", checked R2 and not found) are in-memory only.
// A bounded changelog enables incremental sync for clients.
type avatarCache struct {
	mu          sync.RWMutex
	known       map[string]string // userId -> content hash ("" = not found, non-empty = exists)
	version     uint64            // monotonically increasing, increments on each persisted mutation
	changelog   []changeEntry     // bounded in-memory log of recent mutations
	filePath    string
	broadcastFn func(version uint64, userID, hash string) // called after each mutation to notify WS clients
}

func newAvatarCache(filePath string) *avatarCache {
	ac := &avatarCache{
		known:    make(map[string]string),
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
	if len(lines) == 0 {
		return ac
	}

	startIdx := 0
	migrationNeeded := false

	// check if first line is a version header
	if strings.HasPrefix(lines[0], "version:") {
		vStr := strings.TrimPrefix(lines[0], "version:")
		v, err := strconv.ParseUint(vStr, 10, 64)
		if err != nil {
			log.Printf("[avatar-cache] invalid version line %q, treating as version 0", lines[0])
		} else {
			ac.version = v
		}
		startIdx = 1
	} else {
		// old format — needs migration
		ac.version = 1
		migrationNeeded = true
	}

	for _, line := range lines[startIdx:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			ac.known[parts[0]] = parts[1]
		} else {
			// legacy format: bare userId without hash
			ac.known[parts[0]] = "unknown"
		}
	}

	log.Printf("[avatar-cache] loaded %d user IDs from %s (version %d)", len(ac.known), filePath, ac.version)

	if migrationNeeded {
		ac.rewriteFile()
		log.Printf("[avatar-cache] migrated file to new format with version %d", ac.version)
	}

	return ac
}

// rewriteFile writes the current state to disk. Must be called with ac.mu held.
func (ac *avatarCache) rewriteFile() {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("version:%d\n", ac.version))

	for userID, hash := range ac.known {
		if hash != "" {
			buf.WriteString(userID + ":" + hash + "\n")
		}
	}

	if err := os.WriteFile(ac.filePath, buf.Bytes(), 0644); err != nil {
		log.Printf("[avatar-cache] failed to rewrite cache file: %v", err)
	}
}

// markExists marks a user as having an avatar with the given content hash.
// Increments version, appends to changelog, rewrites file, and broadcasts to WS clients.
func (ac *avatarCache) markExists(userID string, hash string) {
	ac.mu.Lock()

	if ac.known[userID] == hash {
		ac.mu.Unlock()
		return
	}

	ac.known[userID] = hash
	ac.version++
	version := ac.version

	ac.changelog = append(ac.changelog, changeEntry{
		Version: ac.version,
		UserID:  userID,
		Hash:    hash,
	})

	if len(ac.changelog) > maxChangelogEntries {
		ac.changelog = ac.changelog[len(ac.changelog)-maxChangelogEntries:]
	}

	ac.rewriteFile()

	broadcastFn := ac.broadcastFn
	ac.mu.Unlock()

	log.Printf("[avatar-cache] marked %s with hash %s (version %d)", userID, hash, version)

	// broadcast outside the lock to avoid holding it during network I/O
	if broadcastFn != nil {
		broadcastFn(version, userID, hash)
	}
}

// markDeleted removes an asset for a user. Increments version, appends to changelog,
// rewrites file, and broadcasts with hash="" so WS clients know it was deleted.
func (ac *avatarCache) markDeleted(userID string) {
	ac.mu.Lock()

	existing := ac.known[userID]
	if existing == "" {
		ac.mu.Unlock()
		return // nothing to delete
	}

	ac.known[userID] = ""
	ac.version++
	version := ac.version

	ac.changelog = append(ac.changelog, changeEntry{
		Version: ac.version,
		UserID:  userID,
		Hash:    "",
	})

	if len(ac.changelog) > maxChangelogEntries {
		ac.changelog = ac.changelog[len(ac.changelog)-maxChangelogEntries:]
	}

	ac.rewriteFile()

	broadcastFn := ac.broadcastFn
	ac.mu.Unlock()

	log.Printf("[avatar-cache] deleted %s (version %d)", userID, version)

	if broadcastFn != nil {
		broadcastFn(version, userID, "")
	}
}

// lookup returns (hash, cached). If cached is false, the caller should check R2.
// hash == "" means negative cache (checked, not found). hash != "" means avatar exists.
func (ac *avatarCache) lookup(userID string) (hash string, cached bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	hash, cached = ac.known[userID]
	return
}

// setChecked caches the result of an R2 check for a user ID (in-memory only).
// Pass "unknown" for positive results (no hash available), "" for negative results.
// Does NOT touch version or changelog — this is ephemeral R2 lookup caching.
func (ac *avatarCache) setChecked(userID string, hash string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.known[userID] = hash
}

// sync returns changes since the given version. If the version is too old
// or zero, returns a full snapshot of all known avatars.
func (ac *avatarCache) sync(sinceVersion uint64) (version uint64, changes []changeEntry, full bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	version = ac.version

	// can we serve incrementally?
	canIncremental := sinceVersion > 0 && len(ac.changelog) > 0 && sinceVersion >= ac.changelog[0].Version

	if !canIncremental {
		// full snapshot
		full = true
		changes = make([]changeEntry, 0, len(ac.known))
		for userID, hash := range ac.known {
			if hash != "" {
				changes = append(changes, changeEntry{UserID: userID, Hash: hash})
			}
		}
		return
	}

	// incremental: return only changes after sinceVersion
	for _, entry := range ac.changelog {
		if entry.Version > sinceVersion {
			changes = append(changes, entry)
		}
	}
	return
}
