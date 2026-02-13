package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gofiber/fiber/v3"
)

// assetKind parameterizes the upload/delete handlers for avatars vs banners.
type assetKind struct {
	name      string       // "avatar" or "banner"
	prefix    string       // "avatars" or "banners" (R2 key prefix)
	formField string       // multipart form field name
	cache     *avatarCache // the cache for this asset type
}

// checkR2 does a HeadObject to see if an asset exists in R2 for the given user ID.
// prefix is "avatars" or "banners".
func checkR2(r2 *s3.Client, bucket, prefix, userID string) bool {
	_, err := r2.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(prefix + "/" + userID),
	})
	return err == nil
}

// authenticateUser extracts and validates the JWT from the Authorization header,
// then checks that the token subject matches the given userId.
// On failure it sends the appropriate HTTP error response and returns a non-nil error.
func (s *server) authenticateUser(c fiber.Ctx, userId string) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		log.Printf("[auth] user %s: missing or invalid Authorization header", userId)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "authorization required",
		})
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	tokenUserID, err := verifyJWT(tokenString, s.jwtSecret)
	if err != nil {
		log.Printf("[auth] user %s: invalid token: %v", userId, err)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid or expired token",
		})
	}

	if tokenUserID != userId {
		log.Printf("[auth] user %s: token belongs to %s, rejecting", userId, tokenUserID)
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "you can only modify your own profile",
		})
	}

	return nil
}

// handleUpload returns a Fiber handler that uploads an asset (avatar or banner).
// POST /avatars/:userId or POST /banners/:userId
func (s *server) handleUpload(kind assetKind) fiber.Handler {
	return func(c fiber.Ctx) error {
		userId := c.Params("userId")
		log.Printf("[upload] POST /%s/%s - request received", kind.prefix, userId)

		if err := s.authenticateUser(c, userId); err != nil {
			return nil // response already sent
		}
		log.Printf("[upload] %s user %s: authenticated successfully", kind.name, userId)

		file, err := c.FormFile(kind.formField)
		if err != nil {
			log.Printf("[upload] %s user %s: no %s field in form: %v", kind.name, userId, kind.formField, err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("%s file is required", kind.formField),
			})
		}

		log.Printf("[upload] %s user %s: received file %q, size: %d bytes, content-type: %s",
			kind.name, userId, file.Filename, file.Size, file.Header.Get("Content-Type"))

		key := kind.prefix + "/" + userId

		src, err := file.Open()
		if err != nil {
			log.Printf("[upload] %s user %s: failed to open multipart file: %v", kind.name, userId, err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to read uploaded file",
			})
		}
		defer src.Close()

		data, err := io.ReadAll(src)
		if err != nil {
			log.Printf("[upload] %s user %s: failed to read file bytes: %v", kind.name, userId, err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to read uploaded file",
			})
		}
		log.Printf("[upload] %s user %s: read %d bytes from upload", kind.name, userId, len(data))

		format, err := detectFormat(data)
		if err != nil {
			log.Printf("[upload] %s user %s: unsupported format: %v", kind.name, userId, err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "unsupported file format — accepted: PNG, JPG, GIF, WebP, AVIF, MP4",
			})
		}
		log.Printf("[upload] %s user %s: detected format=%s", kind.name, userId, format)

		// respond immediately — client will be notified via WebSocket when processing completes
		log.Printf("[upload] %s user %s: accepted, processing in background", kind.name, userId)

		go func() {
			avifData, err := convertToAVIF(data, format)
			if err != nil {
				log.Printf("[upload] %s user %s: AVIF conversion failed: %v", kind.name, userId, err)
				return
			}

			rawHash := sha256.Sum256(avifData)
			contentHash := hex.EncodeToString(rawHash[:8])
			log.Printf("[upload] %s user %s: content hash=%s", kind.name, userId, contentHash)

			log.Printf("[upload] %s user %s: uploading %d bytes to R2 key %q", kind.name, userId, len(avifData), key)
			_, err = s.r2.PutObject(context.TODO(), &s3.PutObjectInput{
				Bucket:      aws.String(s.bucket),
				Key:         aws.String(key),
				Body:        bytes.NewReader(avifData),
				ContentType: aws.String("image/avif"),
			})
			if err != nil {
				log.Printf("[upload] %s user %s: R2 upload failed: %v", kind.name, userId, err)
				return
			}

			kind.cache.markExists(userId, contentHash)
			log.Printf("[upload] %s user %s: %s processed and uploaded successfully", kind.name, userId, kind.name)
		}()

		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
			"message": fmt.Sprintf("%s upload accepted for user %s, processing in background", kind.name, userId),
		})
	}
}

// handleDelete returns a Fiber handler that deletes an asset (avatar or banner).
// DELETE /avatars/:userId or DELETE /banners/:userId
func (s *server) handleDelete(kind assetKind) fiber.Handler {
	return func(c fiber.Ctx) error {
		userId := c.Params("userId")
		log.Printf("[delete] DELETE /%s/%s - request received", kind.prefix, userId)

		if err := s.authenticateUser(c, userId); err != nil {
			return nil // response already sent
		}

		_, err := s.r2.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(s.bucket),
			Key:    aws.String(kind.prefix + "/" + userId),
		})
		if err != nil {
			log.Printf("[delete] user %s: R2 %s delete failed: %v", userId, kind.name, err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": fmt.Sprintf("failed to delete %s from storage", kind.name),
			})
		}

		kind.cache.markDeleted(userId)
		log.Printf("[delete] user %s: %s deleted successfully", userId, kind.name)
		return c.JSON(fiber.Map{
			"message": fmt.Sprintf("%s deleted for user %s", kind.name, userId),
		})
	}
}
