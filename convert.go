package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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
// PNG may have transparency, so it uses the two-stream alpha approach.
// JPG and static WebP have no alpha, so they use a simple single-stream encode.
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

	var cmd *exec.Cmd
	if ext == "png" {
		// PNG may have alpha — use two-stream approach (color + alpha as separate AV1 streams)
		cmd = exec.CommandContext(ctx, "ffmpeg", "-y",
			"-i", inPath,
			"-filter_complex", "[0:v]format=pix_fmts=yuva444p,split[main][alpha];[alpha]alphaextract[alpha]",
			"-map", "[main]:v",
			"-map", "[alpha]:v",
			"-pix_fmt:0", "yuv420p",
			"-pix_fmt:1", "gray8",
			"-c:v", "libaom-av1",
			"-crf", "30",
			"-crf:1", "40",
			"-still-picture", "1",
			outPath,
		)
		log.Printf("[ffmpeg] converting PNG to AVIF (two-stream: color yuv420p + alpha gray8, still-picture)")
	} else {
		// JPG and static WebP have no alpha — simple single-stream encode
		cmd = exec.CommandContext(ctx, "ffmpeg", "-y",
			"-i", inPath,
			"-c:v", "libaom-av1",
			"-crf", "30",
			"-still-picture", "1",
			outPath,
		)
		log.Printf("[ffmpeg] converting %s to AVIF (single-stream, still-picture)", ext)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg static conversion failed: %w: %s", err, stderr.String())
	}

	return os.ReadFile(outPath)
}

// convertGIFToAVIF converts a GIF (static or animated) to AVIF using ffmpeg.
// Uses two-stream encoding: stream 0 = color (yuv420p), stream 1 = alpha (gray8).
// libaom-av1 does not support yuva420p, so alpha must be a separate AV1 stream.
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

	// GIF uses pal8 with 1-bit transparency. AVIF requires alpha as a separate
	// grayscale AV1 stream. We use filter_complex to:
	// 1. Convert to yuva444p to get full alpha channel
	// 2. Split into two copies
	// 3. Extract alpha channel as grayscale from the second copy
	// Stream 0 (color) uses yuv420p, stream 1 (alpha) uses gray8.
	cmd := exec.CommandContext(ctx, "ffmpeg", "-y",
		"-i", inPath,
		"-filter_complex", "[0:v]format=pix_fmts=yuva444p,split[main][alpha];[alpha]alphaextract[alpha]",
		"-map", "[main]:v",
		"-map", "[alpha]:v",
		"-pix_fmt:0", "yuv420p",
		"-pix_fmt:1", "gray8",
		"-c:v", "libaom-av1",
		"-crf", "30",
		"-crf:1", "40",
		"-vsync", "vfr",
		outPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	log.Printf("[ffmpeg] converting GIF to AVIF (two-stream: color yuv420p + alpha gray8)")
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
