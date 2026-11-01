package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var errFFmpegNotFound = errors.New("ffmpeg not found")

// ffmpegPath is the ffmpeg binary used for merging, resolved by findFFmpeg at
// startup.
var ffmpegPath = "ffmpeg"

// findFFmpeg locates ffmpeg on PATH, in the current directory, or next to the
// downloader's own executable.
func findFFmpeg() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	return findFFmpegFrom(exe)
}

// findFFmpegFrom is findFFmpeg with the downloader's executable path passed in.
//
// Windows users usually drop ffmpeg.exe into the same folder as the
// downloader. Windows searches the current directory implicitly, but since
// Go 1.19 exec refuses a binary found that way (exec.ErrDot), which made the
// merge fail after every track had already been downloaded. Placing ffmpeg
// there is deliberate, so it's accepted as an absolute path.
func findFFmpegFrom(exe string) (string, error) {
	path, err := exec.LookPath("ffmpeg")
	if err == nil {
		return path, nil
	}
	if errors.Is(err, exec.ErrDot) {
		return filepath.Abs(path)
	}

	if exe != "" {
		if path, err := exec.LookPath(filepath.Join(filepath.Dir(exe), "ffmpeg")); err == nil {
			return path, nil
		}
	}
	return "", errFFmpegNotFound
}

// verifyCodecs are the codecs -verify decodes: Crunchyroll's H.264 video and
// AAC audio.
var verifyCodecs = []string{"h264", "aac"}

// missingDecoders returns which of codecs ffmpeg has no decoder for. Merging
// only copies streams, so a build without them still downloads fine, but
// can't verify. Some bundled builds, such as Synology DSM's, leave out H.264.
func missingDecoders(codecs []string) ([]string, error) {
	out, err := exec.Command(ffmpegPath, "-hide_banner", "-decoders").Output()
	if err != nil {
		return nil, fmt.Errorf("list ffmpeg decoders: %w", err)
	}
	available := decoderCodecs(string(out))
	var missing []string
	for _, codec := range codecs {
		if !available[codec] {
			missing = append(missing, codec)
		}
	}
	return missing, nil
}

// decoderCodecs parses the output of `ffmpeg -decoders` into the set of codecs
// that have a decoder. A decoder named differently from its codec, such as
// libopenh264, has the codec appended to its description as "(codec h264)".
func decoderCodecs(list string) map[string]bool {
	codecs := map[string]bool{}
	_, table, ok := strings.Cut(list, "------")
	if !ok {
		return codecs
	}
	for _, line := range strings.Split(table, "\n") {
		// Each line is the capability flags, the decoder name and a description.
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		codec := fields[1]
		if n := len(fields); n >= 4 && fields[n-2] == "(codec" && strings.HasSuffix(fields[n-1], ")") {
			codec = strings.TrimSuffix(fields[n-1], ")")
		}
		codecs[codec] = true
	}
	return codecs
}
