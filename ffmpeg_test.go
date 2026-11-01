package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFakeFFmpeg creates an executable named like ffmpeg in dir and returns
// its path.
func writeFakeFFmpeg(t *testing.T, dir string) string {
	t.Helper()
	name := "ffmpeg"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertSameFile(t *testing.T, got, want string) {
	t.Helper()
	if !filepath.IsAbs(got) {
		t.Errorf("got relative path %q, want an absolute one", got)
	}
	gotInfo, err := os.Stat(got)
	if err != nil {
		t.Fatalf("stat %q: %v", got, err)
	}
	wantInfo, err := os.Stat(want)
	if err != nil {
		t.Fatalf("stat %q: %v", want, err)
	}
	if !os.SameFile(gotInfo, wantInfo) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFindFFmpegOnPath(t *testing.T) {
	dir := t.TempDir()
	want := writeFakeFFmpeg(t, dir)
	t.Setenv("PATH", dir)

	got, err := findFFmpegFrom("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSameFile(t, got, want)
}

func TestFindFFmpegInCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	want := writeFakeFFmpeg(t, dir)
	t.Chdir(dir)
	// A relative PATH entry makes exec.LookPath return exec.ErrDot on every
	// OS, reproducing what Windows does for the current directory.
	t.Setenv("PATH", ".")

	got, err := findFFmpegFrom("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSameFile(t, got, want)
}

func TestFindFFmpegNextToExecutable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	exeDir := t.TempDir()
	want := writeFakeFFmpeg(t, exeDir)

	got, err := findFFmpegFrom(filepath.Join(exeDir, "crunchyroll-downloader"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertSameFile(t, got, want)
}

func TestFindFFmpegMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	exeDir := t.TempDir()

	_, err := findFFmpegFrom(filepath.Join(exeDir, "crunchyroll-downloader"))
	if !errors.Is(err, errFFmpegNotFound) {
		t.Errorf("got error %v, want %v", err, errFFmpegNotFound)
	}
}

func TestDecoderCodecs(t *testing.T) {
	// Trimmed `ffmpeg -decoders` output, with the CRLF line endings it has on
	// Windows.
	list := strings.Join([]string{
		"Decoders:",
		" V..... = Video",
		" A..... = Audio",
		" ------",
		" VFS..D h264                 H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10",
		" V....D libopenh264          OpenH264 H.264 / AVC / MPEG-4 AVC / MPEG-4 part 10 (codec h264)",
		" V..... libdav1d             dav1d AV1 decoder by VideoLAN (codec av1)",
		" A....D aac_fixed            AAC (Advanced Audio Coding) (codec aac)",
		"",
	}, "\r\n")

	got := decoderCodecs(list)
	for _, codec := range []string{"h264", "av1", "aac"} {
		if !got[codec] {
			t.Errorf("codec %s is missing from %v", codec, got)
		}
	}
	// The legend above the table isn't a decoder.
	if got["="] || got["Video"] {
		t.Errorf("legend parsed as decoders: %v", got)
	}
	if got["hevc"] {
		t.Error("hevc reported without a decoder")
	}
}
