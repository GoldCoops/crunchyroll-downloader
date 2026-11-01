package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
)

func useFFmpeg(t *testing.T, path string) {
	t.Helper()
	old := ffmpegPath
	ffmpegPath = path
	t.Cleanup(func() { ffmpegPath = old })
}

func TestVerifyOutput(t *testing.T) {
	path, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is not installed")
	}
	useFFmpeg(t, path)
	if missing, err := missingDecoders(verifyCodecs); err != nil || len(missing) > 0 {
		t.Skipf("ffmpeg can't decode %v: %v", missing, err)
	}

	// encode writes a 4 second H.264/AAC clip with a keyframe every second,
	// passing extra to the output.
	dir := t.TempDir()
	encode := func(name string, extra ...string) string {
		out := filepath.Join(dir, name)
		args := append([]string{"-v", "error", "-y",
			"-f", "lavfi", "-i", "testsrc2=size=320x240:rate=24:duration=4",
			"-f", "lavfi", "-i", "sine=duration=4",
			"-c:v", "libx264", "-g", "24", "-c:a", "aac"}, extra...)
		if b, err := exec.Command(path, append(args, out)...).CombinedOutput(); err != nil {
			t.Skipf("ffmpeg can't encode the test clip: %v\n%s", err, b)
		}
		return out
	}

	if err := verifyOutput(encode("clean.mkv")); err != nil {
		t.Errorf("clean file failed verification: %v", err)
	}

	// Without the key, ffmpeg decodes the encrypted samples as they are: the
	// noise a fragment that was never decrypted would leave behind.
	encrypted := encode("encrypted.mp4",
		"-movflags", "+frag_keyframe+empty_moov+default_base_moof",
		"-encryption_scheme", "cenc-aes-ctr",
		"-encryption_key", "00112233445566778899aabbccddeeff",
		"-encryption_kid", "0123456789abcdef0123456789abcdef")
	if err := verifyOutput(encrypted); err == nil || errors.Is(err, errCannotVerify) {
		t.Errorf("undecrypted file: got %v, want decode errors", err)
	}

	// FFmpeg failing outright, as it does without a decoder for the file's
	// codec, says nothing about the file.
	if err := verifyOutput(filepath.Join(dir, "missing.mkv")); !errors.Is(err, errCannotVerify) {
		t.Errorf("unreadable file: got %v, want %v", err, errCannotVerify)
	}
}

func TestVerifyOutputWithoutFFmpeg(t *testing.T) {
	useFFmpeg(t, filepath.Join(t.TempDir(), "ffmpeg"))

	if err := verifyOutput("episode.mkv"); !errors.Is(err, errCannotVerify) {
		t.Errorf("got %v, want %v", err, errCannotVerify)
	}
}
