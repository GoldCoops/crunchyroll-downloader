package main

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/Eyevinn/mp4ff/aac"
	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/iyear/gowidevine"
	"github.com/iyear/gowidevine/widevinepb"
	gompd "github.com/unki2aut/go-mpd"
)

var playReadySystemID = mp4.UUID{0x9a, 0x04, 0xf0, 0x79, 0x98, 0x40, 0x42, 0x86, 0xab, 0x92, 0xe6, 0x5b, 0xe0, 0x88, 0x5f, 0x95}

func buildPssh(t *testing.T, systemID mp4.UUID, data []byte) []byte {
	t.Helper()
	box := &mp4.PsshBox{SystemID: systemID, Data: data}
	var buf bytes.Buffer
	if err := box.Encode(&buf); err != nil {
		t.Fatalf("encode PSSH box: %v", err)
	}
	return buf.Bytes()
}

func TestToWidevinePssh(t *testing.T) {
	payload := []byte{0x08, 0x01, 0x12, 0x10, 0xaa, 0xbb, 0xcc, 0xdd}

	t.Run("widevine system id is unchanged", func(t *testing.T) {
		original := buildPssh(t, widevineSystemID, payload)
		got, err := toWidevinePssh(original)
		if err != nil {
			t.Fatalf("toWidevinePssh returned error: %v", err)
		}
		if !bytes.Equal(got, original) {
			t.Fatal("toWidevinePssh altered an already-widevine PSSH")
		}
	})

	t.Run("playready system id is rewritten", func(t *testing.T) {
		in := buildPssh(t, playReadySystemID, payload)
		got, err := toWidevinePssh(in)
		if err != nil {
			t.Fatalf("toWidevinePssh returned error: %v", err)
		}

		box, err := mp4.DecodeBox(0, bytes.NewReader(got))
		if err != nil {
			t.Fatalf("decode result: %v", err)
		}
		pssh, ok := box.(*mp4.PsshBox)
		if !ok {
			t.Fatalf("result is %T, want *mp4.PsshBox", box)
		}
		if !bytes.Equal(pssh.SystemID, widevineSystemID) {
			t.Fatalf("system id = %s, want widevine", pssh.SystemID)
		}
		if !bytes.Equal(pssh.Data, payload) {
			t.Fatalf("payload changed: got %x, want %x", pssh.Data, payload)
		}
	})
}

func TestGetPsshPrefersWidevine(t *testing.T) {
	widevineURI := "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"
	playReadyURI := "urn:uuid:9a04f079-9840-4286-ab92-e65be0885f95"
	widevinePssh := "widevine-pssh"
	playReadyPssh := "playready-pssh"

	t.Run("widevine preferred over playready", func(t *testing.T) {
		m := &gompd.MPD{
			Period: []*gompd.Period{
				{AdaptationSets: []*gompd.AdaptationSet{
					{ContentProtections: []gompd.Descriptor{
						{SchemeIDURI: &playReadyURI, CencPSSH: &playReadyPssh},
						{SchemeIDURI: &widevineURI, CencPSSH: &widevinePssh},
					}},
				}},
			},
		}
		if got := getPssh(m); got == nil || *got != widevinePssh {
			t.Fatalf("getPssh() = %v, want the widevine PSSH", got)
		}
	})

	t.Run("falls back when no widevine scheme", func(t *testing.T) {
		m := &gompd.MPD{
			Period: []*gompd.Period{
				{AdaptationSets: []*gompd.AdaptationSet{
					{ContentProtections: []gompd.Descriptor{
						{SchemeIDURI: &playReadyURI, CencPSSH: &playReadyPssh},
					}},
				}},
			},
		}
		if got := getPssh(m); got == nil || *got != playReadyPssh {
			t.Fatalf("getPssh() = %v, want the fallback PSSH", got)
		}
	})

	t.Run("nil when no pssh", func(t *testing.T) {
		m := &gompd.MPD{
			Period: []*gompd.Period{
				{AdaptationSets: []*gompd.AdaptationSet{
					{ContentProtections: []gompd.Descriptor{
						{SchemeIDURI: &widevineURI},
					}},
				}},
			},
		}
		if got := getPssh(m); got != nil {
			t.Fatalf("getPssh() = %v, want nil", got)
		}
	})

	t.Run("representation level widevine pssh", func(t *testing.T) {
		m := &gompd.MPD{
			Period: []*gompd.Period{
				{AdaptationSets: []*gompd.AdaptationSet{
					{Representations: []gompd.Representation{
						{ContentProtections: []gompd.Descriptor{
							{SchemeIDURI: &playReadyURI, CencPSSH: &playReadyPssh},
							{SchemeIDURI: &widevineURI, CencPSSH: &widevinePssh},
						}},
					}},
				}},
			},
		}
		if got := getPssh(m); got == nil || *got != widevinePssh {
			t.Fatalf("getPssh() = %v, want the widevine PSSH", got)
		}
	})
}

var (
	testKID = mp4.UUID{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	testKey = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
)

// buildEncryptedMP4 builds a CENC-encrypted fragmented AAC track laid out the
// way downloadParts writes it to disk: the init segment followed by four media
// segments. The fragments at the clearFragments indices are left unencrypted.
// It returns the init segment, the whole file and the clear sample payloads in
// order.
func buildEncryptedMP4(t *testing.T, clearFragments ...int) (initData, media []byte, samples [][]byte) {
	t.Helper()
	init := mp4.CreateEmptyInit()
	init.AddEmptyTrack(48000, "audio", "jpn")
	if err := init.Moov.Trak.SetAACDescriptor(aac.AAClc, 48000); err != nil {
		t.Fatalf("set AAC descriptor: %v", err)
	}
	iv := []byte{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	ipd, err := mp4.InitProtect(init, testKey, iv, "cenc", testKID, nil)
	if err != nil {
		t.Fatalf("protect init: %v", err)
	}
	var file bytes.Buffer
	if err = init.Encode(&file); err != nil {
		t.Fatalf("encode init: %v", err)
	}
	initData = bytes.Clone(file.Bytes())

	var decodeTime uint64
	for f := 0; f < 4; f++ {
		frag, err := mp4.CreateFragment(uint32(f+1), 1)
		if err != nil {
			t.Fatalf("create fragment: %v", err)
		}
		for s := 0; s < 8; s++ {
			data := make([]byte, 200+37*s)
			for i := range data {
				data[i] = byte(i*7 + s + f)
			}
			samples = append(samples, bytes.Clone(data))
			frag.AddFullSample(mp4.FullSample{
				Sample:     mp4.NewSample(mp4.SyncSampleFlags, 1024, uint32(len(data)), 0),
				DecodeTime: decodeTime,
				Data:       data,
			})
			decodeTime += 1024
		}
		if !slices.Contains(clearFragments, f) {
			if err = mp4.EncryptFragment(frag, testKey, iv, ipd); err != nil {
				t.Fatalf("encrypt fragment %d: %v", f, err)
			}
		}
		if err = frag.Encode(&file); err != nil {
			t.Fatalf("encode fragment %d: %v", f, err)
		}
	}
	return initData, file.Bytes(), samples
}

// testLicenseKeys returns a license with an unrelated content key ahead of the
// track's own, so a decrypt that ignores the KID picks the wrong one.
func testLicenseKeys() []*widevine.Key {
	return []*widevine.Key{
		{Type: widevinepb.License_KeyContainer_CONTENT, ID: bytes.Repeat([]byte{0xaa}, 16), Key: bytes.Repeat([]byte{0xbb}, 16)},
		{Type: widevinepb.License_KeyContainer_CONTENT, ID: testKID, Key: testKey},
	}
}

// TestDecryptMP4MatchesGowidevine checks the streaming decrypt against
// gowidevine's whole-file one, which it replaced, on a fully encrypted track.
func TestDecryptMP4MatchesGowidevine(t *testing.T) {
	initData, media, _ := buildEncryptedMP4(t)

	var got bytes.Buffer
	if err := decryptMP4(initData, bytes.NewReader(media), testLicenseKeys(), &got); err != nil {
		t.Fatalf("decryptMP4: %v", err)
	}
	var want bytes.Buffer
	if err := widevine.DecryptMP4(bytes.NewReader(media), testKey, &want); err != nil {
		t.Fatalf("widevine.DecryptMP4: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatalf("output differs from widevine.DecryptMP4 (%d vs %d bytes)", got.Len(), want.Len())
	}
}

// TestDecryptMP4ClearLead decrypts a track whose first fragment is in the
// clear. gowidevine skipped decrypting the rest of a segment after a clear
// fragment, and a file without styp boxes is a single segment, so it left
// everything after the lead-in encrypted.
func TestDecryptMP4ClearLead(t *testing.T) {
	initData, media, samples := buildEncryptedMP4(t, 0)

	var got bytes.Buffer
	if err := decryptMP4(initData, bytes.NewReader(media), testLicenseKeys(), &got); err != nil {
		t.Fatalf("decryptMP4: %v", err)
	}

	decoded, err := mp4.DecodeFile(bytes.NewReader(got.Bytes()))
	if err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if decoded.Init.Moov.IsEncrypted(1) {
		t.Fatal("output init segment still signals encryption")
	}
	var i int
	for _, seg := range decoded.Segments {
		for _, frag := range seg.Fragments {
			full, err := frag.GetFullSamples(decoded.Init.Moov.Mvex.Trex)
			if err != nil {
				t.Fatalf("read samples: %v", err)
			}
			for _, s := range full {
				if i >= len(samples) || !bytes.Equal(s.Data, samples[i]) {
					t.Fatalf("sample %d was not decrypted to its original payload", i)
				}
				i++
			}
		}
	}
	if i != len(samples) {
		t.Fatalf("got %d samples, want %d", i, len(samples))
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// TestDecryptMP4Streams guards the memory fix: decrypted fragments must be
// written while the input is still being read, rather than after the whole
// track has been loaded into memory.
func TestDecryptMP4Streams(t *testing.T) {
	initData, media, _ := buildEncryptedMP4(t)

	var read int
	src := &countingReader{r: bytes.NewReader(media), onRead: func(n int) { read += n }}
	writtenMidway := false
	out := writerFunc(func(p []byte) (int, error) {
		if read > 0 && read < len(media) {
			writtenMidway = true
		}
		return len(p), nil
	})
	if err := decryptMP4(initData, src, testLicenseKeys(), out); err != nil {
		t.Fatalf("decryptMP4: %v", err)
	}
	if !writtenMidway {
		t.Fatal("nothing was written until the whole input had been read")
	}
}

func TestDecryptMP4RejectsTruncatedFragment(t *testing.T) {
	initData, media, _ := buildEncryptedMP4(t)

	// Cut the file just before the last mdat, leaving its moof dangling.
	file, err := mp4.DecodeFile(bytes.NewReader(media))
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	segs := file.Segments
	lastMdat := segs[len(segs)-1].LastFragment().Mdat
	truncated := media[:lastMdat.StartPos]

	err = decryptMP4(initData, bytes.NewReader(truncated), testLicenseKeys(), io.Discard)
	if err == nil {
		t.Fatal("decryptMP4 accepted a file ending with a moof and no mdat")
	}
}

func TestDecryptMP4RejectsClearFragmentAfterEncrypted(t *testing.T) {
	initData, media, _ := buildEncryptedMP4(t, 2)

	err := decryptMP4(initData, bytes.NewReader(media), testLicenseKeys(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no sample encryption info") {
		t.Fatalf("decryptMP4 error = %v, want one about the unencrypted fragment", err)
	}
}

func TestCheckSampleEncryption(t *testing.T) {
	samples := []mp4.FullSample{{Data: make([]byte, 100)}, {Data: make([]byte, 50)}}
	iv := mp4.InitializationVector(make([]byte, 8))
	ivs := []mp4.InitializationVector{iv, iv}
	perSampleIV := &mp4.TencBox{DefaultPerSampleIVSize: 8}
	ranges := func(clear uint16, protected uint32) []mp4.SubSamplePattern {
		return []mp4.SubSamplePattern{{BytesOfClearData: clear, BytesOfProtectedData: protected}}
	}

	tests := []struct {
		name    string
		senc    *mp4.SencBox
		tenc    *mp4.TencBox
		wantErr string
	}{
		{"full sample encryption", &mp4.SencBox{IVs: ivs}, perSampleIV, ""},
		{"exact subsample ranges", &mp4.SencBox{IVs: ivs, SubSamples: [][]mp4.SubSamplePattern{ranges(10, 90), ranges(50, 0)}}, perSampleIV, ""},
		{"sample without ranges", &mp4.SencBox{IVs: ivs, SubSamples: [][]mp4.SubSamplePattern{ranges(10, 90), nil}}, perSampleIV, ""},
		{"constant IV", &mp4.SencBox{}, &mp4.TencBox{DefaultConstantIV: make([]byte, 16)}, ""},
		{"missing IV", &mp4.SencBox{IVs: ivs[:1]}, perSampleIV, "1 IVs for 2 samples"},
		{"no IVs at all", &mp4.SencBox{}, &mp4.TencBox{}, "neither per-sample nor constant IVs"},
		{"ranges for too few samples", &mp4.SencBox{IVs: ivs, SubSamples: [][]mp4.SubSamplePattern{ranges(10, 90)}}, perSampleIV, "ranges for 1 of 2 samples"},
		{"ranges short of the sample", &mp4.SencBox{IVs: ivs, SubSamples: [][]mp4.SubSamplePattern{ranges(10, 80), ranges(50, 0)}}, perSampleIV, "cover 90 of its 100 bytes"},
		{"ranges past the sample", &mp4.SencBox{IVs: ivs, SubSamples: [][]mp4.SubSamplePattern{ranges(10, 90), ranges(50, 10)}}, perSampleIV, "cover 60 of its 50 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSampleEncryption(samples, tt.senc, tt.tenc)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkSampleEncryption: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("checkSampleEncryption error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckSeig(t *testing.T) {
	tenc := &mp4.TencBox{DefaultIsProtected: 1, DefaultPerSampleIVSize: 8, DefaultKID: testKID}
	seig := func(edit func(*mp4.SeigSampleGroupEntry)) []mp4.Box {
		entry := &mp4.SeigSampleGroupEntry{IsProtected: 1, PerSampleIVSize: 8, KID: testKID}
		if edit != nil {
			edit(entry)
		}
		return []mp4.Box{&mp4.SgpdBox{GroupingType: "seig", SampleGroupEntries: []mp4.SampleGroupEntry{entry}}}
	}

	tests := []struct {
		name    string
		boxes   []mp4.Box
		wantErr bool
	}{
		{"no sample groups", nil, false},
		{"other grouping type", []mp4.Box{&mp4.SgpdBox{GroupingType: "roll"}}, false},
		{"same as the track defaults", seig(nil), false},
		{"another key", seig(func(e *mp4.SeigSampleGroupEntry) { e.KID = bytes.Repeat([]byte{0xaa}, 16) }), true},
		{"samples marked clear", seig(func(e *mp4.SeigSampleGroupEntry) { e.IsProtected = 0 }), true},
		{"another IV size", seig(func(e *mp4.SeigSampleGroupEntry) { e.PerSampleIVSize = 16 }), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkSeig(tt.boxes, tenc); (err != nil) != tt.wantErr {
				t.Fatalf("checkSeig error = %v, want error: %v", err, tt.wantErr)
			}
		})
	}
}
