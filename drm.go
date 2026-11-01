package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/iyear/gowidevine"
	"github.com/iyear/gowidevine/widevinepb"
	"github.com/unki2aut/go-mpd"
)

// widevineSystemID is the Widevine DRM system ID, used to tag PSSH boxes.
var widevineSystemID = mp4.UUID{0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed}

// widevineSchemeSuffix identifies the Widevine ContentProtection element in an
// MPD by its schemeIdUri.
const widevineSchemeSuffix = "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"

// psshFromProtections returns the Widevine PSSH carried by a list of
// ContentProtection elements, falling back to the first PSSH if none of them is
// explicitly Widevine. Crunchyroll also lists a PlayReady/common system ID
// (9a04f079-9840-4286-ab92-e65be0885f95) alongside Widevine, so the first PSSH
// is not always the right one.
func psshFromProtections(protections []mpd.Descriptor) *string {
	var fallback *string
	for _, contentProtection := range protections {
		if contentProtection.CencPSSH == nil {
			continue
		}
		if contentProtection.SchemeIDURI != nil && strings.Contains(*contentProtection.SchemeIDURI, widevineSchemeSuffix) {
			return contentProtection.CencPSSH
		}
		if fallback == nil {
			fallback = contentProtection.CencPSSH
		}
	}
	return fallback
}

// getPssh finds the PSSH in the MPD manifest. Crunchyroll serves two manifest
// shapes: one puts ContentProtection on the AdaptationSet, the other on each
// Representation, so both are searched. The Widevine PSSH is preferred.
func getPssh(m *mpd.MPD) *string {
	if len(m.Period) == 0 {
		return nil
	}
	for _, set := range m.Period[0].AdaptationSets {
		if set == nil {
			continue
		}
		if pssh := psshFromProtections(set.ContentProtections); pssh != nil {
			return pssh
		}
		for _, representation := range set.Representations {
			if pssh := psshFromProtections(representation.ContentProtections); pssh != nil {
				return pssh
			}
		}
	}
	return nil
}

// toWidevinePssh rewrites a PSSH box so its system ID is Widevine's. Crunchyroll
// now serves the Widevine PSSH data inside a box tagged with the PlayReady/common
// system ID, which gowidevine's NewPSSH rejects. The payload itself is left
// untouched; only the system ID field is normalized.
func toWidevinePssh(pssh []byte) ([]byte, error) {
	box, err := mp4.DecodeBox(0, bytes.NewReader(pssh))
	if err != nil {
		return nil, fmt.Errorf("decode PSSH box: %w", err)
	}
	psshBox, ok := box.(*mp4.PsshBox)
	if !ok {
		return nil, fmt.Errorf("box is a %s instead of a PSSH", box.Type())
	}
	if bytes.Equal(psshBox.SystemID, widevineSystemID) {
		return pssh, nil
	}

	psshBox.SystemID = widevineSystemID
	var buf bytes.Buffer
	if err := psshBox.Encode(&buf); err != nil {
		return nil, fmt.Errorf("encode PSSH box: %w", err)
	}
	return buf.Bytes(), nil
}

type CrunchyrollWidevineLicenseResponse struct {
	License string `json:"license"`
}

func sendChallenge(contentId, videoToken string, challenge []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, "https://www.crunchyroll.com/license/v1/license/widevine", bytes.NewReader(challenge))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Cr-Content-Id", contentId)
	req.Header.Set("X-Cr-Video-Token", videoToken)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", "https://static.crunchyroll.com")
	req.Header.Set("Referer", "https://static.crunchyroll.com/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0")
	resp, err := DoRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse JSON response
	res, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result CrunchyrollWidevineLicenseResponse
	if err = json.Unmarshal(res, &result); err != nil {
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(result.License)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func getWidevineDevice() (*widevine.Device, error) {
	var clientID []byte
	var privateKey []byte
	files, _ := os.ReadDir(".")
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".wvd") {
			wvd, err := os.Open(file.Name())
			if err != nil {
				return nil, err
			}

			return widevine.NewDevice(widevine.FromWVD(io.NopCloser(wvd)))
		} else if file.Name() == "client_id.bin" {
			f, err := os.Open("client_id.bin")
			if err != nil {
				return nil, err
			}
			defer f.Close()

			clientID, err = io.ReadAll(f)
		} else if file.Name() == "private_key.pem" {
			f, err := os.Open("private_key.pem")
			if err != nil {
				return nil, err
			}
			defer f.Close()

			privateKey, err = io.ReadAll(f)
			break
		}
	}

	if len(clientID) > 0 && len(privateKey) > 0 {
		return widevine.NewDevice(widevine.FromRaw(clientID, privateKey))
	}

	return nil, nil
}

func getLicense(psshData, contentId, videoToken string) ([]*widevine.Key, error) {
	device, err := getWidevineDevice()
	if device == nil {
		return nil, errors.New("no widevine device provided. You either need:\n- a \".wvd\" file,\n- or \"client_id.bin\" and \"private_key.pem\" files.\nI'm not sharing links for obvious reasons, but search \"ready to use cdms\" on Google :)\n")
	} else if err != nil {
		return nil, err
	}
	cdm := widevine.NewCDM(device)
	decodedPssh, err := base64.StdEncoding.DecodeString(psshData)
	if err != nil {
		return nil, err
	}
	normalizedPssh, err := toWidevinePssh(decodedPssh)
	if err != nil {
		return nil, err
	}
	pssh, err := widevine.NewPSSH(normalizedPssh)
	if err != nil {
		return nil, err
	}

	challenge, parseLicense, err := cdm.GetLicenseChallenge(pssh, widevinepb.LicenseType_AUTOMATIC, false)
	if err != nil {
		return nil, err
	}
	resp, err := sendChallenge(contentId, videoToken, challenge)
	if err != nil {
		return nil, err
	}
	keys, err := parseLicense(resp)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// decryptMP4 decrypts a fragmented MP4 read from media, choosing the content
// key whose ID matches the track's KID. gowidevine's DecryptMP4Auto instead
// uses the first content key in the license, which decrypts to garbage when the
// license carries a separate key per track.
//
// initData is the initialization segment on its own. The KID lives there, so
// the key can be selected without reading the media. media must start with the
// same init segment, followed by the media segments.
//
// The media is decrypted one fragment at a time, so memory use is bounded by
// the largest fragment instead of the whole track. gowidevine's DecryptMP4
// decodes the entire file into memory first, which held every track of an
// episode in RAM at once and exhausted memory on small machines.
//
// Decrypting with the wrong key or IV doesn't fail, it just produces noise, so
// anything mp4ff would get silently wrong is rejected with an error instead of
// leaving a few seconds of garbage in the middle of an otherwise fine file.
func decryptMP4(initData []byte, media io.Reader, licenseKeys []*widevine.Key, output io.Writer) (err error) {
	// mp4ff panics on some malformed input. Decryption runs on a download
	// worker goroutine, where a panic would crash the whole program instead
	// of failing this episode.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("malformed MP4: %v", r)
		}
	}()

	init, err := mp4.DecodeFile(bytes.NewReader(initData))
	if err != nil {
		return fmt.Errorf("decode MP4 init segment: %w", err)
	}
	if init.Init == nil {
		return errors.New("MP4 has no initialization segment")
	}

	decryptInfo, err := mp4.DecryptInit(init.Init)
	if err != nil {
		return fmt.Errorf("read MP4 encryption info: %w", err)
	}
	key, err := contentKeyFor(decryptInfo, licenseKeys)
	if err != nil {
		return err
	}
	for _, trak := range init.Init.Moov.Traks {
		if _, tenc := encryptedTrack(decryptInfo, trak.Tkhd.TrackID); tenc != nil {
			if err = checkSeig(trak.Mdia.Minf.Stbl.Children, tenc); err != nil {
				return err
			}
		}
	}

	// DecryptInit has already stripped the encryption boxes from the init
	// segment, so it can be written out as is.
	if err = init.Init.Encode(output); err != nil {
		return fmt.Errorf("write init segment: %w", err)
	}
	return decryptFragments(media, decryptInfo, key, output)
}

// contentKeyFor returns the license content key matching the KID of the first
// encrypted track that has one.
func contentKeyFor(decryptInfo mp4.DecryptInfo, licenseKeys []*widevine.Key) (*widevine.Key, error) {
	var unmatched []string
	for _, track := range decryptInfo.TrackInfos {
		if track.Sinf == nil || track.Sinf.Schi == nil || track.Sinf.Schi.Tenc == nil {
			continue
		}
		kid := track.Sinf.Schi.Tenc.DefaultKID
		// Match this track's KID with a content key returned by the license.
		for _, key := range licenseKeys {
			if key.Type == widevinepb.License_KeyContainer_CONTENT && bytes.Equal(key.ID, kid) {
				return key, nil
			}
		}
		// Keep looking: a later track may still match a key in the license.
		// The conversion skips UUID's String method, which %x would hex-encode.
		unmatched = append(unmatched, fmt.Sprintf("%x", []byte(kid)))
	}

	if len(unmatched) > 0 {
		return nil, fmt.Errorf("no license key found for MP4 KID(s) %s", strings.Join(unmatched, ", "))
	}
	return nil, errors.New("MP4 has no encrypted tracks")
}

// decryptFragments reads media box by box and writes each fragment (optional
// emsg boxes, a moof and its mdat) to output as soon as it is decrypted. The
// ftyp and moov repeat the init segment decryptMP4 has already written. sidx
// boxes are dropped because decryption shrinks the moofs they index, which is
// also what gowidevine's DecryptMP4 did.
func decryptFragments(media io.Reader, decryptInfo mp4.DecryptInfo, key *widevine.Key, output io.Writer) error {
	var (
		pos       uint64
		frag      *mp4.Fragment
		encrypted bool // whether any fragment so far was encrypted
	)
	for {
		// Positions are tracked from the start of media, as mp4ff's own file
		// decoder does, so absolute sample offsets in the moofs still resolve.
		box, err := mp4.DecodeBox(pos, media)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("decode MP4 box at %d: %w", pos, err)
		}
		boxPos := pos
		pos += box.Size()

		switch b := box.(type) {
		case *mp4.StypBox:
			if err = b.Encode(output); err != nil {
				return fmt.Errorf("write styp: %w", err)
			}
		case *mp4.EmsgBox, *mp4.MoofBox:
			if frag == nil || frag.Moof != nil {
				frag = mp4.NewFragment()
			}
			frag.AddChild(b)
		case *mp4.MdatBox:
			if frag == nil || frag.Moof == nil {
				return fmt.Errorf("mdat at %d has no preceding moof", boxPos)
			}
			frag.AddChild(b)
			var fragEncrypted bool
			if fragEncrypted, err = decryptFragment(frag, decryptInfo, key); err != nil {
				return fmt.Errorf("fragment at %d: %w", frag.Moof.StartPos, err)
			}
			// A clear lead only happens at the start of a stream. A fragment
			// without sample encryption info after that is far more likely
			// broken than in the clear, and passing it through would leave a
			// few seconds of noise in the output.
			if encrypted && !fragEncrypted {
				return fmt.Errorf("fragment at %d has no sample encryption info, but earlier fragments were encrypted", frag.Moof.StartPos)
			}
			encrypted = encrypted || fragEncrypted
			if err = frag.Encode(output); err != nil {
				return fmt.Errorf("write fragment: %w", err)
			}
			frag = nil
		}
	}
	if frag != nil && frag.Moof != nil {
		return errors.New("MP4 ends with a moof that has no mdat")
	}
	return nil
}

// decryptFragment decrypts frag in place and reports whether it was encrypted.
// A fragment with no sample encryption box is in the clear and left untouched:
// a stream may start with unencrypted segments before switching to encrypted
// ones. See https://github.com/iyear/gowidevine/pull/26#issuecomment-2385960551
func decryptFragment(frag *mp4.Fragment, decryptInfo mp4.DecryptInfo, key *widevine.Key) (bool, error) {
	encrypted := false
	for _, traf := range frag.Moof.Trafs {
		hasSenc, parsed := traf.ContainsSencBox()
		if !hasSenc {
			continue
		}
		info, tenc := encryptedTrack(decryptInfo, traf.Tfhd.TrackID)
		if tenc == nil {
			continue // mp4ff leaves tracks in the clear alone
		}
		encrypted = true

		// Every encrypted track is decrypted with the one key that was
		// selected, so one with another KID would come out as noise.
		if !bytes.Equal(tenc.DefaultKID, key.ID) {
			return false, fmt.Errorf("track %d is encrypted with KID %x, not the license key's %x", traf.Tfhd.TrackID, []byte(tenc.DefaultKID), key.ID)
		}
		if err := checkSeig(traf.Children, tenc); err != nil {
			return false, err
		}
		if !parsed {
			if err := traf.ParseReadSenc(tenc.DefaultPerSampleIVSize, frag.Moof.StartPos); err != nil {
				return false, fmt.Errorf("read sample encryption info: %w", err)
			}
		}
		samples, err := frag.GetFullSamples(info.Trex)
		if err != nil {
			return false, fmt.Errorf("read samples: %w", err)
		}
		senc := traf.Senc
		if senc == nil {
			senc = traf.UUIDSenc.Senc
		}
		if err = checkSampleEncryption(samples, senc, tenc); err != nil {
			return false, err
		}
	}
	if !encrypted {
		return false, nil
	}
	if err := mp4.DecryptFragment(frag, decryptInfo, key.Key); err != nil {
		return false, fmt.Errorf("decrypt: %w", err)
	}
	return true, nil
}

// encryptedTrack returns the decryption info of a track and its default
// encryption parameters. tenc is nil for a track in the clear.
func encryptedTrack(decryptInfo mp4.DecryptInfo, trackID uint32) (info mp4.DecryptTrackInfo, tenc *mp4.TencBox) {
	for _, info = range decryptInfo.TrackInfos {
		if info.TrackID == trackID {
			if info.Sinf != nil && info.Sinf.Schi != nil {
				tenc = info.Sinf.Schi.Tenc
			}
			return info, tenc
		}
	}
	return mp4.DecryptTrackInfo{}, nil
}

// checkSeig rejects 'seig' sample group entries in boxes that differ from the
// track's default encryption parameters. mp4ff only takes the IV size from
// them, so a group that switches key (key rotation) or marks samples as clear
// would be decrypted with the default key and come out as noise.
func checkSeig(boxes []mp4.Box, tenc *mp4.TencBox) error {
	for _, box := range boxes {
		sgpd, ok := box.(*mp4.SgpdBox)
		if !ok || sgpd.GroupingType != "seig" {
			continue
		}
		for _, entry := range sgpd.SampleGroupEntries {
			seig, ok := entry.(*mp4.SeigSampleGroupEntry)
			if !ok || seig.IsProtected != tenc.DefaultIsProtected ||
				!bytes.Equal(seig.KID, tenc.DefaultKID) ||
				seig.PerSampleIVSize != tenc.DefaultPerSampleIVSize ||
				!bytes.Equal(seig.ConstantIV, tenc.DefaultConstantIV) ||
				seig.CryptByteBlock != tenc.DefaultCryptByteBlock ||
				seig.SkipByteBlock != tenc.DefaultSkipByteBlock {
				return errors.New("MP4 changes encryption parameters partway through (e.g. key rotation), which isn't supported")
			}
		}
	}
	return nil
}

// checkSampleEncryption verifies that senc fully describes every sample before
// mp4ff decrypts them. On a mismatched IV count mp4ff quietly decrypts with a
// zero IV, on subsample ranges shorter than a sample it leaves the rest of the
// sample encrypted, and on longer ones it panics.
func checkSampleEncryption(samples []mp4.FullSample, senc *mp4.SencBox, tenc *mp4.TencBox) error {
	if tenc.DefaultPerSampleIVSize > 0 {
		if len(senc.IVs) != len(samples) {
			return fmt.Errorf("sample encryption info has %d IVs for %d samples", len(senc.IVs), len(samples))
		}
	} else if len(tenc.DefaultConstantIV) == 0 {
		return errors.New("track has neither per-sample nor constant IVs")
	}

	if len(senc.SubSamples) == 0 {
		return nil // every sample is encrypted in full
	}
	if len(senc.SubSamples) != len(samples) {
		return fmt.Errorf("sample encryption info has subsample ranges for %d of %d samples", len(senc.SubSamples), len(samples))
	}
	for i, sample := range samples {
		if len(senc.SubSamples[i]) == 0 {
			continue // encrypted in full
		}
		var covered uint64
		for _, ss := range senc.SubSamples[i] {
			covered += uint64(ss.BytesOfClearData) + uint64(ss.BytesOfProtectedData)
		}
		if covered != uint64(len(sample.Data)) {
			return fmt.Errorf("subsample ranges of sample %d cover %d of its %d bytes", i, covered, len(sample.Data))
		}
	}
	return nil
}
