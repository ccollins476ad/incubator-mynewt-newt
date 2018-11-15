/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package image

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"

	keywrap "github.com/NickBall/go-aes-key-wrap"
	log "github.com/Sirupsen/logrus"

	"mynewt.apache.org/newt/newt/pkg"
	"mynewt.apache.org/newt/util"
)

// Set this to enable RSA-PSS for RSA signatures, instead of PKCS#1
// v1.5.  Eventually, this should be the default.
var UseRsaPss = false

// Use old image format
var UseV1 = false

// Public key file to encrypt image
var PubKeyFile = ""

type ImageVersion struct {
	Major    uint8
	Minor    uint8
	Rev      uint16
	BuildNum uint32
}

type ImageKey struct {
	// Only one of these members is non-nil.
	Rsa *rsa.PrivateKey
	Ec  *ecdsa.PrivateKey
}

type Image struct {
	SourceBin  string
	SourceImg  string
	TargetImg  string
	Version    ImageVersion
	Keys       []ImageKey
	KeyId      uint8
	Hash       []byte
	SrcSkip    int // Number of bytes to skip from the source image.
	HeaderSize int // If non-zero pad out the header to this size.
	TotalSize  int // Total size, in bytes, of the generated .img file.
}

type ImageHdr struct {
	Magic uint32
	Pad1  uint32
	HdrSz uint16
	Pad2  uint16
	ImgSz uint32
	Flags uint32
	Vers  ImageVersion
	Pad3  uint32
}

type ImageTlvInfo struct {
	Magic     uint16
	TlvTotLen uint16
}

type ImageTrailerTlv struct {
	Type uint8
	Pad  uint8
	Len  uint16
}

type ImageCreator struct {
	Body         []byte
	Version      ImageVersion
	SigKeys      []ImageKey
	PlainSecret  []byte
	CipherSecret []byte
	HeaderSize   int
	InitialHash  []byte
	Bootable     bool

	hash hash.Hash
}

const (
	IMAGE_MAGIC         = 0x96f3b83d /* Image header magic */
	IMAGE_TRAILER_MAGIC = 0x6907     /* Image tlv info magic */
)

const (
	IMAGE_HEADER_SIZE  = 32
	IMAGE_TRAILER_SIZE = 4
	IMAGE_TLV_SIZE     = 4 /* Plus `value` field. */
)

/*
 * Image header flags.
 */
const (
	IMAGEv1_F_PIC                      = 0x00000001
	IMAGEv1_F_SHA256                   = 0x00000002 /* Image contains hash TLV */
	IMAGEv1_F_PKCS15_RSA2048_SHA256    = 0x00000004 /* PKCS15 w/RSA2048 and SHA256 */
	IMAGEv1_F_ECDSA224_SHA256          = 0x00000008 /* ECDSA224 over SHA256 */
	IMAGEv1_F_NON_BOOTABLE             = 0x00000010 /* non bootable image */
	IMAGEv1_F_ECDSA256_SHA256          = 0x00000020 /* ECDSA256 over SHA256 */
	IMAGEv1_F_PKCS1_PSS_RSA2048_SHA256 = 0x00000040 /* RSA-PSS w/RSA2048 and SHA256 */

	IMAGE_F_PIC          = 0x00000001
	IMAGE_F_NON_BOOTABLE = 0x00000002 /* non bootable image */
	IMAGE_F_ENCRYPTED    = 0x00000004 /* encrypted image */
)

/*
 * Image trailer TLV types.
 */
const (
	IMAGEv1_TLV_SHA256   = 1
	IMAGEv1_TLV_RSA2048  = 2
	IMAGEv1_TLV_ECDSA224 = 3
	IMAGEv1_TLV_ECDSA256 = 4

	IMAGE_TLV_KEYHASH  = 0x01
	IMAGE_TLV_SHA256   = 0x10
	IMAGE_TLV_RSA2048  = 0x20
	IMAGE_TLV_ECDSA224 = 0x21
	IMAGE_TLV_ECDSA256 = 0x22
	IMAGE_TLV_ENC_RSA  = 0x30
	IMAGE_TLV_ENC_KEK  = 0x31
)

var imageTlvTypeNameMap = map[uint8]string{
	IMAGE_TLV_KEYHASH:  "KEYHASH",
	IMAGE_TLV_SHA256:   "SHA256",
	IMAGE_TLV_RSA2048:  "RSA2048",
	IMAGE_TLV_ECDSA224: "ECDSA224",
	IMAGE_TLV_ECDSA256: "ECDSA256",
	IMAGE_TLV_ENC_RSA:  "ENC_RSA",
	IMAGE_TLV_ENC_KEK:  "ENC_KEK",
}

/*
 * Data that's going to go to build manifest file
 */
type ImageManifestSizeArea struct {
	Name string `json:"name"`
	Size uint32 `json:"size"`
}

type ImageManifestSizeSym struct {
	Name  string                   `json:"name"`
	Areas []*ImageManifestSizeArea `json:"areas"`
}

type ImageManifestSizeFile struct {
	Name string                  `json:"name"`
	Syms []*ImageManifestSizeSym `json:"sym"`
}

type ImageManifestSizePkg struct {
	Name  string                   `json:"name"`
	Files []*ImageManifestSizeFile `json:"files"`
}

type ImageManifestSizeCollector struct {
	Pkgs []*ImageManifestSizePkg
}

type ImageManifest struct {
	Name       string              `json:"name"`
	Date       string              `json:"build_time"`
	Version    string              `json:"build_version"`
	BuildID    string              `json:"id"`
	Image      string              `json:"image"`
	ImageHash  string              `json:"image_hash"`
	Loader     string              `json:"loader"`
	LoaderHash string              `json:"loader_hash"`
	Pkgs       []*ImageManifestPkg `json:"pkgs"`
	LoaderPkgs []*ImageManifestPkg `json:"loader_pkgs,omitempty"`
	TgtVars    []string            `json:"target"`
	Repos      []ImageManifestRepo `json:"repos"`

	PkgSizes       []*ImageManifestSizePkg `json:"pkgsz"`
	LoaderPkgSizes []*ImageManifestSizePkg `json:"loader_pkgsz,omitempty"`
}

type ImageManifestPkg struct {
	Name string `json:"name"`
	Repo string `json:"repo"`
}

type ImageManifestRepo struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
	Dirty  bool   `json:"dirty,omitempty"`
	URL    string `json:"url,omitempty"`
}

type RepoManager struct {
	repos map[string]ImageManifestRepo
}

type ECDSASig struct {
	R *big.Int
	S *big.Int
}

func ImageTlvTypeName(tlvType uint8) string {
	name, ok := imageTlvTypeNameMap[tlvType]
	if !ok {
		return "???"
	}

	return name
}

func ParseVersion(versStr string) (ImageVersion, error) {
	var err error
	var major uint64
	var minor uint64
	var rev uint64
	var buildNum uint64
	var ver ImageVersion

	components := strings.Split(versStr, ".")
	major, err = strconv.ParseUint(components[0], 10, 8)
	if err != nil {
		return ver, util.FmtNewtError("Invalid version string %s", versStr)
	}
	if len(components) > 1 {
		minor, err = strconv.ParseUint(components[1], 10, 8)
		if err != nil {
			return ver, util.FmtNewtError("Invalid version string %s", versStr)
		}
	}
	if len(components) > 2 {
		rev, err = strconv.ParseUint(components[2], 10, 16)
		if err != nil {
			return ver, util.FmtNewtError("Invalid version string %s", versStr)
		}
	}
	if len(components) > 3 {
		buildNum, err = strconv.ParseUint(components[3], 10, 32)
		if err != nil {
			return ver, util.FmtNewtError("Invalid version string %s", versStr)
		}
	}

	ver.Major = uint8(major)
	ver.Minor = uint8(minor)
	ver.Rev = uint16(rev)
	ver.BuildNum = uint32(buildNum)
	return ver, nil
}

func (ver ImageVersion) String() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ver.Major, ver.Minor, ver.Rev, ver.BuildNum)
}

func NewImage(srcBinPath string, dstImgPath string) (*Image, error) {
	image := &Image{}

	image.SourceBin = srcBinPath
	image.TargetImg = dstImgPath
	return image, nil
}

func OldImage(imgPath string) (*Image, error) {
	image := &Image{}

	image.SourceImg = imgPath

	return image, nil
}

func (image *Image) SetVersion(versStr string) error {
	ver, err := ParseVersion(versStr)
	if err != nil {
		return err
	}

	log.Debugf("Assigning version number %d.%d.%d.%d\n",
		ver.Major, ver.Minor, ver.Rev, ver.BuildNum)

	image.Version = ver

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, image.Version)
	if err != nil {
		fmt.Printf("Bombing out\n")
		return nil
	}

	return nil
}

func ParsePrivateKey(keyBytes []byte) (interface{}, error) {
	var privKey interface{}
	var err error

	block, data := pem.Decode(keyBytes)
	if block != nil && block.Type == "EC PARAMETERS" {
		/*
		 * Openssl prepends an EC PARAMETERS block before the
		 * key itself.  If we see this first, just skip it,
		 * and go on to the data block.
		 */
		block, _ = pem.Decode(data)
	}
	if block != nil && block.Type == "RSA PRIVATE KEY" {
		/*
		 * ParsePKCS1PrivateKey returns an RSA private key from its ASN.1
		 * PKCS#1 DER encoded form.
		 */
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, util.FmtNewtError(
				"Private key parsing failed: %s", err)
		}
	}
	if block != nil && block.Type == "EC PRIVATE KEY" {
		/*
		 * ParseECPrivateKey returns a EC private key
		 */
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, util.FmtNewtError(
				"Private key parsing failed: %s", err)
		}
	}
	if block != nil && block.Type == "PRIVATE KEY" {
		// This indicates a PKCS#8 unencrypted private key.
		// The particular type of key will be indicated within
		// the key itself.
		privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, util.FmtNewtError(
				"Private key parsing failed: %s", err)
		}
	}
	if block != nil && block.Type == "ENCRYPTED PRIVATE KEY" {
		// This indicates a PKCS#8 key wrapped with PKCS#5
		// encryption.
		privKey, err = parseEncryptedPrivateKey(block.Bytes)
		if err != nil {
			return nil, util.FmtNewtError("Unable to decode encrypted private key: %s", err)
		}
	}
	if privKey == nil {
		return nil, util.NewNewtError("Unknown private key format, EC/RSA private " +
			"key in PEM format only.")
	}

	return privKey, nil
}

func ReadKey(filename string) (ImageKey, error) {
	key := ImageKey{}

	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return key, util.FmtNewtError("Error reading key file: %s", err)
	}

	privKey, err := ParsePrivateKey(keyBytes)
	if err != nil {
		return key, err
	}

	switch priv := privKey.(type) {
	case *rsa.PrivateKey:
		key.Rsa = priv
	case *ecdsa.PrivateKey:
		key.Ec = priv
	default:
		return key, util.NewNewtError("Unknown private key format")
	}

	return key, nil
}

func ReadKeys(filenames []string) ([]ImageKey, error) {
	keys := make([]ImageKey, len(filenames))

	for i, filename := range filenames {
		key, err := ReadKey(filename)
		if err != nil {
			return nil, err
		}

		keys[i] = key
	}

	return keys, nil
}

func (key *ImageKey) assertValid() {
	if key.Rsa == nil && key.Ec == nil {
		panic("invalid key; neither RSA nor ECC")
	}

	if key.Rsa != nil && key.Ec != nil {
		panic("invalid key; neither RSA nor ECC")
	}
}

func (image *Image) SetKeys(keys []ImageKey) {
	image.Keys = keys
}

func (key *ImageKey) sigKeyHash() ([]uint8, error) {
	key.assertValid()

	if key.Rsa != nil {
		pubkey, _ := asn1.Marshal(key.Rsa.PublicKey)
		sum := sha256.Sum256(pubkey)
		return sum[:4], nil
	} else {
		switch key.Ec.Curve.Params().Name {
		case "P-224":
			fallthrough
		case "P-256":
			pubkey, _ := x509.MarshalPKIXPublicKey(&key.Ec.PublicKey)
			sum := sha256.Sum256(pubkey)
			return sum[:4], nil
		default:
			return nil, util.NewNewtError("Unsupported ECC curve")
		}
	}
}

func (key *ImageKey) sigLen() uint16 {
	key.assertValid()

	if key.Rsa != nil {
		return 256
	} else {
		switch key.Ec.Curve.Params().Name {
		case "P-224":
			return 68
		case "P-256":
			return 72
		default:
			return 0
		}
	}
}

func (key *ImageKey) sigTlvType() uint8 {
	key.assertValid()

	if UseV1 {
		if key.Rsa != nil {
			return IMAGEv1_TLV_RSA2048
		} else {
			switch key.Ec.Curve.Params().Name {
			case "P-224":
				return IMAGEv1_TLV_ECDSA224
			case "P-256":
				return IMAGEv1_TLV_ECDSA256
			default:
				return 0
			}
		}
	} else {
		if key.Rsa != nil {
			return IMAGE_TLV_RSA2048
		} else {
			switch key.Ec.Curve.Params().Name {
			case "P-224":
				return IMAGE_TLV_ECDSA224
			case "P-256":
				return IMAGE_TLV_ECDSA256
			default:
				return 0
			}
		}
	}
}

func (image *Image) ReSign() error {
	srcImg, err := os.Open(image.SourceImg)
	if err != nil {
		return util.FmtNewtError("Can't open image file %s: %s",
			image.SourceImg, err.Error())
	}

	srcInfo, err := srcImg.Stat()
	if err != nil {
		return util.FmtNewtError("Can't stat image file %s: %s",
			image.SourceImg, err.Error())
	}

	var hdr1 ImageHdrV1
	var hdr2 ImageHdr
	var hdrSz uint16
	var imgSz uint32

	err = binary.Read(srcImg, binary.LittleEndian, &hdr1)
	if err == nil {
		srcImg.Seek(0, 0)
		err = binary.Read(srcImg, binary.LittleEndian, &hdr2)
	}
	if err != nil {
		return util.FmtNewtError("Failing to access image %s: %s",
			image.SourceImg, err.Error())
	}
	if hdr1.Magic == IMAGEv1_MAGIC {
		if uint32(srcInfo.Size()) !=
			uint32(hdr1.HdrSz)+hdr1.ImgSz+uint32(hdr1.TlvSz) {

			return util.FmtNewtError("File %s is not an image\n",
				image.SourceImg)
		}
		imgSz = hdr1.ImgSz
		hdrSz = hdr1.HdrSz
		image.Version = hdr1.Vers

		log.Debugf("Resigning %s (ver %d.%d.%d.%d)", image.SourceImg,
			hdr1.Vers.Major, hdr1.Vers.Minor, hdr1.Vers.Rev,
			hdr1.Vers.BuildNum)
	} else if hdr2.Magic == IMAGE_MAGIC {
		if uint32(srcInfo.Size()) < uint32(hdr2.HdrSz)+hdr2.ImgSz {
			return util.FmtNewtError("File %s is not an image\n",
				image.SourceImg)
		}
		imgSz = hdr2.ImgSz
		hdrSz = hdr2.HdrSz
		image.Version = hdr2.Vers

		log.Debugf("Resigning %s (ver %d.%d.%d.%d)", image.SourceImg,
			hdr2.Vers.Major, hdr2.Vers.Minor, hdr2.Vers.Rev,
			hdr2.Vers.BuildNum)
	} else {
		return util.FmtNewtError("File %s is not an image\n",
			image.SourceImg)
	}
	srcImg.Seek(int64(hdrSz), 0)

	tmpBin, err := ioutil.TempFile("", "")
	if err != nil {
		return util.FmtNewtError("Creating temp file failed: %s",
			err.Error())
	}
	tmpBinName := tmpBin.Name()
	defer os.Remove(tmpBinName)

	log.Debugf("Extracting data from %s:%d-%d to %s\n",
		image.SourceImg, int64(hdrSz), int64(hdrSz)+int64(imgSz), tmpBinName)
	_, err = io.CopyN(tmpBin, srcImg, int64(imgSz))
	srcImg.Close()
	tmpBin.Close()
	if err != nil {
		return util.FmtNewtError("Cannot copy to tmpfile %s: %s",
			tmpBin.Name(), err.Error())
	}

	image.SourceBin = tmpBinName
	image.TargetImg = image.SourceImg
	image.HeaderSize = int(hdrSz)

	return image.Generate(nil)
}

func generateEncTlv(cipherSecret []byte) (RawImageTlv, error) {
	var encType uint8

	if len(cipherSecret) == 256 {
		encType = IMAGE_TLV_ENC_RSA
	} else if len(cipherSecret) == 24 {
		encType = IMAGE_TLV_ENC_KEK
	} else {
		return RawImageTlv{}, util.FmtNewtError("Invalid enc TLV size ")
	}

	return RawImageTlv{
		Header: ImageTrailerTlv{
			Type: encType,
			Pad:  0,
			Len:  uint16(len(cipherSecret)),
		},
		Data: cipherSecret,
	}, nil
}

func generateSigRsa(key *rsa.PrivateKey, hash []byte) ([]byte, error) {
	var signature []byte
	var err error

	if UseRsaPss || !UseV1 {
		opts := rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}
		signature, err = rsa.SignPSS(
			rand.Reader, key, crypto.SHA256, hash, &opts)
	} else {
		signature, err = rsa.SignPKCS1v15(
			rand.Reader, key, crypto.SHA256, hash)
	}
	if err != nil {
		return nil, util.FmtNewtError("Failed to compute signature: %s", err)
	}

	return signature, nil
}

func generateSigEc(key *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		return nil, util.FmtNewtError("Failed to compute signature: %s", err)
	}

	ECDSA := ECDSASig{
		R: r,
		S: s,
	}

	signature, err := asn1.Marshal(ECDSA)
	if err != nil {
		return nil, util.FmtNewtError("Failed to construct signature: %s", err)
	}

	return signature, nil
}

func generateSigTlvRsa(key ImageKey, hash []byte) (RawImageTlv, error) {
	sig, err := generateSigRsa(key.Rsa, hash)
	if err != nil {
		return RawImageTlv{}, err
	}

	return RawImageTlv{
		Header: ImageTrailerTlv{
			Type: key.sigTlvType(),
			Pad:  0,
			Len:  256, /* 2048 bits */
		},
		Data: sig,
	}, nil
}

func generateSigTlvEc(key ImageKey, hash []byte) (RawImageTlv, error) {
	sig, err := generateSigEc(key.Ec, hash)
	if err != nil {
		return RawImageTlv{}, err
	}

	sigLen := key.sigLen()
	if len(sig) > int(sigLen) {
		return RawImageTlv{}, util.FmtNewtError("Something is really wrong\n")
	}

	b := &bytes.Buffer{}

	if _, err := b.Write(sig); err != nil {
		return RawImageTlv{},
			util.FmtNewtError("Failed to append sig: %s", err.Error())
	}

	pad := make([]byte, int(sigLen)-len(sig))
	if _, err := b.Write(pad); err != nil {
		return RawImageTlv{}, util.FmtNewtError(
			"Failed to serialize image trailer: %s", err.Error())
	}

	return RawImageTlv{
		Header: ImageTrailerTlv{
			Type: key.sigTlvType(),
			Pad:  0,
			Len:  sigLen + uint16(len(pad)),
		},
		Data: b.Bytes(),
	}, nil
}

func generateSigTlv(key ImageKey, hash []byte) (RawImageTlv, error) {
	key.assertValid()

	if key.Rsa != nil {
		return generateSigTlvRsa(key, hash)
	} else {
		return generateSigTlvEc(key, hash)
	}
}

func generateKeyHashTlv(key ImageKey) (RawImageTlv, error) {
	key.assertValid()

	keyHash, err := key.sigKeyHash()
	if err != nil {
		return RawImageTlv{}, util.FmtNewtError(
			"Failed to compute hash of the public key: %s", err.Error())
	}

	return RawImageTlv{
		Header: ImageTrailerTlv{
			Type: IMAGE_TLV_KEYHASH,
			Pad:  0,
			Len:  uint16(len(keyHash)),
		},
		Data: keyHash,
	}, nil
}

func GenerateSigTlvs(keys []ImageKey, hash []byte) ([]RawImageTlv, error) {
	var tlvs []RawImageTlv

	for _, key := range keys {
		key.assertValid()

		tlv, err := generateKeyHashTlv(key)
		if err != nil {
			return nil, err
		}
		tlvs = append(tlvs, tlv)

		tlv, err = generateSigTlv(key, hash)
		if err != nil {
			return nil, err
		}
		tlvs = append(tlvs, tlv)
	}

	return tlvs, nil
}

func (image *Image) generateV2(loader *Image) error {
	ic := NewImageCreator()

	srcBin, err := ioutil.ReadFile(image.SourceBin)
	if err != nil {
		return util.FmtNewtError("Can't read app binary: %s", err.Error())
	}

	if image.SrcSkip > len(srcBin) {
		return util.FmtNewtError(
			"request to skip %d bytes of %d byte file (%s)",
			image.SrcSkip, len(srcBin), image.SourceBin)
	}

	for i := 0; i < image.SrcSkip; i++ {
		if srcBin[i] != 0 {
			log.Warnf(
				"Skip requested of image %s; nonzero byte found at offset %d",
				image.SourceBin, image.SrcSkip)
		}
	}

	imgFile, err := os.OpenFile(image.TargetImg,
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return util.FmtNewtError("Can't open target image %s: %s",
			image.TargetImg, err.Error())
	}
	defer imgFile.Close()

	ic.Body = srcBin[image.SrcSkip:]
	ic.Version = image.Version
	ic.SigKeys = image.Keys

	if loader != nil {
		ic.InitialHash = loader.Hash
		ic.Bootable = false
	} else {
		ic.Bootable = true
	}
	ic.HeaderSize = image.HeaderSize

	if PubKeyFile != "" {
		plainSecret := make([]byte, 16)
		if _, err := rand.Read(plainSecret); err != nil {
			return util.FmtNewtError("Random generation error: %s\n", err)
		}

		cipherSecret, err := ReadEncKey(PubKeyFile, plainSecret)
		if err != nil {
			return err
		}

		ic.PlainSecret = plainSecret
		ic.CipherSecret = cipherSecret
	}

	ri, err := ic.Create()
	if err != nil {
		return err
	}

	if _, err := ri.Write(imgFile); err != nil {
		return err
	}

	return nil
}

func parseEncKeyPem(keyBytes []byte, plainSecret []byte) ([]byte, error) {
	b, _ := pem.Decode(keyBytes)
	if b == nil {
		return nil, nil
	}

	if b.Type != "PUBLIC KEY" && b.Type != "RSA PUBLIC KEY" {
		return nil, util.NewNewtError("Invalid PEM file")
	}

	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, util.FmtNewtError(
			"Error parsing pubkey file: %s", err.Error())
	}

	var pubk *rsa.PublicKey
	switch pub.(type) {
	case *rsa.PublicKey:
		pubk = pub.(*rsa.PublicKey)
	default:
		return nil, util.FmtNewtError(
			"Error parsing pubkey file: %s", err.Error())
	}

	rng := rand.Reader
	cipherSecret, err := rsa.EncryptOAEP(
		sha256.New(), rng, pubk, plainSecret, nil)
	if err != nil {
		return nil, util.FmtNewtError(
			"Error from encryption: %s\n", err.Error())
	}

	return cipherSecret, nil
}

func parseEncKeyBase64(keyBytes []byte, plainSecret []byte) ([]byte, error) {
	kek, err := base64.StdEncoding.DecodeString(string(keyBytes))
	if err != nil {
		return nil, util.FmtNewtError(
			"Error decoding kek: %s", err.Error())
	}
	if len(kek) != 16 {
		return nil, util.FmtNewtError(
			"Unexpected key size: %d != 16", len(kek))
	}

	cipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil, util.FmtNewtError(
			"Error creating keywrap cipher: %s", err.Error())
	}

	cipherSecret, err := keywrap.Wrap(cipher, plainSecret)
	if err != nil {
		return nil, util.FmtNewtError("Error key-wrapping: %s", err.Error())
	}

	return cipherSecret, nil
}

func ReadEncKey(filename string, plainSecret []byte) ([]byte, error) {
	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, util.FmtNewtError(
			"Error reading pubkey file: %s", err.Error())
	}

	// Try reading as PEM (asymetric key).
	cipherSecret, err := parseEncKeyPem(keyBytes, plainSecret)
	if err != nil {
		return nil, err
	}
	if cipherSecret != nil {
		return cipherSecret, nil
	}

	// Not PEM; assume this is a base64 encoded symetric key
	cipherSecret, err = parseEncKeyBase64(keyBytes, plainSecret)
	if err != nil {
		return nil, err
	}

	return cipherSecret, nil
}

func NewImageCreator() ImageCreator {
	return ImageCreator{
		hash: sha256.New(),
	}
}

func (ic *ImageCreator) addToHash(itf interface{}) error {
	if err := binary.Write(ic.hash, binary.LittleEndian,
		itf); err != nil {

		return util.FmtNewtError("Failed to hash data: %s", err.Error())
	}

	return nil
}

func (ic *ImageCreator) Create() (RawImage, error) {
	ri := RawImage{}

	if ic.InitialHash != nil {
		if err := ic.addToHash(ic.InitialHash); err != nil {
			return ri, err
		}
	}

	/*
	 * First the header
	 */
	hdr := ImageHdr{
		Magic: IMAGE_MAGIC,
		Pad1:  0,
		HdrSz: IMAGE_HEADER_SIZE,
		Pad2:  0,
		ImgSz: uint32(len(ic.Body)),
		Flags: 0,
		Vers:  ic.Version,
		Pad3:  0,
	}

	if !ic.Bootable {
		hdr.Flags |= IMAGE_F_NON_BOOTABLE
	}

	if ic.CipherSecret != nil {
		hdr.Flags |= IMAGE_F_ENCRYPTED
	}

	if ic.HeaderSize != 0 {
		/*
		 * Pad the header out to the given size.  There will
		 * just be zeros between the header and the start of
		 * the image when it is padded.
		 */
		if ic.HeaderSize < IMAGE_HEADER_SIZE {
			return ri, util.FmtNewtError("Image header must be at "+
				"least %d bytes", IMAGE_HEADER_SIZE)
		}

		hdr.HdrSz = uint16(ic.HeaderSize)
	}

	if err := ic.addToHash(hdr); err != nil {
		return ri, err
	}

	if hdr.HdrSz > IMAGE_HEADER_SIZE {
		/*
		 * Pad the image (and hash) with zero bytes to fill
		 * out the buffer.
		 */
		buf := make([]byte, hdr.HdrSz-IMAGE_HEADER_SIZE)

		if err := ic.addToHash(buf); err != nil {
			return ri, err
		}
	}

	ri.Header = hdr

	var stream cipher.Stream
	if ic.CipherSecret != nil {
		block, err := aes.NewCipher(ic.PlainSecret)
		if err != nil {
			return ri, util.NewNewtError("Failed to create block cipher")
		}
		nonce := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		stream = cipher.NewCTR(block, nonce)
	}

	/*
	 * Followed by data.
	 */
	dataBuf := make([]byte, 16)
	encBuf := make([]byte, 16)
	r := bytes.NewReader(ic.Body)
	w := bytes.Buffer{}
	for {
		cnt, err := r.Read(dataBuf)
		if err != nil && err != io.EOF {
			return ri, util.FmtNewtError(
				"Failed to read from image body: %s", err.Error())
		}
		if cnt == 0 {
			break
		}

		if err := ic.addToHash(dataBuf[0:cnt]); err != nil {
			return ri, err
		}
		if ic.CipherSecret == nil {
			_, err = w.Write(dataBuf[0:cnt])
		} else {
			stream.XORKeyStream(encBuf, dataBuf[0:cnt])
			_, err = w.Write(encBuf[0:cnt])
		}
		if err != nil {
			return ri, util.FmtNewtError(
				"Failed to write to image body: %s", err.Error())
		}
	}
	ri.Body = w.Bytes()

	hashBytes := ic.hash.Sum(nil)

	util.StatusMessage(util.VERBOSITY_VERBOSE,
		"Computed Hash for image as %s\n", hex.EncodeToString(hashBytes))

	// Trailer.
	ri.Trailer = ImageTlvInfo{
		Magic: IMAGE_TRAILER_MAGIC,
	}

	// Hash TLV.
	tlv := RawImageTlv{
		Header: ImageTrailerTlv{
			Type: IMAGE_TLV_SHA256,
			Pad:  0,
			Len:  uint16(len(hashBytes)),
		},
		Data: hashBytes,
	}
	ri.Tlvs = append(ri.Tlvs, tlv)

	tlvs, err := GenerateSigTlvs(ic.SigKeys, hashBytes)
	if err != nil {
		return ri, err
	}
	ri.Tlvs = append(ri.Tlvs, tlvs...)

	if ic.CipherSecret != nil {
		tlv, err := generateEncTlv(ic.CipherSecret)
		if err != nil {
			return ri, err
		}
		ri.Tlvs = append(ri.Tlvs, tlv)
	}

	totalSize, err := ri.TotalSize()
	if err != nil {
		return ri, err
	}
	ri.Trailer.TlvTotLen =
		uint16(totalSize - int(ri.Header.HdrSz) - len(ri.Body))

	return ri, nil
}

func (image *Image) Generate(loader *Image) error {
	if UseV1 {
		return image.generateV1(loader)
	} else {
		return image.generateV2(loader)
	}
}

func CreateBuildId(app *Image, loader *Image) []byte {
	return app.Hash
}

func NewRepoManager() *RepoManager {
	return &RepoManager{
		repos: make(map[string]ImageManifestRepo),
	}
}

func (r *RepoManager) GetImageManifestPkg(
	lpkg *pkg.LocalPackage) *ImageManifestPkg {

	ip := &ImageManifestPkg{
		Name: lpkg.Name(),
	}

	var path string
	if lpkg.Repo().IsLocal() {
		ip.Repo = lpkg.Repo().Name()
		path = lpkg.BasePath()
	} else {
		ip.Repo = lpkg.Repo().Name()
		path = lpkg.BasePath()
	}

	if _, present := r.repos[ip.Repo]; present {
		return ip
	}

	repo := ImageManifestRepo{
		Name: ip.Repo,
	}

	// Make sure we restore the current working dir to whatever it was when
	// this function was called
	cwd, err := os.Getwd()
	if err != nil {
		log.Debugf("Unable to determine current working directory: %v", err)
		return ip
	}
	defer os.Chdir(cwd)

	if err := os.Chdir(path); err != nil {
		return ip
	}

	var res []byte

	res, err = util.ShellCommand([]string{
		"git",
		"rev-parse",
		"HEAD",
	}, nil)
	if err != nil {
		log.Debugf("Unable to determine commit hash for %s: %v", path, err)
		repo.Commit = "UNKNOWN"
	} else {
		repo.Commit = strings.TrimSpace(string(res))
		res, err = util.ShellCommand([]string{
			"git",
			"status",
			"--porcelain",
		}, nil)
		if err != nil {
			log.Debugf("Unable to determine dirty state for %s: %v", path, err)
		} else {
			if len(res) > 0 {
				repo.Dirty = true
			}
		}
		res, err = util.ShellCommand([]string{
			"git",
			"config",
			"--get",
			"remote.origin.url",
		}, nil)
		if err != nil {
			log.Debugf("Unable to determine URL for %s: %v", path, err)
		} else {
			repo.URL = strings.TrimSpace(string(res))
		}
	}
	r.repos[ip.Repo] = repo

	return ip
}

func (r *RepoManager) AllRepos() []ImageManifestRepo {
	keys := make([]string, 0, len(r.repos))
	for k := range r.repos {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	repos := make([]ImageManifestRepo, 0, len(keys))
	for _, key := range keys {
		repos = append(repos, r.repos[key])
	}

	return repos
}

func NewImageManifestSizeCollector() *ImageManifestSizeCollector {
	return &ImageManifestSizeCollector{}
}

func (c *ImageManifestSizeCollector) AddPkg(pkg string) *ImageManifestSizePkg {
	p := &ImageManifestSizePkg{
		Name: pkg,
	}
	c.Pkgs = append(c.Pkgs, p)

	return p
}

func (c *ImageManifestSizePkg) AddSymbol(file string, sym string, area string,
	symSz uint32) {
	f := c.addFile(file)
	s := f.addSym(sym)
	s.addArea(area, symSz)
}

func (p *ImageManifestSizePkg) addFile(file string) *ImageManifestSizeFile {
	for _, f := range p.Files {
		if f.Name == file {
			return f
		}
	}
	f := &ImageManifestSizeFile{
		Name: file,
	}
	p.Files = append(p.Files, f)

	return f
}

func (f *ImageManifestSizeFile) addSym(sym string) *ImageManifestSizeSym {
	s := &ImageManifestSizeSym{
		Name: sym,
	}
	f.Syms = append(f.Syms, s)

	return s
}

func (s *ImageManifestSizeSym) addArea(area string, areaSz uint32) {
	a := &ImageManifestSizeArea{
		Name: area,
		Size: areaSz,
	}
	s.Areas = append(s.Areas, a)
}
