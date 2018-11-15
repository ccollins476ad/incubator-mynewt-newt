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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"

	log "github.com/Sirupsen/logrus"

	"mynewt.apache.org/newt/util"
)

type ImageHdrV1 struct {
	Magic uint32
	TlvSz uint16
	KeyId uint8
	Pad1  uint8
	HdrSz uint16
	Pad2  uint16
	ImgSz uint32
	Flags uint32
	Vers  ImageVersion
	Pad3  uint32
}

func (image *Image) SetKeyV1(key ImageKey, keyId uint8) error {
	image.SetKeys([]ImageKey{key})
	image.KeyId = keyId

	return nil
}

func (key *ImageKey) sigHdrTypeV1() (uint32, error) {
	key.assertValid()

	if key.Rsa != nil {
		if UseRsaPss {
			return IMAGEv1_F_PKCS1_PSS_RSA2048_SHA256, nil
		} else {
			return IMAGEv1_F_PKCS15_RSA2048_SHA256, nil
		}
	} else {
		switch key.Ec.Curve.Params().Name {
		case "P-224":
			return IMAGEv1_F_ECDSA224_SHA256, nil
		case "P-256":
			return IMAGEv1_F_ECDSA256_SHA256, nil
		default:
			return 0, util.FmtNewtError("Unsupported ECC curve")
		}
	}
}

func (image *Image) generateV1(loader *Image) error {
	binFile, err := os.Open(image.SourceBin)
	if err != nil {
		return util.FmtNewtError("Can't open app binary: %s",
			err.Error())
	}
	defer binFile.Close()

	binInfo, err := binFile.Stat()
	if err != nil {
		return util.FmtNewtError("Can't stat app binary %s: %s",
			image.SourceBin, err.Error())
	}

	imgFile, err := os.OpenFile(image.TargetImg,
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return util.FmtNewtError("Can't open target image %s: %s",
			image.TargetImg, err.Error())
	}
	defer imgFile.Close()

	/*
	 * Compute hash while updating the file.
	 */
	hash := sha256.New()

	if loader != nil {
		err = binary.Write(hash, binary.LittleEndian, loader.Hash)
		if err != nil {
			return util.FmtNewtError("Failed to seed hash: %s", err.Error())
		}
	}

	/*
	 * First the header
	 */
	hdr := &ImageHdrV1{
		Magic: IMAGEv1_MAGIC,
		TlvSz: 0,
		KeyId: 0,
		Pad1:  0,
		HdrSz: IMAGE_HEADER_SIZE,
		Pad2:  0,
		ImgSz: uint32(binInfo.Size()) - uint32(image.SrcSkip),
		Flags: 0,
		Vers:  image.Version,
		Pad3:  0,
	}

	if len(image.Keys) > 0 {
		hdr.Flags, err = image.Keys[0].sigHdrTypeV1()
		if err != nil {
			return err
		}

		hdr.TlvSz = 4 + image.Keys[0].sigLen()
		hdr.KeyId = image.KeyId
	}

	hdr.TlvSz += 4 + 32
	hdr.Flags |= IMAGEv1_F_SHA256

	if loader != nil {
		hdr.Flags |= IMAGEv1_F_NON_BOOTABLE
	}

	if image.HeaderSize != 0 {
		/*
		 * Pad the header out to the given size.  There will
		 * just be zeros between the header and the start of
		 * the image when it is padded.
		 */
		if image.HeaderSize < IMAGE_HEADER_SIZE {
			return util.FmtNewtError(
				"Image header must be at least %d bytes", IMAGE_HEADER_SIZE)
		}

		hdr.HdrSz = uint16(image.HeaderSize)
	}

	err = binary.Write(imgFile, binary.LittleEndian, hdr)
	if err != nil {
		return util.FmtNewtError("Failed to serialize image hdr: %s",
			err.Error())
	}
	err = binary.Write(hash, binary.LittleEndian, hdr)
	if err != nil {
		return util.FmtNewtError("Failed to hash data: %s", err.Error())
	}

	if image.HeaderSize > IMAGE_HEADER_SIZE {
		/*
		 * Pad the image (and hash) with zero bytes to fill
		 * out the buffer.
		 */
		buf := make([]byte, image.HeaderSize-IMAGE_HEADER_SIZE)

		_, err = imgFile.Write(buf)
		if err != nil {
			return util.FmtNewtError(
				"Failed to write padding: %s", err.Error())
		}

		_, err = hash.Write(buf)
		if err != nil {
			return util.FmtNewtError("Failed to hash padding: %s", err.Error())
		}
	}

	/*
	 * Skip requested initial part of image.
	 */
	if image.SrcSkip > 0 {
		buf := make([]byte, image.SrcSkip)
		_, err = binFile.Read(buf)
		if err != nil {
			return util.FmtNewtError(
				"Failed to read from %s: %s", image.SourceBin, err.Error())
		}

		nonZero := false
		for _, b := range buf {
			if b != 0 {
				nonZero = true
				break
			}
		}
		if nonZero {
			log.Warnf("Skip requested of image %s, but image not preceeded "+
				"by %d bytes of all zeros",
				image.SourceBin, image.SrcSkip)
		}
	}

	/*
	 * Followed by data.
	 */
	dataBuf := make([]byte, 1024)
	for {
		cnt, err := binFile.Read(dataBuf)
		if err != nil && err != io.EOF {
			return util.FmtNewtError(
				"Failed to read from %s: %s", image.SourceBin, err.Error())
		}
		if cnt == 0 {
			break
		}
		_, err = imgFile.Write(dataBuf[0:cnt])
		if err != nil {
			return util.FmtNewtError(
				"Failed to write to %s: %s", image.TargetImg, err.Error())
		}
		_, err = hash.Write(dataBuf[0:cnt])
		if err != nil {
			return util.FmtNewtError(
				"Failed to hash data: %s", err.Error())
		}
	}

	image.Hash = hash.Sum(nil)

	/*
	 * Trailer with hash of the data
	 */
	tlv := &ImageTrailerTlv{
		Type: IMAGEv1_TLV_SHA256,
		Pad:  0,
		Len:  uint16(len(image.Hash)),
	}
	err = binary.Write(imgFile, binary.LittleEndian, tlv)
	if err != nil {
		return util.FmtNewtError(
			"Failed to serialize image trailer: %s", err.Error())
	}
	_, err = imgFile.Write(image.Hash)
	if err != nil {
		return util.FmtNewtError(
			"Failed to append hash: %s", err.Error())
	}

	tlvs, err := GenerateSigTlvs(image.Keys, image.Hash)
	if err != nil {
		return err
	}
	for _, tlv := range tlvs {
		tlv.Write(imgFile)
	}

	util.StatusMessage(util.VERBOSITY_VERBOSE,
		"Computed Hash for image %s as %s \n",
		image.TargetImg, hex.EncodeToString(image.Hash))

	// XXX: Replace "1" with io.SeekCurrent when go 1.7 becomes mainstream.
	sz, err := imgFile.Seek(0, 1)
	if err != nil {
		return util.FmtNewtError("Failed to calculate file size of generated "+
			"image %s: %s", image.TargetImg, err.Error())
	}
	image.TotalSize = int(sz)

	return nil
}
