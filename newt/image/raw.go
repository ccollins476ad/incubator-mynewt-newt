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
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"mynewt.apache.org/newt/util"
)

type ImageRawTlv struct {
	Header ImageTrailerTlv
	Data   []byte
}

type ImageRaw struct {
	Header  ImageHdr
	Body    []byte
	Trailer ImageTlvInfo
	Tlvs    []ImageRawTlv
}

func parseRawHeader(imgData []byte, offset int) (ImageHdr, int, error) {
	var hdr ImageHdr

	r := bytes.NewReader(imgData)
	r.Seek(int64(offset), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return hdr, 0, util.FmtNewtError(
			"Error reading image header: %s", err.Error())
	}

	if hdr.Magic != IMAGE_MAGIC {
		return hdr, 0, util.FmtNewtError(
			"Image magic incorrect; expected 0x%08x, got 0x%08x",
			IMAGE_MAGIC, hdr.Magic)
	}

	remLen := len(imgData) - offset
	if remLen < int(hdr.HdrSz) {
		return hdr, 0, util.FmtNewtError(
			"Image header incomplete; expected %d bytes, got %d bytes",
			hdr.HdrSz, remLen)
	}

	return hdr, int(hdr.HdrSz), nil
}

func parseRawBody(imgData []byte, hdr ImageHdr,
	offset int) ([]byte, int, error) {

	imgSz := int(hdr.ImgSz)
	remLen := len(imgData) - offset

	if remLen < imgSz {
		return nil, 0, util.FmtNewtError(
			"Image body incomplete; expected %d bytes, got %d bytes",
			imgSz, remLen)
	}

	return imgData[offset : offset+imgSz], imgSz, nil
}

func parseRawTrailer(imgData []byte, offset int) (ImageTlvInfo, int, error) {
	var trailer ImageTlvInfo

	r := bytes.NewReader(imgData)
	r.Seek(int64(offset), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian, &trailer); err != nil {
		return trailer, 0, util.FmtNewtError(
			"Image contains invalid trailer at offset %d: %s",
			offset, err.Error())
	}

	return trailer, IMAGE_TRAILER_SIZE, nil
}

func parseRawTlv(imgData []byte, offset int) (ImageRawTlv, int, error) {
	tlv := ImageRawTlv{}

	r := bytes.NewReader(imgData)
	r.Seek(int64(offset), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian,
		&tlv.Header); err != nil {

		return tlv, 0, util.FmtNewtError(
			"Image contains invalid TLV at offset %d: %s", offset, err.Error())
	}

	if _, err := r.Read(tlv.Data); err != nil {
		return tlv, 0, util.FmtNewtError(
			"Image contains invalid TLV at offset %d: %s", offset, err.Error())
	}

	return tlv, IMAGE_TLV_SIZE + int(tlv.Header.Len), nil
}

func ParseRawImage(imgData []byte) (ImageRaw, error) {
	img := ImageRaw{}
	offset := 0

	hdr, size, err := parseRawHeader(imgData, offset)
	if err != nil {
		return img, err
	}
	offset += size

	body, size, err := parseRawBody(imgData, hdr, offset)
	if err != nil {
		return img, err
	}
	offset += size

	trailer, size, err := parseRawTrailer(imgData, offset)
	if err != nil {
		return img, err
	}
	offset += size

	var tlvs []ImageRawTlv
	for offset < len(imgData) {
		tlv, size, err := parseRawTlv(imgData, offset)
		if err != nil {
			return img, err
		}

		tlvs = append(tlvs, tlv)
		offset += size
	}

	img.Header = hdr
	img.Body = body
	img.Trailer = trailer
	img.Tlvs = tlvs

	return img, nil
}

func ReadRawImage(filename string) (ImageRaw, error) {
	ri := ImageRaw{}

	imgData, err := ioutil.ReadFile(filename)
	if err != nil {
		return ri, util.ChildNewtError(err)
	}

	return ParseRawImage(imgData)
}

func rawHeaderDump(hdr ImageHdr) string {
	lines := []string{
		fmt.Sprintf("Header:"),
		fmt.Sprintf("    Magic: 0x%08x", hdr.Magic),
		fmt.Sprintf("    Pad1: 0x%02x", hdr.Pad1),
		fmt.Sprintf("    HdrSz: %d", hdr.HdrSz),
		fmt.Sprintf("    Pad2: 0x%02x", hdr.Pad2),
		fmt.Sprintf("    ImgSz: %d", hdr.ImgSz),
		fmt.Sprintf("    Flags: 0x%08x", hdr.Flags),
		fmt.Sprintf("    Vers: %s", hdr.Vers.String()),
		fmt.Sprintf("    Pad3: 0x%02x", hdr.Pad3),
	}

	return strings.Join(lines, "\n")
}

func rawTrailerDump(trailer ImageTlvInfo) string {
	lines := []string{
		fmt.Sprintf("trailer:"),
		fmt.Sprintf("    Magic: 0x%08x", trailer.Magic),
		fmt.Sprintf("    TotLen: %d", trailer.TlvTotLen),
	}

	return strings.Join(lines, "\n")
}

func rawTlvDump(tlv ImageRawTlv, tlvIdx int) string {
	lines := []string{
		fmt.Sprintf("tlv%d:", tlvIdx),
		fmt.Sprintf("    Type: %d (%s)",
			tlv.Header.Type, ImageTlvTypeName(tlv.Header.Type)),
		fmt.Sprintf("    Pad: 0x%02x", tlv.Header.Pad),
		fmt.Sprintf("    Len: %d", tlv.Header.Len),
	}

	return strings.Join(lines, "\n")
}

func RawImageDump(img ImageRaw) string {
	var sb strings.Builder

	sb.WriteString(rawHeaderDump(img.Header))
	sb.WriteString("\n\n")
	sb.WriteString(rawTrailerDump(img.Trailer))
	for i, tlv := range img.Tlvs {
		sb.WriteString("\n\n")
		sb.WriteString(rawTlvDump(tlv, i))
	}

	return sb.String()
}

func (tlv *ImageRawTlv) Write(w io.Writer) (int, error) {
	totalSize := 0

	err := binary.Write(w, binary.LittleEndian, &tlv.Header)
	if err != nil {
		return totalSize, util.ChildNewtError(err)
	}
	totalSize += IMAGE_TLV_SIZE

	size, err := w.Write(tlv.Data)
	if err != nil {
		return totalSize, util.ChildNewtError(err)
	}
	totalSize += size

	return totalSize, nil
}

func (i *ImageRaw) Write(w io.Writer) (int, error) {
	totalSize := 0

	err := binary.Write(w, binary.LittleEndian, &i.Header)
	if err != nil {
		return totalSize, util.ChildNewtError(err)
	}
	totalSize += IMAGE_HEADER_SIZE

	size, err := w.Write(i.Body)
	if err != nil {
		return totalSize, util.ChildNewtError(err)
	}
	totalSize += size

	err = binary.Write(w, binary.LittleEndian, &i.Trailer)
	if err != nil {
		return totalSize, util.ChildNewtError(err)
	}
	totalSize += IMAGE_TRAILER_SIZE

	for _, tlv := range i.Tlvs {
		size, err := tlv.Write(w)
		if err != nil {
			return totalSize, util.ChildNewtError(err)
		}
		totalSize += size
	}

	return totalSize, nil
}

func (i *ImageRaw) TotalSize() (int, error) {
	size, err := i.Write(ioutil.Discard)
	if err != nil {
		return 0, util.ChildNewtError(err)
	}
	return size, nil
}
