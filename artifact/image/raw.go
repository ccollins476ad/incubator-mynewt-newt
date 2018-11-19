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
	"encoding/json"
	"io"
	"io/ioutil"
	"os"

	"mynewt.apache.org/newt/util"
)

type RawImageTlv struct {
	Header ImageTrailerTlv
	Data   []byte
}

type RawImage struct {
	Header  ImageHdr
	Body    []byte
	Trailer ImageTlvInfo
	Tlvs    []RawImageTlv
}

type RawImageOffsets struct {
	Header    int
	Body      int
	Trailer   int
	Tlvs      []int
	TotalSize int
}

func (h *ImageHdr) Map(offset int) map[string]interface{} {
	return map[string]interface{}{
		"Magic":  h.Magic,
		"HdrSz":  h.HdrSz,
		"ImgSz":  h.ImgSz,
		"Flags":  h.Flags,
		"Vers":   h.Vers.String(),
		"offset": offset,
	}
}

func rawBodyMap(offset int) map[string]interface{} {
	return map[string]interface{}{
		"offset": offset,
	}
}

func (t *ImageTlvInfo) Map(offset int) map[string]interface{} {
	return map[string]interface{}{
		"Magic":     t.Magic,
		"TlvTotLen": t.TlvTotLen,
		"offset":    offset,
	}
}

func (t *RawImageTlv) Map(offset int) map[string]interface{} {
	return map[string]interface{}{
		"Type":    t.Header.Type,
		"typestr": ImageTlvTypeName(t.Header.Type),
		"Len":     t.Header.Len,
		"offset":  offset,
	}
}

func (img *RawImage) Map() (map[string]interface{}, error) {
	offs, err := img.Offsets()
	if err != nil {
		return nil, err
	}

	m := map[string]interface{}{}
	m["header"] = img.Header.Map(offs.Header)
	m["body"] = rawBodyMap(offs.Body)
	m["trailer"] = img.Trailer.Map(offs.Trailer)

	tlvMaps := []map[string]interface{}{}
	for i, tlv := range img.Tlvs {
		tlvMaps = append(tlvMaps, tlv.Map(offs.Tlvs[i]))
	}
	m["tlvs"] = tlvMaps

	return m, nil
}

func (img *RawImage) Json() (string, error) {
	m, err := img.Map()
	if err != nil {
		return "", err
	}

	b, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		return "", util.ChildNewtError(err)
	}

	return string(b), nil
}

func (tlv *RawImageTlv) Write(w io.Writer) (int, error) {
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

func (i *RawImage) FindTlvs(tlvType uint8) []RawImageTlv {
	var tlvs []RawImageTlv

	for _, tlv := range i.Tlvs {
		if tlv.Header.Type == tlvType {
			tlvs = append(tlvs, tlv)
		}
	}

	return tlvs
}

func (i *RawImage) RemoveTlvsIf(pred func(tlv RawImageTlv) bool) int {
	numRmed := 0
	for idx := 0; idx < len(i.Tlvs); {
		tlv := i.Tlvs[idx]
		if pred(tlv) {
			i.Tlvs = append(i.Tlvs[:idx], i.Tlvs[idx+1:]...)
			numRmed++
		} else {
			idx++
		}
	}

	return numRmed
}

func (i *RawImage) Hash() ([]byte, error) {
	tlvs := i.FindTlvs(IMAGE_TLV_SHA256)
	if len(tlvs) == 0 {
		return nil, util.FmtNewtError("Image does not contain hash TLV")
	}
	if len(tlvs) > 1 {
		return nil, util.FmtNewtError("Image contains %d hash TLVs", len(tlvs))
	}

	return tlvs[0].Data, nil
}

func (i *RawImage) WritePlusOffsets(w io.Writer) (RawImageOffsets, error) {
	offs := RawImageOffsets{}
	offset := 0

	offs.Header = offset

	err := binary.Write(w, binary.LittleEndian, &i.Header)
	if err != nil {
		return offs, util.ChildNewtError(err)
	}
	offset += IMAGE_HEADER_SIZE

	offs.Body = offset
	size, err := w.Write(i.Body)
	if err != nil {
		return offs, util.ChildNewtError(err)
	}
	offset += size

	offs.Trailer = offset
	err = binary.Write(w, binary.LittleEndian, &i.Trailer)
	if err != nil {
		return offs, util.ChildNewtError(err)
	}
	offset += IMAGE_TRAILER_SIZE

	for _, tlv := range i.Tlvs {
		offs.Tlvs = append(offs.Tlvs, offset)
		size, err := tlv.Write(w)
		if err != nil {
			return offs, util.ChildNewtError(err)
		}
		offset += size
	}

	offs.TotalSize = offset

	return offs, nil
}

func (i *RawImage) Offsets() (RawImageOffsets, error) {
	return i.WritePlusOffsets(ioutil.Discard)
}

func (i *RawImage) TotalSize() (int, error) {
	offs, err := i.Offsets()
	if err != nil {
		return 0, err
	}
	return offs.TotalSize, nil
}

func (i *RawImage) Write(w io.Writer) (int, error) {
	offs, err := i.WritePlusOffsets(w)
	if err != nil {
		return 0, err
	}

	return offs.TotalSize, nil
}

func (i *RawImage) WriteToFile(filename string) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return util.ChildNewtError(err)
	}

	if _, err := i.Write(f); err != nil {
		return util.ChildNewtError(err)
	}

	return nil
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

func parseRawTlv(imgData []byte, offset int) (RawImageTlv, int, error) {
	tlv := RawImageTlv{}

	r := bytes.NewReader(imgData)
	r.Seek(int64(offset), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian, &tlv.Header); err != nil {
		return tlv, 0, util.FmtNewtError(
			"Image contains invalid TLV at offset %d: %s", offset, err.Error())
	}

	tlv.Data = make([]byte, tlv.Header.Len)
	if _, err := r.Read(tlv.Data); err != nil {
		return tlv, 0, util.FmtNewtError(
			"Image contains invalid TLV at offset %d: %s", offset, err.Error())
	}

	return tlv, IMAGE_TLV_SIZE + int(tlv.Header.Len), nil
}

func ParseRawImage(imgData []byte) (RawImage, error) {
	img := RawImage{}
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

	var tlvs []RawImageTlv
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

func ReadRawImage(filename string) (RawImage, error) {
	ri := RawImage{}

	imgData, err := ioutil.ReadFile(filename)
	if err != nil {
		return ri, util.ChildNewtError(err)
	}

	return ParseRawImage(imgData)
}
