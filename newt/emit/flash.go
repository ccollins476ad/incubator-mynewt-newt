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

package emit

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	log "github.com/Sirupsen/logrus"

	"mynewt.apache.org/newt/artifact/flash"
	"mynewt.apache.org/newt/newt/newtutil"
	"mynewt.apache.org/newt/util"
)

const HEADER_PATH = "sysflash/sysflash.h"
const C_VAR_NAME = "sysflash_map_dflt"
const C_VAR_COMMENT = `/**
 * This flash map definition is used for two purposes:
 * 1. To locate the meta area, which contains the true flash map definition.
 * 2. As a fallback in case the meta area cannot be read from flash.
 */
`

func flashMapVarDecl(fm flash.FlashMap) string {
	return fmt.Sprintf("const struct flash_area %s[%d]", C_VAR_NAME,
		len(fm.Areas))
}

func writeFlashAreaHeader(w io.Writer, area flash.FlashArea) {
	fmt.Fprintf(w, "#define %-40s %d\n", area.Name, area.Id)
}

func writeFlashMapHeader(w io.Writer, fm flash.FlashMap) {
	fmt.Fprintf(w, newtutil.GeneratedPreamble())

	fmt.Fprintf(w, "#ifndef H_MYNEWT_SYSFLASH_\n")
	fmt.Fprintf(w, "#define H_MYNEWT_SYSFLASH_\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "#include \"flash_map/flash_map.h\"\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "%s", C_VAR_COMMENT)
	fmt.Fprintf(w, "extern %s;\n", flashMapVarDecl(fm))
	fmt.Fprintf(w, "\n")

	for _, area := range fm.SortedAreas() {
		writeFlashAreaHeader(w, area)
	}

	fmt.Fprintf(w, "\n#endif\n")
}

func sizeComment(size int) string {
	if size%1024 != 0 {
		return ""
	}

	return fmt.Sprintf(" /* %d kB */", size/1024)
}

func writeFlashAreaSrc(w io.Writer, area flash.FlashArea) {
	fmt.Fprintf(w, "    /* %s */\n", area.Name)
	fmt.Fprintf(w, "    {\n")
	fmt.Fprintf(w, "        .fa_id = %d,\n", area.Id)
	fmt.Fprintf(w, "        .fa_device_id = %d,\n", area.Device)
	fmt.Fprintf(w, "        .fa_off = 0x%08x,\n", area.Offset)
	fmt.Fprintf(w, "        .fa_size = %d,%s\n", area.Size,
		sizeComment(area.Size))
	fmt.Fprintf(w, "    },\n")
}

func writeFlashMapSrc(w io.Writer, fm flash.FlashMap) {
	fmt.Fprintf(w, newtutil.GeneratedPreamble())

	fmt.Fprintf(w, "#include \"%s\"\n", HEADER_PATH)
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "%s", C_VAR_COMMENT)
	fmt.Fprintf(w, "%s = {", flashMapVarDecl(fm))

	for _, area := range fm.SortedAreas() {
		fmt.Fprintf(w, "\n")
		writeFlashAreaSrc(w, area)
	}

	fmt.Fprintf(w, "};\n")
}

func ensureFlashMapWrittenGen(path string, contents []byte) error {
	writeReqd, err := util.FileContentsChanged(path, contents)
	if err != nil {
		return err
	}
	if !writeReqd {
		log.Debugf("flash map unchanged; not writing file (%s).", path)
		return nil
	}

	log.Debugf("flash map changed; writing file (%s).", path)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return util.NewNewtError(err.Error())
	}

	if err := ioutil.WriteFile(path, contents, 0644); err != nil {
		return util.NewNewtError(err.Error())
	}

	return nil
}

func EnsureFlashMapWritten(
	fm flash.FlashMap,
	srcDir string,
	includeDir string,
	targetName string) error {

	buf := bytes.Buffer{}
	writeFlashMapSrc(&buf, fm)
	if err := ensureFlashMapWrittenGen(
		fmt.Sprintf("%s/%s-sysflash.c", srcDir, targetName),
		buf.Bytes()); err != nil {

		return err
	}

	buf = bytes.Buffer{}
	writeFlashMapHeader(&buf, fm)
	if err := ensureFlashMapWrittenGen(
		includeDir+"/"+HEADER_PATH, buf.Bytes()); err != nil {
		return err
	}

	return nil
}
