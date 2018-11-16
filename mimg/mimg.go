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

package main

import (
	"fmt"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"

	"mynewt.apache.org/newt/newt/image"
	"mynewt.apache.org/newt/util"
)

var mimgVersion = "0.0.1"
var optReplaceSigs bool
var optOutFilename string
var optInPlace bool

func MimgUsage(cmd *cobra.Command, err error) {
	if err != nil {
		sErr := err.(*util.NewtError)
		log.Debugf("%s", sErr.StackTrace)
		fmt.Fprintf(os.Stderr, "Error: %s\n", sErr.Text)
	}

	if cmd != nil {
		fmt.Printf("\n")
		fmt.Printf("%s - ", cmd.Name())
		cmd.Help()
	}
	os.Exit(1)
}

func runShowCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		MimgUsage(cmd, nil)
	}

	img, err := image.ReadRawImage(args[0])
	if err != nil {
		MimgUsage(cmd, err)
	}

	s, err := img.Json()
	if err != nil {
		MimgUsage(nil, err)
	}
	fmt.Printf("%s\n", s)
}

func runSignCmd(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		MimgUsage(cmd, nil)
	}

	inFilename := args[0]

	var outFilename string
	if optOutFilename != "" {
		if optInPlace {
			MimgUsage(cmd, util.FmtNewtError(
				"Only one of --outfile (-o) or --inplace (-i) options allowed"))
		}

		outFilename = optOutFilename
	} else if optInPlace {
		outFilename = inFilename
	} else {
		MimgUsage(cmd, util.FmtNewtError(
			"--outfile (-o) or --inplace (-i) option required"))
	}

	img, err := image.ReadRawImage(inFilename)
	if err != nil {
		MimgUsage(cmd, err)
	}

	keys, err := image.ReadKeys(args[1:])
	if err != nil {
		MimgUsage(cmd, err)
	}

	hash, err := img.Hash()
	if err != nil {
		MimgUsage(cmd, util.FmtNewtError(
			"Failed to read hash from specified image: %s", err.Error()))
	}

	tlvs, err := image.GenerateSigTlvs(keys, hash)
	if err != nil {
		MimgUsage(nil, err)
	}

	if optReplaceSigs {
		cnt := img.RemoveTlvsIf(func(tlv image.RawImageTlv) bool {
			return tlv.Header.Type == image.IMAGE_TLV_KEYHASH ||
				tlv.Header.Type == image.IMAGE_TLV_RSA2048 ||
				tlv.Header.Type == image.IMAGE_TLV_ECDSA224 ||
				tlv.Header.Type == image.IMAGE_TLV_ECDSA256
		})

		log.Debugf("Removed %d existing signatures", cnt)
	}

	img.Tlvs = append(img.Tlvs, tlvs...)

	if err := img.WriteToFile(outFilename); err != nil {
		MimgUsage(nil, err)
	}
}

func mimgCmd() *cobra.Command {
	mimgHelpText := ""
	mimgHelpEx := ""

	mimgCmd := &cobra.Command{
		Use:     "mimg",
		Short:   "mimg is a tool to help you compose and build your own OS",
		Long:    mimgHelpText,
		Example: mimgHelpEx,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	versHelpText := `Display the mimg version number`
	versHelpEx := "  mimg version"
	versCmd := &cobra.Command{
		Use:     "version",
		Short:   "Display the mimg version number",
		Long:    versHelpText,
		Example: versHelpEx,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("%s\n", mimgVersion)
		},
	}
	mimgCmd.AddCommand(versCmd)

	showHelpText := ""
	showHelpEx := ""
	showCmd := &cobra.Command{
		Use:     "show",
		Long:    showHelpText,
		Example: showHelpEx,
		Run: func(cmd *cobra.Command, args []string) {
			runShowCmd(cmd, args)
		},
	}
	mimgCmd.AddCommand(showCmd)

	signHelpText := ""
	signHelpEx := ""
	signCmd := &cobra.Command{
		Use:     "sign",
		Long:    signHelpText,
		Example: signHelpEx,
		Run: func(cmd *cobra.Command, args []string) {
			runSignCmd(cmd, args)
		},
	}

	signCmd.PersistentFlags().BoolVarP(&optReplaceSigs, "replace", "r", false,
		"Replace existing signatures rather than appending")
	signCmd.PersistentFlags().StringVarP(&optOutFilename, "outfile", "o", "",
		"File to write to")
	signCmd.PersistentFlags().BoolVarP(&optInPlace, "inplace", "i", false,
		"Replace input file")

	mimgCmd.AddCommand(signCmd)

	return mimgCmd
}

func main() {
	cmd := mimgCmd()

	cmd.Execute()
}
