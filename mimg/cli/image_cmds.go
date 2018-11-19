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

package cli

import (
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"

	"mynewt.apache.org/newt/newt/image"
	"mynewt.apache.org/newt/util"
)

func readImage(filename string) (image.RawImage, error) {
	img, err := image.ReadRawImage(filename)
	if err != nil {
		return img, err
	}

	log.Debugf("Successfully read image %s", filename)
	return img, nil
}

func writeImage(img image.RawImage, filename string) error {
	if err := img.WriteToFile(filename); err != nil {
		return err
	}

	log.Debugf("Wrote image %s", filename)
	return nil
}

func runShowCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		MimgUsage(cmd, nil)
	}

	img, err := readImage(args[0])
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
	outFilename, err := CalcOutFilename(inFilename)
	if err != nil {
		MimgUsage(cmd, err)
	}

	img, err := readImage(inFilename)
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

	img.Tlvs = append(img.Tlvs, tlvs...)

	if err := writeImage(img, outFilename); err != nil {
		MimgUsage(nil, err)
	}
}

func runRmsigsCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		MimgUsage(cmd, nil)
	}

	inFilename := args[0]
	outFilename, err := CalcOutFilename(inFilename)
	if err != nil {
		MimgUsage(cmd, err)
	}

	img, err := readImage(inFilename)
	if err != nil {
		MimgUsage(cmd, err)
	}

	cnt := img.RemoveTlvsIf(func(tlv image.RawImageTlv) bool {
		return tlv.Header.Type == image.IMAGE_TLV_KEYHASH ||
			tlv.Header.Type == image.IMAGE_TLV_RSA2048 ||
			tlv.Header.Type == image.IMAGE_TLV_ECDSA224 ||
			tlv.Header.Type == image.IMAGE_TLV_ECDSA256
	})

	log.Debugf("Removed %d existing signatures", cnt)

	if err := writeImage(img, outFilename); err != nil {
		MimgUsage(nil, err)
	}
}

func AddImageCommands(cmd *cobra.Command) {
	imageHelpText := ""
	imageHelpEx := ""
	imageCmd := &cobra.Command{
		Use:     "image",
		Long:    imageHelpText,
		Example: imageHelpEx,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Usage()
		},
	}
	cmd.AddCommand(imageCmd)

	showHelpText := ""
	showHelpEx := ""
	showCmd := &cobra.Command{
		Use:     "show",
		Long:    showHelpText,
		Example: showHelpEx,
		Run:     runShowCmd,
	}
	imageCmd.AddCommand(showCmd)

	signHelpText := ""
	signHelpEx := ""
	signCmd := &cobra.Command{
		Use:     "sign",
		Long:    signHelpText,
		Example: signHelpEx,
		Run:     runSignCmd,
	}

	signCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o", "",
		"File to write to")
	signCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	imageCmd.AddCommand(signCmd)

	rmsigsHelpText := ""
	rmsigsHelpEx := ""
	rmsigsCmd := &cobra.Command{
		Use:     "rmsigs",
		Long:    rmsigsHelpText,
		Example: rmsigsHelpEx,
		Run:     runRmsigsCmd,
	}

	rmsigsCmd.PersistentFlags().StringVarP(&OptOutFilename, "outfile", "o", "",
		"File to write to")
	rmsigsCmd.PersistentFlags().BoolVarP(&OptInPlace, "inplace", "i", false,
		"Replace input file")

	imageCmd.AddCommand(rmsigsCmd)
}
