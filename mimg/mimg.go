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

	y, err := img.Yaml()
	if err != nil {
		MimgUsage(nil, err)
	}
	fmt.Printf("%s\n", y)
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

	return mimgCmd
}

func main() {
	cmd := mimgCmd()

	cmd.Execute()
}
