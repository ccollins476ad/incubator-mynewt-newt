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

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"

	"mynewt.apache.org/newt/mimg/cli"
	"mynewt.apache.org/newt/util"
)

var MimgLogLevel log.Level
var mimgVersion = "0.0.1"

func main() {
	mimgHelpText := ""
	mimgHelpEx := ""

	logLevelStr := ""
	mimgCmd := &cobra.Command{
		Use:     "mimg",
		Short:   "mimg is a tool to help you compose and build your own OS",
		Long:    mimgHelpText,
		Example: mimgHelpEx,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logLevel, err := log.ParseLevel(logLevelStr)
			if err != nil {
				cli.MimgUsage(nil, util.ChildNewtError(err))
			}
			MimgLogLevel = logLevel

			if err := util.Init(MimgLogLevel, "",
				util.VERBOSITY_DEFAULT); err != nil {

				cli.MimgUsage(nil, err)
			}
		},

		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	mimgCmd.PersistentFlags().StringVarP(&logLevelStr, "loglevel", "l",
		"WARN", "Log level")

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

	cli.AddImageCommands(mimgCmd)
	cli.AddMfgCommands(mimgCmd)

	mimgCmd.Execute()
}
