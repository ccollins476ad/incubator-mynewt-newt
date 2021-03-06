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

package util

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"

	"mynewt.apache.org/newt/viper"
)

var Verbosity int
var logFile *os.File

func ParseEqualsPair(v string) (string, string, error) {
	s := strings.Split(v, "=")
	return s[0], s[1], nil
}

type NewtError struct {
	Text       string
	StackTrace []byte
}

const (
	VERBOSITY_SILENT  = 0
	VERBOSITY_QUIET   = 1
	VERBOSITY_DEFAULT = 2
	VERBOSITY_VERBOSE = 3
)

func (se *NewtError) Error() string {
	return se.Text + "\n" + string(se.StackTrace)
}

func NewNewtError(msg string) *NewtError {
	err := &NewtError{
		Text:       msg,
		StackTrace: make([]byte, 65536),
	}

	stackLen := runtime.Stack(err.StackTrace, true)
	err.StackTrace = err.StackTrace[:stackLen]

	return err
}

func FmtNewtError(format string, args ...interface{}) *NewtError {
	return NewNewtError(fmt.Sprintf(format, args...))
}

// Print Silent, Quiet and Verbose aware status messages to stdout.
func StatusMessage(level int, message string, args ...interface{}) {
	if Verbosity >= level {
		str := fmt.Sprintf(message, args...)
		os.Stdout.WriteString(str)
		os.Stdout.Sync()

		if logFile != nil {
			logFile.WriteString(str)
		}
	}
}

// Print Silent, Quiet and Verbose aware status messages to stderr.
func ErrorMessage(level int, message string, args ...interface{}) {
	if Verbosity >= level {
		fmt.Fprintf(os.Stderr, message, args...)
	}
}

func NodeExist(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	} else {
		return false
	}
}

// Check whether the node (either dir or file) specified by path exists
func NodeNotExist(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return true
	} else {
		return false
	}
}

func FileModificationTime(path string) (time.Time, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		epoch := time.Unix(0, 0)
		if os.IsNotExist(err) {
			return epoch, nil
		} else {
			return epoch, NewNewtError(err.Error())
		}
	}

	return fileInfo.ModTime(), nil
}

func ChildDirs(path string) ([]string, error) {
	children, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, NewNewtError(err.Error())
	}

	childDirs := []string{}
	for _, child := range children {
		name := child.Name()
		if !filepath.HasPrefix(name, ".") &&
			!filepath.HasPrefix(name, "..") &&
			child.IsDir() {

			childDirs = append(childDirs, name)
		}
	}

	return childDirs, nil
}

func Min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func Max(x, y int) int {
	if x > y {
		return x
	}
	return y
}

type logFormatter struct{}

func (f *logFormatter) Format(entry *log.Entry) ([]byte, error) {
	// 2016/03/16 12:50:47 [DEBUG]

	b := &bytes.Buffer{}

	b.WriteString(entry.Time.Format("2006/01/02 15:04:05 "))
	b.WriteString("[" + strings.ToUpper(entry.Level.String()) + "] ")
	b.WriteString(entry.Message)
	b.WriteByte('\n')

	return b.Bytes(), nil
}

func initLog(level log.Level, logFilename string) error {
	log.SetLevel(level)

	var writer io.Writer
	if logFilename == "" {
		writer = os.Stderr
	} else {
		var err error
		logFile, err = os.Create(logFilename)
		if err != nil {
			return NewNewtError(err.Error())
		}

		writer = io.MultiWriter(os.Stderr, logFile)
	}

	log.SetOutput(writer)
	log.SetFormatter(&logFormatter{})

	return nil
}

// Initialize the util module
func Init(logLevel log.Level, logFile string, verbosity int) error {
	// Configure logging twice.  First just configure the filter for stderr;
	// second configure the logfile if there is one.  This needs to happen in
	// two steps so that the log level is configured prior to the attempt to
	// open the log file.  The correct log level needs to be applied to file
	// error messages.
	if err := initLog(logLevel, ""); err != nil {
		return err
	}
	if logFile != "" {
		if err := initLog(logLevel, logFile); err != nil {
			return err
		}
	}

	Verbosity = verbosity

	return nil
}

// Read in the configuration file specified by name, in path
// return a new viper config object if successful, and error if not
func ReadConfig(path string, name string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigName(name)
	v.AddConfigPath(path)

	err := v.ReadInConfig()
	if err != nil {
		return nil, NewNewtError(fmt.Sprintf("Error reading %s.yml: %s",
			filepath.Join(path, name), err.Error()))
	} else {
		return v, nil
	}
}

func DescendantDirsOfParent(rootPath string, parentName string, fullPath bool) ([]string, error) {
	rootPath = path.Clean(rootPath)

	if NodeNotExist(rootPath) {
		return []string{}, nil
	}

	children, err := ChildDirs(rootPath)
	if err != nil {
		return nil, err
	}

	dirs := []string{}
	if path.Base(rootPath) == parentName {
		for _, child := range children {
			if fullPath {
				child = rootPath + "/" + child
			}

			dirs = append(dirs, child)
		}
	} else {
		for _, child := range children {
			childPath := rootPath + "/" + child
			subDirs, err := DescendantDirsOfParent(childPath, parentName,
				fullPath)
			if err != nil {
				return nil, err
			}

			dirs = append(dirs, subDirs...)
		}
	}

	return dirs, nil
}

// Execute the command specified by cmdStr on the shell and return results
func ShellCommand(cmdStr string) ([]byte, error) {
	log.Debug(cmdStr)
	cmd := exec.Command("sh", "-c", cmdStr)

	o, err := cmd.CombinedOutput()
	log.Debugf("o=%s", string(o))
	if err != nil {
		return o, NewNewtError(string(o))
	} else {
		return o, nil
	}
}

// Run interactive shell command
func ShellInteractiveCommand(cmdStr []string) error {
	log.Print("[VERBOSE] " + cmdStr[0])

	//
	// Block SIGINT, at least.
	// Otherwise Ctrl-C meant for gdb would kill newt.
	//
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		<-c
	}()

	// Transfer stdin, stdout, and stderr to the new process
	// and also set target directory for the shell to start in.
	pa := os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	}

	// Start up a new shell.
	proc, err := os.StartProcess(cmdStr[0], cmdStr, &pa)
	if err != nil {
		signal.Stop(c)
		return NewNewtError(err.Error())
	}

	// Release and exit
	_, err = proc.Wait()
	if err != nil {
		signal.Stop(c)
		return NewNewtError(err.Error())
	}
	signal.Stop(c)
	return nil
}

func CopyFile(srcFile string, destFile string) error {
	_, err := ShellCommand(fmt.Sprintf("mkdir -p %s", filepath.Dir(destFile)))
	if err != nil {
		return err
	}
	if _, err := ShellCommand(fmt.Sprintf("cp -Rf %s %s", srcFile,
		destFile)); err != nil {
		return err
	}
	return nil
}

func CopyDir(srcDir, destDir string) error {
	return CopyFile(srcDir, destDir)
}

// Reads each line from the specified text file into an array of strings.  If a
// line ends with a backslash, it is concatenated with the following line.
func ReadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, NewNewtError(err.Error())
	}
	defer file.Close()

	lines := []string{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		concatted := false

		if len(lines) != 0 {
			prevLine := lines[len(lines)-1]
			if len(prevLine) > 0 && prevLine[len(prevLine)-1:] == "\\" {
				prevLine = prevLine[:len(prevLine)-1]
				prevLine += line
				lines[len(lines)-1] = prevLine

				concatted = true
			}
		}

		if !concatted {
			lines = append(lines, line)
		}
	}

	if scanner.Err() != nil {
		return lines, NewNewtError(scanner.Err().Error())
	}

	return lines, nil
}

// Removes all duplicate strings from the specified array, while preserving
// order.
func UniqueStrings(elems []string) []string {
	set := make(map[string]bool)
	result := make([]string, 0)

	for _, elem := range elems {
		if !set[elem] {
			result = append(result, elem)
			set[elem] = true
		}
	}

	return result
}

// Sorts whitespace-delimited lists of strings.
//
// @param wsSepStrings          A list of strings; each string contains one or
//                                  more whitespace-delimited tokens.
//
// @return                      A slice containing all the input tokens, sorted
//                                  alphabetically.
func SortFields(wsSepStrings ...string) []string {
	slice := []string{}

	for _, s := range wsSepStrings {
		slice = append(slice, strings.Fields(s)...)
	}

	slice = UniqueStrings(slice)
	sort.Strings(slice)
	return slice
}
