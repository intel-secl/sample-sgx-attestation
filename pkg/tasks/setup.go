/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bufio"
	"github.com/pkg/errors"
	"os"
	"strings"
)

// ReadAnswerFileToEnv dumps all the settings from input answer file
// into a environment variables
func ReadAnswerFileToEnv(filename string) error {
	fin, err := os.Open(filename)
	if err != nil {
		return errors.Wrap(err, "Failed to load answer file")
	}
	scanner := bufio.NewScanner(fin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" ||
			strings.HasPrefix(line, "#") {
			continue
		}
		equalSign := strings.Index(line, "=")
		if equalSign > 0 {
			key := line[0:equalSign]
			val := line[equalSign+1:]
			if key != "" &&
				val != "" {
				os.Setenv(key, val)
			}
		}
	}
	return nil
}
