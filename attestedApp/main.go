/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"os"
)

func main() {
	var app *App
	app = &App {
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println("Tenant Application returned with error:", err.Error())
		os.Exit(1)
	}
}
