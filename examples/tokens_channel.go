/*
Copyright (c) 2019 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This example shows how to get notified when new tokens are received from the authentication
// service.

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/openshift-online/uhc-sdk-go/pkg/client"
)

func main() {
	// Create a context:
	ctx := context.Background()

	// Create a logger that has the debug level enabled:
	logger, err := client.NewGoLoggerBuilder().
		Debug(true).
		Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't build logger: %v\n", err)
		os.Exit(1)
	}

	// Create the channel that will be used to receive token notifications and start the
	// goroutine that will process the notifications:
	channel := make(chan string)
	parser := new(jwt.Parser)
	processor := func() {
		for token := range channel {
			claims := make(jwt.MapClaims)
			_, _, err = parser.ParseUnverified(token, claims)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Can't parse token: %v\n", err)
				os.Exit(1)
			}
			switch claims["typ"].(string) {
			case "Offline":
				fmt.Printf("New offline access token is '%s'\n", token)
			case "Refresh":
				fmt.Printf("New refresh token is '%s'\n", token)
			case "Bearer":
				fmt.Printf("New bearer token is '%s'\n", token)
			}
		}
	}
	go processor()

	// Create the connection, and remember to close it:
	token := os.Getenv("UHC_TOKEN")
	connection, err := client.NewConnectionBuilder().
		Logger(logger).
		Tokens(token).
		TokensChannel(channel).
		BuildContext(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't build client: %v\n", err)
		os.Exit(1)
	}
	defer connection.Close()

	// Repeatedly get tokens. Most iterations will return the tokens stored in memory by the
	// connection, but when those expire new ones will be requested to the authentication
	// service and notified via the channel.
	for {
		_, _, err = connection.TokensContext(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Can't get tokens: %v\n", err)
			break
		}
		time.Sleep(1 * time.Second)
	}
}
