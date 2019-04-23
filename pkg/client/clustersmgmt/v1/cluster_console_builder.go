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

// IMPORTANT: This file has been generated automatically, refrain from modifying it manually as all
// your changes will be lost when the file is generated again.

package v1 // github.com/openshift-online/uhc-sdk-go/pkg/client/clustersmgmt/v1

// ClusterConsoleBuilder contains the data and logic needed to build 'cluster_console' objects.
//
// Information about the console of a cluster.
type ClusterConsoleBuilder struct {
	url *string
}

// NewClusterConsole creates a new builder of 'cluster_console' objects.
func NewClusterConsole() *ClusterConsoleBuilder {
	return new(ClusterConsoleBuilder)
}

// URL sets the value of the 'URL' attribute
// to the given value.
//
//
func (b *ClusterConsoleBuilder) URL(value string) *ClusterConsoleBuilder {
	b.url = &value
	return b
}

// Build creates a 'cluster_console' object using the configuration stored in the builder.
func (b *ClusterConsoleBuilder) Build() (object *ClusterConsole, err error) {
	object = new(ClusterConsole)
	if b.url != nil {
		object.url = b.url
	}
	return
}
