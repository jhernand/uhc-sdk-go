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

package v1 // github.com/openshift-online/uhc-sdk-go/pkg/client/accountsmgmt/v1

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	time "time"

	"github.com/openshift-online/uhc-sdk-go/pkg/client/errors"
	"github.com/openshift-online/uhc-sdk-go/pkg/client/helpers"
)

// CurrentAccountClient is the client of the 'current_account' resource.
//
// Manages the current authenticated account.
type CurrentAccountClient struct {
	transport http.RoundTripper
	path      string
}

// NewCurrentAccountClient creates a new client for the 'current_account'
// resource using the given transport to sned the requests and receive the
// responses.
func NewCurrentAccountClient(transport http.RoundTripper, path string) *CurrentAccountClient {
	client := new(CurrentAccountClient)
	client.transport = transport
	client.path = path
	return client
}

// Get creates a request for the 'get' method.
//
// Retrieves the details of the account.
func (c *CurrentAccountClient) Get() *CurrentAccountGetRequest {
	request := new(CurrentAccountGetRequest)
	request.transport = c.transport
	request.path = c.path
	return request
}

// CurrentAccountGetRequest is the request for the 'get' method.
type CurrentAccountGetRequest struct {
	transport http.RoundTripper
	path      string
	context   context.Context
	cancel    context.CancelFunc
	query     url.Values
	header    http.Header
}

// Context sets the context that will be used to send the request.
func (r *CurrentAccountGetRequest) Context(value context.Context) *CurrentAccountGetRequest {
	r.context = value
	return r
}

// Timeout sets a timeout for the completete request.
func (r *CurrentAccountGetRequest) Timeout(value time.Duration) *CurrentAccountGetRequest {
	helpers.SetTimeout(&r.context, &r.cancel, value)
	return r
}

// Deadline sets a deadline for the completete request.
func (r *CurrentAccountGetRequest) Deadline(value time.Time) *CurrentAccountGetRequest {
	helpers.SetDeadline(&r.context, &r.cancel, value)
	return r
}

// Parameter adds a query parameter.
func (r *CurrentAccountGetRequest) Parameter(name string, value interface{}) *CurrentAccountGetRequest {
	helpers.AddValue(&r.query, name, value)
	return r
}

// Header adds a request header.
func (r *CurrentAccountGetRequest) Header(name string, value interface{}) *CurrentAccountGetRequest {
	helpers.AddHeader(&r.header, name, value)
	return r
}

// Send sends this request, waits for the response, and returns it.
func (r *CurrentAccountGetRequest) Send() (result *CurrentAccountGetResponse, err error) {
	query := helpers.CopyQuery(r.query)
	header := helpers.CopyHeader(r.header)
	uri := &url.URL{
		Path:     r.path,
		RawQuery: query.Encode(),
	}
	request := &http.Request{
		Method: http.MethodGet,
		URL:    uri,
		Header: header,
	}
	response, err := r.transport.RoundTrip(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	result = new(CurrentAccountGetResponse)
	result.status = response.StatusCode
	result.header = response.Header
	if result.status >= 400 {
		result.err, err = errors.UnmarshalError(response.Body)
		if err != nil {
			return
		}
		err = result.err
		return
	}
	err = result.unmarshal(response.Body)
	if err != nil {
		return
	}
	return
}

// CurrentAccountGetResponse is the response for the 'get' method.
type CurrentAccountGetResponse struct {
	status int
	header http.Header
	err    *errors.Error
	body   *Account
}

// Status returns the response status code.
func (r *CurrentAccountGetResponse) Status() int {
	return r.status
}

// Header returns header of the response.
func (r *CurrentAccountGetResponse) Header() http.Header {
	return r.header
}

// Error returns the response error.
func (r *CurrentAccountGetResponse) Error() *errors.Error {
	return r.err
}

// Body returns the value of the 'body' parameter.
//
//
func (r *CurrentAccountGetResponse) Body() *Account {
	return r.body
}

// unmarshal is the method used internally to unmarshal responses to the
// 'get' method.
func (r *CurrentAccountGetResponse) unmarshal(reader io.Reader) error {
	var err error
	decoder := json.NewDecoder(reader)
	data := new(accountData)
	err = decoder.Decode(data)
	if err != nil {
		return err
	}
	r.body, err = data.unwrap()
	if err != nil {
		return err
	}
	return err
}
