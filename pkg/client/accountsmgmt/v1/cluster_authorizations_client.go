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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	time "time"

	"github.com/openshift-online/uhc-sdk-go/pkg/client/errors"
	"github.com/openshift-online/uhc-sdk-go/pkg/client/helpers"
)

// ClusterAuthorizationsClient is the client of the 'cluster_authorizations' resource.
//
// Manages cluster authorizations.
type ClusterAuthorizationsClient struct {
	transport http.RoundTripper
	path      string
}

// NewClusterAuthorizationsClient creates a new client for the 'cluster_authorizations'
// resource using the given transport to sned the requests and receive the
// responses.
func NewClusterAuthorizationsClient(transport http.RoundTripper, path string) *ClusterAuthorizationsClient {
	client := new(ClusterAuthorizationsClient)
	client.transport = transport
	client.path = path
	return client
}

// Post creates a request for the 'post' method.
//
// Authorizes new cluster creation against an existing subscription.
func (c *ClusterAuthorizationsClient) Post() *ClusterAuthorizationsPostRequest {
	request := new(ClusterAuthorizationsPostRequest)
	request.transport = c.transport
	request.path = c.path
	return request
}

// ClusterAuthorizationsPostRequest is the request for the 'post' method.
type ClusterAuthorizationsPostRequest struct {
	transport http.RoundTripper
	path      string
	context   context.Context
	cancel    context.CancelFunc
	query     url.Values
	header    http.Header
	request   *ClusterAuthorizationRequest
}

// Context sets the context that will be used to send the request.
func (r *ClusterAuthorizationsPostRequest) Context(value context.Context) *ClusterAuthorizationsPostRequest {
	r.context = value
	return r
}

// Timeout sets a timeout for the completete request.
func (r *ClusterAuthorizationsPostRequest) Timeout(value time.Duration) *ClusterAuthorizationsPostRequest {
	helpers.SetTimeout(&r.context, &r.cancel, value)
	return r
}

// Deadline sets a deadline for the completete request.
func (r *ClusterAuthorizationsPostRequest) Deadline(value time.Time) *ClusterAuthorizationsPostRequest {
	helpers.SetDeadline(&r.context, &r.cancel, value)
	return r
}

// Parameter adds a query parameter.
func (r *ClusterAuthorizationsPostRequest) Parameter(name string, value interface{}) *ClusterAuthorizationsPostRequest {
	helpers.AddValue(&r.query, name, value)
	return r
}

// Header adds a request header.
func (r *ClusterAuthorizationsPostRequest) Header(name string, value interface{}) *ClusterAuthorizationsPostRequest {
	helpers.AddHeader(&r.header, name, value)
	return r
}

// Request sets the value of the 'request' parameter.
//
//
func (r *ClusterAuthorizationsPostRequest) Request(value *ClusterAuthorizationRequest) *ClusterAuthorizationsPostRequest {
	r.request = value
	return r
}

// Send sends this request, waits for the response, and returns it.
func (r *ClusterAuthorizationsPostRequest) Send() (result *ClusterAuthorizationsPostResponse, err error) {
	query := helpers.CopyQuery(r.query)
	header := helpers.CopyHeader(r.header)
	buffer := new(bytes.Buffer)
	err = r.marshal(buffer)
	if err != nil {
		return
	}
	uri := &url.URL{
		Path:     r.path,
		RawQuery: query.Encode(),
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL:    uri,
		Header: header,
		Body:   ioutil.NopCloser(buffer),
	}
	response, err := r.transport.RoundTrip(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	result = new(ClusterAuthorizationsPostResponse)
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

// marshall is the method used internally to marshal requests for the
// 'post' method.
func (r *ClusterAuthorizationsPostRequest) marshal(writer io.Writer) error {
	var err error
	encoder := json.NewEncoder(writer)
	data, err := r.request.wrap()
	if err != nil {
		return err
	}
	err = encoder.Encode(data)
	return err
}

// ClusterAuthorizationsPostResponse is the response for the 'post' method.
type ClusterAuthorizationsPostResponse struct {
	status   int
	header   http.Header
	err      *errors.Error
	response *ClusterAuthorizationResponse
}

// Status returns the response status code.
func (r *ClusterAuthorizationsPostResponse) Status() int {
	return r.status
}

// Header returns header of the response.
func (r *ClusterAuthorizationsPostResponse) Header() http.Header {
	return r.header
}

// Error returns the response error.
func (r *ClusterAuthorizationsPostResponse) Error() *errors.Error {
	return r.err
}

// Response returns the value of the 'response' parameter.
//
//
func (r *ClusterAuthorizationsPostResponse) Response() *ClusterAuthorizationResponse {
	return r.response
}

// unmarshal is the method used internally to unmarshal responses to the
// 'post' method.
func (r *ClusterAuthorizationsPostResponse) unmarshal(reader io.Reader) error {
	var err error
	decoder := json.NewDecoder(reader)
	data := new(clusterAuthorizationResponseData)
	err = decoder.Decode(data)
	if err != nil {
		return err
	}
	r.response, err = data.unwrap()
	if err != nil {
		return err
	}
	return err
}
