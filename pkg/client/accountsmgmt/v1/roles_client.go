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
	"path"
	time "time"

	"github.com/openshift-online/uhc-sdk-go/pkg/client/errors"
	"github.com/openshift-online/uhc-sdk-go/pkg/client/helpers"
)

// RolesClient is the client of the 'roles' resource.
//
// Manages the collection of roles.
type RolesClient struct {
	transport http.RoundTripper
	path      string
}

// NewRolesClient creates a new client for the 'roles'
// resource using the given transport to sned the requests and receive the
// responses.
func NewRolesClient(transport http.RoundTripper, path string) *RolesClient {
	client := new(RolesClient)
	client.transport = transport
	client.path = path
	return client
}

// List creates a request for the 'list' method.
//
// Retrieves a list of roles.
func (c *RolesClient) List() *RolesListRequest {
	request := new(RolesListRequest)
	request.transport = c.transport
	request.path = c.path
	return request
}

// Add creates a request for the 'add' method.
//
// Creates a new role.
func (c *RolesClient) Add() *RolesAddRequest {
	request := new(RolesAddRequest)
	request.transport = c.transport
	request.path = c.path
	return request
}

// Role returns the target 'role' resource for the given identifier.
//
// Reference to the service that manages a specific role.
func (c *RolesClient) Role(id string) *RoleClient {
	return NewRoleClient(c.transport, path.Join(c.path, id))
}

// RolesListRequest is the request for the 'list' method.
type RolesListRequest struct {
	transport http.RoundTripper
	path      string
	context   context.Context
	cancel    context.CancelFunc
	query     url.Values
	header    http.Header
	page      *int
	size      *int
	total     *int
}

// Context sets the context that will be used to send the request.
func (r *RolesListRequest) Context(value context.Context) *RolesListRequest {
	r.context = value
	return r
}

// Timeout sets a timeout for the completete request.
func (r *RolesListRequest) Timeout(value time.Duration) *RolesListRequest {
	helpers.SetTimeout(&r.context, &r.cancel, value)
	return r
}

// Deadline sets a deadline for the completete request.
func (r *RolesListRequest) Deadline(value time.Time) *RolesListRequest {
	helpers.SetDeadline(&r.context, &r.cancel, value)
	return r
}

// Parameter adds a query parameter.
func (r *RolesListRequest) Parameter(name string, value interface{}) *RolesListRequest {
	helpers.AddValue(&r.query, name, value)
	return r
}

// Header adds a request header.
func (r *RolesListRequest) Header(name string, value interface{}) *RolesListRequest {
	helpers.AddHeader(&r.header, name, value)
	return r
}

// Page sets the value of the 'page' parameter.
//
// Index of the requested page, where one corresponds to the first page.
//
// Default value is `1`.
func (r *RolesListRequest) Page(value int) *RolesListRequest {
	r.page = &value
	return r
}

// Size sets the value of the 'size' parameter.
//
// Maximum number of items that will be contained in the returned page.
//
// Default value is `100`.
func (r *RolesListRequest) Size(value int) *RolesListRequest {
	r.size = &value
	return r
}

// Total sets the value of the 'total' parameter.
//
// Total number of items of the collection that match the search criteria,
// regardless of the size of the page.
func (r *RolesListRequest) Total(value int) *RolesListRequest {
	r.total = &value
	return r
}

// Send sends this request, waits for the response, and returns it.
func (r *RolesListRequest) Send() (result *RolesListResponse, err error) {
	query := helpers.CopyQuery(r.query)
	if r.page != nil {
		helpers.AddValue(&query, "page", *r.page)
	}
	if r.size != nil {
		helpers.AddValue(&query, "size", *r.size)
	}
	if r.total != nil {
		helpers.AddValue(&query, "total", *r.total)
	}
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
	result = new(RolesListResponse)
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

// RolesListResponse is the response for the 'list' method.
type RolesListResponse struct {
	status int
	header http.Header
	err    *errors.Error
	page   *int
	size   *int
	total  *int
	items  *RoleList
}

// Status returns the response status code.
func (r *RolesListResponse) Status() int {
	return r.status
}

// Header returns header of the response.
func (r *RolesListResponse) Header() http.Header {
	return r.header
}

// Error returns the response error.
func (r *RolesListResponse) Error() *errors.Error {
	return r.err
}

// Page returns the value of the 'page' parameter.
//
// Index of the requested page, where one corresponds to the first page.
//
// Default value is `1`.
func (r *RolesListResponse) Page() int {
	if r.page != nil {
		return *r.page
	}
	return 0
}

// Size returns the value of the 'size' parameter.
//
// Maximum number of items that will be contained in the returned page.
//
// Default value is `100`.
func (r *RolesListResponse) Size() int {
	if r.size != nil {
		return *r.size
	}
	return 0
}

// Total returns the value of the 'total' parameter.
//
// Total number of items of the collection that match the search criteria,
// regardless of the size of the page.
func (r *RolesListResponse) Total() int {
	if r.total != nil {
		return *r.total
	}
	return 0
}

// Items returns the value of the 'items' parameter.
//
// Retrieved list of roles.
func (r *RolesListResponse) Items() *RoleList {
	return r.items
}

// unmarshal is the method used internally to unmarshal responses to the
// 'list' method.
func (r *RolesListResponse) unmarshal(reader io.Reader) error {
	var err error
	decoder := json.NewDecoder(reader)
	data := new(rolesListResponseData)
	err = decoder.Decode(data)
	if err != nil {
		return err
	}
	r.page = data.Page
	r.size = data.Size
	r.total = data.Total
	r.items, err = data.Items.unwrap()
	if err != nil {
		return err
	}
	return err
}

// rolesListResponseData is the structure used internally to unmarshal
// the response of the 'list' method.
type rolesListResponseData struct {
	Page  *int         "json:\"page,omitempty\""
	Size  *int         "json:\"size,omitempty\""
	Total *int         "json:\"total,omitempty\""
	Items roleListData "json:\"items,omitempty\""
}

// RolesAddRequest is the request for the 'add' method.
type RolesAddRequest struct {
	transport http.RoundTripper
	path      string
	context   context.Context
	cancel    context.CancelFunc
	query     url.Values
	header    http.Header
	body      *Role
}

// Context sets the context that will be used to send the request.
func (r *RolesAddRequest) Context(value context.Context) *RolesAddRequest {
	r.context = value
	return r
}

// Timeout sets a timeout for the completete request.
func (r *RolesAddRequest) Timeout(value time.Duration) *RolesAddRequest {
	helpers.SetTimeout(&r.context, &r.cancel, value)
	return r
}

// Deadline sets a deadline for the completete request.
func (r *RolesAddRequest) Deadline(value time.Time) *RolesAddRequest {
	helpers.SetDeadline(&r.context, &r.cancel, value)
	return r
}

// Parameter adds a query parameter.
func (r *RolesAddRequest) Parameter(name string, value interface{}) *RolesAddRequest {
	helpers.AddValue(&r.query, name, value)
	return r
}

// Header adds a request header.
func (r *RolesAddRequest) Header(name string, value interface{}) *RolesAddRequest {
	helpers.AddHeader(&r.header, name, value)
	return r
}

// Body sets the value of the 'body' parameter.
//
// Role data.
func (r *RolesAddRequest) Body(value *Role) *RolesAddRequest {
	r.body = value
	return r
}

// Send sends this request, waits for the response, and returns it.
func (r *RolesAddRequest) Send() (result *RolesAddResponse, err error) {
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
	result = new(RolesAddResponse)
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
// 'add' method.
func (r *RolesAddRequest) marshal(writer io.Writer) error {
	var err error
	encoder := json.NewEncoder(writer)
	data, err := r.body.wrap()
	if err != nil {
		return err
	}
	err = encoder.Encode(data)
	return err
}

// RolesAddResponse is the response for the 'add' method.
type RolesAddResponse struct {
	status int
	header http.Header
	err    *errors.Error
	body   *Role
}

// Status returns the response status code.
func (r *RolesAddResponse) Status() int {
	return r.status
}

// Header returns header of the response.
func (r *RolesAddResponse) Header() http.Header {
	return r.header
}

// Error returns the response error.
func (r *RolesAddResponse) Error() *errors.Error {
	return r.err
}

// Body returns the value of the 'body' parameter.
//
// Role data.
func (r *RolesAddResponse) Body() *Role {
	return r.body
}

// unmarshal is the method used internally to unmarshal responses to the
// 'add' method.
func (r *RolesAddResponse) unmarshal(reader io.Reader) error {
	var err error
	decoder := json.NewDecoder(reader)
	data := new(roleData)
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
