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

// AccountsClient is the client of the 'accounts' resource.
//
// Manages the collection of accounts.
type AccountsClient struct {
	transport http.RoundTripper
	path      string
}

// NewAccountsClient creates a new client for the 'accounts'
// resource using the given transport to sned the requests and receive the
// responses.
func NewAccountsClient(transport http.RoundTripper, path string) *AccountsClient {
	client := new(AccountsClient)
	client.transport = transport
	client.path = path
	return client
}

// List creates a request for the 'list' method.
//
// Retrieves the list of accounts.
func (c *AccountsClient) List() *AccountsListRequest {
	request := new(AccountsListRequest)
	request.transport = c.transport
	request.path = c.path
	return request
}

// Add creates a request for the 'add' method.
//
// Creates a new account.
func (c *AccountsClient) Add() *AccountsAddRequest {
	request := new(AccountsAddRequest)
	request.transport = c.transport
	request.path = c.path
	return request
}

// Account returns the target 'account' resource for the given identifier.
//
// Reference to the service that manages an specific account.
func (c *AccountsClient) Account(id string) *AccountClient {
	return NewAccountClient(c.transport, path.Join(c.path, id))
}

// AccountsListRequest is the request for the 'list' method.
type AccountsListRequest struct {
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
func (r *AccountsListRequest) Context(value context.Context) *AccountsListRequest {
	r.context = value
	return r
}

// Timeout sets a timeout for the completete request.
func (r *AccountsListRequest) Timeout(value time.Duration) *AccountsListRequest {
	helpers.SetTimeout(&r.context, &r.cancel, value)
	return r
}

// Deadline sets a deadline for the completete request.
func (r *AccountsListRequest) Deadline(value time.Time) *AccountsListRequest {
	helpers.SetDeadline(&r.context, &r.cancel, value)
	return r
}

// Parameter adds a query parameter.
func (r *AccountsListRequest) Parameter(name string, value interface{}) *AccountsListRequest {
	helpers.AddValue(&r.query, name, value)
	return r
}

// Header adds a request header.
func (r *AccountsListRequest) Header(name string, value interface{}) *AccountsListRequest {
	helpers.AddHeader(&r.header, name, value)
	return r
}

// Page sets the value of the 'page' parameter.
//
// Index of the requested page, where one corresponds to the first page.
//
// Default value is `1`.
func (r *AccountsListRequest) Page(value int) *AccountsListRequest {
	r.page = &value
	return r
}

// Size sets the value of the 'size' parameter.
//
// Maximum number of items that will be contained in the returned page.
//
// Default value is `100`.
func (r *AccountsListRequest) Size(value int) *AccountsListRequest {
	r.size = &value
	return r
}

// Total sets the value of the 'total' parameter.
//
// Total number of items of the collection that match the search criteria,
// regardless of the size of the page.
func (r *AccountsListRequest) Total(value int) *AccountsListRequest {
	r.total = &value
	return r
}

// Send sends this request, waits for the response, and returns it.
func (r *AccountsListRequest) Send() (result *AccountsListResponse, err error) {
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
	result = new(AccountsListResponse)
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

// AccountsListResponse is the response for the 'list' method.
type AccountsListResponse struct {
	status int
	header http.Header
	err    *errors.Error
	page   *int
	size   *int
	total  *int
	items  *AccountList
}

// Status returns the response status code.
func (r *AccountsListResponse) Status() int {
	return r.status
}

// Header returns header of the response.
func (r *AccountsListResponse) Header() http.Header {
	return r.header
}

// Error returns the response error.
func (r *AccountsListResponse) Error() *errors.Error {
	return r.err
}

// Page returns the value of the 'page' parameter.
//
// Index of the requested page, where one corresponds to the first page.
//
// Default value is `1`.
func (r *AccountsListResponse) Page() int {
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
func (r *AccountsListResponse) Size() int {
	if r.size != nil {
		return *r.size
	}
	return 0
}

// Total returns the value of the 'total' parameter.
//
// Total number of items of the collection that match the search criteria,
// regardless of the size of the page.
func (r *AccountsListResponse) Total() int {
	if r.total != nil {
		return *r.total
	}
	return 0
}

// Items returns the value of the 'items' parameter.
//
// Retrieved list of accounts.
func (r *AccountsListResponse) Items() *AccountList {
	return r.items
}

// unmarshal is the method used internally to unmarshal responses to the
// 'list' method.
func (r *AccountsListResponse) unmarshal(reader io.Reader) error {
	var err error
	decoder := json.NewDecoder(reader)
	data := new(accountsListResponseData)
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

// accountsListResponseData is the structure used internally to unmarshal
// the response of the 'list' method.
type accountsListResponseData struct {
	Page  *int            "json:\"page,omitempty\""
	Size  *int            "json:\"size,omitempty\""
	Total *int            "json:\"total,omitempty\""
	Items accountListData "json:\"items,omitempty\""
}

// AccountsAddRequest is the request for the 'add' method.
type AccountsAddRequest struct {
	transport http.RoundTripper
	path      string
	context   context.Context
	cancel    context.CancelFunc
	query     url.Values
	header    http.Header
	body      *Account
}

// Context sets the context that will be used to send the request.
func (r *AccountsAddRequest) Context(value context.Context) *AccountsAddRequest {
	r.context = value
	return r
}

// Timeout sets a timeout for the completete request.
func (r *AccountsAddRequest) Timeout(value time.Duration) *AccountsAddRequest {
	helpers.SetTimeout(&r.context, &r.cancel, value)
	return r
}

// Deadline sets a deadline for the completete request.
func (r *AccountsAddRequest) Deadline(value time.Time) *AccountsAddRequest {
	helpers.SetDeadline(&r.context, &r.cancel, value)
	return r
}

// Parameter adds a query parameter.
func (r *AccountsAddRequest) Parameter(name string, value interface{}) *AccountsAddRequest {
	helpers.AddValue(&r.query, name, value)
	return r
}

// Header adds a request header.
func (r *AccountsAddRequest) Header(name string, value interface{}) *AccountsAddRequest {
	helpers.AddHeader(&r.header, name, value)
	return r
}

// Body sets the value of the 'body' parameter.
//
// Account data.
func (r *AccountsAddRequest) Body(value *Account) *AccountsAddRequest {
	r.body = value
	return r
}

// Send sends this request, waits for the response, and returns it.
func (r *AccountsAddRequest) Send() (result *AccountsAddResponse, err error) {
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
	result = new(AccountsAddResponse)
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
func (r *AccountsAddRequest) marshal(writer io.Writer) error {
	var err error
	encoder := json.NewEncoder(writer)
	data, err := r.body.wrap()
	if err != nil {
		return err
	}
	err = encoder.Encode(data)
	return err
}

// AccountsAddResponse is the response for the 'add' method.
type AccountsAddResponse struct {
	status int
	header http.Header
	err    *errors.Error
	body   *Account
}

// Status returns the response status code.
func (r *AccountsAddResponse) Status() int {
	return r.status
}

// Header returns header of the response.
func (r *AccountsAddResponse) Header() http.Header {
	return r.header
}

// Error returns the response error.
func (r *AccountsAddResponse) Error() *errors.Error {
	return r.err
}

// Body returns the value of the 'body' parameter.
//
// Account data.
func (r *AccountsAddResponse) Body() *Account {
	return r.body
}

// unmarshal is the method used internally to unmarshal responses to the
// 'add' method.
func (r *AccountsAddResponse) unmarshal(reader io.Reader) error {
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
