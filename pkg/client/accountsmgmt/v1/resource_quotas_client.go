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

// ResourceQuotasClient is the client of the 'resource_quotas' resource.
//
// Manages the collection of resource quotas for an organization.
type ResourceQuotasClient struct {
	transport http.RoundTripper
	path      string
}

// NewResourceQuotasClient creates a new client for the 'resource_quotas'
// resource using the given transport to sned the requests and receive the
// responses.
func NewResourceQuotasClient(transport http.RoundTripper, path string) *ResourceQuotasClient {
	client := new(ResourceQuotasClient)
	client.transport = transport
	client.path = path
	return client
}

// List creates a request for the 'list' method.
//
// Retrieves the list of resource quotas.
func (c *ResourceQuotasClient) List() *ResourceQuotasListRequest {
	request := new(ResourceQuotasListRequest)
	request.transport = c.transport
	request.path = c.path
	return request
}

// Add creates a request for the 'add' method.
//
// Creates a new resource quota.
func (c *ResourceQuotasClient) Add() *ResourceQuotasAddRequest {
	request := new(ResourceQuotasAddRequest)
	request.transport = c.transport
	request.path = c.path
	return request
}

// ResourceQuota returns the target 'resource_quota' resource for the given identifier.
//
// Reference to the service that manages an specific resource quota.
func (c *ResourceQuotasClient) ResourceQuota(id string) *ResourceQuotaClient {
	return NewResourceQuotaClient(c.transport, path.Join(c.path, id))
}

// ResourceQuotasListRequest is the request for the 'list' method.
type ResourceQuotasListRequest struct {
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
func (r *ResourceQuotasListRequest) Context(value context.Context) *ResourceQuotasListRequest {
	r.context = value
	return r
}

// Timeout sets a timeout for the completete request.
func (r *ResourceQuotasListRequest) Timeout(value time.Duration) *ResourceQuotasListRequest {
	helpers.SetTimeout(&r.context, &r.cancel, value)
	return r
}

// Deadline sets a deadline for the completete request.
func (r *ResourceQuotasListRequest) Deadline(value time.Time) *ResourceQuotasListRequest {
	helpers.SetDeadline(&r.context, &r.cancel, value)
	return r
}

// Parameter adds a query parameter.
func (r *ResourceQuotasListRequest) Parameter(name string, value interface{}) *ResourceQuotasListRequest {
	helpers.AddValue(&r.query, name, value)
	return r
}

// Header adds a request header.
func (r *ResourceQuotasListRequest) Header(name string, value interface{}) *ResourceQuotasListRequest {
	helpers.AddHeader(&r.header, name, value)
	return r
}

// Page sets the value of the 'page' parameter.
//
// Index of the requested page, where one corresponds to the first page.
//
// Default value is `1`.
func (r *ResourceQuotasListRequest) Page(value int) *ResourceQuotasListRequest {
	r.page = &value
	return r
}

// Size sets the value of the 'size' parameter.
//
// Maximum number of items that will be contained in the returned page.
//
// Default value is `100`.
func (r *ResourceQuotasListRequest) Size(value int) *ResourceQuotasListRequest {
	r.size = &value
	return r
}

// Total sets the value of the 'total' parameter.
//
// Total number of items of the collection that match the search criteria,
// regardless of the size of the page.
func (r *ResourceQuotasListRequest) Total(value int) *ResourceQuotasListRequest {
	r.total = &value
	return r
}

// Send sends this request, waits for the response, and returns it.
func (r *ResourceQuotasListRequest) Send() (result *ResourceQuotasListResponse, err error) {
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
	result = new(ResourceQuotasListResponse)
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

// ResourceQuotasListResponse is the response for the 'list' method.
type ResourceQuotasListResponse struct {
	status int
	header http.Header
	err    *errors.Error
	page   *int
	size   *int
	total  *int
	items  *ResourceQuotaList
}

// Status returns the response status code.
func (r *ResourceQuotasListResponse) Status() int {
	return r.status
}

// Header returns header of the response.
func (r *ResourceQuotasListResponse) Header() http.Header {
	return r.header
}

// Error returns the response error.
func (r *ResourceQuotasListResponse) Error() *errors.Error {
	return r.err
}

// Page returns the value of the 'page' parameter.
//
// Index of the requested page, where one corresponds to the first page.
//
// Default value is `1`.
func (r *ResourceQuotasListResponse) Page() int {
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
func (r *ResourceQuotasListResponse) Size() int {
	if r.size != nil {
		return *r.size
	}
	return 0
}

// Total returns the value of the 'total' parameter.
//
// Total number of items of the collection that match the search criteria,
// regardless of the size of the page.
func (r *ResourceQuotasListResponse) Total() int {
	if r.total != nil {
		return *r.total
	}
	return 0
}

// Items returns the value of the 'items' parameter.
//
// Retrieved list of resource quotas.
func (r *ResourceQuotasListResponse) Items() *ResourceQuotaList {
	return r.items
}

// unmarshal is the method used internally to unmarshal responses to the
// 'list' method.
func (r *ResourceQuotasListResponse) unmarshal(reader io.Reader) error {
	var err error
	decoder := json.NewDecoder(reader)
	data := new(resourceQuotasListResponseData)
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

// resourceQuotasListResponseData is the structure used internally to unmarshal
// the response of the 'list' method.
type resourceQuotasListResponseData struct {
	Page  *int                  "json:\"page,omitempty\""
	Size  *int                  "json:\"size,omitempty\""
	Total *int                  "json:\"total,omitempty\""
	Items resourceQuotaListData "json:\"items,omitempty\""
}

// ResourceQuotasAddRequest is the request for the 'add' method.
type ResourceQuotasAddRequest struct {
	transport http.RoundTripper
	path      string
	context   context.Context
	cancel    context.CancelFunc
	query     url.Values
	header    http.Header
	body      *ResourceQuota
}

// Context sets the context that will be used to send the request.
func (r *ResourceQuotasAddRequest) Context(value context.Context) *ResourceQuotasAddRequest {
	r.context = value
	return r
}

// Timeout sets a timeout for the completete request.
func (r *ResourceQuotasAddRequest) Timeout(value time.Duration) *ResourceQuotasAddRequest {
	helpers.SetTimeout(&r.context, &r.cancel, value)
	return r
}

// Deadline sets a deadline for the completete request.
func (r *ResourceQuotasAddRequest) Deadline(value time.Time) *ResourceQuotasAddRequest {
	helpers.SetDeadline(&r.context, &r.cancel, value)
	return r
}

// Parameter adds a query parameter.
func (r *ResourceQuotasAddRequest) Parameter(name string, value interface{}) *ResourceQuotasAddRequest {
	helpers.AddValue(&r.query, name, value)
	return r
}

// Header adds a request header.
func (r *ResourceQuotasAddRequest) Header(name string, value interface{}) *ResourceQuotasAddRequest {
	helpers.AddHeader(&r.header, name, value)
	return r
}

// Body sets the value of the 'body' parameter.
//
// Resource quota data.
func (r *ResourceQuotasAddRequest) Body(value *ResourceQuota) *ResourceQuotasAddRequest {
	r.body = value
	return r
}

// Send sends this request, waits for the response, and returns it.
func (r *ResourceQuotasAddRequest) Send() (result *ResourceQuotasAddResponse, err error) {
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
	result = new(ResourceQuotasAddResponse)
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
func (r *ResourceQuotasAddRequest) marshal(writer io.Writer) error {
	var err error
	encoder := json.NewEncoder(writer)
	data, err := r.body.wrap()
	if err != nil {
		return err
	}
	err = encoder.Encode(data)
	return err
}

// ResourceQuotasAddResponse is the response for the 'add' method.
type ResourceQuotasAddResponse struct {
	status int
	header http.Header
	err    *errors.Error
	body   *ResourceQuota
}

// Status returns the response status code.
func (r *ResourceQuotasAddResponse) Status() int {
	return r.status
}

// Header returns header of the response.
func (r *ResourceQuotasAddResponse) Header() http.Header {
	return r.header
}

// Error returns the response error.
func (r *ResourceQuotasAddResponse) Error() *errors.Error {
	return r.err
}

// Body returns the value of the 'body' parameter.
//
// Resource quota data.
func (r *ResourceQuotasAddResponse) Body() *ResourceQuota {
	return r.body
}

// unmarshal is the method used internally to unmarshal responses to the
// 'add' method.
func (r *ResourceQuotasAddResponse) unmarshal(reader io.Reader) error {
	var err error
	decoder := json.NewDecoder(reader)
	data := new(resourceQuotaData)
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
