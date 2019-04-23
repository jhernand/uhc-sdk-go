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

// CloudRegionKind is the name of the type used to represent objects
// of type 'cloud_region'.
const CloudRegionKind = "CloudRegion"

// CloudRegionLinkKind is the name of the type used to represent links
// to objects of type 'cloud_region'.
const CloudRegionLinkKind = "CloudRegionLink"

// CloudRegionNilKind is the name of the type used to nil references
// to objects of type 'cloud_region'.
const CloudRegionNilKind = "CloudRegionNil"

// CloudRegion represents the values of the 'cloud_region' type.
//
// Description of a region of a cloud provider.
type CloudRegion struct {
	id            *string
	href          *string
	link          bool
	name          *string
	displayName   *string
	cloudProvider *CloudProvider
}

// Kind returns the name of the type of the object.
func (o *CloudRegion) Kind() string {
	if o == nil {
		return CloudRegionNilKind
	}
	if o.link {
		return CloudRegionLinkKind
	}
	return CloudRegionKind
}

// ID returns the identifier of the object.
func (o *CloudRegion) ID() string {
	if o != nil && o.id != nil {
		return *o.id
	}
	return ""
}

// GetID returns the identifier of the object and a flag indicating if the
// identifier has a value.
func (o *CloudRegion) GetID() (value string, ok bool) {
	ok = o != nil && o.id != nil
	if ok {
		value = *o.id
	}
	return
}

// Link returns true iif this is a link.
func (o *CloudRegion) Link() bool {
	return o != nil && o.link
}

// HREF returns the link to the object.
func (o *CloudRegion) HREF() string {
	if o != nil && o.href != nil {
		return *o.href
	}
	return ""
}

// GetHREF returns the link of the object and a flag indicating if the
// link has a value.
func (o *CloudRegion) GetHREF() (value string, ok bool) {
	ok = o != nil && o.href != nil
	if ok {
		value = *o.href
	}
	return
}

// Name returns the value of the 'name' attribute, or
// the zero value of the type if the attribute doesn't have a value.
//
// Human friendly identifier of the region, for example `us-east-1`.
//
// NOTE: Currently for all cloud provideers and all regions `id` and `name` have exactly
// the same values.
func (o *CloudRegion) Name() string {
	if o != nil && o.name != nil {
		return *o.name
	}
	return ""
}

// GetName returns the value of the 'name' attribute and
// a flag indicating if the attribute has a value.
//
// Human friendly identifier of the region, for example `us-east-1`.
//
// NOTE: Currently for all cloud provideers and all regions `id` and `name` have exactly
// the same values.
func (o *CloudRegion) GetName() (value string, ok bool) {
	ok = o != nil && o.name != nil
	if ok {
		value = *o.name
	}
	return
}

// DisplayName returns the value of the 'display_name' attribute, or
// the zero value of the type if the attribute doesn't have a value.
//
// Name of the region for display purposes, for example `N. Virginia`.
func (o *CloudRegion) DisplayName() string {
	if o != nil && o.displayName != nil {
		return *o.displayName
	}
	return ""
}

// GetDisplayName returns the value of the 'display_name' attribute and
// a flag indicating if the attribute has a value.
//
// Name of the region for display purposes, for example `N. Virginia`.
func (o *CloudRegion) GetDisplayName() (value string, ok bool) {
	ok = o != nil && o.displayName != nil
	if ok {
		value = *o.displayName
	}
	return
}

// CloudProvider returns the value of the 'cloud_provider' attribute, or
// the zero value of the type if the attribute doesn't have a value.
//
// Link to the cloud provider that the region belongs to.
func (o *CloudRegion) CloudProvider() *CloudProvider {
	if o == nil {
		return nil
	}
	return o.cloudProvider
}

// GetCloudProvider returns the value of the 'cloud_provider' attribute and
// a flag indicating if the attribute has a value.
//
// Link to the cloud provider that the region belongs to.
func (o *CloudRegion) GetCloudProvider() (value *CloudProvider, ok bool) {
	ok = o != nil && o.cloudProvider != nil
	if ok {
		value = o.cloudProvider
	}
	return
}

// CloudRegionList is a list of values of the 'cloud_region' type.
type CloudRegionList struct {
	items []*CloudRegion
}

// Len returns the length of the list.
func (l *CloudRegionList) Len() int {
	if l == nil {
		return 0
	}
	return len(l.items)
}

// Slice returns an slice containing the items of the list. The returned slice is a
// copy of the one used internally, so it can be modified without affecting the
// internal representation.
//
// If you don't need to modify the returned slice consider using the Each or Range
// functions, as they don't need to allocate a new slice.
func (l *CloudRegionList) Slice() []*CloudRegion {
	var slice []*CloudRegion
	if l == nil {
		slice = make([]*CloudRegion, 0)
	} else {
		slice = make([]*CloudRegion, len(l.items))
		copy(slice, l.items)
	}
	return slice
}

// Each runs the given function for each item of the list, in order. If the function
// returns false the iteration stops, otherwise it continues till all the elements
// of the list have been processed.
func (l *CloudRegionList) Each(f func(item *CloudRegion) bool) {
	if l == nil {
		return
	}
	for _, item := range l.items {
		if !f(item) {
			break
		}
	}
}

// Range runs the given function for each index and item of the list, in order. If
// the function returns false the iteration stops, otherwise it continues till all
// the elements of the list have been processed.
func (l *CloudRegionList) Range(f func(index int, item *CloudRegion) bool) {
	if l == nil {
		return
	}
	for index, item := range l.items {
		if !f(index, item) {
			break
		}
	}
}
