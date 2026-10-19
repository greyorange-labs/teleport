// Teleport
// Copyright (C) 2026  GreyOrange
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package ui

import (
	"time"

	"github.com/gravitational/teleport/api/types"
)

// AccessRequestUserInfo identifies a user referenced by an access request.
type AccessRequestUserInfo struct {
	Username string `json:"username"`
}

// AccessRequestResource is a resource referenced by an access request. The
// JSON shape matches the `Resource` type of the web UI.
type AccessRequestResource struct {
	ID AccessRequestResourceID `json:"id"`
}

// AccessRequestResourceID is the unique identifier of a requested resource.
type AccessRequestResourceID struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	ClusterName     string `json:"clusterName"`
	SubResourceName string `json:"subResourceName,omitempty"`
}

// AccessRequestReview is a single review of an access request.
type AccessRequestReview struct {
	Author          string                `json:"author"`
	AuthorInfo      AccessRequestUserInfo `json:"authorInfo"`
	State           string                `json:"state"`
	Reason          string                `json:"reason"`
	Roles           []string              `json:"roles"`
	Created         time.Time             `json:"created"`
	AssumeStartTime *time.Time            `json:"assumeStartTime,omitempty"`
}

// AccessRequest is the web UI representation of a [types.AccessRequest].
// The JSON shape is what `makeAccessRequest` in the web UI parses.
type AccessRequest struct {
	ID                     string                  `json:"id"`
	State                  string                  `json:"state"`
	User                   string                  `json:"user"`
	UserInfo               AccessRequestUserInfo   `json:"userInfo"`
	Expires                *time.Time              `json:"expires,omitempty"`
	Created                time.Time               `json:"created"`
	MaxDuration            *time.Time              `json:"maxDuration,omitempty"`
	RequestTTL             *time.Time              `json:"requestTTL,omitempty"`
	SessionTTL             *time.Time              `json:"sessionTTL,omitempty"`
	Roles                  []string                `json:"roles"`
	RequestReason          string                  `json:"requestReason"`
	ResolveReason          string                  `json:"resolveReason"`
	Reviews                []AccessRequestReview   `json:"reviews"`
	SuggestedReviewersInfo []AccessRequestUserInfo `json:"suggestedReviewersInfo"`
	ThresholdNames         []string                `json:"thresholdNames"`
	Resources              []AccessRequestResource `json:"resources"`
	AssumeStartTime        *time.Time              `json:"assumeStartTime,omitempty"`
	ReasonMode             string                  `json:"reasonMode"`
	ReasonPrompts          []string                `json:"reasonPrompts"`
	RequestKind            int32                   `json:"requestKind"`
}

// MakeAccessRequest converts a [types.AccessRequest] to its web UI representation.
func MakeAccessRequest(req types.AccessRequest) AccessRequest {
	reviews := make([]AccessRequestReview, 0, len(req.GetReviews()))
	for _, r := range req.GetReviews() {
		reviews = append(reviews, AccessRequestReview{
			Author:          r.Author,
			AuthorInfo:      AccessRequestUserInfo{Username: r.Author},
			State:           r.ProposedState.String(),
			Reason:          r.Reason,
			Roles:           nonNil(r.Roles),
			Created:         r.Created,
			AssumeStartTime: r.AssumeStartTime,
		})
	}

	reviewers := make([]AccessRequestUserInfo, 0, len(req.GetSuggestedReviewers()))
	for _, name := range req.GetSuggestedReviewers() {
		reviewers = append(reviewers, AccessRequestUserInfo{Username: name})
	}

	thresholdNames := []string{}
	for _, t := range req.GetThresholds() {
		if t.Name != "" {
			thresholdNames = append(thresholdNames, t.Name)
		}
	}

	resources := []AccessRequestResource{}
	for _, id := range req.GetAllRequestedResourceIDs() {
		resources = append(resources, AccessRequestResource{
			ID: AccessRequestResourceID{
				Kind:            id.Id.Kind,
				Name:            id.Id.Name,
				ClusterName:     id.Id.ClusterName,
				SubResourceName: id.Id.SubResourceName,
			},
		})
	}

	return AccessRequest{
		ID:                     req.GetName(),
		State:                  req.GetState().String(),
		User:                   req.GetUser(),
		UserInfo:               AccessRequestUserInfo{Username: req.GetUser()},
		Expires:                timePtr(req.GetAccessExpiry()),
		Created:                req.GetCreationTime(),
		MaxDuration:            timePtr(req.GetMaxDuration()),
		RequestTTL:             timePtr(req.Expiry()),
		SessionTTL:             timePtr(req.GetSessionTLL()),
		Roles:                  nonNil(req.GetRoles()),
		RequestReason:          req.GetRequestReason(),
		ResolveReason:          req.GetResolveReason(),
		Reviews:                reviews,
		SuggestedReviewersInfo: reviewers,
		ThresholdNames:         thresholdNames,
		Resources:              resources,
		AssumeStartTime:        req.GetAssumeStartTime(),
		ReasonMode:             string(types.RequestReasonModeOptional),
		ReasonPrompts:          []string{},
		RequestKind:            int32(req.GetRequestKind()),
	}
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
