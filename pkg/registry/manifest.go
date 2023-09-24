// Copyright 2018 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type catalog struct {
	Repos []string `json:"repositories"`
}

type listTags struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type manifest struct {
	contentType string
	blob        []byte
}

type manifests struct {
	manifestHandler ManifestHandler
	lock            sync.RWMutex
	log             *log.Logger
}

func isManifest(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "manifests"
}

func isTags(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "tags"
}

func isCatalog(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 2 {
		return false
	}

	return elems[len(elems)-1] == "_catalog"
}

// Returns whether this url should be handled by the referrers handler
func isReferrers(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "referrers"
}

// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pulling-an-image-manifest
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pushing-an-image
func (m *manifests) handle(resp http.ResponseWriter, req *http.Request) *regError {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	target := elem[len(elem)-1]
	repo := strings.Join(elem[1:len(elem)-2], "/")

	switch req.Method {
	case http.MethodGet:
		m.lock.RLock()
		defer m.lock.RUnlock()

		c, ok := m.manifestHandler.GetRepo(repo, req.URL.Query().Get("ns"))
		if !ok {
			return &regError{
				Status:  http.StatusNotFound,
				Code:    "NAME_UNKNOWN",
				Message: "Unknown name",
			}
		}
		m, ok := c[target]
		if !ok {
			return &regError{
				Status:  http.StatusNotFound,
				Code:    "MANIFEST_UNKNOWN",
				Message: "Unknown manifest",
			}
		}

		h, _, _ := v1.SHA256(bytes.NewReader(m.blob))
		resp.Header().Set("Docker-Content-Digest", h.String())
		resp.Header().Set("Content-Type", m.contentType)
		resp.Header().Set("Content-Length", fmt.Sprint(len(m.blob)))
		resp.WriteHeader(http.StatusOK)
		io.Copy(resp, bytes.NewReader(m.blob))
		return nil

	case http.MethodHead:
		m.lock.RLock()
		defer m.lock.RUnlock()

		if _, ok := m.manifestHandler.GetRepo(repo, req.URL.Query().Get("ns")); !ok {
			return &regError{
				Status:  http.StatusNotFound,
				Code:    "NAME_UNKNOWN",
				Message: "Unknown name",
			}
		}
		m, ok := m.manifestHandler.GetManifest(repo, target, req.URL.Query().Get("ns"))
		if !ok {
			return &regError{
				Status:  http.StatusNotFound,
				Code:    "MANIFEST_UNKNOWN",
				Message: "Unknown manifest",
			}
		}

		h, _, _ := v1.SHA256(bytes.NewReader(m.blob))
		resp.Header().Set("Docker-Content-Digest", h.String())
		resp.Header().Set("Content-Type", m.contentType)
		resp.Header().Set("Content-Length", fmt.Sprint(len(m.blob)))
		resp.WriteHeader(http.StatusOK)
		return nil

	case http.MethodPut:
		b := &bytes.Buffer{}
		io.Copy(b, req.Body)
		h, _, _ := v1.SHA256(bytes.NewReader(b.Bytes()))
		digest := h.String()
		mf := manifest{
			blob:        b.Bytes(),
			contentType: req.Header.Get("Content-Type"),
		}

		// If the manifest is a manifest list, check that the manifest
		// list's constituent manifests are already uploaded.
		// This isn't strictly required by the registry API, but some
		// registries require this.
		if types.MediaType(mf.contentType).IsIndex() {
			if err := func() *regError {
				m.lock.RLock()
				defer m.lock.RUnlock()

				im, err := v1.ParseIndexManifest(b)
				if err != nil {
					return &regError{
						Status:  http.StatusBadRequest,
						Code:    "MANIFEST_INVALID",
						Message: err.Error(),
					}
				}
				for _, desc := range im.Manifests {
					if !desc.MediaType.IsDistributable() {
						continue
					}
					if desc.MediaType.IsIndex() || desc.MediaType.IsImage() {
						if _, found := m.manifestHandler.GetManifest(repo, desc.Digest.String(), req.URL.Query().Get("ns")); !found {
							return &regError{
								Status:  http.StatusNotFound,
								Code:    "MANIFEST_UNKNOWN",
								Message: fmt.Sprintf("Sub-manifest %q not found", desc.Digest),
							}
						}
					} else {
						// TODO: Probably want to do an existence check for blobs.
						m.log.Printf("TODO: Check blobs for %q", desc.Digest)
					}
				}
				return nil
			}(); err != nil {
				return err
			}
		}

		m.lock.Lock()
		defer m.lock.Unlock()

		if _, ok := m.manifestHandler.GetRepo(repo, req.URL.Query().Get("ns")); !ok {
			m.manifestHandler.CreateRepo(repo, req.URL.Query().Get("ns"))
		}

		// Allow future references by target (tag) and immutable digest.
		// See https://docs.docker.com/engine/reference/commandline/pull/#pull-an-image-by-digest-immutable-identifier.
		m.manifestHandler.PutManifest(repo, digest, mf, req.URL.Query().Get("ns"))
		m.manifestHandler.PutManifest(repo, target, mf, req.URL.Query().Get("ns"))
		resp.Header().Set("Docker-Content-Digest", digest)
		resp.WriteHeader(http.StatusCreated)
		return nil

	case http.MethodDelete:
		m.lock.Lock()
		defer m.lock.Unlock()
		if _, ok := m.manifestHandler.GetRepo(repo, req.URL.Query().Get("ns")); !ok {
			return &regError{
				Status:  http.StatusNotFound,
				Code:    "NAME_UNKNOWN",
				Message: "Unknown name",
			}
		}

		_, ok := m.manifestHandler.GetManifest(repo, target, req.URL.Query().Get("ns"))
		if !ok {
			return &regError{
				Status:  http.StatusNotFound,
				Code:    "MANIFEST_UNKNOWN",
				Message: "Unknown manifest",
			}
		}

		m.manifestHandler.DeleteManifest(repo, target, req.URL.Query().Get("ns"))
		resp.WriteHeader(http.StatusAccepted)
		return nil

	default:
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "METHOD_UNKNOWN",
			Message: "We don't understand your method + url",
		}
	}
}

func (m *manifests) handleTags(resp http.ResponseWriter, req *http.Request) *regError {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	repo := strings.Join(elem[1:len(elem)-2], "/")

	if req.Method == "GET" {
		m.lock.RLock()
		defer m.lock.RUnlock()

		c, ok := m.manifestHandler.GetRepo(repo, req.URL.Query().Get("ns"))
		if !ok {
			return &regError{
				Status:  http.StatusNotFound,
				Code:    "NAME_UNKNOWN",
				Message: "Unknown name",
			}
		}

		var tags []string
		for tag := range c {
			if !strings.Contains(tag, "sha256:") {
				tags = append(tags, tag)
			}
		}
		sort.Strings(tags)

		// https://github.com/opencontainers/distribution-spec/blob/b505e9cc53ec499edbd9c1be32298388921bb705/detail.md#tags-paginated
		// Offset using last query parameter.
		if last := req.URL.Query().Get("last"); last != "" {
			for i, t := range tags {
				if t > last {
					tags = tags[i:]
					break
				}
			}
		}

		// Limit using n query parameter.
		if ns := req.URL.Query().Get("n"); ns != "" {
			if n, err := strconv.Atoi(ns); err != nil {
				return &regError{
					Status:  http.StatusBadRequest,
					Code:    "BAD_REQUEST",
					Message: fmt.Sprintf("parsing n: %v", err),
				}
			} else if n < len(tags) {
				tags = tags[:n]
			}
		}

		tagsToList := listTags{
			Name: repo,
			Tags: tags,
		}

		msg, _ := json.Marshal(tagsToList)
		resp.Header().Set("Content-Length", fmt.Sprint(len(msg)))
		resp.WriteHeader(http.StatusOK)
		io.Copy(resp, bytes.NewReader([]byte(msg)))
		return nil
	}

	return &regError{
		Status:  http.StatusBadRequest,
		Code:    "METHOD_UNKNOWN",
		Message: "We don't understand your method + url",
	}
}

func (m *manifests) handleCatalog(resp http.ResponseWriter, req *http.Request) *regError {
	query := req.URL.Query()
	nStr := query.Get("n")
	n := 10000
	if nStr != "" {
		n, _ = strconv.Atoi(nStr)
	}

	if req.Method == "GET" {
		m.lock.RLock()
		defer m.lock.RUnlock()

		repos := m.manifestHandler.ListRepos(n, req.URL.Query().Get("ns"))

		repositoriesToList := catalog{
			Repos: repos,
		}

		msg, _ := json.Marshal(repositoriesToList)
		resp.Header().Set("Content-Length", fmt.Sprint(len(msg)))
		resp.WriteHeader(http.StatusOK)
		io.Copy(resp, bytes.NewReader([]byte(msg)))
		return nil
	}

	return &regError{
		Status:  http.StatusBadRequest,
		Code:    "METHOD_UNKNOWN",
		Message: "We don't understand your method + url",
	}
}

// TODO: implement handling of artifactType querystring
func (m *manifests) handleReferrers(resp http.ResponseWriter, req *http.Request) *regError {
	// Ensure this is a GET request
	if req.Method != "GET" {
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "METHOD_UNKNOWN",
			Message: "We don't understand your method + url",
		}
	}

	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	target := elem[len(elem)-1]
	repo := strings.Join(elem[1:len(elem)-2], "/")

	// Validate that incoming target is a valid digest
	if _, err := v1.NewHash(target); err != nil {
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "UNSUPPORTED",
			Message: "Target must be a valid digest",
		}
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	digestToManifestMap, repoExists := m.manifestHandler.GetRepo(repo, req.URL.Query().Get("ns"))
	if !repoExists {
		return &regError{
			Status:  http.StatusNotFound,
			Code:    "NAME_UNKNOWN",
			Message: "Unknown name",
		}
	}

	im := v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     []v1.Descriptor{},
	}
	for digest, manifest := range digestToManifestMap {
		h, err := v1.NewHash(digest)
		if err != nil {
			continue
		}
		var refPointer struct {
			Subject *v1.Descriptor `json:"subject"`
		}
		json.Unmarshal(manifest.blob, &refPointer)
		if refPointer.Subject == nil {
			continue
		}
		referenceDigest := refPointer.Subject.Digest
		if referenceDigest.String() != target {
			continue
		}
		// At this point, we know the current digest references the target
		var imageAsArtifact struct {
			Config struct {
				MediaType string `json:"mediaType"`
			} `json:"config"`
		}
		json.Unmarshal(manifest.blob, &imageAsArtifact)
		im.Manifests = append(im.Manifests, v1.Descriptor{
			MediaType:    types.MediaType(manifest.contentType),
			Size:         int64(len(manifest.blob)),
			Digest:       h,
			ArtifactType: imageAsArtifact.Config.MediaType,
		})
	}
	msg, _ := json.Marshal(&im)
	resp.Header().Set("Content-Length", fmt.Sprint(len(msg)))
	resp.Header().Set("Content-Type", string(types.OCIImageIndex))
	resp.WriteHeader(http.StatusOK)
	io.Copy(resp, bytes.NewReader([]byte(msg)))
	return nil
}

type manifestMemHandler struct {
	// maps repo -> manifest tag/digest -> manifest
	manifests map[string]map[string]manifest
}

// ManifestHandler represents a minimal manifest storage backend, capable of serving
// blob contents.
type ManifestHandler interface {
	CreateRepo(repo string, ns string)
	ListRepos(max int, ns string) []string
	GetRepo(repo string, ns string) (map[string]manifest, bool)
	PutManifest(repo, tag string, value manifest, ns string)
	GetManifest(repo, tag string, ns string) (manifest, bool)
	DeleteManifest(repo, target string, ns string)
}

func NewInMemoryManifestHandler() ManifestHandler {
	return &manifestMemHandler{manifests: map[string]map[string]manifest{}}
}

func (m manifestMemHandler) CreateRepo(repo string, ns string) {
	m.manifests["/"+ns+"/"+repo] = make(map[string]manifest, 2)
}

func (m manifestMemHandler) DeleteManifest(repo, target string, ns string) {
	delete(m.manifests["/"+ns+"/"+repo], target)
}

func (m manifestMemHandler) ListRepos(n int, ns string) []string {
	var repos []string
	countRepos := 0
	// TODO: implement pagination
	for key := range m.manifests {
		if countRepos >= n {
			break
		}
		countRepos++

		repos = append(repos, key)
	}
	return repos
}

func (m manifestMemHandler) GetRepo(repo string, ns string) (map[string]manifest, bool) {
	man, err := m.manifests["/"+ns+"/"+repo]
	return man, err
}

func (m manifestMemHandler) GetManifest(repo, tag string, ns string) (manifest, bool) {
	man, err := m.manifests["/"+ns+"/"+repo][tag]
	return man, err
}

func (m manifestMemHandler) PutManifest(repo, tag string, value manifest, ns string) {
	m.manifests["/"+ns+"/"+repo][tag] = value
}
