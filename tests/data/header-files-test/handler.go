// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Handler responds to an HTTP request.
type Handler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// Router is an HTTP request multiplexer that matches the URL
// of each incoming request against a list of registered patterns.
type Router struct {
	mu       sync.RWMutex
	routes   map[string]Handler
	notFound Handler
}

// NewRouter creates a new Router instance.
func NewRouter() *Router {
	return &Router{
		routes: make(map[string]Handler),
	}
}

// Handle registers the handler for the given pattern.
func (r *Router) Handle(pattern string, handler Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[pattern] = handler
}

// HandleFunc registers the handler function for the given pattern.
func (r *Router) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	r.Handle(pattern, http.HandlerFunc(handler))
}

// ServeHTTP dispatches the request to the handler whose
// pattern most closely matches the request URL.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	handler, ok := r.routes[req.URL.Path]
	r.mu.RUnlock()

	if !ok {
		if r.notFound != nil {
			r.notFound.ServeHTTP(w, req)
			return
		}
		http.NotFound(w, req)
		return
	}

	handler.ServeHTTP(w, req)
}

// JSONResponse writes a JSON response with the given status code.
func JSONResponse(w http.ResponseWriter, statusCode int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	return json.NewEncoder(w).Encode(data)
}

// ReadJSON reads a JSON request body into the given destination.
func ReadJSON(r *http.Request, dst interface{}) error {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("reading body: %w", err)
	}
	return json.Unmarshal(body, dst)
}