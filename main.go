// go-nslookup-service
// Single-file Go HTTP service that accepts a POST request with JSON {"domain":"example.com"}
// and returns the resolved IP addresses as JSON.
// Also includes a Dockerfile and a sample Kubernetes manifest in comments below.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// request payload
type lookupRequest struct {
	Domain string `json:"domain"`
}

// response payload
type lookupResponse struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips"`
	Error  string   `json:"error,omitempty"`
}

func main() {
	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}

	http.HandleFunc("/healthz", healthHandler)
	http.HandleFunc("/lookup", lookupHandler)

	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("starting server on %s\n", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server failed: %v", err)
		}
	}()

	// graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown failed: %v", err)
	}
	log.Println("server stopped")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func lookupHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("received request for /lookup")
	if r.Method != http.MethodPost {
		log.Printf("method not allowed: %s", r.Method)
		writeJSON(w, http.StatusMethodNotAllowed, lookupResponse{Error: "method not allowed"})
		return
	}

	var req lookupRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		log.Printf("invalid request payload: %v", err)
		writeJSON(w, http.StatusBadRequest, lookupResponse{Error: "invalid request payload"})
		return
	}

	req.Domain = strings.TrimSpace(req.Domain)
	if req.Domain == "" {
		log.Println("domain not provided")
		writeJSON(w, http.StatusBadRequest, lookupResponse{Error: "domain is required"})
		return
	}

	if strings.ContainsAny(req.Domain, " ") || strings.Contains(req.Domain, "/") {
		log.Printf("invalid domain format: %s", req.Domain)
		writeJSON(w, http.StatusBadRequest, lookupResponse{Error: "invalid domain"})
		return
	}

	log.Printf("performing DNS lookup for domain: %s", req.Domain)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ips, err := resolveDomain(ctx, req.Domain)
	if err != nil {
		log.Printf("lookup failed for %s: %v", req.Domain, err)
		writeJSON(w, http.StatusOK, lookupResponse{Domain: req.Domain, IPs: nil, Error: err.Error()})
		return
	}

	log.Printf("lookup success for %s: %v", req.Domain, ips)
	writeJSON(w, http.StatusOK, lookupResponse{Domain: req.Domain, IPs: ips})
}


// resolveDomain performs a DNS lookup for the given domain and returns a list of IP strings.
// It uses the standard library resolver (which follows system resolver settings, similar to nslookup behavior).
func resolveDomain(ctx context.Context, domain string) ([]string, error) {
	// strip trailing dot if present
	d := strings.TrimSuffix(domain, ".")
	// prefer LookupIPAddr which is newer and returns both v4 and v6
	ch := make(chan []string, 1)
	errCh := make(chan error, 1)

	go func() {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, d)
		if err != nil {
			errCh <- err
			return
		}
		out := make([]string, 0, len(ips))
		for _, ip := range ips {
			out = append(out, ip.IP.String())
		}
		ch <- out
	}()

	select {
	case <-ctx.Done():
		return nil, errors.New("lookup timed out")
	case err := <-errCh:
		return nil, err
	case out := <-ch:
		if len(out) == 0 {
			return nil, errors.New("no addresses found")
		}
		return out, nil
	}
}

/*
Dockerfile (included here for convenience):

# build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /go-nslookup-service ./

# final image
FROM scratch
COPY --from=builder /go-nslookup-service /go-nslookup-service
EXPOSE 8080
ENTRYPOINT ["/go-nslookup-service"]

---

Sample Kubernetes deployment (you can adapt for Choreo container image):

apiVersion: apps/v1
kind: Deployment
metadata:
  name: go-nslookup-service
spec:
  replicas: 1
  selector:
    matchLabels:
      app: go-nslookup-service
  template:
    metadata:
      labels:
        app: go-nslookup-service
    spec:
      containers:
        - name: go-nslookup-service
          image: <YOUR_REGISTRY>/go-nslookup-service:latest
          ports:
            - containerPort: 8080
          env:
            - name: PORT
              value: "8080"

---

Service:
apiVersion: v1
kind: Service
metadata:
  name: go-nslookup-svc
spec:
  type: ClusterIP
  selector:
    app: go-nslookup-service
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080


README / Usage notes:
1. Build locally: docker build -t <your-registry>/go-nslookup-service:latest .
2. Push to registry reachable by Choreo.
3. In Choreo, create a service using the container image and expose an HTTP endpoint.
   - Ensure the container has network access to the DNS server you want it to query.
   - If you need to force a particular DNS server inside Kubernetes, configure the cluster DNS or use a sidecar.
4. API:
   - POST /lookup
     Content-Type: application/json
     Body: {"domain": "example.com"}
   - Response: {"domain":"example.com","ips":["93.184.216.34"]}

Security tips:
- Consider adding rate limiting and authentication if exposing publicly.
- Validate domain names more strictly for production.
- If you must run system 'nslookup' binary for parity, you'd need to include it in the image and exec it; current implementation uses Go's resolver which mirrors system resolver behaviour.
*/


func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Printf("failed to write json response: %v", err)
	}
}
