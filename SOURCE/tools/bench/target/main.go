// sbox-bench-target: a small, dependency-free measurement endpoint used by the
// SBOX benchmark harness (tools/bench). It is never installed by the product.
//
//	GET  /204                -> 204 No Content (small-request latency)
//	GET  /small              -> 1 KiB deterministic body
//	GET  /bytes?n=N&seed=S   -> N deterministic pseudo-random bytes; header X-SHA256
//	POST /upload             -> {"bytes":N,"sha256":"..."} of the request body
//	UDP  echo on -udp port   -> echoes each datagram (loss/RTT/jitter)
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

// The payload for (n, seed) is a 1 MiB xorshift64 block repeated; the Python
// client regenerates the same block to verify SHA-256 without a reference file.
const blockSize = 1 << 20

var blocks = map[uint64][]byte{}

func block(seed uint64) []byte {
	if b, ok := blocks[seed]; ok {
		return b
	}
	b := make([]byte, blockSize)
	x := seed*0x9E3779B97F4A7C15 + 1
	for i := 0; i < blockSize; i += 8 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		binary.LittleEndian.PutUint64(b[i:], x)
	}
	blocks[seed] = b
	return b
}

func writePayload(w io.Writer, n int64, seed uint64) error {
	b := block(seed)
	for n > 0 {
		chunk := int64(len(b))
		if n < chunk {
			chunk = n
		}
		if _, err := w.Write(b[:chunk]); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

func digest(n int64, seed uint64) string {
	h := sha256.New()
	writePayload(h, n, seed)
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	addr := flag.String("http", "0.0.0.0:18080", "HTTP listen address")
	udp := flag.String("udp", "0.0.0.0:18081", "UDP echo listen address")
	flag.Parse()

	// Blocks are built once before serving; the map is read-only afterwards.
	for s := uint64(0); s <= 16; s++ {
		block(s)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/204", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/small", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1024")
		writePayload(w, 1024, 7)
	})
	mux.HandleFunc("/bytes", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.ParseInt(r.URL.Query().Get("n"), 10, 64)
		if err != nil || n < 0 || n > 4<<30 {
			http.Error(w, "bad n", http.StatusBadRequest)
			return
		}
		seed, _ := strconv.ParseUint(r.URL.Query().Get("seed"), 10, 64)
		if seed > 16 {
			http.Error(w, "seed must be 0..16", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("hash") == "1" {
			w.Header().Set("X-SHA256", digest(n, seed))
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		writePayload(w, n, seed)
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		h := sha256.New()
		start := time.Now()
		n, err := io.Copy(h, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"bytes": n, "sha256": hex.EncodeToString(h.Sum(nil)), "seconds": time.Since(start).Seconds()})
	})

	go func() {
		pc, err := net.ListenPacket("udp", *udp)
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, 65535)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			pc.WriteTo(buf[:n], a)
		}
	}()
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
