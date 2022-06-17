package web

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/go-chi/httprate"
	"io"
	"io/fs"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-systemd/activation"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"github.com/librespeed/speedtest/config"
	"github.com/librespeed/speedtest/iputils"
	"github.com/librespeed/speedtest/results"
	"github.com/pires/go-proxyproto"
	log "github.com/sirupsen/logrus"
)

const (
	// chunk size is 1 mib
	chunkSize       = 1 * 1024 * 1024
	chunkMax        = 100
	uploadBodyLimit = 100 * 1024 * 1024
)

var (
	//go:embed assets
	defaultAssets embed.FS
	// generate random data for download test on start to minimize runtime overhead
	randomData = getRandomData(chunkSize)
)

func ListenAndServe(conf *config.Config) error {
	r := chi.NewRouter()
	r.Use(middleware.GetHead)

	cs := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS", "HEAD"},
		AllowedHeaders: []string{"*"},
	})

	r.Use(cs.Handler)
	r.Use(middleware.NoCache)
	r.Use(middleware.Recoverer)

	var assetFS http.FileSystem
	if fi, err := os.Stat(conf.AssetsPath); os.IsNotExist(err) || !fi.IsDir() {
		log.Warnf("Configured asset path %s does not exist or is not a directory, using default assets", conf.AssetsPath)
		sub, err := fs.Sub(defaultAssets, "assets")
		if err != nil {
			log.Fatalf("Failed when processing default assets: %s", err)
		}
		assetFS = http.FS(sub)
	} else {
		assetFS = justFilesFilesystem{fs: http.Dir(conf.AssetsPath), readDirBatchSize: 2}
	}

	r.HandleFunc("/empty", empty)
	r.HandleFunc("/backend/empty", empty)
	r.Get("/garbage", garbage)
	r.Get("/backend/garbage", garbage)

	// PHP frontend default values compatibility
	r.HandleFunc("/empty.php", empty)
	r.HandleFunc("/backend/empty.php", empty)
	r.Get("/garbage.php", garbage)
	r.Get("/backend/garbage.php", garbage)

	r.Post("/results/telemetry", results.Record)
	r.Post("/backend/results/telemetry", results.Record)
	r.Post("/results/telemetry.php", results.Record)
	r.Post("/backend/results/telemetry.php", results.Record)

	as := r.Group(nil)
	as.Use(httprate.Limit(
		100,
		time.Minute*10,
		httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			return r.URL.Path + iputils.GetClientIP(r), nil
		}),
	))
	as.Get("/*", pages(assetFS))

	tg := r.Group(nil)
	tg.Use(httprate.Limit(
		20,
		time.Minute,
		httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			return r.URL.Path + iputils.GetClientIP(r), nil
		}),
	))
	tg.Get("/captcha", genCaptcha)
	tg.Get("/token", getToken)
	tg.Get("/stats.php", results.Stats)
	tg.Get("/backend/stats.php", results.Stats)
	tg.HandleFunc("/stats", results.Stats)
	tg.HandleFunc("/backend/stats", results.Stats)
	tg.HandleFunc("/backend/results-api.php", results.PublicStats)
	tg.Get("/getIP.php", getIP)
	tg.Get("/backend/getIP.php", getIP)
	tg.Get("/getIP", getIP)
	tg.Get("/backend/getIP", getIP)
	tg.Get("/results", results.DrawPNG)
	tg.Get("/results/", results.DrawPNG)
	tg.Get("/backend/results", results.DrawPNG)
	tg.Get("/backend/results/", results.DrawPNG)
	go listenProxyProtocol(conf, r)

	// See if systemd socket activation has been used when starting our process
	listeners, err := activation.Listeners()
	if err != nil {
		log.Fatalf("Error whilst checking for systemd socket activation %s", err)
	}

	var s error

	switch len(listeners) {
	case 0:
		addr := net.JoinHostPort(conf.BindAddress, conf.Port)
		log.Infof("Starting backend server on %s", addr)

		// TLS and HTTP/2.
		if conf.EnableTLS {
			log.Info("Use TLS connection.")
			if !(conf.EnableHTTP2) {
				srv := &http.Server{
					Addr:         addr,
					Handler:      r,
					TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
				}
				s = srv.ListenAndServeTLS(conf.TLSCertFile, conf.TLSKeyFile)
			} else {
				s = http.ListenAndServeTLS(addr, conf.TLSCertFile, conf.TLSKeyFile, r)
			}
		} else {
			if conf.EnableHTTP2 {
				log.Errorf("TLS is mandatory for HTTP/2. Ignore settings that enable HTTP/2.")
			}
			s = http.ListenAndServe(addr, r)
		}
	case 1:
		log.Info("Starting backend server on inherited file descriptor via systemd socket activation")
		if conf.BindAddress != "" || conf.Port != "" {
			log.Errorf("Both an address/port (%s:%s) has been specificed in the config AND externally configured socket activation has been detected", conf.BindAddress, conf.Port)
			log.Fatal(`Please deconfigure socket activation (e.g. in systemd unit files), or set both 'bind_address' and 'listen_port' to ''`)
		}
		s = http.Serve(listeners[0], r)
	default:
		log.Fatalf("Asked to listen on %s sockets via systemd activation.  Sorry we currently only support listening on 1 socket.", len(listeners))
	}
	return s
}

func listenProxyProtocol(conf *config.Config, r *chi.Mux) {
	if conf.ProxyProtocolPort != "0" {
		addr := net.JoinHostPort(conf.BindAddress, conf.ProxyProtocolPort)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Cannot listen on proxy protocol port %s: %s", conf.ProxyProtocolPort, err)
		}

		pl := &proxyproto.Listener{Listener: l}
		defer pl.Close()

		log.Infof("Starting proxy protocol listener on %s", addr)
		log.Fatal(http.Serve(pl, r))
	}
}

func pages(fs http.FileSystem) http.HandlerFunc {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/" {
			r.RequestURI = "/index.html"
		}

		http.FileServer(fs).ServeHTTP(w, r)
	}

	return fn
}

func empty(w http.ResponseWriter, r *http.Request) {
	ip := iputils.GetClientIP(r)
	if iputils.IsLimited(ip) {
		w.WriteHeader(403)
		_, _ = fmt.Fprintf(w, "traffic limit")
		return
	}

	if !CheckToken(r) {
		w.WriteHeader(403)
		_, _ = fmt.Fprintf(w, "bad token")
		return
	}

	n, err := io.CopyN(ioutil.Discard, r.Body, uploadBodyLimit)
	iputils.AddTraffic(ip, n)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
}

func garbage(w http.ResponseWriter, r *http.Request) {
	ip := iputils.GetClientIP(r)
	if iputils.IsLimited(ip) {
		w.WriteHeader(403)
		_, _ = fmt.Fprintf(w, "traffic limit")
		return
	}

	if !CheckToken(r) {
		w.WriteHeader(403)
		_, _ = fmt.Fprintf(w, "bad token")
		return
	}

	w.Header().Set("Content-Description", "File Transfer")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=random.dat")
	w.Header().Set("Content-Transfer-Encoding", "binary")

	// chunk size set to 4 by default
	chunks := 4

	ckSize := r.FormValue("ckSize")
	if ckSize != "" {
		i, err := strconv.ParseInt(ckSize, 10, 64)
		if err != nil {
			log.Errorf("Invalid chunk size: %s", ckSize)
			log.Warnf("Will use default value %d", chunks)
		} else {
			if i > chunkMax {
				chunks = chunkMax
			} else {
				chunks = int(i)
			}
		}
	}

	chunkSize := int64(len(randomData))
	for i := 0; i < chunks; i++ {
		iputils.AddTraffic(ip, chunkSize)
		if _, err := w.Write(randomData); err != nil {
			break
		}
	}
}

func getIP(w http.ResponseWriter, r *http.Request) {
	if !CheckToken(r) {
		w.WriteHeader(403)
		_, _ = fmt.Fprintf(w, "bad token")
		return
	}

	var ret results.Result

	clientIP := iputils.GetClientIP(r)
	isSpecialIP := true
	switch {
	case clientIP == "::1":
		ret.ProcessedString = clientIP + " - localhost IPv6 access"
	case strings.HasPrefix(clientIP, "fe80:"):
		ret.ProcessedString = clientIP + " - link-local IPv6 access"
	case strings.HasPrefix(clientIP, "127."):
		ret.ProcessedString = clientIP + " - localhost IPv4 access"
	case strings.HasPrefix(clientIP, "10."):
		ret.ProcessedString = clientIP + " - private IPv4 access"
	case regexp.MustCompile(`^172\.(1[6-9]|2\d|3[01])\.`).MatchString(clientIP):
		ret.ProcessedString = clientIP + " - private IPv4 access"
	case strings.HasPrefix(clientIP, "192.168"):
		ret.ProcessedString = clientIP + " - private IPv4 access"
	case strings.HasPrefix(clientIP, "169.254"):
		ret.ProcessedString = clientIP + " - link-local IPv4 access"
	case regexp.MustCompile(`^100\.([6-9][0-9]|1[0-2][0-7])\.`).MatchString(clientIP):
		ret.ProcessedString = clientIP + " - CGNAT IPv4 access"
	default:
		isSpecialIP = false
	}

	if isSpecialIP {
		b, _ := json.Marshal(&ret)
		if _, err := w.Write(b); err != nil {
			log.Errorf("Error writing to client: %s", err)
		}
		return
	}

	getISPInfo := r.FormValue("isp") == "true"
	distanceUnit := r.FormValue("distance")
	ret.ProcessedString = clientIP

	if getISPInfo {
		ispInfo := iputils.GetIPInfo(clientIP)
		ret.RawISPInfo = ispInfo

		display := ispInfo.Isp
		if ispInfo.Isp == "" {
			display = "Unknown ISP"
		} else {
			if ispInfo.Country != "" {
				display += " " + ispInfo.Country
			}
			if ispInfo.Region != "" {
				display += ", " + ispInfo.Region
			}
			if ispInfo.City != "" {
				display += ", " + ispInfo.City
			}
			display += " (" + calculateDistance(ispInfo.Latitude, ispInfo.Longitude, distanceUnit) + ")"
		}
		ret.ProcessedString += " - " + display
	}

	render.JSON(w, r, ret)
}
