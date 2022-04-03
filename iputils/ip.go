package iputils

import (
	"encoding/json"
	"fmt"
	"github.com/librespeed/speedtest/config"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type IPInfoResponse struct {
	IP           string `json:"ip"`
	Hostname     string `json:"hostname"`
	City         string `json:"city"`
	Region       string `json:"region"`
	Country      string `json:"country"`
	Location     string `json:"loc"`
	Organization string `json:"org"`
	Postal       string `json:"postal"`
	Timezone     string `json:"timezone"`
	Readme       string `json:"readme"`
	Isp          string `json:"isp"`
}

var (
	ispInfoCache      = make(map[string]IPInfoResponse, 0)
	ispInfoCacheLock  = sync.RWMutex{}
	cli               = http.Client{Timeout: time.Second * 10}
	trafficLStatic    = make(map[string]int64)
	lockTrafficStatic = sync.RWMutex{}
	removeIspRegexp   = regexp.MustCompile(`AS\d+\s`)
	removeIsp2Regexp  = regexp.MustCompile(`\s\([\S\s]+\)$`)
)

func init() {
	go resetTraffic()
}

func AddTraffic(ip string, traffic int64) {
	lockTrafficStatic.Lock()
	t, _ := trafficLStatic[ip]
	trafficLStatic[ip] = t + traffic
	lockTrafficStatic.Unlock()
}

func resetTraffic() {
	for {
		time.Sleep(time.Hour * 24)
		lockTrafficStatic.Lock()
		trafficLStatic = make(map[string]int64)
		lockTrafficStatic.Unlock()
		log.Infof("Reset traffic limit")
	}
}

func IsLimited(ip string) bool {
	conf := config.LoadedConfig()
	if conf.IPDailyTrafficLimit == 0 {
		return false
	}
	lockTrafficStatic.RLock()
	defer lockTrafficStatic.RUnlock()
	if trafficLStatic[ip] > conf.IPDailyTrafficLimit*1024*1024*1024 {
		log.Warnf("IP %s is block, daily traffic limited", ip)
		return true
	}
	return false
}

func GetClientIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if config.LoadedConfig().EnableXFFIP {
		xff := r.Header.Get("X-Forwarded-For")
		i := strings.LastIndex(xff, ", ")
		if i != -1 {
			xff = xff[:i]
		}
		if xff != "" && net.ParseIP(xff) != nil {
			return xff
		}
	}
	return ip
}

func GetIPInfo(clientIP string) IPInfoResponse {
	ispInfoCacheLock.RLock()
	ispInfo, ok := ispInfoCache[clientIP]
	ispInfoCacheLock.RUnlock()
	if !ok {
		var err error
		ispInfo, err = getIPInfo(clientIP)
		isp := removeIspRegexp.ReplaceAllString(ispInfo.Organization, "")
		isp = removeIsp2Regexp.ReplaceAllString(isp, "")
		ispInfo.Isp = isp
		if err != nil {
			ispInfoCacheLock.Lock()
			ispInfoCache[clientIP] = ispInfo
			ispInfoCacheLock.Unlock()
		}
	}
	return ispInfo
}

func getIPInfoURL(address string) string {
	apiKey := config.LoadedConfig().IPInfoAPIKey

	ipInfoURL := `https://ipinfo.io/%s/json`
	if address != "" {
		ipInfoURL = fmt.Sprintf(ipInfoURL, address)
	} else {
		ipInfoURL = "https://ipinfo.io/json"
	}

	if apiKey != "" {
		ipInfoURL += "?token=" + apiKey
	}

	return ipInfoURL
}

func getIPInfo(addr string) (IPInfoResponse, error) {
	var ret IPInfoResponse

	resp, err := cli.Get(getIPInfoURL(addr))
	if err != nil {
		log.Errorf("Error getting response from ipinfo.io: %s", err)
		return ret, err
	}

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading response from ipinfo.io: %s", err)
		return ret, err
	}
	defer func() { _ = resp.Body.Close() }()

	if err := json.Unmarshal(raw, &ret); err != nil {
		log.Errorf("Error parsing response from ipinfo.io: %s", err)
	}

	return ret, err
}
