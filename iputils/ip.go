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
	"strconv"
	"strings"
	"sync"
	"time"
)

type IPInfo struct {
	IP        string  `json:"ip"`
	City      string  `json:"city"`
	Region    string  `json:"region"`
	Country   string  `json:"country"`
	Timezone  string  `json:"timezone"`
	Isp       string  `json:"isp"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

var (
	ispInfoCache      = make(map[string]IPInfo, 0)
	ispInfoCacheLock  = sync.RWMutex{}
	cli               = http.Client{Timeout: time.Second * 10}
	trafficLStatic    = make(map[string]int64)
	lockTrafficStatic = sync.RWMutex{}
	removeIspRegexp   = regexp.MustCompile(`AS\d+\s`)
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

func GetIPInfo(clientIP string) IPInfo {
	ispInfoCacheLock.RLock()
	ipInfo, ok := ispInfoCache[clientIP]
	ispInfoCacheLock.RUnlock()
	if !ok {
		var err error
		var caller IPApi

		provider := config.LoadedConfig().GeoIPApiProvider
		switch provider {
		case "ip.sb":
			caller = &IPSbApi{}
		default:
			caller = &IPInfoApi{}
		}
		
		ipInfo, err = caller.GetIPInfo(clientIP)
		if err != nil {
			ispInfoCacheLock.Lock()
			ispInfoCache[clientIP] = ipInfo
			ispInfoCacheLock.Unlock()
		}
	}
	return ipInfo
}

type IPApi interface {
	GetIPInfo(string) (IPInfo, error)
}

type IPSbApi struct {
}

func (IPSbApi) GetIPInfo(ip string) (IPInfo, error) {
	var ret IPInfo
	url := fmt.Sprintf("https://api.ip.sb/geoip/%s", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("Error new request response from ip.sb: %s", err)
		return ret, err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0")

	resp, err := cli.Do(req)
	if err != nil {
		log.Errorf("Error getting response from ip.sb: %s", err)
		return ret, err
	}

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading response from ip.sb: %s", err)
		return ret, err
	}
	defer func() { _ = resp.Body.Close() }()

	var r IPInfo
	if err := json.Unmarshal(raw, &r); err != nil {
		log.Errorf("Error parsing response from ip.sb: %s", err)
	}

	return r, err
}

type IPInfoApi struct {
}

type IPInfoApiResp struct {
	IP           string `json:"ip"`
	City         string `json:"city"`
	Region       string `json:"region"`
	Country      string `json:"country"`
	Location     string `json:"loc"`
	Organization string `json:"org"`
	Timezone     string `json:"timezone"`
	Isp          string `json:"isp"`
}

func (IPInfoApi) GetIPInfo(ip string) (IPInfo, error) {
	var ret IPInfo
	resp, err := cli.Get(getIPInfoURL(ip))
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

	var r IPInfoApiResp
	if err := json.Unmarshal(raw, &r); err != nil {
		log.Errorf("Error parsing response from ipinfo.io: %s", err)
	}

	var latitude, longitude float64
	parts := strings.Split(r.Location, ",")
	if len(parts) == 2 {
		latitude, _ = strconv.ParseFloat(parts[0], 64)
		longitude, _ = strconv.ParseFloat(parts[1], 64)
	}
	isp := removeIspRegexp.ReplaceAllString(r.Organization, "")
	ret = IPInfo{
		IP:        r.IP,
		City:      r.City,
		Region:    r.Region,
		Country:   r.Country,
		Timezone:  r.Timezone,
		Isp:       isp,
		Latitude:  latitude,
		Longitude: longitude,
	}
	return ret, err
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
