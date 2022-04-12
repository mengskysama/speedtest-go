package config

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"strconv"
)

type Config struct {
	BindAddress       string  `mapstructure:"bind_address"`
	Port              string  `mapstructure:"listen_port"`
	ProxyProtocolPort string  `mapstructure:"proxyprotocol_port"`
	ServerLat         float64 `mapstructure:"server_lat"`
	ServerLng         float64 `mapstructure:"server_lng"`
	IPInfoAPIKey      string  `mapstructure:"ipinfo_api_key"`
	GeoIPApiProvider  string  `mapstructure:"geo_ip_api_provider"`

	StatsPassword string `mapstructure:"statistics_password"`

	AssetsPath string `mapstructure:"assets_path"`

	DatabaseType     string `mapstructure:"database_type"`
	DatabaseHostname string `mapstructure:"database_hostname"`
	DatabaseName     string `mapstructure:"database_name"`
	DatabaseUsername string `mapstructure:"database_username"`
	DatabasePassword string `mapstructure:"database_password"`

	DatabaseFile string `mapstructure:"database_file"`

	EnableHTTP2 bool   `mapstructure:"enable_http2"`
	EnableTLS   bool   `mapstructure:"enable_tls"`
	TLSCertFile string `mapstructure:"tls_cert_file"`
	TLSKeyFile  string `mapstructure:"tls_key_file"`

	EnableResultPNG     bool  `mapstructure:"enable_result_png"`
	IPDailyTrafficLimit int64 `mapstructure:"ip_daily_traffic_limit"`
	SameIPMultiLogs     bool  `mapstructure:"same_ip_multi_logs"`
	EnableXFFIP         bool  `mapstructure:"enable_xff_ip"`

	EnableCaptcha     bool   `mapstructure:"enable_captcha"`
	InflightTestLimit int64  `mapstructure:"inflight_test_limit"`
	TokenTTLDuration  string `mapstructure:"token_ttl_duration"`
}

var (
	configFile   string
	loadedConfig *Config = nil
)

func init() {
	viper.SetDefault("listen_port", "8989")
	viper.SetDefault("proxyprotocol_port", "0")
	viper.SetDefault("download_chunks", 4)
	viper.SetDefault("distance_unit", "K")
	viper.SetDefault("enable_cors", false)
	viper.SetDefault("statistics_password", "PASSWORD")
	viper.SetDefault("database_type", "postgresql")
	viper.SetDefault("database_hostname", "localhost")
	viper.SetDefault("database_name", "speedtest")
	viper.SetDefault("database_username", "postgres")
	viper.SetDefault("enable_tls", false)
	viper.SetDefault("enable_http2", false)
	viper.SetDefault("enable_result_png", false)
	viper.SetDefault("ip_daily_traffic_limit", 0)
	viper.SetDefault("same_ip_multi_logs", false)
	viper.SetDefault("enable_xff_ip", false)
	viper.SetDefault("geo_ip_api_provider", "ip.sb")

	// incompatible config
	viper.SetDefault("enable_captcha", false)
	viper.SetDefault("inflight_test_limit", 0)
	viper.SetDefault("token_ttl_duration", "60s")

	viper.SetConfigName("settings")
	viper.AddConfigPath(".")
}

func Load(configPath string) Config {
	var conf Config

	configFile = configPath
	viper.SetConfigFile(configPath)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Warnf("No config file found in search paths, using default values")
			os.Create(configPath)
			_ = viper.WriteConfig()
		} else {
			log.Fatalf("Error reading config: %s", err)
		}
	}

	ApplyEnvSettings()

	if err := viper.Unmarshal(&conf); err != nil {
		log.Fatalf("Error parsing config: %s", err)
	}

	loadedConfig = &conf
	return conf
}

func ApplyEnvSettings() {
	if os.Getenv("ENABLE_CAPTCHA") != "" {
		if os.Getenv("ENABLE_CAPTCHA") == "0" {
			viper.Set("enable_captcha", false)
		} else {
			viper.Set("enable_captcha", true)
		}
	}

	if os.Getenv("INFLIGHT_TEST_LIMIT") != "" {
		n, _ := strconv.ParseInt(os.Getenv("INFLIGHT_TEST_LIMIT"), 10, 64)
		viper.SetDefault("inflight_test_limit", n)
	}
}

func LoadedConfig() *Config {
	if loadedConfig == nil {
		Load(configFile)
	}
	return loadedConfig
}
