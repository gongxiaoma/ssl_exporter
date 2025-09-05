package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

// Config 定义配置文件的顶层结构
type Config struct {
	CertFiles   []CertFilesConfig   `mapstructure:"certfiles"`
	CertDomains []CertDomainsConfig `mapstructure:"certdomains"`
}

// CertFilesConfig 定义单个证书的配置
type CertFilesConfig struct {
	Name string `mapstructure:"name"`
	Path string `mapstructure:"path"`
}

// CertDomainsConfig 定义远程证书的配置
type CertDomainsConfig struct {
	Name string `mapstructure:"name"`
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// certNotBefore 指标记录证书NotBefore时间戳
// certNotAfter 指标记录证书NotAfter时间戳
// certDaysRemaining 指标记录证书剩余天数
var (
	certNotBefore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssl_cert_not_before_timestamp",
			Help: "The 'NotBefore' (start time) of the SSL certificate as a Unix timestamp.",
		},
		[]string{"name", "path"},
	)
	certNotAfter = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssl_cert_not_after_timestamp",
			Help: "The 'NotAfter' (expiry time) of the SSL certificate as a Unix timestamp.",
		},
		[]string{"name", "path"},
	)
	certDaysRemaining = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssl_cert_days_remaining",                       // 指标名称
			Help: "Number of days until the certificate expires.", // 指标说明
		},
		[]string{"name", "path"}, //指标标签：证书名称和路径
	)
)

/**
* init在程序启动时执行一次，注册Prometheus指标
 */
func init() {
	prometheus.MustRegister(certNotBefore)
	prometheus.MustRegister(certNotAfter)
	prometheus.MustRegister(certDaysRemaining)
}

/**
* loadConfig加载配置文件
 * @param configPath
 * @return *Config
 * @return error
*/
func loadConfig(configPath string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("yml")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// 定义Config结构体，将配置映射到结构体并返回
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &cfg, nil
}

/**
* parseCert解析证书文件
 * @param certPath
 * @return *x509.Certificate
 * @return error
*/
func parseCert(certPath string) (*x509.Certificate, error) {
	// 读取证书文件内容
	data, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	// 优先尝试PEM格式（开头是BEGIN CERTIFICATE）
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}

	// 如果不是PEM，就尝试DER格式（二进制文件，打开是乱码）
	return x509.ParseCertificate(data)
}

/**
* fetchRemoteCert解析远程证书
 * @param CertDomainsConfig
 * @return *x509.Certificate
 * @return error
*/
func fetchRemoteCert(cd CertDomainsConfig) (*x509.Certificate, error) {
	// 构建地址
	addr := fmt.Sprintf("%s:%d", cd.Host, cd.Port)

	// 建立 TLS 连接
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // 跳过验证，只取证书
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 获取对端证书链
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates from %s", addr)
	}

	// 返回第一个证书（一般是服务端证书）
	return state.PeerCertificates[0], nil
}

/**
* updateMetrics更新Prometheus指标
 * @param *Config
*/
func updateMetrics(cfg *Config) {
	// 清理旧数据，避免标签残留
	certNotBefore.Reset()
	certNotAfter.Reset()
	certDaysRemaining.Reset()

	// 遍历配置中的所有证书
	for _, certConf := range cfg.CertFiles {
		// 解析证书
		cert, err := parseCert(certConf.Path)
		if err != nil {
			log.Printf("Failed to parse cert %s (%s): %v", certConf.Name, certConf.Path, err)
			continue
		}

		// 获取 NotBefore 时间戳
		notBefore := float64(cert.NotBefore.Unix())
		// 获取 NotAfter 时间戳
		notAfter := float64(cert.NotAfter.Unix())
		// 计算剩余天数
		daysRemaining := cert.NotAfter.Sub(time.Now()).Hours() / 24

		// 更新指标
		certNotBefore.WithLabelValues(certConf.Name, certConf.Path).Set(notBefore)
		certNotAfter.WithLabelValues(certConf.Name, certConf.Path).Set(notAfter)
		certDaysRemaining.WithLabelValues(certConf.Name, certConf.Path).Set(daysRemaining)
	}

	// 更新远程服务证书指标
	for _, cd := range cfg.CertDomains {
		cert, err := fetchRemoteCert(cd)
		if err != nil {
			log.Printf("Failed to fetch cert from %s:%d (%s): %v", cd.Host, cd.Port, cd.Name, err)
			continue
		}

		notBefore := float64(cert.NotBefore.Unix())
		notAfter := float64(cert.NotAfter.Unix())
		daysRemaining := cert.NotAfter.Sub(time.Now()).Hours() / 24

		certNotBefore.WithLabelValues(cd.Name, fmt.Sprintf("%s:%d", cd.Host, cd.Port)).Set(notBefore)
		certNotAfter.WithLabelValues(cd.Name, fmt.Sprintf("%s:%d", cd.Host, cd.Port)).Set(notAfter)
		certDaysRemaining.WithLabelValues(cd.Name, fmt.Sprintf("%s:%d", cd.Host, cd.Port)).Set(daysRemaining)
	}

}

/**
* main主方法
 */
func main() {
	configPath := "config.yml"
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 自定义 handler，在每次 scrape 时执行 updateMetrics
	http.Handle("/metrics", promhttp.InstrumentHandlerCounter(
		prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "ssl_exporter_scrapes_total",
				Help: "Total scrapes by Prometheus.",
			},
			[]string{},
		),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			updateMetrics(cfg)
			promhttp.Handler().ServeHTTP(w, r)
		}),
	))

	log.Println("SSL Exporter is running on :9101/metrics")
	log.Fatal(http.ListenAndServe(":9101", nil))
}
