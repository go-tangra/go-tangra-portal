package metrics

import (
	"context"
	"os"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	commonMetrics "github.com/go-tangra/go-tangra-common/metrics"
)

const namespace = "tangra"
const subsystem = "portal"

// Collector holds all Prometheus metrics for the portal (admin-service) module.
type Collector struct {
	log    *log.Helper
	server *commonMetrics.MetricsServer

	// User metrics
	UsersTotal prometheus.Gauge

	// Role metrics
	RolesTotal prometheus.Gauge

	// Tenant metrics
	TenantsTotal prometheus.Gauge

	// Menu metrics
	MenusTotal prometheus.Gauge

	// gRPC request metrics
	RequestDuration *prometheus.HistogramVec
	RequestsTotal  *prometheus.CounterVec
}

// NewCollector creates and registers all portal Prometheus metrics.
func NewCollector(ctx *bootstrap.Context) *Collector {
	c := &Collector{
		log: ctx.NewLoggerHelper("portal/metrics"),

		UsersTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "users_total",
			Help:      "Total number of users.",
		}),

		RolesTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "roles_total",
			Help:      "Total number of roles.",
		}),

		TenantsTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "tenants_total",
			Help:      "Total number of tenants.",
		}),

		MenusTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "menus_total",
			Help:      "Total number of menus.",
		}),

		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "grpc_request_duration_seconds",
			Help:      "Histogram of gRPC request durations in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method"}),

		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "grpc_requests_total",
			Help:      "Total number of gRPC requests by method and status.",
		}, []string{"method", "status"}),
	}

	prometheus.MustRegister(
		c.UsersTotal,
		c.RolesTotal,
		c.TenantsTotal,
		c.MenusTotal,
		c.RequestDuration,
		c.RequestsTotal,
	)

	addr := os.Getenv("METRICS_ADDR")
	if addr == "" {
		addr = ":7790"
	}
	c.server = commonMetrics.NewMetricsServer(addr, nil, ctx.GetLogger())

	go func() {
		if err := c.server.Start(); err != nil {
			c.log.Errorf("Metrics server failed: %v", err)
		}
	}()

	return c
}

// Stop shuts down the metrics HTTP server.
func (c *Collector) Stop(ctx context.Context) {
	if c.server != nil {
		c.server.Stop(ctx)
	}
}

// --- User helpers ---

// UserCreated increments the user counter.
func (c *Collector) UserCreated() {
	c.UsersTotal.Inc()
}

// UserDeleted decrements the user counter.
func (c *Collector) UserDeleted() {
	c.UsersTotal.Dec()
}

// --- Role helpers ---

// RoleCreated increments the role counter.
func (c *Collector) RoleCreated() {
	c.RolesTotal.Inc()
}

// RoleDeleted decrements the role counter.
func (c *Collector) RoleDeleted() {
	c.RolesTotal.Dec()
}

// --- Tenant helpers ---

// TenantCreated increments the tenant counter.
func (c *Collector) TenantCreated() {
	c.TenantsTotal.Inc()
}

// TenantDeleted decrements the tenant counter.
func (c *Collector) TenantDeleted() {
	c.TenantsTotal.Dec()
}

// Middleware returns a Kratos middleware that records gRPC request metrics.
func (c *Collector) Middleware() middleware.Middleware {
	return commonMetrics.NewServerMiddleware(c.RequestDuration, c.RequestsTotal)
}

// --- Menu helpers ---

// MenuCreated increments the menu counter.
func (c *Collector) MenuCreated() {
	c.MenusTotal.Inc()
}

// MenuDeleted decrements the menu counter.
func (c *Collector) MenuDeleted() {
	c.MenusTotal.Dec()
}
