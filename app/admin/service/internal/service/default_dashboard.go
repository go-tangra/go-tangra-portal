package service

import (
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/schema"
)

// builtinAdminWidgets defines dashboard widgets for the admin portal's own statistics
// and TimescaleDB-powered time-series analytics.
// These are always available regardless of which modules are registered.
var builtinAdminWidgets = []*ParsedWidget{
	// ── Snapshot Statistics ──────────────────────────────────────────
	{
		ID:          "admin.users_total",
		Name:        "Total Users",
		Description: "Active and total user counts",
		Icon:        "lucide:users",
		WidgetType:  "stat_card",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics",
			Method:   "GET",
		},
		DataMapping: map[string]string{
			"value_path": "admin.users.activeCount",
			"total_path": "admin.users.totalCount",
			"label":      "Users",
		},
		DefaultSize: WidgetSize{Width: 3, Height: 1},
		Tags:        []string{"admin", "overview"},
		Authority:   []string{"platform:admin", "tenant:manager"},
	},
	{
		ID:          "admin.tenants_total",
		Name:        "Total Tenants",
		Description: "Active and total tenant counts",
		Icon:        "lucide:building",
		WidgetType:  "stat_card",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics",
			Method:   "GET",
		},
		DataMapping: map[string]string{
			"value_path": "admin.tenants.activeCount",
			"total_path": "admin.tenants.totalCount",
			"label":      "Tenants",
		},
		DefaultSize: WidgetSize{Width: 3, Height: 1},
		Tags:        []string{"admin", "overview"},
		Authority:   []string{"platform:admin"},
	},
	{
		ID:          "admin.roles_total",
		Name:        "Total Roles",
		Description: "Active and total role counts",
		Icon:        "lucide:shield",
		WidgetType:  "stat_card",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics",
			Method:   "GET",
		},
		DataMapping: map[string]string{
			"value_path": "admin.roles.activeCount",
			"total_path": "admin.roles.totalCount",
			"label":      "Roles",
		},
		DefaultSize: WidgetSize{Width: 3, Height: 1},
		Tags:        []string{"admin", "overview"},
		Authority:   []string{"platform:admin"},
	},

	// ── TimescaleDB Time-Series Widgets ─────────────────────────────
	{
		ID:          "admin.api_request_volume",
		Name:        "API Request Volume",
		Description: "API request volume over time (stacked area chart powered by TimescaleDB time_bucket)",
		Icon:        "lucide:activity",
		WidgetType:  "area_chart",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics/ts/api-requests",
			Method:   "GET",
			Params:   map[string]string{"interval": "1h", "range": "7d"},
		},
		DataMapping: map[string]string{
			"categories_path": "buckets",
			"series_data":     "series",
			"series_fields":   "total,success,errors",
			"series_labels":   "Total,Success,Errors",
			"stacked":         "false",
		},
		DefaultSize: WidgetSize{Width: 6, Height: 2},
		Tags:        []string{"admin", "time-series", "api"},
		Authority:   []string{"platform:admin", "tenant:manager"},
	},
	{
		ID:          "admin.api_latency_percentiles",
		Name:        "API Latency (P50/P95/P99)",
		Description: "API response latency percentiles over time using TimescaleDB PERCENTILE_CONT",
		Icon:        "lucide:timer",
		WidgetType:  "line_chart",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics/ts/api-latency",
			Method:   "GET",
			Params:   map[string]string{"interval": "1h", "range": "7d"},
		},
		DataMapping: map[string]string{
			"categories_path": "buckets",
			"series_data":     "series",
			"series_fields":   "p50,p95,p99",
			"series_labels":   "P50,P95,P99",
		},
		DefaultSize: WidgetSize{Width: 6, Height: 2},
		Tags:        []string{"admin", "time-series", "performance"},
		Authority:   []string{"platform:admin", "tenant:manager"},
	},
	{
		ID:          "admin.login_activity",
		Name:        "Login Activity",
		Description: "Login success/failure trends over time using TimescaleDB time_bucket",
		Icon:        "lucide:log-in",
		WidgetType:  "area_chart",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics/ts/login-activity",
			Method:   "GET",
			Params:   map[string]string{"interval": "1d", "range": "30d"},
		},
		DataMapping: map[string]string{
			"categories_path": "buckets",
			"series_data":     "series",
			"series_fields":   "success,failed,locked",
			"series_labels":   "Success,Failed,Locked",
			"stacked":         "true",
		},
		DefaultSize: WidgetSize{Width: 6, Height: 2},
		Tags:        []string{"admin", "time-series", "security"},
		Authority:   []string{"platform:admin"},
	},
	{
		ID:          "admin.active_users",
		Name:        "Active Users",
		Description: "Unique active users and IPs over time using TimescaleDB COUNT(DISTINCT)",
		Icon:        "lucide:user-check",
		WidgetType:  "area_chart",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics/ts/active-users",
			Method:   "GET",
			Params:   map[string]string{"interval": "1d", "range": "30d"},
		},
		DataMapping: map[string]string{
			"categories_path": "buckets",
			"series_data":     "series",
			"series_fields":   "unique_users,unique_ips",
			"series_labels":   "Users,IP Addresses",
		},
		DefaultSize: WidgetSize{Width: 6, Height: 2},
		Tags:        []string{"admin", "time-series"},
		Authority:   []string{"platform:admin", "tenant:manager"},
	},
	{
		ID:          "admin.login_heatmap",
		Name:        "Login Heatmap",
		Description: "Login activity by hour of day and day of week (GitHub-style heatmap)",
		Icon:        "lucide:calendar-days",
		WidgetType:  "heatmap",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics/ts/login-heatmap",
			Method:   "GET",
			Params:   map[string]string{"range": "30d"},
		},
		DataMapping: map[string]string{
			"hours_path": "hours",
			"days_path":  "days",
			"data_path":  "data",
			"max_path":   "maxValue",
		},
		DefaultSize: WidgetSize{Width: 6, Height: 2},
		Tags:        []string{"admin", "time-series", "security"},
		Authority:   []string{"platform:admin"},
	},
	{
		ID:          "admin.top_endpoints",
		Name:        "Top API Endpoints",
		Description: "Most-used API endpoints with latency and error rate",
		Icon:        "lucide:list-ordered",
		WidgetType:  "table",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics/ts/top-endpoints",
			Method:   "GET",
			Params:   map[string]string{"range": "7d", "limit": "10"},
		},
		DataMapping: map[string]string{
			"items_path": "endpoints",
			"columns":    "method,path,totalRequests,avgLatencyMs,errorRate",
		},
		DefaultSize: WidgetSize{Width: 6, Height: 3},
		Tags:        []string{"admin", "time-series", "performance"},
		Authority:   []string{"platform:admin"},
	},
	{
		ID:          "admin.failed_logins_trend",
		Name:        "Failed Logins",
		Description: "Failed login attempts with sparkline trend (7-day comparison)",
		Icon:        "lucide:shield-alert",
		WidgetType:  "sparkline_card",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics/ts/security",
			Method:   "GET",
		},
		DataMapping: map[string]string{
			"value_path":          "failedLogins7d",
			"change_percent_path": "changePercent",
			"trend_path":          "trend",
			"sparkline_path":      "sparkline",
			"label":               "Failed Logins (7d)",
			"invert_colors":       "true",
		},
		DefaultSize: WidgetSize{Width: 3, Height: 2},
		Tags:        []string{"admin", "time-series", "security"},
		Authority:   []string{"platform:admin"},
	},
	{
		ID:          "admin.api_error_rate",
		Name:        "API Error Rate",
		Description: "Current API error rate with trend indicator and sparkline",
		Icon:        "lucide:alert-circle",
		WidgetType:  "sparkline_card",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics/ts/api-error-rate",
			Method:   "GET",
		},
		DataMapping: map[string]string{
			"value_path":          "errorRatePercent",
			"change_percent_path": "changePercent",
			"trend_path":          "trend",
			"sparkline_path":      "sparkline",
			"label":               "Error Rate (%)",
			"invert_colors":       "true",
		},
		DefaultSize: WidgetSize{Width: 3, Height: 2},
		Tags:        []string{"admin", "time-series", "performance"},
		Authority:   []string{"platform:admin", "tenant:manager"},
	},
	{
		ID:          "admin.user_status_pie",
		Name:        "Users by Status",
		Description: "Pie chart of user statuses",
		Icon:        "lucide:pie-chart",
		WidgetType:  "pie_chart",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics",
			Method:   "GET",
		},
		DataMapping: map[string]string{
			"data_path": "admin.users.byStatus",
			"label":     "User Status",
		},
		DefaultSize: WidgetSize{Width: 4, Height: 2},
		Tags:        []string{"admin", "chart"},
		Authority:   []string{"platform:admin"},
	},
	{
		ID:          "admin.tenant_types_pie",
		Name:        "Tenants by Type",
		Description: "Pie chart of tenant types (trial, paid, internal, partner)",
		Icon:        "lucide:pie-chart",
		WidgetType:  "pie_chart",
		DataSource: WidgetDataSource{
			Endpoint: "/admin/v1/statistics",
			Method:   "GET",
		},
		DataMapping: map[string]string{
			"data_path": "admin.tenants.byType",
			"label":     "Tenant Type",
		},
		DefaultSize: WidgetSize{Width: 4, Height: 2},
		Tags:        []string{"admin", "chart"},
		Authority:   []string{"platform:admin"},
	},
}

// defaultDashboardWidgets defines the default dashboard layout.
// Widgets for unavailable modules are filtered out when serving.
var defaultDashboardWidgets = []schema.DashboardWidgetConfig{
	// ── Row 0-1: Overview stat cards ────────────────────────────────
	{WidgetID: "admin.users_total", GridX: 0, GridY: 0, GridW: 3, GridH: 2},
	{WidgetID: "lcm.issued_certs_total", GridX: 3, GridY: 0, GridW: 3, GridH: 2},
	{WidgetID: "paperless.documents_total", GridX: 6, GridY: 0, GridW: 3, GridH: 2},
	{WidgetID: "ipam.addresses_total", GridX: 9, GridY: 0, GridW: 3, GridH: 2},

	// ── Row 2-3: More stat cards ────────────────────────────────────
	{WidgetID: "deployer.targets_total", GridX: 0, GridY: 2, GridW: 3, GridH: 2},
	{WidgetID: "lcm.expiring_soon", GridX: 3, GridY: 2, GridW: 3, GridH: 2},
	{WidgetID: "warden.total_secrets", GridX: 6, GridY: 2, GridW: 3, GridH: 2},
	{WidgetID: "executor.total_scripts", GridX: 9, GridY: 2, GridW: 3, GridH: 2},

	// ── Row 4-5: Additional stat cards ──────────────────────────────
	{WidgetID: "asset.total_assets", GridX: 0, GridY: 4, GridW: 3, GridH: 2},
	{WidgetID: "admin.roles_total", GridX: 3, GridY: 4, GridW: 3, GridH: 2},
	{WidgetID: "executor.total_executions", GridX: 6, GridY: 4, GridW: 3, GridH: 2},
	{WidgetID: "warden.folders_count", GridX: 9, GridY: 4, GridW: 3, GridH: 2},

	// ── Row 6-8: Time-Series Charts (TimescaleDB powered) ──────────
	{WidgetID: "admin.api_request_volume", GridX: 0, GridY: 6, GridW: 6, GridH: 3},
	{WidgetID: "admin.api_latency_percentiles", GridX: 6, GridY: 6, GridW: 6, GridH: 3},

	// ── Row 9-11: Module Charts ─────────────────────────────────────
	{WidgetID: "lcm.certificate_status_pie", GridX: 0, GridY: 9, GridW: 4, GridH: 3},
	{WidgetID: "paperless.document_status_bar", GridX: 4, GridY: 9, GridW: 4, GridH: 3},
	{WidgetID: "deployer.job_trends_line", GridX: 8, GridY: 9, GridW: 4, GridH: 3},

	// ── Row 12-14: Security + Performance ───────────────────────────
	{WidgetID: "admin.login_activity", GridX: 0, GridY: 12, GridW: 6, GridH: 3},
	{WidgetID: "admin.failed_logins_trend", GridX: 6, GridY: 12, GridW: 3, GridH: 3},
	{WidgetID: "admin.api_error_rate", GridX: 9, GridY: 12, GridW: 3, GridH: 3},

	// ── Row 15-19: Gauges + Heatmap ─────────────────────────────────
	{WidgetID: "deployer.success_gauge", GridX: 0, GridY: 15, GridW: 3, GridH: 4},
	{WidgetID: "ipam.utilization_gauge", GridX: 3, GridY: 15, GridW: 3, GridH: 4},
	{WidgetID: "admin.login_heatmap", GridX: 6, GridY: 15, GridW: 6, GridH: 4},

	// ── Row 19-22: Executor + Active Users ──────────────────────────
	{WidgetID: "executor.execution_success", GridX: 0, GridY: 19, GridW: 4, GridH: 4},
	{WidgetID: "executor.recent_errors", GridX: 4, GridY: 19, GridW: 4, GridH: 3},
	{WidgetID: "admin.active_users", GridX: 8, GridY: 19, GridW: 4, GridH: 3},

	// ── Row 23-26: Top Endpoints + Errors ───────────────────────────
	{WidgetID: "admin.top_endpoints", GridX: 0, GridY: 23, GridW: 6, GridH: 4},
	{WidgetID: "lcm.recent_errors", GridX: 6, GridY: 23, GridW: 6, GridH: 3},
}
