package service

import (
	"context"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"
	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data/ent/schema"
	"github.com/go-tangra/go-tangra-portal/pkg/middleware/auth"

	adminV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/admin/service/v1"
)

// DashboardService implements the DashboardService gRPC service.
type DashboardService struct {
	adminV1.UnimplementedDashboardServiceServer
	log           *log.Helper
	registry      *ModuleRegistry
	dashboardRepo *data.UserDashboardRepo
}

// NewDashboardService creates a new DashboardService.
func NewDashboardService(
	ctx *bootstrap.Context,
	registry *ModuleRegistry,
	dashboardRepo *data.UserDashboardRepo,
) *DashboardService {
	return &DashboardService{
		log:           ctx.NewLoggerHelper("dashboard-service/admin-service"),
		registry:      registry,
		dashboardRepo: dashboardRepo,
	}
}

// ListWidgets returns the widget catalog from all registered modules plus built-in admin widgets.
func (s *DashboardService) ListWidgets(ctx context.Context, req *adminV1.ListWidgetsRequest) (*adminV1.ListWidgetsResponse, error) {
	// Collect widgets from all healthy modules
	moduleWidgets := s.registry.GetAllDashboardWidgets()

	// Combine with built-in admin widgets
	allWidgets := make([]*ParsedWidget, 0, len(builtinAdminWidgets)+len(moduleWidgets))
	allWidgets = append(allWidgets, builtinAdminWidgets...)
	allWidgets = append(allWidgets, moduleWidgets...)

	// Apply filters
	var filtered []*adminV1.WidgetDefinition
	for _, w := range allWidgets {
		// Filter by module_id
		if req.ModuleId != nil && *req.ModuleId != "" {
			moduleID := strings.Split(w.ID, ".")[0]
			if moduleID != *req.ModuleId {
				continue
			}
		}

		// Filter by widget_type
		if req.WidgetType != nil && *req.WidgetType != "" {
			if w.WidgetType != *req.WidgetType {
				continue
			}
		}

		// Filter by tag
		if req.Tag != nil && *req.Tag != "" {
			hasTag := false
			for _, t := range w.Tags {
				if t == *req.Tag {
					hasTag = true
					break
				}
			}
			if !hasTag {
				continue
			}
		}

		filtered = append(filtered, parsedWidgetToProto(w))
	}

	return &adminV1.ListWidgetsResponse{
		Widgets: filtered,
		Total:   int32(len(filtered)),
	}, nil
}

// GetUserDashboard returns the current user's dashboard layout.
func (s *DashboardService) GetUserDashboard(ctx context.Context, _ *adminV1.GetUserDashboardRequest) (*adminV1.GetUserDashboardResponse, error) {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	userID := operator.GetUserId()
	tenantID := operator.GetTenantId()

	// Try to load user's saved dashboard
	entity, err := s.dashboardRepo.GetByUser(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}

	if entity != nil {
		// Return saved dashboard
		widgets := make([]*adminV1.DashboardWidget, 0, len(entity.Widgets))
		for _, w := range entity.Widgets {
			widgets = append(widgets, schemaWidgetToProto(&w))
		}

		dashboard := &adminV1.UserDashboard{
			Id:        entity.ID,
			Name:      entity.Name,
			Widgets:   widgets,
			IsDefault: false,
		}
		if entity.CreatedAt != nil {
			dashboard.CreatedAt = timestamppb.New(*entity.CreatedAt)
		}
		if entity.UpdatedAt != nil {
			dashboard.UpdatedAt = timestamppb.New(*entity.UpdatedAt)
		}

		return &adminV1.GetUserDashboardResponse{Dashboard: dashboard}, nil
	}

	// Return default dashboard (filtered for available modules)
	return &adminV1.GetUserDashboardResponse{
		Dashboard: s.buildDefaultDashboard(),
	}, nil
}

// SaveUserDashboard saves the user's dashboard layout.
func (s *DashboardService) SaveUserDashboard(ctx context.Context, req *adminV1.SaveUserDashboardRequest) (*adminV1.SaveUserDashboardResponse, error) {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	userID := operator.GetUserId()
	tenantID := operator.GetTenantId()

	// Convert proto widgets to schema widgets
	widgets := make([]schema.DashboardWidgetConfig, 0, len(req.GetWidgets()))
	for _, w := range req.GetWidgets() {
		cfg := schema.DashboardWidgetConfig{
			WidgetID: w.GetWidgetId(),
			GridX:    w.GetGridX(),
			GridY:    w.GetGridY(),
			GridW:    w.GetGridW(),
			GridH:    w.GetGridH(),
		}
		if w.GetConfig() != nil {
			cfg.Config = structToMap(w.GetConfig())
		}
		widgets = append(widgets, cfg)
	}

	name := req.GetName()
	if name == "" {
		name = "My Dashboard"
	}

	entity, err := s.dashboardRepo.Upsert(ctx, userID, tenantID, name, widgets)
	if err != nil {
		return nil, err
	}

	// Convert back to proto
	protoWidgets := make([]*adminV1.DashboardWidget, 0, len(entity.Widgets))
	for _, w := range entity.Widgets {
		protoWidgets = append(protoWidgets, schemaWidgetToProto(&w))
	}

	dashboard := &adminV1.UserDashboard{
		Id:      entity.ID,
		Name:    entity.Name,
		Widgets: protoWidgets,
	}
	if entity.CreatedAt != nil {
		dashboard.CreatedAt = timestamppb.New(*entity.CreatedAt)
	}
	if entity.UpdatedAt != nil {
		dashboard.UpdatedAt = timestamppb.New(*entity.UpdatedAt)
	}

	return &adminV1.SaveUserDashboardResponse{Dashboard: dashboard}, nil
}

// ResetUserDashboard resets the user's dashboard to the default layout.
func (s *DashboardService) ResetUserDashboard(ctx context.Context, _ *adminV1.ResetUserDashboardRequest) (*adminV1.ResetUserDashboardResponse, error) {
	operator, err := auth.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	userID := operator.GetUserId()
	tenantID := operator.GetTenantId()

	// Delete user's saved dashboard
	if err := s.dashboardRepo.Delete(ctx, userID, tenantID); err != nil {
		return nil, err
	}

	return &adminV1.ResetUserDashboardResponse{
		Dashboard: s.buildDefaultDashboard(),
	}, nil
}

// buildDefaultDashboard creates the default dashboard, filtering out widgets for unavailable modules.
func (s *DashboardService) buildDefaultDashboard() *adminV1.UserDashboard {
	// Build a set of available widget IDs
	availableWidgets := make(map[string]bool)
	for _, w := range builtinAdminWidgets {
		availableWidgets[w.ID] = true
	}
	for _, w := range s.registry.GetAllDashboardWidgets() {
		availableWidgets[w.ID] = true
	}

	// Filter default layout to only include available widgets
	var widgets []*adminV1.DashboardWidget
	for _, w := range defaultDashboardWidgets {
		if availableWidgets[w.WidgetID] {
			widgets = append(widgets, schemaWidgetToProto(&w))
		}
	}

	return &adminV1.UserDashboard{
		Name:      "Default Dashboard",
		Widgets:   widgets,
		IsDefault: true,
	}
}

// parsedWidgetToProto converts a ParsedWidget to a proto WidgetDefinition.
func parsedWidgetToProto(w *ParsedWidget) *adminV1.WidgetDefinition {
	moduleID := ""
	if parts := strings.SplitN(w.ID, ".", 2); len(parts) > 0 {
		moduleID = parts[0]
	}

	def := &adminV1.WidgetDefinition{
		Id:         w.ID,
		ModuleId:   moduleID,
		Name:       w.Name,
		Description: w.Description,
		Icon:       w.Icon,
		WidgetType: w.WidgetType,
		DataSource: &adminV1.WidgetDataSourceProto{
			Endpoint: w.DataSource.Endpoint,
			Method:   w.DataSource.Method,
			Params:   w.DataSource.Params,
		},
		DefaultSize: &adminV1.WidgetSizeProto{
			Width:  w.DefaultSize.Width,
			Height: w.DefaultSize.Height,
		},
		Tags:      w.Tags,
		Authority: w.Authority,
	}

	// Convert data_mapping to Struct
	if len(w.DataMapping) > 0 {
		fields := make(map[string]*structpb.Value, len(w.DataMapping))
		for k, v := range w.DataMapping {
			fields[k] = structpb.NewStringValue(v)
		}
		def.DataMapping = &structpb.Struct{Fields: fields}
	}

	return def
}

// schemaWidgetToProto converts a DashboardWidgetConfig to a proto DashboardWidget.
func schemaWidgetToProto(w *schema.DashboardWidgetConfig) *adminV1.DashboardWidget {
	dw := &adminV1.DashboardWidget{
		WidgetId: w.WidgetID,
		GridX:    w.GridX,
		GridY:    w.GridY,
		GridW:    w.GridW,
		GridH:    w.GridH,
	}

	if len(w.Config) > 0 {
		dw.Config = mapToStruct(w.Config)
	}

	return dw
}

// structToMap converts a protobuf Struct to a map[string]any.
func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	result := make(map[string]any, len(s.Fields))
	for k, v := range s.Fields {
		result[k] = v.AsInterface()
	}
	return result
}

// mapToStruct converts a map[string]any to a protobuf Struct.
func mapToStruct(m map[string]any) *structpb.Struct {
	s, err := structpb.NewStruct(m)
	if err != nil {
		return nil
	}
	return s
}
