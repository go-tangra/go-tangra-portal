package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	echopb "github.com/go-tangra/go-tangra-portal/api/gen/go/echo/service/v1"
)

// Version is the service version
const Version = "1.0.0"

// Message represents a stored message (internal representation)
type Message struct {
	ID        string
	Content   string
	Author    string
	CreatedAt time.Time
	Metadata  map[string]string
}

// EchoService implements the gRPC echo service
type EchoService struct {
	echopb.UnimplementedEchoServiceServer
	log      *log.Helper
	messages map[string]*Message
	mu       sync.RWMutex
}

// NewEchoService creates a new EchoService
func NewEchoService(logger log.Logger) *EchoService {
	return &EchoService{
		log:      log.NewHelper(log.With(logger, "module", "echo/service")),
		messages: make(map[string]*Message),
	}
}

// Echo returns the input message with a timestamp
func (s *EchoService) Echo(ctx context.Context, req *echopb.EchoRequest) (*echopb.EchoResponse, error) {
	userID := s.getUserID(ctx)
	s.log.Infof("Echo called by user %s with message: %s", userID, req.GetMessage())

	return &echopb.EchoResponse{
		Message:   req.GetMessage(),
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListMessages returns a list of stored messages
func (s *EchoService) ListMessages(ctx context.Context, req *echopb.ListMessagesRequest) (*echopb.ListMessagesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = 10
	}
	page := int(req.GetPage())
	if page <= 0 {
		page = 1
	}

	// Convert map to slice for pagination
	var allMessages []*Message
	for _, msg := range s.messages {
		if req.GetFilter() != "" {
			if !containsIgnoreCase(msg.Content, req.GetFilter()) {
				continue
			}
		}
		allMessages = append(allMessages, msg)
	}

	total := len(allMessages)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	var result []*echopb.Message
	for _, msg := range allMessages[start:end] {
		result = append(result, &echopb.Message{
			Id:        msg.ID,
			Content:   msg.Content,
			Author:    msg.Author,
			CreatedAt: timestamppb.New(msg.CreatedAt),
			Metadata:  msg.Metadata,
		})
	}

	return &echopb.ListMessagesResponse{
		Messages: result,
		Total:    int32(total),
		Page:     int32(page),
		PageSize: int32(pageSize),
	}, nil
}

// GetMessage returns a specific message by ID
func (s *EchoService) GetMessage(ctx context.Context, req *echopb.GetMessageRequest) (*echopb.GetMessageResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	msg, ok := s.messages[req.GetId()]
	if !ok {
		return nil, fmt.Errorf("message not found: %s", req.GetId())
	}

	return &echopb.GetMessageResponse{
		Message: &echopb.Message{
			Id:        msg.ID,
			Content:   msg.Content,
			Author:    msg.Author,
			CreatedAt: timestamppb.New(msg.CreatedAt),
			Metadata:  msg.Metadata,
		},
	}, nil
}

// CreateMessage creates a new message
func (s *EchoService) CreateMessage(ctx context.Context, req *echopb.CreateMessageRequest) (*echopb.CreateMessageResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	author := req.GetAuthor()
	if author == "" {
		author = s.getUserID(ctx)
	}

	msg := &Message{
		ID:        uuid.New().String(),
		Content:   req.GetContent(),
		Author:    author,
		CreatedAt: time.Now(),
		Metadata:  req.GetMetadata(),
	}

	s.messages[msg.ID] = msg
	s.log.Infof("Created message: %s by %s", msg.ID, msg.Author)

	return &echopb.CreateMessageResponse{
		Message: &echopb.Message{
			Id:        msg.ID,
			Content:   msg.Content,
			Author:    msg.Author,
			CreatedAt: timestamppb.New(msg.CreatedAt),
			Metadata:  msg.Metadata,
		},
	}, nil
}

// DeleteMessage deletes a message by ID
func (s *EchoService) DeleteMessage(ctx context.Context, req *echopb.DeleteMessageRequest) (*echopb.DeleteMessageResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.messages[req.GetId()]; !ok {
		return nil, fmt.Errorf("message not found: %s", req.GetId())
	}

	delete(s.messages, req.GetId())
	s.log.Infof("Deleted message: %s", req.GetId())

	return &echopb.DeleteMessageResponse{
		Success: true,
	}, nil
}

// HealthCheck returns the health status of the service
func (s *EchoService) HealthCheck(ctx context.Context, _ *echopb.HealthCheckRequest) (*echopb.HealthCheckResponse, error) {
	return &echopb.HealthCheckResponse{
		Status:    "healthy",
		Version:   Version,
		Timestamp: timestamppb.Now(),
	}, nil
}

// getUserID extracts the user ID from gRPC metadata
func (s *EchoService) getUserID(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "anonymous"
	}
	if vals := md.Get("x-md-global-user-id"); len(vals) > 0 {
		return vals[0]
	}
	if vals := md.Get("x-md-global-username"); len(vals) > 0 {
		return vals[0]
	}
	return "anonymous"
}

// containsIgnoreCase checks if s contains substr (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	if substr == "" {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			pc := substr[j]
			if sc != pc && sc != pc+32 && sc != pc-32 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
