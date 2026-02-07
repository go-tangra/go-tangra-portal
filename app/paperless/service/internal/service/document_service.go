package service

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/go-tangra/go-tangra-portal/app/paperless/service/internal/data"

	paperlessV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/paperless/service/v1"
)

type DocumentService struct {
	paperlessV1.UnimplementedPaperlessDocumentServiceServer

	log          *log.Helper
	documentRepo *data.DocumentRepo
	categoryRepo *data.CategoryRepo
	permRepo     *data.PermissionRepo
	storage      *data.StorageClient
}

func NewDocumentService(
	ctx *bootstrap.Context,
	documentRepo *data.DocumentRepo,
	categoryRepo *data.CategoryRepo,
	permRepo *data.PermissionRepo,
	storage *data.StorageClient,
) *DocumentService {
	return &DocumentService{
		log:          ctx.NewLoggerHelper("paperless/service/document"),
		documentRepo: documentRepo,
		categoryRepo: categoryRepo,
		permRepo:     permRepo,
		storage:      storage,
	}
}

// CreateDocument creates a new document with file upload
func (s *DocumentService) CreateDocument(ctx context.Context, req *paperlessV1.CreateDocumentRequest) (*paperlessV1.CreateDocumentResponse, error) {
	tenantID := getTenantIDFromContext(ctx)
	createdBy := getUserIDAsUint32(ctx)
	userID := getUserIDFromContext(ctx)

	// Detect MIME type if not provided
	mimeType := req.MimeType
	if mimeType == "" {
		mimeType = http.DetectContentType(req.FileContent)
	}

	// Generate document ID first for storage path
	documentID := generateUUID()

	// Get category ID for storage path
	var categoryID string
	if req.CategoryId != nil {
		categoryID = *req.CategoryId
	}

	// Upload to storage
	uploadResult, err := s.storage.Upload(ctx, tenantID, categoryID, documentID, req.FileName, req.FileContent, mimeType)
	if err != nil {
		s.log.Errorf("failed to upload file: %v", err)
		return nil, paperlessV1.ErrorStorageOperationError("failed to upload file")
	}

	// Determine source
	source := "DOCUMENT_SOURCE_UPLOAD"
	if req.Source != paperlessV1.DocumentSource_DOCUMENT_SOURCE_UNSPECIFIED {
		source = req.Source.String()
	}

	// Create document record
	document, err := s.documentRepo.Create(ctx, tenantID, req.CategoryId, req.Name, req.Description,
		uploadResult.Key, req.FileName, uploadResult.Size, mimeType, uploadResult.Checksum,
		req.Tags, source, createdBy)
	if err != nil {
		// Cleanup uploaded file on failure
		_ = s.storage.Delete(ctx, uploadResult.Key)
		return nil, err
	}

	// Grant owner permission to creator
	if createdBy != nil {
		_, err = s.permRepo.Create(ctx, tenantID, "RESOURCE_TYPE_DOCUMENT", document.ID, "RELATION_OWNER", "SUBJECT_TYPE_USER", userID, createdBy, nil)
		if err != nil {
			s.log.Warnf("failed to grant owner permission: %v", err)
		}
	}

	proto, err := s.documentRepo.ToProtoWithCategoryPath(ctx, document)
	if err != nil {
		return nil, err
	}

	return &paperlessV1.CreateDocumentResponse{
		Document: proto,
	}, nil
}

// GetDocument gets a document by ID
func (s *DocumentService) GetDocument(ctx context.Context, req *paperlessV1.GetDocumentRequest) (*paperlessV1.GetDocumentResponse, error) {
	document, err := s.documentRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if document == nil {
		return nil, paperlessV1.ErrorDocumentNotFound("document not found")
	}

	proto, err := s.documentRepo.ToProtoWithCategoryPath(ctx, document)
	if err != nil {
		return nil, err
	}

	return &paperlessV1.GetDocumentResponse{
		Document: proto,
	}, nil
}

// ListDocuments lists documents
func (s *DocumentService) ListDocuments(ctx context.Context, req *paperlessV1.ListDocumentsRequest) (*paperlessV1.ListDocumentsResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	page := uint32(1)
	if req.Page != nil {
		page = *req.Page
	}
	pageSize := uint32(20)
	if req.PageSize != nil {
		pageSize = *req.PageSize
	}

	var status *string
	if req.Status != nil && *req.Status != paperlessV1.DocumentStatus_DOCUMENT_STATUS_UNSPECIFIED {
		s := req.Status.String()
		status = &s
	}

	documents, total, err := s.documentRepo.List(ctx, tenantID, req.CategoryId, status, req.NameFilter, req.MimeTypeFilter, req.IncludeSubcategories, page, pageSize)
	if err != nil {
		return nil, err
	}

	protoDocuments := make([]*paperlessV1.Document, 0, len(documents))
	for _, doc := range documents {
		proto, err := s.documentRepo.ToProtoWithCategoryPath(ctx, doc)
		if err != nil {
			return nil, err
		}
		protoDocuments = append(protoDocuments, proto)
	}

	return &paperlessV1.ListDocumentsResponse{
		Documents: protoDocuments,
		Total:     uint32(total),
	}, nil
}

// UpdateDocument updates document metadata
func (s *DocumentService) UpdateDocument(ctx context.Context, req *paperlessV1.UpdateDocumentRequest) (*paperlessV1.UpdateDocumentResponse, error) {
	updatedBy := getUserIDAsUint32(ctx)

	var status *string
	if req.Status != nil && *req.Status != paperlessV1.DocumentStatus_DOCUMENT_STATUS_UNSPECIFIED {
		s := req.Status.String()
		status = &s
	}

	document, err := s.documentRepo.Update(ctx, req.Id, req.Name, req.Description, status, req.Tags, req.UpdateTags, updatedBy)
	if err != nil {
		return nil, err
	}

	proto, err := s.documentRepo.ToProtoWithCategoryPath(ctx, document)
	if err != nil {
		return nil, err
	}

	return &paperlessV1.UpdateDocumentResponse{
		Document: proto,
	}, nil
}

// DeleteDocument deletes a document
func (s *DocumentService) DeleteDocument(ctx context.Context, req *paperlessV1.DeleteDocumentRequest) (*emptypb.Empty, error) {
	tenantID := getTenantIDFromContext(ctx)

	// Get document to retrieve file key
	document, err := s.documentRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if document == nil {
		return nil, paperlessV1.ErrorDocumentNotFound("document not found")
	}

	// Delete document record
	if err := s.documentRepo.Delete(ctx, req.Id, req.Permanent); err != nil {
		return nil, err
	}

	// If permanent delete, also delete from storage
	if req.Permanent {
		if err := s.storage.Delete(ctx, document.FileKey); err != nil {
			s.log.Warnf("failed to delete file from storage: %v", err)
		}
	}

	// Delete associated permissions
	_ = s.permRepo.DeleteByResource(ctx, tenantID, "RESOURCE_TYPE_DOCUMENT", req.Id)

	return &emptypb.Empty{}, nil
}

// MoveDocument moves a document to a different category
func (s *DocumentService) MoveDocument(ctx context.Context, req *paperlessV1.MoveDocumentRequest) (*paperlessV1.MoveDocumentResponse, error) {
	document, err := s.documentRepo.Move(ctx, req.Id, req.NewCategoryId)
	if err != nil {
		return nil, err
	}

	proto, err := s.documentRepo.ToProtoWithCategoryPath(ctx, document)
	if err != nil {
		return nil, err
	}

	return &paperlessV1.MoveDocumentResponse{
		Document: proto,
	}, nil
}

// DownloadDocument downloads document content
func (s *DocumentService) DownloadDocument(ctx context.Context, req *paperlessV1.DownloadDocumentRequest) (*paperlessV1.DownloadDocumentResponse, error) {
	document, err := s.documentRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if document == nil {
		return nil, paperlessV1.ErrorDocumentNotFound("document not found")
	}

	// Download from storage
	content, err := s.storage.Download(ctx, document.FileKey)
	if err != nil {
		s.log.Errorf("failed to download file: %v", err)
		return nil, paperlessV1.ErrorStorageOperationError("failed to download file")
	}

	return &paperlessV1.DownloadDocumentResponse{
		Content:  content,
		FileName: document.FileName,
		MimeType: document.MimeType,
		FileSize: document.FileSize,
	}, nil
}

// GetDocumentDownloadUrl generates a presigned download URL
func (s *DocumentService) GetDocumentDownloadUrl(ctx context.Context, req *paperlessV1.GetDocumentDownloadUrlRequest) (*paperlessV1.GetDocumentDownloadUrlResponse, error) {
	document, err := s.documentRepo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if document == nil {
		return nil, paperlessV1.ErrorDocumentNotFound("document not found")
	}

	// Default expiration: 1 hour
	expiresIn := time.Hour
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		expiresIn = time.Duration(*req.ExpiresIn) * time.Second
	}

	url, err := s.storage.GetPresignedURL(ctx, document.FileKey, expiresIn)
	if err != nil {
		s.log.Errorf("failed to generate presigned URL: %v", err)
		return nil, paperlessV1.ErrorStorageOperationError("failed to generate download URL")
	}

	expiresAt := time.Now().Add(expiresIn)

	return &paperlessV1.GetDocumentDownloadUrlResponse{
		Url:       url,
		ExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

// SearchDocuments searches documents
func (s *DocumentService) SearchDocuments(ctx context.Context, req *paperlessV1.SearchDocumentsRequest) (*paperlessV1.SearchDocumentsResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	page := uint32(1)
	if req.Page != nil {
		page = *req.Page
	}
	pageSize := uint32(20)
	if req.PageSize != nil {
		pageSize = *req.PageSize
	}

	var status *string
	if req.Status != nil && *req.Status != paperlessV1.DocumentStatus_DOCUMENT_STATUS_UNSPECIFIED {
		s := req.Status.String()
		status = &s
	}

	documents, total, err := s.documentRepo.Search(ctx, tenantID, req.Query, req.CategoryId, req.IncludeSubcategories, status, req.MimeTypeFilter, req.Tags, page, pageSize)
	if err != nil {
		return nil, err
	}

	protoDocuments := make([]*paperlessV1.Document, 0, len(documents))
	for _, doc := range documents {
		proto, err := s.documentRepo.ToProtoWithCategoryPath(ctx, doc)
		if err != nil {
			return nil, err
		}
		protoDocuments = append(protoDocuments, proto)
	}

	return &paperlessV1.SearchDocumentsResponse{
		Documents: protoDocuments,
		Total:     uint32(total),
	}, nil
}

// BatchDeleteDocuments batch deletes documents
func (s *DocumentService) BatchDeleteDocuments(ctx context.Context, req *paperlessV1.BatchDeleteDocumentsRequest) (*paperlessV1.BatchDeleteDocumentsResponse, error) {
	tenantID := getTenantIDFromContext(ctx)

	// For permanent deletes, get file keys first
	var fileKeys []string
	if req.Permanent {
		for _, id := range req.Ids {
			doc, err := s.documentRepo.GetByID(ctx, id)
			if err == nil && doc != nil {
				fileKeys = append(fileKeys, doc.FileKey)
			}
		}
	}

	deletedCount, failedIDs, err := s.documentRepo.BatchDelete(ctx, req.Ids, req.Permanent)
	if err != nil {
		return nil, err
	}

	// Delete files from storage for permanent deletes
	if req.Permanent {
		for _, key := range fileKeys {
			if err := s.storage.Delete(ctx, key); err != nil {
				s.log.Warnf("failed to delete file from storage: %v", err)
			}
		}
	}

	// Delete permissions for successfully deleted documents
	for _, id := range req.Ids {
		found := false
		for _, failedID := range failedIDs {
			if id == failedID {
				found = true
				break
			}
		}
		if !found {
			_ = s.permRepo.DeleteByResource(ctx, tenantID, "RESOURCE_TYPE_DOCUMENT", id)
		}
	}

	return &paperlessV1.BatchDeleteDocumentsResponse{
		DeletedCount: uint32(deletedCount),
		FailedIds:    failedIDs,
	}, nil
}

// generateUUID generates a new UUID
func generateUUID() string {
	return "00000000-0000-0000-0000-000000000000" // Placeholder - will use github.com/google/uuid in actual implementation
}
