package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	notificationv1 "buf.build/gen/go/go-tangra/notification/protocolbuffers/go/notification/service/v1"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"
)

// Notification template + channel names registered in notification-service.
const (
	templateNameUserActivation = "portal-user-activation-template"
	notifChannelName           = "Default SMTP"
)

var userActivationSubject = `Activate your {{.ProductName}} account`

var userActivationBody = `<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <h2>Welcome, {{.FullName}}</h2>
  <p>Your account on <strong>{{.ProductName}}</strong> has been activated by an administrator.</p>
  <p>Use the one-time link below to set your password and sign in. The link expires on <strong>{{.ExpiresAt}}</strong>.</p>
  <p style="margin: 24px 0;">
    <a href="{{.ActivateURL}}"
       style="background: #1677FF; color: #fff; padding: 12px 18px; border-radius: 4px; text-decoration: none;">
      Set my password
    </a>
  </p>
  <p>If the button does not work, copy and paste this URL into your browser:</p>
  <p style="word-break: break-all;"><a href="{{.ActivateURL}}">{{.ActivateURL}}</a></p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
  <p style="color: #999; font-size: 11px;">
    Your password must be at least 12 characters long and include uppercase, lowercase, a digit and a symbol.
    If you did not expect this message you can safely ignore it — the link will expire automatically.
  </p>
</body>
</html>`

// NotificationHelper lazily registers and sends portal notification templates.
type NotificationHelper struct {
	log    *log.Helper
	client *data.NotificationClient

	mu          sync.Mutex
	templateIDs map[string]string
}

// NewNotificationHelper always returns a non-nil helper so Wire is happy even
// when the client couldn't dial notification-service; every exported method
// becomes a no-op in that case because NotificationClient.SendNotification
// handles a nil receiver.
func NewNotificationHelper(ctx *bootstrap.Context, client *data.NotificationClient) *NotificationHelper {
	return &NotificationHelper{
		log:         ctx.NewLoggerHelper("admin/notification-helper"),
		client:      client,
		templateIDs: make(map[string]string),
	}
}

func (h *NotificationHelper) ensureUserActivationTemplate(ctx context.Context) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if id, ok := h.templateIDs[templateNameUserActivation]; ok {
		return id, nil
	}

	tmpl, err := h.client.FindTemplateByName(ctx, templateNameUserActivation)
	if err != nil {
		return "", fmt.Errorf("search template: %w", err)
	}
	if tmpl != nil {
		h.templateIDs[templateNameUserActivation] = tmpl.GetId()
		return tmpl.GetId(), nil
	}

	channelID, err := h.client.FindChannelByName(ctx, notifChannelName)
	if err != nil {
		return "", fmt.Errorf("find channel %q: %w", notifChannelName, err)
	}

	created, err := h.client.CreateTemplate(ctx, &notificationv1.CreateTemplateRequest{
		Name:      templateNameUserActivation,
		ChannelId: channelID,
		Subject:   userActivationSubject,
		Body:      userActivationBody,
		Variables: "ProductName,FullName,ActivateURL,ExpiresAt",
		IsDefault: false,
	})
	if err != nil {
		return "", fmt.Errorf("create template: %w", err)
	}

	h.templateIDs[templateNameUserActivation] = created.GetId()
	h.log.Infof("Registered notification template %q: %s", templateNameUserActivation, created.GetId())
	return created.GetId(), nil
}

// SendUserActivation sends the activation email. It is a no-op if the helper
// is nil, the recipient is empty, or delivery fails — callers treat it as
// best-effort and rely on logs for diagnostics.
func (h *NotificationHelper) SendUserActivation(ctx context.Context, recipient string, vars map[string]string) error {
	if h == nil || recipient == "" {
		return nil
	}
	templateID, err := h.ensureUserActivationTemplate(ctx)
	if err != nil {
		h.log.Warnf("Failed to ensure user-activation template: %v", err)
		return err
	}
	if _, err := h.client.SendNotification(ctx, templateID, recipient, vars); err != nil {
		h.log.Warnf("Failed to send user-activation email to %s: %v", recipient, err)
		return err
	}
	return nil
}
