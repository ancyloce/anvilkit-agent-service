package telemetry

import (
	"context"
	"log/slog"
	"strings"
)

type Redactor struct{ secrets []string }

func NewRedactor(values []string) *Redactor {
	secrets := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			secrets = append(secrets, value)
		}
	}
	return &Redactor{secrets: secrets}
}
func (r *Redactor) ContainsSecret(value string) bool {
	for _, secret := range r.secrets {
		if strings.Contains(value, secret) {
			return true
		}
	}
	return false
}
func (r *Redactor) String(value string) string {
	for _, secret := range r.secrets {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}

type Handler struct {
	next     slog.Handler
	redactor *Redactor
}

func NewHandler(next slog.Handler, redactor *Redactor) *Handler {
	return &Handler{next: next, redactor: redactor}
}
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}
func (h *Handler) Handle(ctx context.Context, record slog.Record) error {
	clean := slog.NewRecord(record.Time, record.Level, h.redactor.String(record.Message), record.PC)
	record.Attrs(func(item slog.Attr) bool { clean.AddAttrs(h.clean(item)); return true })
	return h.next.Handle(ctx, clean)
}
func (h *Handler) WithAttrs(attributes []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, len(attributes))
	for index, item := range attributes {
		clean[index] = h.clean(item)
	}
	return &Handler{next: h.next.WithAttrs(clean), redactor: h.redactor}
}
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{next: h.next.WithGroup(name), redactor: h.redactor}
}
func (h *Handler) clean(item slog.Attr) slog.Attr {
	if item.Value.Kind() == slog.KindString {
		item.Value = slog.StringValue(h.redactor.String(item.Value.String()))
	}
	return item
}
