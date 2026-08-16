// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"errors"
	"net/url"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/runtime/netguard"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

var (
	ErrMissingTraceURL     = errors.New("runtime tracing: missing trace URL")
	ErrMissingServiceName  = errors.New("runtime tracing: missing service name")
	ErrUnsupportedTraceURL = errors.New("runtime tracing: unsupported trace URL scheme")
	ErrInsecureTraceURL    = errors.New("runtime tracing: http trace URL requires localhost, loopback, or https")
)

// NewProvider initializes an OTLP/HTTP trace provider.
func NewProvider(ctx context.Context, svcName string, traceURL url.URL, instanceID string, fraction float64) (*trace.TracerProvider, error) {
	if traceURL == (url.URL{}) {
		return nil, ErrMissingTraceURL
	}
	if svcName == "" {
		return nil, ErrMissingServiceName
	}

	var client otlptrace.Client
	switch traceURL.Scheme {
	case "http":
		if !netguard.InsecureHTTPAllowed(traceURL) {
			return nil, ErrInsecureTraceURL
		}
		client = otlptracehttp.NewClient(
			otlptracehttp.WithEndpoint(traceURL.Host),
			otlptracehttp.WithURLPath(traceURL.Path),
			otlptracehttp.WithInsecure(),
		)
	case "https":
		client = otlptracehttp.NewClient(
			otlptracehttp.WithEndpoint(traceURL.Host),
			otlptracehttp.WithURLPath(traceURL.Path),
		)
	default:
		return nil, ErrUnsupportedTraceURL
	}

	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, err
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String(svcName),
		attribute.String("host.id", instanceID),
	}
	hostAttrs, err := resource.New(ctx, resource.WithHost(), resource.WithOSDescription(), resource.WithContainer())
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, hostAttrs.Attributes()...)

	provider := trace.NewTracerProvider(
		trace.WithSampler(trace.TraceIDRatioBased(fraction)),
		trace.WithBatcher(exporter),
		trace.WithResource(resource.NewWithAttributes(semconv.SchemaURL, attrs...)),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return provider, nil
}
