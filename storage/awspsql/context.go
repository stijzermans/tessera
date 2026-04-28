// Copyright 2026 The Tessera authors. All Rights Reserved.
// Modifications Copyright 2026 TrustEngine. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package awspsql

import (
	"context"

	"go.uber.org/zap"
)

// TenantContextKey is the context key for tenant ID.
const TenantContextKey = "tenantID"

// WithTenantID returns a new context with the tenant ID set.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantContextKey, tenantID)
}

// TenantIDFromContext extracts the tenant ID from context.
func TenantIDFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(TenantContextKey)
	id, ok := v.(string)
	return id, ok
}

// WithTenantLogger returns a new context with a per-tenant logger.
func WithTenantLogger(ctx context.Context, logger *zap.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

type loggerKey struct{}

// LoggerFromContext extracts the logger from context.
func LoggerFromContext(ctx context.Context) *zap.Logger {
	l, _ := ctx.Value(loggerKey{}).(*zap.Logger)
	return l
}
