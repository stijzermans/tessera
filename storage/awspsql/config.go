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
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Config holds configuration for the S3 + PostgreSQL multi-tenant Tessera backend.
//
// A single instance of this configuration may be shared across many tenants; each
// Storage created from it is bound to a specific TenantID.
type Config struct {
	// TenantID identifies the tenant this Storage instance serves. Required.
	//
	// All S3 object keys are prefixed with "tenants/<TenantID>/" and all PostgreSQL
	// rows are scoped to this tenant via tenant_id columns and Row Level Security.
	TenantID string

	// SDKConfig is an optional AWS config used when configuring the S3 client.
	// If nil, config.LoadDefaultConfig() is used.
	SDKConfig *aws.Config
	// S3Options is an optional function used to configure the S3 client (useful
	// when targeting non-AWS S3-compatible services such as MinIO).
	S3Options func(*s3.Options)
	// Bucket is the name of the S3 bucket holding tile and bundle objects.
	Bucket string
	// BucketPrefix is an optional prefix prepended to every key (before the
	// per-tenant prefix), useful when sharing a bucket across deployments.
	BucketPrefix string

	// PGConnStr is the libpq-style PostgreSQL connection string.
	PGConnStr string
	// MaxOpenConns caps the size of the pgx connection pool. Zero means default.
	// To tune idle-connection lifetime, set pool_max_conn_idle_time in PGConnStr;
	// pgxpool has no upper-bound-on-idle equivalent of database/sql's MaxIdleConns.
	MaxOpenConns int

	// HTTPClient is used for non-S3 HTTP requests. If nil, http.DefaultClient is used.
	HTTPClient *http.Client
}
