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
	"log/slog"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/sigstore/rekor-tiles/v2/internal/tessera-backend/s3-psql-multitenant"

var (
	meter  = otel.Meter(meterName)
	tracer = otel.Tracer(meterName)
)

var (
	errorTypeKey  = attribute.Key("error.type")
	numEntriesKey = attribute.Key("tessera.numEntries")
	objectPathKey = attribute.Key("tessera.objectPath")
	opNameKey     = attribute.Key("op_name")
	tenantIDKey   = attribute.Key("tenant.id")

	opsHistogram metric.Int64Histogram
	publishCount metric.Int64Counter

	histogramBuckets = []float64{0, 1, 2, 5, 10, 20, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1200, 1400, 1600, 1800, 2000, 2500, 3000, 4000, 5000, 6000, 8000, 10000}
)

func init() {
	var err error

	opsHistogram, err = meter.Int64Histogram(
		"tessera.appender.ops.duration",
		metric.WithDescription("Duration of calls to storage operations"),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(histogramBuckets...))
	if err != nil {
		slog.ErrorContext(context.Background(), "Failed to create opsHistogram metric", slog.Any("error", err))
		os.Exit(1)
	}

	publishCount, err = meter.Int64Counter(
		"tessera.appender.checkpoint.publication.counter",
		metric.WithDescription("Number of checkpoint publication attempts by result"),
		metric.WithUnit("{call}"))
	if err != nil {
		slog.ErrorContext(context.Background(), "Failed to create checkpoint publication counter metric", slog.Any("error", err))
		os.Exit(1)
	}
}
