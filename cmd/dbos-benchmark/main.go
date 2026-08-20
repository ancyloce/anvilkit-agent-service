// Command dbos-benchmark is the reproducible DBOS load probe.
// It is evidence tooling, not the Agent Service runtime.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	"github.com/jackc/pgx/v5/pgxpool"
)

type result struct {
	LoadModel             string  `json:"loadModel"`
	SDK                   string  `json:"sdk"`
	Postgres              string  `json:"postgres"`
	Concurrency           int     `json:"concurrency"`
	ArrivalRatePerSecond  int     `json:"arrivalRatePerSecond"`
	Successes             int64   `json:"successes"`
	Failures              int64   `json:"failures"`
	CreateP50Millis       float64 `json:"createP50Millis"`
	CreateP95Millis       float64 `json:"createP95Millis"`
	CompletionP50Millis   float64 `json:"completionP50Millis"`
	CompletionP95Millis   float64 `json:"completionP95Millis"`
	AcknowledgedP50Millis float64 `json:"acknowledgedP50Millis"`
	AcknowledgedP95Millis float64 `json:"acknowledgedP95Millis"`
	ThroughputPerSecond   float64 `json:"throughputPerSecond"`
	ElapsedMillis         float64 `json:"elapsedMillis"`
	HeapAllocBytesBefore  uint64  `json:"heapAllocBytesBefore"`
	HeapAllocBytesAfter   uint64  `json:"heapAllocBytesAfter"`
	TotalAllocBytesDelta  uint64  `json:"totalAllocBytesDelta"`
	ProcessGoroutinesPeak int     `json:"processGoroutinesPeak"`
}

func percentile(values []time.Duration, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	index := int(float64(len(values)-1) * p)
	return float64(values[index]) / float64(time.Millisecond)
}

func main() {
	concurrency := flag.Int("concurrency", 500, "simultaneous durable creates")
	postgresVersion := flag.String("postgres-version", "17", "tested Postgres major")
	journalURL := flag.String("journal-url", "", "independent receipt/decision journal URL")
	arrivalRate := flag.Int("rate", 20, "durable-create arrivals per second")
	flag.Parse()

	databaseURL := os.Getenv("DBOS_SYSTEM_DATABASE_URL")
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "DBOS_SYSTEM_DATABASE_URL is required")
		os.Exit(2)
	}
	if *concurrency < 1 || *concurrency > 5000 {
		fmt.Fprintln(os.Stderr, "concurrency must be within the approved 1..5000 range")
		os.Exit(2)
	}
	if *arrivalRate < 1 || *arrivalRate > 200 {
		fmt.Fprintln(os.Stderr, "rate must be within the approved 1..200 creates/second range")
		os.Exit(2)
	}
	var err error
	var journal *pgxpool.Pool
	if *journalURL != "" {
		journal, err = pgxpool.New(context.Background(), *journalURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create journal pool: %v\n", err)
			os.Exit(1)
		}
		defer journal.Close()
		if _, err = journal.Exec(context.Background(), `CREATE TABLE IF NOT EXISTS benchmark_receipts (
			fact_id text PRIMARY KEY, state text NOT NULL, recorded_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
			fmt.Fprintf(os.Stderr, "create journal schema: %v\n", err)
			os.Exit(1)
		}
	}

	ctx, err := dbos.NewContext(context.Background(), dbos.Config{
		AppName:            "anvilkit-agent-dbos-benchmark",
		ApplicationVersion: "dbos-benchmark",
		DatabaseURL:        databaseURL,
		DatabaseSchema:     "dbos_benchmark",
		ExecutorID:         "dbos-benchmark",
		Logger:             slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create DBOS context: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if shutdownErr := dbos.Shutdown(ctx, 30*time.Second); shutdownErr != nil {
			fmt.Fprintf(os.Stderr, "shutdown DBOS context: %v\n", shutdownErr)
		}
	}()

	workflow := func(workflowContext dbos.Context, input int) (int, error) {
		return dbos.RunAsStep(workflowContext, func(context.Context) (int, error) {
			return input * 2, nil
		}, dbos.WithStepName("durable-create-proof"))
	}
	dbos.RegisterWorkflow(ctx, workflow, dbos.WithWorkflowName("DurableCreateBenchmark"))
	if err := dbos.Launch(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "launch DBOS: %v\n", err)
		os.Exit(1)
	}

	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	creates := make([]time.Duration, *concurrency)
	completions := make([]time.Duration, *concurrency)
	acknowledged := make([]time.Duration, *concurrency)
	start := time.Now()
	var successes atomic.Int64
	var failures atomic.Int64
	var peak atomic.Int64
	var wait sync.WaitGroup
	wait.Add(*concurrency)
	for index := range *concurrency {
		go func() {
			defer wait.Done()
			delay := time.Duration(index) * time.Second / time.Duration(*arrivalRate)
			timer := time.NewTimer(delay)
			defer timer.Stop()
			<-timer.C
			started := time.Now()
			factID := fmt.Sprintf("benchmark-%d-%d", start.UnixNano(), index)
			handle, runErr := dbos.RunWorkflow(ctx, workflow, index,
				dbos.WithWorkflowID(factID))
			creates[index] = time.Since(started)
			if runErr != nil {
				failures.Add(1)
				return
			}
			if journal != nil {
				if _, journalErr := journal.Exec(ctx, `INSERT INTO benchmark_receipts(fact_id, state) VALUES ($1, 'outcome')`, factID); journalErr != nil {
					failures.Add(1)
					return
				}
			}
			acknowledged[index] = time.Since(started)
			value, resultErr := handle.GetResult()
			completions[index] = time.Since(started)
			if resultErr != nil || value != index*2 {
				failures.Add(1)
				return
			}
			successes.Add(1)
		}()
	}
	done := make(chan struct{})
	go func() { wait.Wait(); close(done) }()
	for {
		select {
		case <-done:
			goto finished
		case <-time.After(10 * time.Millisecond):
			current := int64(runtime.NumGoroutine())
			for current > peak.Load() && !peak.CompareAndSwap(peak.Load(), current) {
			}
		}
	}

finished:
	elapsed := time.Since(start)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	report := result{
		LoadModel:             "agent-service-load-model",
		SDK:                   "github.com/dbos-inc/dbos-transact-golang@v1.1.0",
		Postgres:              *postgresVersion,
		Concurrency:           *concurrency,
		ArrivalRatePerSecond:  *arrivalRate,
		Successes:             successes.Load(),
		Failures:              failures.Load(),
		CreateP50Millis:       percentile(creates, 0.50),
		CreateP95Millis:       percentile(creates, 0.95),
		CompletionP50Millis:   percentile(completions, 0.50),
		CompletionP95Millis:   percentile(completions, 0.95),
		AcknowledgedP50Millis: percentile(acknowledged, 0.50),
		AcknowledgedP95Millis: percentile(acknowledged, 0.95),
		ThroughputPerSecond:   float64(successes.Load()) / elapsed.Seconds(),
		ElapsedMillis:         float64(elapsed) / float64(time.Millisecond),
		HeapAllocBytesBefore:  before.HeapAlloc,
		HeapAllocBytesAfter:   after.HeapAlloc,
		TotalAllocBytesDelta:  after.TotalAlloc - before.TotalAlloc,
		ProcessGoroutinesPeak: int(peak.Load()),
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "encode report: %v\n", err)
		os.Exit(1)
	}
	if failures.Load() != 0 {
		os.Exit(1)
	}
}
