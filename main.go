package main

import (
	"context"
	"crypto/tls"
	"flag"
	"maps"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog/v2"
)

var (
	insecureListenAddress string
	upstream              string
	metadataUpstream      string
	tlsSkipVerify         bool
	bearerFile            string
	forceGet              bool
)

func parseFlag() {
	flag.StringVar(&insecureListenAddress, "insecure-listen-address", "127.0.0.1:9099", "The address which proxy listens on")
	flag.StringVar(&upstream, "upstream", "http://127.0.0.1:9090", "The upstream thanos URL")
	flag.StringVar(&metadataUpstream, "metadata-upstream", "http://127.0.0.1:9090", "The upstream metadata API provider URL")
	flag.BoolVar(&tlsSkipVerify, "tlsSkipVerify", false, "Skip TLS Verification")
	flag.StringVar(&bearerFile, "bearer-file", "", "File containing bearer token for API requests")
	flag.BoolVar(&forceGet, "force-get", false, "Force api.Client to use GET by rejecting POST requests")
	flag.Parse()
}

var metricMetadata map[string][]v1.Metadata
var mutex = &sync.RWMutex{}
var metadataRequestTimeout = 5 * time.Second
var metadataPollInterval = 1 * time.Minute
var metadataErrorRetryInterval = 1 * time.Minute

func main() {
	parseFlag()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// DefaultRoundTripper is used if no RoundTripper is set in Config.
	var roundTripper http.RoundTripper = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: tlsSkipVerify,
		},
	}
	// Create a new client.
	c, err := api.NewClient(api.Config{
		Address:      upstream,
		RoundTripper: roundTripper,
	})
	if err != nil {
		klog.Fatalf("error creating API client:", err)
	}

	// Create a new client for metadata.
	metadataC, err := api.NewClient(api.Config{
		Address:      metadataUpstream,
		RoundTripper: roundTripper,
	})
	if err != nil {
		klog.Fatalf("error creating API metadata client:", err)
	}

	// Collect client options
	options := []clientOption{}
	if bearerFile != "" {
		fullPath, err := filepath.Abs(bearerFile)
		if err != nil {
			klog.Fatalf("error locating bearer file:", err)
		}
		dirName, fileName := filepath.Split(fullPath)
		bearer, err := readBearerToken(os.DirFS(dirName), fileName)
		if err != nil {
			klog.Fatalf("error reading bearer file:", err)
		}
		options = append(options, withToken(bearer))
	}
	if forceGet {
		klog.Infof("Forcing api,Client to use GET requests")
		options = append(options, withGet)
	}
	if c, err = newClient(c, options...); err != nil {
		klog.Fatalf("error building custom API client:", err)
	}
	apiClient := v1.NewAPI(c)

	if metadataC, err = newClient(metadataC, options...); err != nil {
		klog.Fatalf("error building custom metadata API client:", err)
	}
	apiMetadataClient := v1.NewAPI(metadataC)

	go func() {
		var err error
		tick := time.NewTicker(1 * time.Nanosecond)
		defer tick.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}

			klog.Infof("refreshing metric metadata")
			mutex.Lock()
			metadataCtx, metadataCancel := context.WithTimeout(ctx, metadataRequestTimeout)
			metricMetadata, err = apiMetadataClient.Metadata(metadataCtx, "", "")
			mutex.Unlock()
			if err != nil {
				klog.Errorf("error refreshing metric metadata: %s", err.Error())
				tick.Reset(metadataErrorRetryInterval)
			} else {
				tick.Reset(metadataPollInterval)
			}
			metadataCancel()
		}
	}()

	// server mux
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/federate", func(w http.ResponseWriter, r *http.Request) {
		federate(ctx, w, r, apiClient)
	})

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	startServer(insecureListenAddress, mux, cancel)
}

func federate(ctx context.Context, w http.ResponseWriter, r *http.Request, apiClient v1.API) {
	params := r.URL.Query()
	matchQueries := params["match[]"]

	// negotiate content type, this will inform the encoder how to format the output
	contentType := expfmt.NegotiateIncludingOpenMetrics(r.Header)

	nctx, ncancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer ncancel()
	if params.Del("match[]"); len(params) > 0 {
		nctx = addValues(nctx, params)
	}
	for _, matchQuery := range matchQueries {
		start := time.Now()
		// Ignoring warnings for now.
		val, _, err := apiClient.Query(nctx, matchQuery, start)
		responseTime := time.Since(start).Seconds()

		if err != nil {
			klog.Errorf("query failed: %s", err.Error())
			scrapeDurations.With(prometheus.Labels{
				"match_query": matchQuery,
				"status_code": "500",
			}).Observe(responseTime)
			w.WriteHeader(http.StatusInternalServerError)
			ncancel()
			return
		}
		if val.Type() != model.ValVector {
			klog.Errorf("query result is not a vector: %v", val.Type())
			scrapeDurations.With(prometheus.Labels{
				"match_query": matchQuery,
				"status_code": "502",
			}).Observe(responseTime)
			// TODO: should we continue to the next query?
			w.WriteHeader(http.StatusInternalServerError)
			ncancel()
			return
		}
		scrapeDurations.With(prometheus.Labels{
			"match_query": matchQuery,
			"status_code": "200",
		}).Observe(responseTime)

		w.Header().Set("Content-Type", string(contentType))
		printVector(w, contentType, val)
	}
}

// this is an alternative implementation of the original code. In order to be as compliant as possible with
// prometheus endpoint content negotiation, we need to transform model.Value into io_prometheus_client.MetricFamily
// to be able to reuse the expfmt package.
//
// This requires a bunch of manual work since there is nothing in the SDK that supports this path, and is subject
// to be broken if the SDK changes.
//
// In order to be able to create a MetricFamily we rely on Prometheus Metadata API. Thanos Queriers do not support
// this API, so the upstream needs to be the Prometheus server. That kind of compromises the whole point of this module.
//
// The metadata is refreshed asynchronously on a predefined interval not to put that on the critical path
func printVector(w http.ResponseWriter, contentType expfmt.Format, v model.Value) {
	vec := v.(model.Vector)
	encoder := expfmt.NewEncoder(w, contentType)

	// clone to prevent locking the metadata for the entire duration of the encoding
	mutex.RLock()
	mMetadata := maps.Clone(metricMetadata)
	mutex.RUnlock()

	histogramSeen := make(map[model.Fingerprint]*io_prometheus_client.Metric)

	metricFamilies := make(map[string]*io_prometheus_client.MetricFamily)
	for _, sample := range vec {
		// value.Metric brings the metric name as a label, so we allocate one less so it does not end up as a label in the metric family
		labelPairs := make([]*io_prometheus_client.LabelPair, 0, len(sample.Metric)-1) // we dont add metric name as label
		var metricName string
		for labelName, labelValue := range sample.Metric {
			ln := string(labelName)
			lv := string(labelValue)
			if ln == model.MetricNameLabel {
				metricName = lv
				continue
			}
			// will be added as a label by the encoder
			if ln == model.BucketLabel {
				continue
			}
			labelPairs = append(labelPairs, &io_prometheus_client.LabelPair{
				Name:  &ln,
				Value: &lv,
			})
		}

		strippedMetricName := metricName
		isHistogramSum := strings.HasSuffix(metricName, "_sum")
		isHistogramCount := strings.HasSuffix(metricName, "_count")
		isTotal := strings.HasSuffix(metricName, "_total")
		isHistogram := strings.HasSuffix(metricName, "_bucket") || isHistogramSum || isHistogramCount
		if isHistogram || isTotal {
			strippedMetricName = metricName[:strings.LastIndex(metricName, "_")]
		}

		mms, ok := mMetadata[strippedMetricName]
		if !ok {
			// some metrics are registered with the suffixes (e.g. gauges with _count), so we need to try the original name
			mms, ok = mMetadata[metricName]
			if !ok {
				// either metadata refresh will eventually fix this or there is something else going on
				klog.Warningf("metadata not found for metric %s, metric metadata will be stubbed out and type set to unknown", metricName)
			}
		}

		if len(mms) > 1 {
			// FIXME how to deal with this?
			klog.Warningf("metric %s has multiple metadata entries, using the first one", metricName)
		}

		// counters suffix has a special treatment. We only strip the suffix to query the metadata API
		if isTotal {
			strippedMetricName = metricName
		}

		// recover on unknown metrics by stubbing it out and setting to unknown type
		var mm v1.Metadata
		if len(mms) == 0 {
			mm = v1.Metadata{
				Type: v1.MetricTypeUnknown,
				Help: "no help found",
				Unit: "no unit found",
			}
		} else {
			mm = mms[0]
		}

		mf, ok := metricFamilies[strippedMetricName]
		if !ok {
			var mType io_prometheus_client.MetricType
			switch mm.Type {
			case v1.MetricTypeCounter:
				mType = io_prometheus_client.MetricType_COUNTER
			case v1.MetricTypeGauge:
				mType = io_prometheus_client.MetricType_GAUGE
			case v1.MetricTypeHistogram:
				mType = io_prometheus_client.MetricType_HISTOGRAM
			case v1.MetricTypeSummary:
				mType = io_prometheus_client.MetricType_SUMMARY
			case v1.MetricTypeUnknown:
				mType = io_prometheus_client.MetricType_UNTYPED
			default:
				klog.Warningf("unknown metric type %s for metric %s, dropping metric", mm.Type, metricName)
			}

			mf = &io_prometheus_client.MetricFamily{
				Name: &strippedMetricName,
				Help: &mm.Help,
				Type: &mType,
				Unit: &mm.Unit,
			}

			mf.Metric = make([]*io_prometheus_client.Metric, 0)
			metricFamilies[strippedMetricName] = mf
		}

		// we use the fingerprints to cluster the various buckets for the same combination of labels for the same metric
		// into the same io_prometheus_client.Metric. Then that metric will have multiple Buckets that come out
		// of "le"
		// get metric fingerprint, ignore "le" and "__name__" label on histograms to get a canonical fingerprint
		clonedMetric := sample.Metric.Clone()
		delete(clonedMetric, model.BucketLabel)
		// we need to strip the metric name suffixes so we can cluster _bucket, _total and _sum metrics of a histogram
		// otherwise the label fingerprint wouldn't match
		clonedMetric[model.MetricNameLabel] = model.LabelValue(strippedMetricName)
		fingerprint := clonedMetric.Fingerprint()

		switch mm.Type {
		case v1.MetricTypeCounter:
			metric := &io_prometheus_client.Metric{
				Label:       labelPairs,
				TimestampMs: proto.Int64(sample.Timestamp.UnixNano() / 1000),
				Counter: &io_prometheus_client.Counter{
					Value: proto.Float64(float64(sample.Value)),
				},
			}

			mf.Metric = append(mf.Metric, metric)
		case v1.MetricTypeGauge:
			metric := &io_prometheus_client.Metric{
				Label:       labelPairs,
				TimestampMs: proto.Int64(sample.Timestamp.UnixNano() / 1000),
				Gauge: &io_prometheus_client.Gauge{
					Value: proto.Float64(float64(sample.Value)),
				},
			}

			mf.Metric = append(mf.Metric, metric)
		case v1.MetricTypeHistogram:
			var metric *io_prometheus_client.Metric
			_, metricAlreadySeen := histogramSeen[fingerprint]
			if metricAlreadySeen {
				metric = histogramSeen[fingerprint]
			} else {
				metric = &io_prometheus_client.Metric{
					Label:       labelPairs,
					TimestampMs: proto.Int64(sample.Timestamp.UnixNano() / 1000),
				}
				histogramSeen[fingerprint] = metric
			}

			if metric.Histogram == nil {
				metric.Histogram = &io_prometheus_client.Histogram{}
			}

			if isHistogramCount {
				metric.Histogram.SampleCount = proto.Uint64(uint64(sample.Value))
			} else if isHistogramSum {
				metric.Histogram.SampleSum = proto.Float64(float64(sample.Value))
			} else {
				lessOrEqual := sample.Metric[model.BucketLabel]
				upperFloat, err := strconv.ParseFloat(string(lessOrEqual), 64)
				if err != nil {
					klog.Warningf("error parsing bucket upper bound %s on histogram %s, dropping bucket", lessOrEqual, metricName)
					continue
				}

				b := &io_prometheus_client.Bucket{
					UpperBound:      proto.Float64(upperFloat),
					CumulativeCount: proto.Uint64(uint64(sample.Value)),
				}
				metric.Histogram.Bucket = append(metric.Histogram.Bucket, b)
			}

			if !metricAlreadySeen {
				mf.Metric = append(mf.Metric, metric)
			}
		case v1.MetricTypeSummary:
			// FIXME how to deal with this?
			klog.Warningf("unsupported summary type on metric %s, dropping metric", metricName)
			continue
		case v1.MetricTypeUnknown:
			metric := &io_prometheus_client.Metric{
				Label:       labelPairs,
				TimestampMs: proto.Int64(sample.Timestamp.UnixNano() / 1000),
				Untyped: &io_prometheus_client.Untyped{
					Value: proto.Float64(float64(sample.Value)),
				},
			}

			mf.Metric = append(mf.Metric, metric)
		default:
			klog.Warningf("unknown metric type %s on %s, dropping metric", mm.Type, metricName)
			continue
		}
	}

	// spec indicates order by metric family is optional. SpiceDB already does, and makes it easier for humans
	orderedKeys := make([]string, 0, len(metricFamilies))
	for k := range metricFamilies {
		orderedKeys = append(orderedKeys, k)
	}
	sort.Strings(orderedKeys)

	// buckets MUST be sorted by upper bound, as required by the spec
	// See https://github.com/prometheus/OpenMetrics/blob/main/specification/OpenMetrics.md#histogram-1
	for _, family := range metricFamilies {
		if *family.Type.Enum() == io_prometheus_client.MetricType_HISTOGRAM {
			for _, metric := range family.Metric {
				sort.Slice(metric.Histogram.Bucket, func(i, j int) bool {
					return *metric.Histogram.Bucket[i].UpperBound < *metric.Histogram.Bucket[j].UpperBound
				})
			}
		}
	}

	for _, key := range orderedKeys {
		if err := encoder.Encode(metricFamilies[key]); err != nil {
			klog.Errorf("error encoding metric family: %s", err.Error())
		}
	}

	// Needed so the OpenMetrics encoder adds #EOF
	if closer, ok := encoder.(expfmt.Closer); ok {
		if err := closer.Close(); err != nil {
			klog.Errorf("error closing encoder: %s", err.Error())
		}
	}

}
