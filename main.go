package main

import (
	"context"
	"crypto/tls"
	"flag"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			klog.Infof("refreshing metric metadata")
			mutex.Lock()
			metadataCtx, metadataCancel := context.WithTimeout(ctx, 5*time.Second)
			metricMetadata, err = apiMetadataClient.Metadata(metadataCtx, "", "")
			mutex.Unlock()
			if err != nil {
				klog.Errorf("error refreshing metric metadata: %s", err.Error())
				time.Sleep(250 * time.Millisecond)
			} else {
				time.Sleep(1 * time.Minute)
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
			labelPairs = append(labelPairs, &io_prometheus_client.LabelPair{
				Name:  &ln,
				Value: &lv,
			})
		}

		strippedMetricName := metricName
		if strings.HasSuffix(metricName, "_bucket") || strings.HasSuffix(metricName, "_sum") ||
			strings.HasSuffix(metricName, "_count") || strings.HasSuffix(metricName, "_total") {
			strippedMetricName = metricName[:strings.LastIndex(metricName, "_")]
		}
		mms, ok := mMetadata[strippedMetricName]
		if !ok {
			// either metadata refresh will eventually fix this or there is something else going on
			klog.Warningf("metadata not found for metric %s, metric metadata will be stubbed out and type set to unknown", metricName)
		}

		if len(mms) > 1 {
			// FIXME how to deal with this?
			klog.Warningf("metric %s has multiple metadata entries, using the first one", metricName)
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

		mf, ok := metricFamilies[metricName]
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
				klog.Warningf("unknown metric type %s for metric %s, dropping metric", mm.Type, strippedMetricName)
			}

			mf = &io_prometheus_client.MetricFamily{
				Name: &metricName,
				Help: &mm.Help,
				Type: &mType,
				Unit: &mm.Unit,
			}

			mf.Metric = make([]*io_prometheus_client.Metric, 0)
			metricFamilies[metricName] = mf
		}

		metric := &io_prometheus_client.Metric{
			Label:       labelPairs,
			TimestampMs: proto.Int64(sample.Timestamp.UnixNano() / 1000),
		}
		switch mm.Type {
		case v1.MetricTypeCounter:
			metric.Counter = &io_prometheus_client.Counter{
				Value: proto.Float64(float64(sample.Value)),
			}
		case v1.MetricTypeGauge:
			metric.Gauge = &io_prometheus_client.Gauge{
				Value: proto.Float64(float64(sample.Value)),
			}
		case v1.MetricTypeHistogram:
			metric.Histogram = &io_prometheus_client.Histogram{
				SampleCount: proto.Uint64(0),
				SampleSum:   proto.Float64(0),
			}
			hist := sample.Histogram
			if hist != nil {
				metric.Histogram = &io_prometheus_client.Histogram{
					SampleCount: proto.Uint64(uint64(hist.Count)),
					SampleSum:   proto.Float64(float64(hist.Sum)),
					Bucket:      make([]*io_prometheus_client.Bucket, 0, len(hist.Buckets)),
				}
				for _, bucket := range sample.Histogram.Buckets {
					upperFloat, err := strconv.ParseFloat(bucket.Upper.String(), 64)
					if err != nil {
						klog.Warningf("error parsing bucket upper bound %s on histogram %s, dropping bucket", bucket.Upper, strippedMetricName)
						continue
					}
					b := &io_prometheus_client.Bucket{
						UpperBound:      proto.Float64(upperFloat),
						CumulativeCount: proto.Uint64(uint64(bucket.Count)),
					}
					metric.Histogram.Bucket = append(metric.Histogram.Bucket, b)
				}
			}
		case v1.MetricTypeSummary:
			// FIXME how to deal with this?
			klog.Warningf("unsupported summary type on metric %s, dropping metric", strippedMetricName)
			continue
		case v1.MetricTypeUnknown:
			metric.Untyped = &io_prometheus_client.Untyped{
				Value: proto.Float64(float64(sample.Value)),
			}
		default:
			klog.Warningf("unknown metric type %s on %s, dropping metric", mm.Type, strippedMetricName)
			continue
		}
		mf.Metric = append(mf.Metric, metric)
	}

	for _, fm := range metricFamilies {
		if err := encoder.Encode(fm); err != nil {
			klog.Errorf("error encoding metric family: %s", err.Error())
		}
	}
}
