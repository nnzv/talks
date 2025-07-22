#### 0. Table of Contents

* [1. Start Minikube](#1-start-minikube)
* [2. Install Tetragon](#2-install-tetragon)
* [3. (Optional) Handy alias](#3-optional-handy-alias)
* [4. Apply the lab manifest](#4-apply-the-lab-manifest)
* [5. Demo commands](#5-demo-commands)
* [6. Watch events](#6-watch-events)
* [7. NOTE about `Override`](#7-note-about-override)

#### 1. Start Minikube

```bash
minikube start --nodes=1 --memory=8192 --cpus=4 --kubernetes-version=v1.32.0
```

#### 2. Install Tetragon

```bash
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system --version 1.4.1
```

#### 3. (Optional) Handy alias

```bash
alias tetra="kubectl exec -i -n kube-system ds/tetragon -c tetragon -- tetra"
```

#### 4. Apply the lab manifest

```bash
kubectl apply -f lab.yml
```

#### 5. Demo commands

```bash
# create the file
kubectl exec -it sleep-infinity -- touch /secret-file

# allowed (should succeed)
kubectl exec -it sleep-infinity -- /bin/cat /secret-file

# blocked (should be killed)
kubectl exec -it sleep-infinity -- /usr/bin/head -c1 /secret-file
```

#### 6. Watch events

```bash
tetra getevents -o compact --event-type process_kprobe
```

#### 7. NOTE about `Override`

`action: Override` is commented out in `lab.yml` because many Minikube kernels (e.g., default kvm2 ISO 5.10.x) do **not** support the `bpf_override_return` helper or BPF-LSM. If enabled without support, the policy fails to load.

Check support:

```bash
kubectl logs -n kube-system ds/tetragon -c tetragon | grep "BPF detected features"
```

You need `override_return: true` **and** `lsm: true`. If both are true, you may uncomment:

```yaml
- action: Override
  argError: -13   # EACCES
```

Use with care; a bad override can block critical processes.
