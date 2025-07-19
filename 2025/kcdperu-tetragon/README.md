```
minikube start --nodes=1 --memory=8192 --cpus=4 --kubernetes-version=1.32
```

```
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system --version 1.4.1
```

<!-- ``` -->
<!-- alias tetra="kubectl exec -i -n kube-system ds/tetragon -c tetragon -- tetra" -->
<!-- ``` -->

```
kubectl create -f lab.yml
```

```
kubectl exec -it sleep-infinity -- touch /secret-file
```

```
kubectl exec -it sleep-infinity -- /bin/cat /secret-file
```

```
kubectl exec -it sleep-infinity -- /bad/cat /secret-file
```

```
kubectl exec -it sleep-infinity -- /nok/cat /secret-file
```
