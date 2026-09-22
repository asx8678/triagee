# Kubernetes deployment (standalone)

This guide runs the whole application inside one Kubernetes cluster with no
external services: the release image from [`app/Dockerfile`](../Dockerfile),
an in-pod reverse proxy sidecar, and a PostgreSQL StatefulSet with a persistent
volume. It is the container equivalent of the systemd/Caddy topology in
[DEPLOYMENT](DEPLOYMENT.md) and preserves every boundary that document and
[LOCAL_RUNTIME](../LOCAL_RUNTIME.md) define.

```text
                     Internet
                        │ TLS (wss + https)
                 ┌──────▼──────┐
                 │   Ingress   │  real client IPs (X-Forwarded-For)
                 └──────┬──────┘
                 ┌──────▼──────┐
                 │  Service    │ :80
                 └──────┬──────┘
        ┌───────────────▼──────────────────┐
        │ Pod: triage                       │
        │  ┌────────────────────────────┐  │
        │  │ proxy sidecar (nginx):8080  │──┼── platform-facing port only
        │  └──────────┬─────────────────┘  │
        │  ┌──────────▼─────────────────┐  │
        │  │ app (beam) 127.0.0.1:4000  │  │ loopback-only listener
        │  └──────────┬─────────────────┘  │
        └─────────────┼────────────────────┘
                      │ ecto://...
              ┌───────▼────────┐   ┌─────────┐
              │ StatefulSet   │◄──│ PVC     │
              │ postgres:18   │   │ 10Gi    │
              └────────────────┘   └─────────┘
```

## Why the proxy sidecar is mandatory

`config/runtime.exs` refuses every listener bind except `127.0.0.1`/`::1` — a
deliberate trust boundary. Inside a pod that means **the app is reachable only
from its own container**: a Service or kubelet probe targeting the pod IP:4000
is refused. Exactly one local reverse proxy therefore fronts the app inside
the pod, exactly as Caddy fronts it on the VPS. Do not relax `TRIAGE_BIND`;
the proxy reproduces the documented shared-deployment topology instead.

Everything below is example YAML — adapt names, storage class, ingress class,
and domains to your cluster. The manifests are deliberately complete so the
differences from your environment are the only edits.

## 1. Build the image

```sh
docker build -f app/Dockerfile -t <registry>/triage:0.1.0 app/
docker push <registry>/triage:0.1.0
```

The build is pinned to the project's Elixir/OTP pair, runs `mix assets.setup`
so the release contains the generated stylesheet and vendor scripts, and bakes
in `PHX_SERVER=true` plus the loopback bind. No secret is baked in —
`SECRET_KEY_BASE` and `DATABASE_URL` are required at **runtime** and the
container refuses to boot without them (fail-closed, like the VPS release).

## 2. Namespace and secret

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: triage
---
apiVersion: v1
kind: Secret
metadata:
  name: triage-secrets
  namespace: triage
stringData:
  # One per environment; mix phx.gen.secret
  SECRET_KEY_BASE: "REPLACE_WITH_generated_secret"
  # URL-encode the password. The same value appears in POSTGRES_PASSWORD below.
  DATABASE_URL: "ecto://triage:REPLACE_WITH_PASSWORD@triage-postgres:5432/triage_prod"
  POSTGRES_PASSWORD: "REPLACE_WITH_PASSWORD"
  # Public hostname — drives URL generation and LiveView websocket origin checks.
  PHX_HOST: "triage.example.com"
```

Ticket-creation credentials (`ADO_ORG_URL`, `ADO_PROJECT`, `ADO_PAT`,
`ADO_WORK_ITEM_TYPE`, `ADO_AREA_PATH`) are optional and follow
[AZURE_CREDENTIALS](AZURE_CREDENTIALS.md) — least privilege, never in the
image or Git.

## 3. PostgreSQL

Either point `DATABASE_URL` at a managed instance, or run it in-cluster:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: triage-postgres
  namespace: triage
spec:
  serviceName: triage-postgres
  replicas: 1
  selector:
    matchLabels: { app: triage-postgres }
  template:
    metadata:
      labels: { app: triage-postgres }
    spec:
      containers:
        - name: postgres
          image: postgres:18
          env:
            - name: POSTGRES_USER
              value: triage
            - name: POSTGRES_DB
              value: triage_prod
            - name: POSTGRES_PASSWORD
              valueFrom: { secretKeyRef: { name: triage-secrets, key: POSTGRES_PASSWORD } }
          ports:
            - containerPort: 5432
              name: postgres
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
          readinessProbe:
            exec: { command: ["pg_isready", "-U", "triage", "-d", "triage_prod"] }
  volumeClaimTemplates:
    - metadata: { name: data }
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: standard          # your cluster's class
        resources: { requests: { storage: 10Gi } }
---
apiVersion: v1
kind: Service
metadata:
  name: triage-postgres
  namespace: triage
spec:
  clusterIP: None                        # headless: stable DNS per replica
  selector: { app: triage-postgres }
  ports:
    - port: 5432
      targetPort: postgres
```

## 4. Migrations (Job, before every rollout)

Migrations are additive and must run before the new release serves traffic
(same ordering as the VPS procedure):

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: triage-migrate
  namespace: triage
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: <registry>/triage:0.1.0
          command: ["/app/bin/triage", "eval", "Triage.Release.migrate()"]
          envFrom:
            - secretRef: { name: triage-secrets }
```

On every release: `kubectl delete job triage-migrate -n triage --ignore-not-found
&& kubectl apply -f migrate-job.yaml && kubectl wait --for=condition=complete
job/triage-migrate -n triage` before applying the new Deployment. One migrator
at a time — never run it in parallel with scaled replicas' initContainers.

## 5. The application Deployment

The proxy sidecar owns the only platform-facing port and forwards to the
app's loopback listener. Probes use `exec` + `curl` because a kubelet
`httpGet` probe connects to the pod IP, which the app refuses by design.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: triage-proxy
  namespace: triage
data:
  default.conf: |
    server {
      listen 8080;
      server_name _;

      location / {
        proxy_pass http://127.0.0.1:4000;
        proxy_http_version 1.1;

        # LiveView websocket
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Host drives URL generation and websocket origin checks
        proxy_set_header Host $host;

        # Pass the edge's headers through unchanged — do NOT append our own
        # hop (see "Client IP preservation" below).
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;

        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: triage
  namespace: triage
spec:
  replicas: 1                           # scale-out notes below
  strategy:
    type: RollingUpdate
  selector:
    matchLabels: { app: triage }
  template:
    metadata:
      labels: { app: triage }
    spec:
      terminationGracePeriodSeconds: 30   # drains open LiveView sockets
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: <registry>/triage:0.1.0
          envFrom:
            - secretRef: { name: triage-secrets }
          ports:
            - containerPort: 4000
          livenessProbe:
            exec: { command: ["curl", "-fsS", "--max-time", "5", "http://127.0.0.1:4000/health"] }
            initialDelaySeconds: 15
            periodSeconds: 30
          readinessProbe:
            exec: { command: ["curl", "-fsS", "--max-time", "5", "http://127.0.0.1:4000/health"] }
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests: { cpu: 250m, memory: 512Mi }
            limits: { cpu: "1", memory: 1Gi }
          volumeMounts:
            - name: tmp
              mountPath: /tmp
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
        - name: proxy
          # The official *unprivileged* image: runs as USER 101 with only
          # >1024 listeners, so pod-level runAsNonRoot holds for the sidecar too.
          image: nginxinc/nginx-unprivileged:1.27-alpine
          ports:
            - containerPort: 8080
              name: http
          volumeMounts:
            - name: proxy-config
              mountPath: /etc/nginx/conf.d
            - name: tmp
              mountPath: /tmp
          readinessProbe:
            httpGet: { path: /health, port: 8080 }
            initialDelaySeconds: 3
          resources:
            requests: { cpu: 50m, memory: 32Mi }
            limits: { cpu: 200m, memory: 64Mi }
      volumes:
        - name: proxy-config
          configMap: { name: triage-proxy }
        - name: tmp
          emptyDir: { medium: Memory }
```

The app container image already sets `PHX_SERVER=true`, `TRIAGE_BIND=127.0.0.1`,
`PORT=4000`, `HOME=/tmp` and `RELEASE_TMP=/tmp`, which is why the read-only
root filesystem works (the BEAM writes only to `/tmp`). The pod-level
`runAsNonRoot: true` therefore holds for both containers: the app runs as its
built-in uid 1000 and the sidecar as the unprivileged image's uid 101.

## 6. Service and Ingress

```yaml
apiVersion: v1
kind: Service
metadata:
  name: triage
  namespace: triage
spec:
  selector: { app: triage }
  ports:
    - port: 80
      targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: triage
  namespace: triage
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod   # your issuer
spec:
  ingressClassName: nginx
  tls:
    - hosts: ["triage.example.com"]
      secretName: triage-tls
  rules:
    - host: "triage.example.com"
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service: { name: triage, port: { number: 80 } }
```

The app's `force_ssl` honors `X-Forwarded-Proto` (the sidecar passes it from
the edge), so TLS termination at the ingress does not create redirect loops,
and production session cookies stay HTTPS-only. LiveView's websocket is
standard `wss` — the nginx ingress class handles the `Upgrade` handshake
natively.

### Client IP preservation (do not skip)

Login throttling keys on the **rightmost `X-Forwarded-For` entry reported by
the in-pod proxy** — the same trusted-hop rule as the VPS Caddy setup. The
sidecar therefore passes the edge's header through *unchanged* instead of
appending its own (cluster-internal) hop, and the ingress must set the real
client:

* Keep `externalTrafficPolicy: Local` on the ingress-controller's Service (or
  enable PROXY protocol end to end) so the edge sees true source IPs.
* nginx-ingress appends the real client to `X-Forwarded-For` by default — keep
  that.
* A client-spoofed prefix (`X-Forwarded-For: 1.2.3.4`) ends up *before* the
  edge-appended real address, and the app uses only the rightmost entry, so
  spoofing cannot select another victim's throttle bucket.

If the sidecar appended instead, every user would share one ingress-pod bucket
and 50 failed logins could lock out unrelated users again.

## 7. First-run account provisioning

There is no public signup. After the first successful rollout, provision the
first account with a one-off Job. Put the initial password in a dedicated
Secret (not the database password), and delete both after the account exists:

```sh
kubectl -n triage create secret generic triage-bootstrap \
  --from-literal=TRIAGE_ACCOUNT_EMAIL='admin@example.com' \
  --from-literal=TRIAGE_ACCOUNT_ROLE=admin \
  --from-literal=TRIAGE_ACCOUNT_PASSWORD='initial-password-12-bytes-min'
```

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: triage-bootstrap
  namespace: triage
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: bootstrap
          image: <registry>/triage:0.1.0
          command: ["/app/bin/triage", "eval", "Triage.Accounts.bootstrap!()"]
          envFrom:
            - secretRef: { name: triage-bootstrap }
            - secretRef: { name: triage-secrets }   # DATABASE_URL
```

```sh
kubectl -n triage delete job triage-bootstrap
kubectl -n triage delete secret triage-bootstrap   # the password never existed in the repo
```

## 8. Scaling beyond one replica

The default is one replica, which needs nothing else. To scale out:

1. Add a **headless Service** for the app (`clusterIP: None`, selector
   `app: triage`) and set `DNS_CLUSTER_QUERY=triage-headless.triage.svc.cluster.local`
   — the bundled `dns_cluster` forms the Erlang cluster so workspace
   broadcasts reach every node.
2. Every replica must share the same `SECRET_KEY_BASE` (cookie signing).
3. LiveView sockets live on one BEAM node: enable ingress session affinity
   (`nginx.ingress.kubernetes.io/affinity: "cookie"`), and leave
   `POD`-per-replica connection budgets in mind (`POOL_SIZE` defaults to 10
   database connections per replica).

## 9. Backups

`scripts/backup_db.sh` (pg_dump with explicit `PG*` environment) adapts to a
CronJob; store archives off-cluster, keep retention and restore rehearsals per
[DEPLOYMENT](DEPLOYMENT.md), and restore only into a **fresh** database name —
never adopt or overwrite a live one.

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: triage-pgdump
  namespace: triage
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: pgdump
              image: postgres:18
              command: ["sh", "-c", "pg_dump --no-password --format=custom -f /backups/triage-$(date +%Y%m%d%H%M%S).dump && find /backups -mtime +14 -delete"]
              env:
                - { name: PGHOST, value: triage-postgres }
                - { name: PGUSER, value: triage }
                - { name: PGDATABASE, value: triage_prod }
                - name: PGPASSWORD
                  valueFrom: { secretKeyRef: { name: triage-secrets, key: POSTGRES_PASSWORD } }
              volumeMounts:
                - name: backups
                  mountPath: /backups
          volumes:
            - name: backups
              persistentVolumeClaim: { claimName: triage-backups }   # create a PVC; sync it off-cluster
```

## 10. Verification checklist

```sh
kubectl -n triage logs job/triage-migrate -f          # clean exit
kubectl -n triage rollout status deploy/triage
curl -fsS https://triage.example.com/health           # {"status":"ok"} through TLS→sidecar→loopback
curl -fsSI https://triage.example.com/ | head -1      # 200 or a login redirect — never 502/503
```

Then in a browser: sign in with the provisioned account, open the workspace,
confirm the LiveView websocket connects (devtools shows a `wss://` frame to
`/live/websocket`), save a review draft, and if ticket creation is configured,
run the [AZURE_CREDENTIALS](AZURE_CREDENTIALS.md) verification probes.

## Security summary

| Boundary | How it holds in Kubernetes |
|---|---|
| Loopback-only listener | `runtime.exs` refuses other binds; only the in-pod sidecar may talk to the app; the pod's platform-facing port is the proxy, not the BEAM |
| TLS everywhere user-facing | Ingress termination; app enforces HTTPS redirect via `X-Forwarded-Proto` and secure cookies |
| Secrets | Kubernetes Secrets only; never in the image, Git, CLI arguments, or logs; boot fails closed without `SECRET_KEY_BASE`/`DATABASE_URL` |
| Login throttling per client | Rightmost-XFF rule from the edge, sidecar passes through (see §6) |
| No public signup | Bootstrap Job provisions accounts; Skip is compiled out of prod builds |
| Container hardening | Non-root uid 1000, `readOnlyRootFilesystem`, no privilege escalation, minimal runtime packages |
| Least-privilege Azure token | Optional; per [AZURE_CREDENTIALS](AZURE_CREDENTIALS.md) |

What is **not** covered here: a real cluster is an operator acceptance step.
Validate the image build, DNS/TLS, storage class, ingress websockets, a
migrate-rollback rehearsal on a representative copy, and the restore drill
before relying on this in production.
