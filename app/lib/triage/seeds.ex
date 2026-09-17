defmodule Triage.Seeds do
  @moduledoc """
  Demo inventory fixtures built from REAL public advisories.

  Every advisory in @fleet is a genuine CVE record: identifiers, descriptions,
  severities and fixed versions come from the NVD API
  (https://services.nvd.nist.gov/rest/json/cves/2.0) and, for the Go ecosystem
  entries, from the Go Vulnerability Database (https://vuln.go.dev) — fetched
  2026-09-16 and pinned here so the demo runs offline. Severity labels are the
  NVD CVSS v3.1 base severities at fetch time (scores noted in 
  comments). What is simulated is the LOCAL estate: which package copies our
  demo images happen to contain, who runs them, and whether the scanner still
  sees each finding. A finding row therefore reads "this image contains this
  package, which is affected by this real advisory" — never a claim that the
  real project was shipped or fixed here.

  Fleet shape (69 findings, 64 distinct advisories):

    * 30 CRITICAL advisories (containerd, Traefik, Jupyter Enterprise Gateway,
      Budibase, Flowise, Apache NiFi, n8n, Perl, PJSIP, Casdoor, froxlor,
      Chromium, Juggle, Dokku, Firefox ESR, plus Go-ecosystem Gitea, OpenChoreo
      and Semaphore UI records), including five pinned lifecycle examples —
      cleared after ten days, cleared within two days, still observed,
      scanner-suppressed, and cleared/observed-again/suppressed;
    * 20 HIGH advisories, including one advisory (CVE-2026-60002, OpenSSH)
      reported against three package occurences across two teams, a reopened
      finding (CVE-2026-57236, Nokogiri) that also demonstrates one advisory
      recorded at two severities, and Go-ecosystem records for amqp091-go and
      ffuf;
    * 5 LOW advisories, one of them scanner-suppressed (suppression is not
      mitigation evidence);
    * 3 MEDIUM-only advisories (VictoriaMetrics, grpc, Infracost — all Go
      ecosystem), one of which disappeared from a complete unfiltered
      collection: disappearance is not proof of remediation;
    * an image with unknown deployment context (namespace `(unknown)`;
    * eight demo images, including edge gateway, search service, background worker
      and media processor with curl/libcurl, Log4j Core, OpenSSL, zlib, libwebp
      and glibc examples; the additional library descriptions are concise public
      advisory summaries, with illustrative deployments;
    * demo images across prod, staging and dev environments with
      operator-declared exposure and impact evidence.

  Running `seed/1` again updates `last_seen` timestamps but never duplicates
  rows or lifecycle events, and never invents history that a real collection
  did not record.
  """

  alias Triage.Inventory
  alias Triage.Repo
  import Ecto.Query

  @appeared ~U[2026-08-01 06:00:00Z]
  @resolved ~U[2026-08-05 06:00:00Z]
  @reopened ~U[2026-08-06 06:00:00Z]
  @recent ~U[2026-09-09 06:00:00Z]

  # The demo fleet spans exactly the three delivery environments.
  @env_prod "prod"
  @env_staging "staging"
  @env_dev "dev"

  # CRITICAL lifecycle examples: appeared → cleared ("handled"),
  # appeared → cleared fast, appeared → still observed, appeared → cleared →
  # observed again → suppressed, and appeared → suppressed.
  @crit_appeared ~U[2026-08-10 06:00:00Z]
  @crit_cleared ~U[2026-08-20 06:00:00Z]
  @crit_late_appeared ~U[2026-08-24 06:00:00Z]
  @crit_late_cleared ~U[2026-08-26 06:00:00Z]
  @crit_reappeared ~U[2026-08-28 06:00:00Z]
  @crit_still_open ~U[2026-08-15 06:00:00Z]

  # Advisory fleet: {cve, package, installed version, reported fix, severity,
  # image, lifecycle role, description}. Descriptions are the vendors'/CNAs'
  # own text as published by NVD.
  @fleet [
    # Additional real library advisories. Descriptions are concise summaries of
    # https://cveawg.mitre.org/api/cve/<CVE-ID>; curl uses its vendor advisory:
    # https://curl.se/docs/CVE-2023-38545.html
    # Infrastructure placements are illustrative, not discovered deployments.
    {"CVE-2023-38545", "libcurl", "8.3.0", "8.4.0", "HIGH", :edge, "open",
     "SOCKS5 heap buffer overflow in curl and libcurl. A long hostname during a slow SOCKS5 proxy handshake can overflow a heap buffer when remote hostname resolution is requested. Affects 7.69.0 through 8.3.0; fixed in 8.4.0."},
    {"CVE-2023-38545", "curl", "8.3.0", "8.4.0", "HIGH", :x, nil,
     "curl shares the vulnerable SOCKS5 handshake implementation with libcurl. Long hostnames and a slow SOCKS5 handshake can trigger a heap buffer overflow. Fixed in 8.4.0."},
    {"CVE-2021-44228", "log4j-core", "2.14.1", "2.17.1", "CRITICAL", :search, "open",
     "Log4Shell: attacker-controlled log messages can trigger JNDI lookups and remote code execution in vulnerable Apache Log4j Core configurations. This affects log4j-core, not log4j-api alone. The demo upgrade target is 2.17.1, which also includes subsequent Log4j security fixes."},
    {"CVE-2022-0778", "libssl", "3.0.1", "3.0.2", "HIGH", :edge, "open",
     "OpenSSL certificate parsing can enter an infinite loop in BN_mod_sqrt when processing crafted elliptic-curve parameters, causing denial of service before certificate signature verification. Fixed in the 3.0 branch by 3.0.2."},
    {"CVE-2022-0778", "libcrypto", "3.0.1", "3.0.2", "HIGH", :worker, nil,
     "OpenSSL BN_mod_sqrt can loop indefinitely on attacker-controlled non-prime moduli. Applications parsing malicious certificates or elliptic-curve keys can suffer denial of service. Fixed in OpenSSL 3.0.2."},
    {"CVE-2022-37434", "zlib", "1.2.12", nil, "HIGH", :worker, "open",
     "A large gzip header extra field can trigger a heap buffer over-read or overflow in zlib inflate. Only applications calling inflateGetHeader are affected; library presence alone does not prove exploitability."},
    {"CVE-2023-4863", "libwebp", "1.3.1", "1.3.2", "HIGH", :media, "open",
     "Heap buffer overflow in libwebp decoding permits out-of-bounds memory writes when processing crafted WebP content. The vulnerable library is used by browsers and image-processing services. Fixed in libwebp 1.3.2."},
    {"CVE-2023-4911", "glibc", "2.37", nil, "HIGH", :worker, "supp",
     "Looney Tunables: a buffer overflow in the GNU C Library dynamic loader while processing GLIBC_TUNABLES can allow local privilege escalation when launching set-user-ID binaries. Distribution backports determine the appropriate fixed package version."},

    # CVE-2026-53492 — CRITICAL 9.6, published 2026-07-01
    {"CVE-2026-53492", "containerd", "2.2.4", "2.3.2", "CRITICAL", :a, nil,
     "containerd is an open-source container runtime. In Versions prior to 2.3.2, 2.2.5 and 2.1.9, the CRI implementation improperly trusts Container Device Interface (CDI) annotations found within untrusted checkpoint image metadata during container restoration. When restoring a container from a checkpoint, containerd preserves CDI-related annotations from the checkpoint archive rather than relying solely on the pod's create-time specification. This allows a user with pod creation permissions to bypass standard Kubernetes resource allocation and device plugin enforcement, injecting arbitrary CDI edits (such as device nodes and host mounts) into the restored container. Successful exploitation requires that the node has CDI enabled and contains a matching host CDI specification for the requested device; environments where CDI is disabled or lacking sensitive device specifications are not affected. This issue has been fixed in versions 2.3.2, 2.2.5 and 2.1.9."},
    # CVE-2026-50195 — CRITICAL 9.9, published 2026-07-01
    {"CVE-2026-50195", "containerd", "2.2.4", "2.2.5", "CRITICAL", :b, nil,
     "containerd is an open-source container runtime. Versions prior to 2.3.2, 2.2.5 and 2.1.9 contain a vulnerability in the CRI checkpoint import process where it fails to validate the image references specified within a checkpoint image's configuration. An attacker with permissions to create pods can use a crafted checkpoint image to force containerd to pull a malicious image and assign it an arbitrary local tag, thereby poisoning the node's local image cache. Subsequently, if other pods on the same node attempt to use the poisoned tag with an IfNotPresent (or Never) pull policy, they will unknowingly execute the attacker's malicious image instead of the legitimate one. This can lead to a compromise of the affected pods, allowing the attacker to execute arbitrary code under the victim pod's identity. This issue has been fixed in versions 2.3.2, 2.2.5 and 2.1.9."},
    # CVE-2026-48020 — CRITICAL 10, published 2026-06-23
    {"CVE-2026-48020", "traefik", "3.7.2", "3.7.3", "CRITICAL", :c, nil,
     "Traefik is an HTTP reverse proxy and load balancer. Prior to 2.11.48, 3.6.19, and 3.7.3, there is a high severity vulnerability in Traefik's StripPrefix middleware that allows an unauthenticated attacker to bypass route-level authentication and authorization. When a public router matches on a PathPrefix rule and applies the StripPrefix middleware, a request path containing .. or its percent-encoded form %2e%2e can match the public route at routing time and then, after the prefix is stripped and the path is normalized, resolve to a path served by a separate, authenticated router. As a result, an attacker can reach protected backend paths — such as admin or internal configuration endpoints — without satisfying the authentication middleware attached to the protected router. This vulnerability is fixed in 2.11.48, 3.6.19, and 3.7.3."},
    # CVE-2026-48491 — CRITICAL 10, published 2026-06-23
    {"CVE-2026-48491", "traefik", "3.7.2", "3.7.3", "CRITICAL", :c, nil,
     "Traefik is an HTTP reverse proxy and load balancer. From 3.7.0 until 3.7.3, there is a high severity vulnerability in Traefik's domain-fronting protection (SNICheck) that allows an unauthenticated client to bypass mutual TLS enforced through wildcard router TLSOptions. When a router uses a wildcard host rule such as Host(*.example.com) with stricter TLS options (for example RequireAndVerifyClientCert), SNICheck resolves the TLS options for the HTTP Host header using exact map lookups only and never applies wildcard matching. If another permissive SNI is served on the same entrypoint, an attacker can complete the TLS handshake under the permissive options and then send an HTTP Host header targeting the wildcard-protected backend, reaching it without presenting a client certificate. This affects the regular HTTPS / HTTP-2 path and does not require HTTP/3. This vulnerability is fixed in 3.7.3."},
    # CVE-2026-44181 — CRITICAL 10, published 2026-07-16
    {"CVE-2026-44181", "jupyter-enterprise-gateway", "3.2.1", "3.3.0", "CRITICAL", :a, nil,
     "Jupyter Enterprise Gateway launches remote Jupyter Notebook kernels across distributed clusters like Apache Spark, Kubernetes, and Docker Swarm. In versions 2.0.0rc2 and above, prior to 3.3.0, the environment variables (KERNEL_XXX) used during the rendering of the Kubernetes manifest are vulnerable to Server Side Template Injection (SSTI). By including Jinja2 template expressions it is possible to execution Python code and OS Commands in the Enterprise Gateway service. The code can use or steal the Kubernetes service account token, which can steal Kubernetes secrets and be used to fully compromise the Kubernetes cluster by scheduling a privileged pod or a pod with a hostPath volume mount. This issue has been fixed in version 3.3.0."},
    # CVE-2026-44182 — CRITICAL 10, published 2026-07-16
    {"CVE-2026-44182", "jupyter-enterprise-gateway", "3.2.1", "3.3.0", "CRITICAL", :c, nil,
     "Jupyter Enterprise Gateway launches remote Jupyter Notebook kernels across distributed clusters like Apache Spark, Kubernetes, and Docker Swarm. In versions prior to 3.3.0, the server interpolates untrusted environment variables (e.g., KERNEL_XXX) into Kubernetes manifests without YAML-aware escaping, enabling YAML injection attacks. Attackers can inject new fields, overwrite critical fields (e.g., duplicate securityContext keys, where the last one prevails), and inject document boundaries (--- for new documents, ... for end-of-document) to generate multiple resources, potentially creating arbitrary types, such as privileged pods. The Jinja2 template for the Kubernetes manifest contains several kernel_xxx variables, such as kernel_working_dir that are used when rendering the manifest and are all vectors for YAML injection. This issue has been fixed in version 3.3.0."},
    # CVE-2026-54350 — CRITICAL 10, published 2026-06-26
    {"CVE-2026-54350", "budibase", "3.39.0", "3.39.12", "CRITICAL", :b, nil,
     "Budibase is an open-source low-code platform. Prior to 3.39.12, an unauthenticated visitor of any published Budibase app reads every document of the backing MongoDB, CouchDB, Elasticsearch, DynamoDB-PartiQL, or REST-with-JSON-body collection and, where the builder has published a PUBLIC write query, modifies every document of that collection with one HTTP request. enrichContext at packages/server/src/sdk/workspace/queries/queries.ts:121-138 substitutes parameter values into the raw JSON body of a query, then JSON.parses the result. The validator validateQueryInputs at packages/server/src/api/controllers/query/index.ts:61-71 rejects only Handlebars markers ({{, }}) in user input and does not escape JSON metacharacters (\", \\, }). A parameter value containing a closing quote and additional keys lifts attacker-controlled fields into the parsed filter object. For Mongo find, the parsed filter passes directly to collection.find() (packages/server/src/integrations/mongodb.ts:506-510). Duplicate-key JSON parsing overrides the builder's {name: \"...\"} with {name: {$exists: true}} and returns every document. The same primitive against an updateMany query (mongodb.ts:577-585) widens the filter scope to the full collection while the builder-controlled $set body runs against every matched document. The authorized middleware at packages/server/src/middleware/authorized.ts:141-148 short-circuits when the query's role is PUBLIC. CSRF is not enforced on this path. POST /api/v2/queries/:queryId (packages/server/src/api/routes/query.ts:63) accepts the call with no session, only an x-budibase-app-id header that is public from the published-app URL. This vulnerability is fixed in 3.39.12."},
    # CVE-2026-69264 — CRITICAL 9.8, published 2026-08-04
    {"CVE-2026-69264", "flowise", "3.1.0", "3.1.3", "CRITICAL", :a, nil,
     "Prior to 3.1.3, Flowise CSVAgent interpolates an attacker-controlled segment of the csvFile data URI directly into a Python source-code template that is then executed by Pyodide. Because Pyodide is loaded with the default js bridge to globalThis, which on Node.js exposes eval and dynamic import, the attacker can break out of the Python string literal, hand a JavaScript string to js.eval, dynamically import Node built-in modules such as fs and child_process, and execute arbitrary file I/O or OS commands as the Flowise process. The two validator paths around this code, validatePythonCodeForDataFrame and validateCustomReadCSVFunction, are never applied to the bootstrap template. A workspace user with chatflows:create or agentflows/chatflows update permission can plant a CSV Agent node with a crafted csvFile; once the chatflow is exposed via POST /api/v1/prediction/:id, any unauthenticated request triggers host remote code execution. This issue is fixed in version 3.1.3."},
    # CVE-2026-70477 — CRITICAL 9.8, published 2026-08-04
    {"CVE-2026-70477", "flowise", "3.1.2", "3.1.3", "CRITICAL", :b, nil,
     "Flowise is a drag & drop user interface to build a customized large language model flow. Prior to 3.1.3, a prompt injection sent to a chatflow using a CSV Agent node can cause the LLM to respond with a malicious Python script that bypasses the blocklist validator and executes in an unsandboxed Pyodide environment. The specific flaw exists within the run method of the CSV_Agents class, where untrusted data is used to construct an LLM prompt and the resulting pythonCode is validated by validatePythonCodeForDataFrame before execution. An attacker can leverage this to execute arbitrary code in the context of the service account. This issue is fixed in 3.1.3."},
    # CVE-2026-73487 — CRITICAL 9.8, published 2026-08-13
    {"CVE-2026-73487", "flowise", "3.1.2", nil, "CRITICAL", :c, nil,
     "Flowise before 3.1.3 contains a regex-based Python code validator bypass in CSV and Airtable Agent nodes that allows unauthenticated attackers to inject malicious code via prompt injection. Attackers can exploit unblocked pandas functions like pd.read_json() to exfiltrate datasets, perform SSRF against internal services, or achieve code execution through the unauthenticated prediction API."},
    # CVE-2026-70470 — CRITICAL 9.8, published 2026-08-04
    {"CVE-2026-70470", "flowise", "3.1.2", "3.1.3", "CRITICAL", :b, nil,
     "Flowise is a drag & drop user interface to build a customized large language model flow. Prior to 3.1.3, Flowise validatePythonCodeForDataFrame in packages/components/src/pythonCodeValidator.ts can be bypassed with Unicode homoglyph identifiers, allowing arbitrary Python execution inside Pyodide and full OS command execution on the Flowise host via Pyodide js module interop. The validator gates pyodide.runPythonAsync in packages/components/nodes/agents/CSVAgent/CSVAgent.ts and packages/components/nodes/agents/AirtableAgent/AirtableAgent.ts with an ASCII word-boundary blacklist. JavaScript regex word boundaries are ASCII-only, while Python 3 NFKC-normalizes identifiers at parse time, so homoglyph forms such as __cl𝐚ss__, __subcl𝐚sses__, __b𝐚se__, and __b𝐮iltins__ bypass the blacklist and are parsed as their ASCII equivalents. This issue is fixed in version 3.1.3."},
    # CVE-2026-68979 — CRITICAL 9.8, published 2026-08-03
    {"CVE-2026-68979", "apache-nifi", "2.10.0", "2.11.0", "CRITICAL", :c, nil,
     "Apache NiFI 1.10.0 through 2.10.0 provide a Parameter Context update REST API method that does not enforce authorization checking on components referencing Parameter values. Updating a Parameter Context can change parameter values that affect referencing components, but framework authorization was limited to read and write privileges on the Parameter Context itself. As a result of the missing authorization, an authenticated user authorized to modify a Parameter Context, but not authorized on referencing components, could alter Parameter values affecting those components. In deployments where a Parameter value contains executable scripting content, updating a Parameter can result in code execution during automatic component validation, without starting the referencing component. The impact was limited to stopped components by existing verification checks, and the issue applies only to deployments that use component-level authorization policies. Upgrading to Apache NiFi 2.11.0 is the recommended mitigation, which aligns the Parameter Context update method authorization with other methods, adding authorization checking on affected components."},
    # CVE-2026-44792 — CRITICAL 9, published 2026-06-23
    {"CVE-2026-44792", "n8n", "2.22.0", "2.22.1", "CRITICAL", :a, nil,
     "n8n is an open source workflow automation platform. Prior to 1.123.43, 2.22.1, and 2.20.7, an attacker with write access to the git repository connected to an n8n Source Control configuration could commit a malicious Data Table JSON file containing a crafted column name. When an administrator performed a Source Control Pull, n8n imported the file and could lead to SQL injection on the internal PostgreSQL instance. Exploitation requires the n8n instance uses PostgreSQL as its database backend, the Source Control feature is enabled and connected to a repository the attacker can write to, and an administrator triggers a Source Control Pull. This vulnerability is fixed in 1.123.43, 2.22.1, and 2.20.7."},
    # CVE-2026-77070 — CRITICAL 9.8, published 2026-08-20
    {"CVE-2026-77070", "n8n", "1.123.68", "1.123.69", "CRITICAL", :b, nil,
     "n8n before 1.123.69, 2.33.4, and 2.34.1 contains a NoSQL injection vulnerability in the MongoDB node's Find, Delete, and Aggregate operations, which parse the Query parameter as JSON after expression resolution without sanitizing MongoDB operators. An attacker who can influence the resolved query (e.g., via externally-controlled data) can inject operators such as $ne or $where, turning an intended single-document lookup into full-collection disclosure, full-collection deletion, or other operations on the database server."},
    # CVE-2026-13221 — CRITICAL 9.1, published 2026-07-13
    {"CVE-2026-13221", "perl", "5.43.2", "5.43.10", "CRITICAL", :a, nil,
     "Perl versions before 5.40.5-RC1, from 5.41.0 before 5.42.3-RC1, from 5.43.0 before 5.43.10 produce silently incorrect regular expression matches when an alternation of more than 65535 fixed string branches is compiled into a trie in Perl_study_chunk. When such branches are combined into a trie, the delta between the first branch and the shared tail is stored in a 16-bit field. A branch count above 65535 overflows the field, and the trie's match decision table is truncated with no warning or error. A pattern of this shape produces false positive matches (matching strings it should not) and false negative matches (failing to match strings it should). When such a pattern gates an access or filtering decision, the result is wrong."},
    # CVE-2026-57163 — CRITICAL 9.1, published 2026-09-04
    {"CVE-2026-57163", "pjsip", "2.16", nil, "CRITICAL", :a, nil,
     "PJSIP is a free and open source multimedia communication library written in C. Prior to commit c4a151a, a stack buffer overflow exists in the GnuTLS TLS backend when parsing the Subject Alternative Name extension of a peer certificate (tls_cert_get_info() in ssl_sock_gtls.c). Only GnuTLS builds are affected (--with-gnutls); OpenSSL and Apple SecureTransport/Network.framework builds are not affected. While extracting certificate information after a TLS handshake, an incorrect buffer-size value can cause an oversized SubjectAltName entry to be written past the end of a fixed-size stack buffer. A network-positioned attacker presenting a crafted certificate — a malicious server to a connecting client, or a malicious client to a server that requests certificates — can trigger this during the TLS handshake, before any SIP-level authentication. Impact may range from unexpected application termination to control flow hijack/memory corruption. This issue has been patched via commit c4a151a."},
    # CVE-2026-91998 — CRITICAL 9.9, published 2026-09-15
    {"CVE-2026-91998", "casdoor", "4.3.0", nil, "CRITICAL", :c, nil,
     "Casdoor through 4.4.0 contains an authorization bypass vulnerability in the /api/mcp endpoint that allows attackers with any application's clientId and clientSecret to gain unrestricted access to user administration across all organizations. Attackers can enumerate user records including password salts and email addresses, create administrator accounts, modify existing users, and delete them in any organization by supplying legitimate credentials from a single application."},
    # CVE-2026-53622 — CRITICAL 10, published 2026-06-23
    {"CVE-2026-53622", "traefik", "3.7.2", "3.7.3", "CRITICAL", :a, "handled",
     "Traefik is an HTTP reverse proxy and load balancer. Versions prior to 3.7.3, 3.6.18, and 2.11.51 have a critical vulnerability in Traefik's HTTP/3 (QUIC) TLS configuration selection that allows unauthenticated clients to bypass router-specific mTLS enforcement. When HTTP/3 is enabled on an entrypoint, the TLS handshake selects the applicable TLS configuration through an exact, case-sensitive lookup on the SNI value, which fails to match wildcard host patterns (e.g., *.example.com) or case variants of the configured hostname. Because the handshake falls back to the default TLS configuration — which may not require client certificates — a client can complete the QUIC handshake without presenting a certificate, while the subsequent HTTP routing layer still dispatches the request to a backend protected by a router-specific mTLS policy. The issue affects deployments where HTTP/3 is enabled, a router uses a wildcard Host rule or case-insensitive hostname matching, a router-specific TLSOptions enforces client certificate authentication, and UDP access to the entrypoint is reachable by an attacker. This vulnerability is fixed in versions 3.7.3, 3.6.18, and 2.11.51."},
    # CVE-2026-54763 — CRITICAL 10, published 2026-07-06
    {"CVE-2026-54763", "traefik", "3.7.4", "3.7.6", "CRITICAL", :b, "fast",
     "Traefik is an HTTP reverse proxy and load balancer. Prior to v2.11.51, v3.6.22, and v3.7.6, Traefik's BasicAuth, DigestAuth, and ForwardAuth middlewares strip canonical-cased spoofed identity headers before writing Traefik's own value, but do not account for underscore-variant header names, which many backends normalize identically to dashed forms. An attacker able to reach a protected route can inject an underscore-variant header that survives Traefik's stripping and reaches the backend alongside, or on the unauthenticated ForwardAuth authResponseHeaders path instead of, the value Traefik intended to set, spoofing identity or authorization context. This issue is fixed in versions v2.11.51, v3.6.22, and v3.7.6."},
    # CVE-2026-48930 — CRITICAL 9.8, published 2026-06-26
    {"CVE-2026-48930", "nodejs", "24.5.0", nil, "CRITICAL", :b, "open",
     "A flaw in Node.js TLS hostname handling can cause Embedded-nul hostnames can lead to silent authority rebinding due to c-string truncation in resolver bindings. This vulnerability affects all supported release lines: **Node.js 22**, **Node.js 24**, and **Node.js 26**."},
    # CVE-2026-33267 — CRITICAL 10, published 2026-07-29
    {"CVE-2026-33267", "trafficserver", "9.2.0", "9.2.15", "CRITICAL", :a, "supp",
     "Improper Input Validation vulnerability in Apache Traffic Server. This issue affects Apache Traffic Server: from 9.2.0 through 9.2.14, from 10.1.0 through 10.1.3. Users are recommended to upgrade to version 9.2.15 or 10.1.4, which fixes the issue."},
    # CVE-2026-54526 — CRITICAL 9.9, published 2026-07-16
    {"CVE-2026-54526", "argo-workflows", "3.7.0", "3.7.15", "CRITICAL", :c, "back",
     "Argo Workflows is an open source container-native workflow engine for orchestrating parallel jobs on Kubernetes. Prior to 3.7.15 and 4.0.6, the allow-list fix for CVE-2026-31892 is incomplete because workflow/util/merge.go ValidateUserOverrides and SanitizeUserWorkflowSpec walk only the top-level fields of WorkflowSpec via reflection, and WorkflowSpec.ArtifactGC is allow-listed wholesale; the struct behind that field, WorkflowLevelArtifactGC, has a PodSpecPatch sub-field whose contents flow unmodified into util.ApplyPodSpecPatch on the artifact-GC pod, the same sink the original fix closed for WorkflowSpec.PodSpecPatch, so a user submitting a Workflow under templateReferencing: Strict or Secure (against a referenced WorkflowTemplate that declares an output artifact and setting spec.artifactGC.strategy: OnWorkflowCompletion) can still inject an arbitrary strategic merge patch into the artifact-GC pod, including hostPath volumes, privileged: true, arbitrary image and command, and hostNetwork: true, defeating the stated purpose of Strict/Secure reference mode. This issue is fixed in versions 3.7.15 and 4.0.6."},
    # CVE-2026-90937 — CRITICAL 9.9, published 2026-09-14
    {"CVE-2026-90937", "froxlor", "2.2.4", "2.2.5", "CRITICAL", :c, nil,
     "froxlor versions before 2.2.5 fail to validate newline characters in subdomain redirect URLs, allowing authenticated customers to inject arbitrary nginx or Apache configuration directives. Attackers can supply URLs containing literal newlines that are written verbatim into vhost config files during cron rebuild, enabling web server configuration corruption, denial of service, or hijacking of HTTP responses across hosted domains."},
    # CVE-2026-13782 — CRITICAL 10, published 2026-06-30
    {"CVE-2026-13782", "chromium", "150.0.7870.0", "150.0.7871.46", "CRITICAL", :a, nil,
     "Use after free in Browser in Google Chrome prior to 150.0.7871.47 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: Critical)"},
    # CVE-2026-67208 — CRITICAL 9.8, published 2026-07-30
    {"CVE-2026-67208", "juggle", "1.6.0", nil, "CRITICAL", :c, nil,
     "Juggle through 1.6.0 contains a remote code execution vulnerability that allows unauthenticated remote attackers to execute arbitrary OS commands by connecting to the exposed H2 database web console using default shipped credentials. Attackers can access the unprotected /h2-console endpoint, authenticate with default credentials, and leverage the H2 CREATE ALIAS Runtime.exec() technique to execute arbitrary commands, resulting in root-level code execution when running the stock Docker image."},
    # CVE-2026-45405 — CRITICAL 9, published 2026-06-26
    {"CVE-2026-45405", "dokku", "0.38.1", "0.38.2", "CRITICAL", :c, nil,
     "Dokku is a docker-powered PaaS. Prior to 0.38.2, the git:from-archive and certs:add commands extract user-supplied tar/zip archives into temporary directories without sanitizing member paths or preventing symlink traversal. GNU tar creates symlinks during extraction and follows them for subsequent entries, allowing an attacker to write arbitrary files anywhere writable by the dokku user — including overwriting ~/.ssh/authorized_keys to gain unrestricted shell access. This vulnerability is fixed in 0.38.2."},
    # CVE-2026-60004 — CRITICAL 9.8, published 2026-08-26 # Go ecosystem advisory (vuln.go.dev / NVD)
    {"CVE-2026-60004", "gitea", "1.27.0", "1.27.1", "CRITICAL", :c, nil,
     "Gitea before 1.27.1 allows remote code execution via the diffpatch API through Git hook installation."},
    # CVE-2026-73842 — CRITICAL 9, published 2026-08-13 # Go ecosystem advisory (vuln.go.dev / NVD)
    {"CVE-2026-73842", "openchoreo", "1.1.2", "1.1.3", "CRITICAL", :c, nil,
     "OpenChoreo is a complete, open-source developer platform for Kubernetes. Prior to 1.0.3, 1.1.3, and 1.2.0-rc.2, internal/cluster-gateway/server.go exposed /api/proxy/, /api/exec/, and /api/wirelogs/ on an internal listener without requiring a client certificate or token, allowing any network-reachable caller to read tenant Kubernetes Secrets, mutate workloads, and execute commands across connected data planes. This issue is fixed in versions 1.0.3, 1.1.3, and 1.2.0-rc.2."},
    # CVE-2026-73294 — CRITICAL 9.9, published 2026-08-12 # Go ecosystem advisory (vuln.go.dev / NVD)
    {"CVE-2026-73294", "semaphore", "0.0.0-20260704181911-7e8a9434bd81", nil, "CRITICAL", :c, nil,
     "Semaphore UI is a web interface for managing DevOps tools. Prior to 2.18.17 and 2.19.5-beta2, repository git_url handling passes an attacker-controlled --upload-pack option to CmdGitClient.GetLastRemoteCommitHash through POST /api/project/{id}/repositories and scheduled commit-hash polling, allowing a project Manager or Owner to execute arbitrary OS commands in the Semaphore server process. This issue is fixed in versions 2.18.17 and 2.19.5-beta2."},
    # CVE-2026-84141 — CRITICAL 9.8, published 2026-09-01
    {"CVE-2026-84141", "firefox-esr", "153.1.0", "153.2.0", "CRITICAL", :c, nil,
     "Integer overflow in the Graphics: ImageLib component. This vulnerability was fixed in Firefox 155, Firefox ESR 153.2, Thunderbird 155, and Thunderbird 153.2."},
    # CVE-2026-60002 — HIGH 7.7, published 2026-07-08
    {"CVE-2026-60002", "openssh-client", "1:10.2p1", "1:10.4p1", "HIGH", :a, nil,
     "ssh in OpenSSH before 10.4 can have a use-after-free when a server changes its host key during a key re-exchange. (This outcome occurs only on the client side.)"},
    # CVE-2026-60002 — HIGH 7.7, published 2026-07-08
    {"CVE-2026-60002", "openssh-client-common", "1:10.2p1", nil, "HIGH", :a, nil,
     "ssh in OpenSSH before 10.4 can have a use-after-free when a server changes its host key during a key re-exchange. (This outcome occurs only on the client side.)"},
    # CVE-2026-60002 — HIGH 7.7, published 2026-07-08
    {"CVE-2026-60002", "openssh-sftp-server", "1:10.2p1", "1:10.4p1", "HIGH", :b, nil,
     "ssh in OpenSSH before 10.4 can have a use-after-free when a server changes its host key during a key re-exchange. (This outcome occurs only on the client side.)"},
    # CVE-2026-6331 — HIGH 7.5, published 2026-06-25
    {"CVE-2026-6331", "libwolfssl", "5.7.6", "5.9.2", "HIGH", :b, nil,
     "HMAC zero-length tag forgery in EVP_DigestVerifyFinal, where a zero-length tag could be accepted as valid during HMAC verification. In the OpenSSL-compatibility HMAC verify path the supplied signature length was only checked as not exceeding the MAC length, so a zero-length or otherwise truncated tag could pass verification. The fix requires the supplied tag length to exactly equal the MAC length and rejects a zero-length MAC, so a forged short or empty tag is no longer accepted."},
    # CVE-2026-57236 — HIGH 8.2, published 2026-06-25
    {"CVE-2026-57236", "nokogiri", "1.18.9", "1.19.4", "HIGH", :a, "reopened",
     "Nokogiri is an open source XML and HTML library for the Ruby programming language. Prior to 1.19.4, calling Document#encoding= with an invalid encoding (e.g., a non-string, or a string containing a null byte) raises an exception, but only after freeing the document's current encoding string without replacing it. The document is left referencing freed memory, so the next call to Document#encoding reads invalid memory, which can cause a segfault or leak freed bytes into a Ruby String. Affects the CRuby (libxml2) implementation only; JRuby is not affected. This vulnerability is fixed in 1.19.4."},
    # CVE-2026-57236 — MEDIUM 8.2, published 2026-06-25
    {"CVE-2026-57236", "nokogiri", "1.19.0", nil, "MEDIUM", :c, nil,
     "Nokogiri is an open source XML and HTML library for the Ruby programming language. Prior to 1.19.4, calling Document#encoding= with an invalid encoding (e.g., a non-string, or a string containing a null byte) raises an exception, but only after freeing the document's current encoding string without replacing it. The document is left referencing freed memory, so the next call to Document#encoding reads invalid memory, which can cause a segfault or leak freed bytes into a Ruby String. Affects the CRuby (libxml2) implementation only; JRuby is not affected. This vulnerability is fixed in 1.19.4."},
    # CVE-2026-79921 — HIGH 8.9, published 2026-08-26 # Go ecosystem advisory (vuln.go.dev / NVD)
    {"CVE-2026-79921", "amqp091-go", "1.12.0", "1.13.0", "HIGH", :b, nil,
     "amqp091-go is a Go AMQP 0.9.1 client. Before version 1.13.0, a compromised or malicious AMQP broker can force the client to allocate resources for and process content body frames that exceed the negotiated frame_max limit. This can lead to unexpected memory consumption or application-layer denial of service (DoS), bypassing the protocol's built-in framing constraints. Version 1.13.0 contains a fix. No known workarounds are available."},
    # CVE-2026-73232 — HIGH 7.5, published 2026-08-11 # Go ecosystem advisory (vuln.go.dev / NVD)
    {"CVE-2026-73232", "ffuf", "2.1.0", "2.2.0", "HIGH", :a, nil,
     "ffuf is a fast web fuzzer written in Go. Prior to 2.2.0, ffuf allows a malicious target server to cause an out-of-memory denial of service because the response size guard in pkg/runner/simple.go checks only the compressed Content-Length while io.ReadAll reads gzip, brotli, deflate, transparently decompressed, or chunked response bodies without a decompressed-size bound. This issue is fixed in version 2.2.0."},
    # CVE-2026-53109 — HIGH 7.8, published 2026-06-24
    {"CVE-2026-53109", "linux-kernel", "6.18.0", "6.18.33", "HIGH", :b, nil,
     "In the Linux kernel, the following vulnerability has been resolved: powerpc/pgtable-frag: Fix bad page state in pte_frag_destroy powerpc uses pt_frag_refcount as a reference counter for tracking it's pte and pmd page table fragments. For PTE table, in case of Hash with 64K pagesize, we have 16 fragments of 4K size in one 64K page. Patch series [1] \"mm: free retracted page table by RCU\" added pte_free_defer() to defer the freeing of PTE tables when retract_page_tables() is called for madvise MADV_COLLAPSE on shmem range. [1]: https://lore.kernel.org/all/7cd843a9-aa80-14f-5eb2-33427363c20@google.com/ pte_free_defer() sets the active flag on the corresponding fragment's folio & calls pte_fragment_free(), which reduces the pt_frag_refcount. When pt_frag_refcount reaches 0 (no active fragment using the folio), it checks if the folio active flag is set, if set, it calls call_rcu to free the folio, it the active flag is unset then it calls pte_free_now(). Now, this can lead to following problem in a corner case... [ 265.351553][ T183] BUG: Bad page state in process a.out pfn:20d62 [ 265.353555][ T183] page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x20d62 [ 265.355457][ T183] flags: 0x3ffff800000100(active|node=0|zone=0|lastcpupid=0x7ffff) [ 265.358719][ T183] raw: 003ffff800000100 0000000000000000 5deadbeef0000122 0000000000000000 [ 265.360177][ T183] raw: 0000000000000000 c0000000119caf58 00000000ffffffff 0000000000000000 [ 265.361438][ T183] page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set [ 265.362572][ T183] Modules linked in: [ 265.364622][ T183] CPU: 0 UID: 0 PID: 183 Comm: a.out Not tainted 6.18.0-rc3-00141-g1ddeaaace7ff-dirty #53 VOLUNTARY [ 265.364785][ T183] Hardware name: IBM pSeries (emulated by qemu) POWER10 (architected) 0x801200 0xf000006 of:SLOF,git-ee03ae pSeries [ 265.364908][ T183] Call Trace: [ 265.364955][ T183] [c000000011e6f7c0] [c000000001cfaa18] dump_stack_lvl+0x130/0x148 (unreliable) [ 265.365202][ T183] [c000000011e6f7f0] [c000000000794758] bad_page+0xb4/0x1c8 [ 265.365384][ T183] [c000000011e6f890] [c00000000079c020] __free_frozen_pages+0x838/0xd08 [ 265.365554][ T183] [c000000011e6f980] [c0000000000a70ac] pte_frag_destroy+0x298/0x310 [ 265.365729][ T183] [c000000011e6fa30] [c0000000000aa764] arch_exit_mmap+0x34/0x218 [ 265.365912][ T183] [c000000011e6fa80] [c000000000751698] exit_mmap+0xb8/0x820 [ 265.366080][ T183] [c000000011e6fc30] [c0000000001b1258] __mmput+0x98/0x300 [ 265.366244][ T183] [c000000011e6fc80] [c0000000001c81f8] do_exit+0x470/0x1508 [ 265.366421][ T183] [c000000011e6fd70] [c0000000001c95e4] do_group_exit+0x88/0x148 [ 265.366602][ T183] [c000000011e6fdc0] [c0000000001c96ec] pid_child_should_wake+0x0/0x178 [ 265.366780][ T183] [c000000011e6fdf0] [c00000000003a270] system_call_exception+0x1b0/0x4e0 [ 265.366958][ T183] [c000000011e6fe50] [c00000000000d05c] system_call_vectored_common+0x15c/0x2ec The bad page state error occurs when such a folio gets freed (with active flag set), from do_exit() path in parallel. ... this can happen when the pte fragment was allocated from this folio, but when all the fragments get freed, the pte_frag_refcount still had some unused fragments. Now, if this process exits, with such folio as it's cached pte_frag in mm->context, then during pte_frag_destroy(), we simply call pagetable_dtor() and pagetable_free(), meaning it doesn't clear the active flag. This, can lead to the above bug. Since we are anyway in do_exit() path, then if the refcount is 0, then I guess it should be ok to simply clear the folio active flag before calling pagetable_dtor() & pagetable_free()."},
    # CVE-2026-64433 — HIGH 7.8, published 2026-07-25
    {"CVE-2026-64433", "linux-kernel", "6.12.90", "6.12.96", "HIGH", :a, nil,
     "In the Linux kernel, the following vulnerability has been resolved: Bluetooth: MGMT: Fix UAF of hci_conn_params in add_device_complete add_device_complete() runs from the hci_cmd_sync_work kworker, which holds only hci_req_sync_lock and *not* hci_dev_lock. It calls hci_conn_params_lookup() and then dereferences the returned object (params->flags) without taking hci_dev_lock: params = hci_conn_params_lookup(hdev, &cp->addr.bdaddr, le_addr_type(cp->addr.type)); ... device_flags_changed(NULL, hdev, &cp->addr.bdaddr, cp->addr.type, hdev->conn_flags, params ? params->flags : 0); hci_conn_params_lookup() walks hdev->le_conn_params and is documented to require hdev->lock. A concurrent MGMT_OP_REMOVE_DEVICE (remove_device()), which does run under hci_dev_lock, can call hci_conn_params_free() to list_del() and kfree() the very object the lookup returned, so the subsequent params->flags read touches freed memory [0]. Hold hci_dev_lock() across the hci_conn_params_lookup() and the read of params->flags (and the matching event emission) so the lookup result cannot be freed by a concurrent remove_device() before it is used, honouring the locking contract of hci_conn_params_lookup(). [0]: (trailing page/memory-state dump trimmed) BUG: KASAN: slab-use-after-free in add_device_complete+0x358/0x3d8 net/bluetooth/mgmt.c:7671 Read of size 1 at addr ffff000017ab26c1 by task kworker/u9:8/388 CPU: 1 UID: 0 PID: 388 Comm: kworker/u9:8 Not tainted 7.0.11 #20 PREEMPT Hardware name: linux,dummy-virt (DT) Workqueue: hci0 hci_cmd_sync_work Call trace: show_stack+0x2c/0x3c arch/arm64/kernel/stacktrace.c:499 (C) __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0xb4/0xd4 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0x118/0x5d8 mm/kasan/report.c:482 kasan_report+0xb0/0xf4 mm/kasan/report.c:595 __asan_report_load1_noabort+0x20/0x2c mm/kasan/report_generic.c:378 add_device_complete+0x358/0x3d8 net/bluetooth/mgmt.c:7671 hci_cmd_sync_work+0x14c/0x240 net/bluetooth/hci_sync.c:334 process_one_work+0x628/0xd38 kernel/workqueue.c:3289 process_scheduled_works kernel/workqueue.c:3372 [inline] worker_thread+0x7a8/0xac0 kernel/workqueue.c:3453 kthread+0x39c/0x444 kernel/kthread.c:436 ret_from_fork+0x10/0x20 arch/arm64/kernel/entry.S:860 Allocated by task 3401: kasan_save_stack+0x3c/0x64 mm/kasan/common.c:57 kasan_save_track+0x20/0x3c mm/kasan/common.c:78 kasan_save_alloc_info+0x40/0x54 mm/kasan/generic.c:570 poison_kmalloc_redzone mm/kasan/common.c:398 [inline] __kasan_kmalloc+0xd4/0xd8 mm/kasan/common.c:415 kasan_kmalloc include/linux/kasan.h:263 [inline] __kmalloc_cache_noprof+0x1b0/0x458 mm/slub.c:5385 kmalloc_noprof include/linux/slab.h:950 [inline] kzalloc_noprof include/linux/slab.h:1188 [inline] hci_conn_params_add+0x10c/0x4b0 net/bluetooth/hci_core.c:2279 hci_conn_params_set net/bluetooth/mgmt.c:5162 [inline] add_device+0x5b4/0xa54 net/bluetooth/mgmt.c:7755 hci_mgmt_cmd net/bluetooth/hci_sock.c:1721 [inline] hci_sock_sendmsg+0x10b4/0x1dd0 net/bluetooth/hci_sock.c:1841 sock_sendmsg_nosec net/socket.c:727 [inline] __sock_sendmsg+0xe0/0x128 net/socket.c:742 sock_write_iter+0x250/0x390 net/socket.c:1195 new_sync_write fs/read_write.c:595 [inline] vfs_write+0x66c/0xab0 fs/read_write.c:688 ksys_write+0x1fc/0x24c fs/read_write.c:740 __do_sys_write fs/read_write.c:751 [inline] __se_sys_write fs/read_write.c:748 [inline] __arm64_sys_write+0x70/0xa4 fs/read_write.c:748 __invoke_syscall arch/arm64/kernel/syscall.c:35 [inline] invoke_syscall+0x84/0x2a8 arch/arm64/kernel/syscall.c:49 el0_svc_common.constprop.0+0xe4/0x294 arch/arm64/kernel/syscall.c:132 do_el0_svc+0x44/0x5c arch/arm64/kernel/syscall.c:151 el0_svc+0x38/0xac arch/arm64/kernel/entry-common.c:724 el0t_64_sync_handler+0xa0/0xe4 arch/arm64/kernel/entry-common.c:743 el0t_64_sync+0x198/0x19c arch/arm64/kernel/entry.S:596 Freed by task 3740: kasan_save_stack+0x3c/0x64 ---truncated---"},
    # CVE-2026-46680 — HIGH 7.8, published 2026-07-01
    {"CVE-2026-46680", "containerd", "2.2.3", "2.2.4", "HIGH", :x, nil,
     "containerd is an open-source container runtime. In versions prior to 1.7.32, 2.0.9, 2.2.4 and 2.3.1, containers launched with a numeric User directive that cannot be parsed as a 32-bit integer are incorrectly treated as a username, leading to runAsNonRoot evasion. If a crafted image provides an /etc/passwd file mapping this large numeric string to root, the container ultimately runs as root (UID 0). This allows the Kubernetes runAsNonRoot restriction to be bypassed, causing unexpected behavior for environments that require containers to run as a non-root user. This issue has been fixed in versions 1.7.32, 2.0.9, 2.2.4 and 2.3.1."},
    # CVE-2026-53488 — HIGH 8.8, published 2026-07-01
    {"CVE-2026-53488", "containerd", "2.1.8", "2.1.9", "HIGH", :c, nil,
     "containerd is an open-source container runtime. In versions prior to 1.7.33, 2.3.2, 2.2.5, 2.1.9, and 2.0.10 the CRI plugin propagates labels from an image config (LABEL instruction in Dockerfile) to a container without validation. This may result in executing an arbitrary command on the host, via a plugin that consumes container labels for some operations. This issue has been fixed in versions 1.7.33, 2.3.2, 2.2.5, 2.1.9, and 2.0.10."},
    # CVE-2026-52747 — HIGH 8.6, published 2026-07-10
    {"CVE-2026-52747", "modsecurity", "3.0.15", "3.0.16", "HIGH", :b, nil,
     "ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx. Prior to 3.0.16, the multipart/form-data request body parser in libmodsecurity silently removes embedded line breaks from non-file form-field values before exporting them to ARGS and ARGS_POST because src/request_body_processor/multipart.cc overwrites reserved bytes in m_reserve instead of appending the current buffer. This creates a parser differential between ModSecurity and backend applications that preserve line breaks in form fields, allowing rules that inspect ARGS or ARGS_POST to miss payloads whose dangerous syntax depends on a line break. This issue is fixed in version 3.0.16."},
    # CVE-2026-65602 — HIGH 8.8, published 2026-07-22
    {"CVE-2026-65602", "traefik", "3.7.6", "3.7.7", "HIGH", :a, nil,
     "Traefik 3.6.0 through 3.6.22 and 3.7.0 through 3.7.6 fail to enforce the crossProviderNamespaces allowlist for IngressRouteTCP service serversTransport references (the allowlist was only enforced for HTTP serversTransport references). A low-privileged Kubernetes user in a namespace not listed in crossProviderNamespaces can set serversTransport: foo@file on an IngressRouteTCP service, causing Traefik to accept the forbidden cross-provider reference and use a file-provider TCPServersTransport — including privileged backend mTLS client certificates, SPIFFE identity, or PROXY-protocol settings. This is fixed in 3.6.23 and 3.7.7."},
    # CVE-2026-65601 — HIGH 8.8, published 2026-07-22
    {"CVE-2026-65601", "traefik", "3.7.6", "3.7.7", "HIGH", :b, nil,
     "Traefik versions 3.7.0 through 3.7.6 contain a namespace confusion vulnerability in the Kubernetes Gateway API provider. When resolving HTTPRoute.spec.rules[].backendRefs[].filters[].extensionRef, Traefik used the backend Service namespace instead of the HTTPRoute namespace. A low-privileged route author holding a ReferenceGrant for a cross-namespace Service could therefore bind a Traefik Middleware from the backend namespace without a separate grant for that middleware, potentially injecting trusted reverse-proxy identity headers into downstream requests. The issue is fixed in version 3.7.7."},
    # CVE-2026-58043 — HIGH 8.4, published 2026-07-30
    {"CVE-2026-58043", "nodejs", "24.18.0", nil, "HIGH", :c, nil,
     "A flaw in Node.js Permission Model enforcement can over-grant filesystem access across radix-tree prefix boundaries. Under `--permission`, an attacker who is granted access to one path can abuse boundary handling to read from or write to paths outside the intended filesystem allowlist. This vulnerability affects Node.js **main**, **22.x**, **24.x**, and **26.x**."},
    # CVE-2026-58065 — HIGH 8.1, published 2026-07-13
    {"CVE-2026-58065", "apache-airflow-providers-git", "0.4.0", "0.4.1", "HIGH", :x, nil,
     "The Apache Airflow Git provider runs its git-over-SSH operations with `StrictHostKeyChecking=no` by default, disabling SSH host-key verification. An attacker who can intercept the network path between an Airflow worker and the Git server can impersonate the server (man-in-the-middle), capturing the SSH deploy key or injecting malicious repository content. Deployments that use the Git DAG bundle or Git provider to clone over SSH with a deploy key are affected. The fix changes the default to verify host keys; upgrade to apache-airflow-providers-git `0.4.1` or later and configure a `known_hosts` file."},
    # CVE-2026-43871 — HIGH 7.5, published 2026-07-27
    {"CVE-2026-43871", "apache-thrift", "0.23.0", "0.24.0", "HIGH", :b, nil,
     "Loop with Unreachable Exit Condition ('Infinite Loop') vulnerability in Apache Thrift Python, Go, PHP and Java bindings.This issue affects Apache Thrift: before 0.24.0. Users are recommended to upgrade to version 0.24.0, which fixes the issue."},
    # CVE-2026-45309 — HIGH 7.5, published 2026-07-17
    {"CVE-2026-45309", "asyncssh", "2.22.0", "2.23.0", "HIGH", :x, nil,
     "AsyncSSH is a Python package which provides an asynchronous client and server implementation of the SSHv2 protocol on top of the Python asyncio framework. Prior to 2.23.0, AsyncSSH expands the OpenSSH-compatible AuthorizedKeysFile %u token in asyncssh/config.py, asyncssh/connection.py, asyncssh/auth_keys.py, and asyncssh/misc.py with the raw SSH username during pre-authentication server config reload, allowing a server configured with AuthorizedKeysFile authorized_keys/%u to read an authorized-keys file outside the intended directory when the SSH username contains /, \\, or .. path traversal segments and authenticate with an attacker-selected key file. This issue is fixed in version 2.23.0."},
    # CVE-2026-78675 — HIGH 8.4, published 2026-08-25
    {"CVE-2026-78675", "gitpython", "3.1.57", "3.1.59", "HIGH", :x, nil,
     "GitPython before 3.1.59 fails to disable merge_includes when parsing .gitmodules, allowing attackers to disclose local file content by including arbitrary file paths via [include] directives. Attackers can craft a malicious .gitmodules file with include directives pointing to sensitive files; when repo.submodules is accessed, GitConfigParser raises MissingSectionHeaderError embedding the target file's first line verbatim in the exception message."},
    # CVE-2026-66297 — HIGH 8, published 2026-08-05
    {"CVE-2026-66297", "livebook", "0.19.8", "0.19.9", "HIGH", :x, nil,
     "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection) vulnerability in livebook-dev livebook allows command injection into generated deployment setup commands. LivebookWeb.Hub.Teams.DeploymentGroupAgentComponent.docker_instructions/2 and LivebookWeb.Hub.Teams.DeploymentGroupAgentComponent.fly_instructions/4 in lib/livebook_web/live/hub/teams/deployment_group_agent_component.ex interpolate deployment group environment variable values into the generated Docker and Fly.io setup commands without shell escaping. The values originate from the deployment group configuration and reach the sinks through Livebook.Hubs.Dockerfile.online_docker_info/3. Both sinks place the value inside a double-quoted shell word, so a value containing a command substitution such as $(...) or backticks is evaluated by the shell without any need to break out of the quoting, and a literal double quote terminates the quoted word and allows arbitrary further tokens. The generated command is displayed in the Livebook web interface with a copy button, so a user who copies it and runs it without reviewing it first executes the injected commands on their own machine, under their own account. An attacker requires privileges sufficient to set deployment group environment variables, while the resulting code execution occurs on the machine of whoever runs the generated command. The Kubernetes instructions are not affected, because they render the same values into a YAML manifest with escaping rather than into a shell command. This issue affects livebook: from 0.13.0 before 0.18.7 and from 0.19.0 before 0.19.9."},
    # CVE-2026-59856 — HIGH 7.8, published 2026-07-09
    {"CVE-2026-59856", "vim", "9.2.0600", "9.2.0736", "HIGH", :a, nil,
     "Vim is an open source, command line text editor. Prior to 9.2.0736, the PHP omni-completion script in runtime/autoload/phpcomplete.vim interpolates a class or trait name, taken from the contents of the edited buffer, into a search() pattern that is run via win_execute() without escaping. A name containing a single quote can terminate the search() string argument early, and because the bar is honored as an Ex command separator, the remainder of the name is run as Ex commands; via the :! command this allows arbitrary operating-system command execution when a victim opens a crafted PHP file and invokes omni-completion. This issue is fixed in version 9.2.0736."},
    # CVE-2026-56351 — HIGH 8.2, published 2026-06-24
    {"CVE-2026-56351", "n8n", "2.3.0", "2.4.0", "HIGH", :x, nil,
     "n8n before version 2.4.0 contains a sql injection vulnerability in MySQL, PostgreSQL, and Microsoft SQL nodes that allows authenticated users to inject arbitrary SQL through unescaped identifier values in node configuration parameters. Attackers with workflow creation permissions can supply specially crafted table or column names to execute unauthorized database commands and compromise data integrity."},
    # CVE-2026-48931 — LOW 3.7, published 2026-06-22
    {"CVE-2026-48931", "nodejs", "24.5.0", nil, "LOW", :b, "lowsupp",
     "A flaw in Node.js HTTP Agent can cause a client to accept as valid a response that is send before the client has sent the request. This vulnerability affects all supported release lines: **Node.js 22**, **Node.js 24**, and **Node.js 26**."},
    # CVE-2026-45232 — LOW 3.1, published 2026-05-20
    {"CVE-2026-45232", "rsync", "3.4.1", "3.4.3", "LOW", :a, nil,
     "Rsync versions before 3.4.3 contain an off-by-one out-of-bounds stack write vulnerability in the establish_proxy_connection() function in socket.c that allows network attackers to corrupt stack memory by sending a malformed HTTP proxy response. Attackers can exploit this by positioning themselves between the client and proxy or controlling the proxy server to send a response line of 1023 or more bytes without a newline terminator, causing a null byte to be written to an out-of-bounds stack address when the RSYNC_PROXY environment variable is set."},
    # CVE-2026-84969 — LOW 3.7, published 2026-09-03
    {"CVE-2026-84969", "mongodb-c-driver", "2.5.1", "2.5.2", "LOW", :b, nil,
     "A memory-handling error in the BSON-to-JSON conversion helpers of the MongoDB C Driver can write a small number of bytes past the end of a heap buffer when a binary field is encoded and the output is cut short at a caller-configured length limit. A party who supplies the document content, with no privileges on the application that links the driver, may cause a small amount of data outside the intended buffer to be altered."},
    # CVE-2026-50243 — LOW 3.7, published 2026-07-22
    {"CVE-2026-50243", "unbound", "1.25.1", "1.25.2", "LOW", :c, nil,
     "In NLnet Labs Unbound 1.6.2 up to and including 1.25.1, when Unbound is configured with the 'respip' module in front of the validator together with a 'response-ip' redirect rule or an RPZ file with an RPZ-IP trigger, the rewriting handler does not check the security status of the upstream answer and can instead rewrite a BOGUS A/AAAA answer to point to an operator's configured IP. If the validator finds an expired or otherwise invalid RRSIG on an answer whose A record falls within a 'response-ip'/RPZ configuration, the answer is still rewritten and given a hard coded security level of INSECURE. This results in the client receiving an INSECURE NOERROR reply rewritten by the operator's configured IP. A malicious actor can exploit the possible poisonous effect by spoofing a BOGUS A/AAAA answer that falls inside the operator's configured subnet rewrites. Such DNSSEC protected answers are then insecurely redirected to the operator's configured target."},
    # CVE-2026-73087 — LOW 2.3, published 2026-08-11 # Go ecosystem advisory (vuln.go.dev / NVD)
    {"CVE-2026-73087", "dozzle", "1.29.0", nil, "LOW", :c, nil,
     "Dozzle is a realtime log viewer for docker containers. From 10.5.2 until 10.6.15, the isBlockedIP SSRF guard in internal/notification/dispatcher/webhook.go, used by safeDialContext for webhook notification URLs, does not inspect IPv4 addresses embedded in 6to4, NAT64, Teredo, or IPv4-compatible IPv6 addresses, allowing an authenticated user to reach loopback or link-local targets that the guard intends to block. This issue is fixed in version 10.6.15."},
    # CVE-2026-61625 — MEDIUM 6.8, published 2026-08-20 # Go ecosystem advisory (vuln.go.dev / NVD)
    {"CVE-2026-61625", "victoria-metrics", "1.145.0", "1.146.0", "MEDIUM", :a, "gone",
     "VictoriaMetrics is a scalable solution for monitoring and managing time series data. Prior to 1.122.25, 1.136.12, and 1.146.0, vmrestore does not validate backup part path components before using lib/backup/actions/restore.go and lib/backup/fslocal/fslocal.go to write restored data below storageDataPath. An attacker who can supply or modify an S3, GCS, Azure Blob Storage, or other backup source can place .. components in object names. When an operator restores that source, the crafted names can create or overwrite files outside the intended restore root within the filesystem permissions of the vmrestore process. This issue is fixed in versions 1.122.25, 1.136.12, and 1.146.0."},
    # CVE-2026-84303 — MEDIUM 6.3, published 2026-09-01 # Go ecosystem advisory (vuln.go.dev / NVD)
    {"CVE-2026-84303", "grpc", "1.83.0", "1.83.1", "MEDIUM", :b, nil,
     "gRPC-Go is the Go language implementation of gRPC. Prior to 1.83.1, the xDS RBAC HTTP filter in internal/xds/httpfilter/rbac/rbac.go does not lowercase header matcher names in normalizeHeaderMatcher even though incoming metadata keys are lowercase. A DENY policy using a mixed-case name such as X-Role or User-Agent therefore does not match and fails open, allowing requests that should be rejected. The same case mismatch permits :Scheme or Grpc-Status to evade gRFC A41 validation and prevents Host from being rewritten to :authority. This issue is fixed in version 1.83.1."},
    # CVE-2026-71494 — MEDIUM 5.9, published 2026-08-21 # Go ecosystem advisory (vuln.go.dev / NVD)
    {"CVE-2026-71494", "infracost", "0.10.44", "0.10.45", "MEDIUM", :c, nil,
     "Infracost provides cloud cost intelligence for engineers, AI coding agents, and CI/CD. Prior to 0.10.45, internal/hcl/remote_variables_loader.go and related Terraform Cloud, remote-plan, and Terragrunt registry request paths can attach a configured Terraform Cloud or registry token to a destination hostname derived from untrusted Terraform input without confirming that it is the configured trusted host. When a CI run provides a token while scanning attacker-controlled Terraform, including pull_request_target or a same-repository pull request, an attacker can direct the request to an attacker-controlled host and disclose the token. Standard fork pull_request workflows without secrets are not exposed. This issue is fixed in version 0.10.45."}
  ]

  def seed(now \\ @recent) do
    Repo.transaction(fn ->
      image_a =
        image!(
          "sha256:aaa1111111111111111111111111111111111111111111111111111111111111",
          "registry.internal/app-a",
          "1.0",
          "Demo service A image",
          now
        )

      image_b =
        image!(
          "sha256:bbbb222222222222222222222222222222222222222222222222222222222222",
          "registry.internal/app-b",
          "2.0",
          "Demo service B image",
          now
        )

      image_c =
        image!(
          "sha256:cccc333333333333333333333333333333333333333333333333333333333333",
          "registry.internal/shared-base",
          "9",
          "Demo shared base image",
          now
        )

      image_x =
        image!(
          "sha256:dddd444444444444444444444444444444444444444444444444444444444444",
          "registry.internal/ci-runner",
          "2026.09",
          "Demo CI runner image",
          now
        )

      placement!(image_a, "web", "alpha", @env_prod, now)
      placement!(image_a, "web", "beta", @env_prod, now)
      placement!(image_b, "web", "beta", @env_staging, now)
      # app-b also runs for beta in prod (same image, second environment).
      placement!(image_b, "web", "beta", @env_prod, now)
      placement!(image_c, "(unknown)", "alpha", @env_dev, now)
      placement!(image_x, "ci", "alpha", @env_prod, now)

      # Explicit operator-declared exposure evidence (never inferred from names).
      # Idempotency: record evidence only when the placement has none yet.
      seed_exposure!(
        image_a,
        "web",
        "alpha",
        @env_prod,
        "internet_exposed",
        "seed:operator declared",
        now
      )

      seed_exposure!(
        image_a,
        "web",
        "beta",
        @env_prod,
        "internet_exposed",
        "seed:operator declared",
        now
      )

      seed_exposure!(
        image_b,
        "web",
        "beta",
        @env_staging,
        "internal",
        "seed:operator declared",
        now
      )

      # image_c placement intentionally has NO evidence → stays exposure `unknown`.
      seed_exposure!(
        image_x,
        "ci",
        "alpha",
        @env_prod,
        "internal",
        "seed:operator declared",
        now
      )

      # Operator-declared business impact for one placement. Never inferred from
      # severity, namespace or exposure.
      seed_impact!(image_a, "web", "alpha", @env_prod, "critical", "seed:operator declared", now)

      infrastructure =
        for {key, digit, service, namespace, owner} <- [
              {:edge, "e", "edge-gateway", "ingress", "platform"},
              {:search, "f", "search-service", "search", "data"},
              {:worker, "1", "background-worker", "jobs", "platform"},
              {:media, "2", "media-processor", "media", "media"}
            ],
            into: %{} do
          image =
            image!(
              "sha256:" <> String.duplicate(digit, 64),
              "registry.internal/" <> service,
              "demo-1.0",
              "Demo infrastructure: " <> service <> " (illustrative affected libraries)",
              now
            )

          placement!(image, namespace, owner, @env_prod, now)
          placement!(image, namespace, owner, @env_staging, now)
          {key, image}
        end

      images = Map.merge(%{a: image_a, b: image_b, c: image_c, x: image_x}, infrastructure)

      for {cve, package, version, fix, severity, image, life, description} <- @fleet do
        finding =
          finding!(
            Map.fetch!(images, image),
            cve,
            package,
            version,
            severity,
            fix,
            description,
            now: now,
            suppressed: life in ["supp", "back", "lowsupp"]
          )

        pin_history!(finding, history_for(finding, life))
      end

      # Decision history: one live acceptance and one expired mitigation, so the
      # demo shows a covered advisory and an advisory that came back.
      seed_decision!(%{
        cve: "CVE-2026-53492",
        decision: "accepted_risk",
        reason:
          "Demo decision: containerd runtime upgrade is staged with the quarterly node refresh.",
        actor: "local-operator",
        decided_at: now,
        expires_at: DateTime.add(now, 30, :day)
      })

      seed_decision!(%{
        cve: "CVE-2026-60002",
        decision: "mitigated",
        reason: "Demo decision: temporary ingress rule, expired with the old ingress.",
        actor: "local-operator",
        decided_at: DateTime.add(now, -60, :day),
        expires_at: DateTime.add(now, -30, :day)
      })

      seed_intel!(now)

      {:ok, suppressed_count: Inventory.summary_counts().suppressed}
    end)
    |> case do
      {:ok, _} -> :ok
      other -> other
    end
  end

  # Pinned observation history per lifecycle role. `nil` rows keep only the
  # natural "appeared" event recorded by upsert_finding.
  defp history_for(_finding, nil), do: nil

  defp history_for(_finding, "handled"),
    do: %{
      first_seen: @crit_appeared,
      resolved_at: @crit_cleared,
      reopen_count: 0,
      events: [{"appeared", @crit_appeared}, {"resolved", @crit_cleared}]
    }

  defp history_for(_finding, "fast"),
    do: %{
      first_seen: @crit_late_appeared,
      resolved_at: @crit_late_cleared,
      reopen_count: 0,
      events: [{"appeared", @crit_late_appeared}, {"resolved", @crit_late_cleared}]
    }

  defp history_for(_finding, "open"),
    do: %{
      first_seen: @crit_still_open,
      resolved_at: nil,
      reopen_count: 0,
      events: [{"appeared", @crit_still_open}]
    }

  defp history_for(_finding, "supp"),
    do: %{
      first_seen: @crit_appeared,
      resolved_at: nil,
      reopen_count: 0,
      events: [{"appeared", @crit_appeared}]
    }

  defp history_for(_finding, "back"),
    do: %{
      first_seen: @crit_appeared,
      resolved_at: nil,
      reopen_count: 1,
      events: [
        {"appeared", @crit_appeared},
        {"resolved", @crit_cleared},
        {"reopened", @crit_reappeared}
      ]
    }

  defp history_for(_finding, "reopened"),
    do: %{
      first_seen: @appeared,
      resolved_at: nil,
      reopen_count: 1,
      events: [{"appeared", @appeared}, {"resolved", @resolved}, {"reopened", @reopened}]
    }

  defp history_for(_finding, "gone"),
    do: %{
      first_seen: @appeared,
      resolved_at: @resolved,
      reopen_count: 0,
      events: [{"appeared", @appeared}, {"resolved", @resolved}]
    }

  defp history_for(_finding, "lowsupp"), do: nil
  defp history_for(_finding, "medium"), do: nil

  defp image!(digest, repository, tag, description, now) do
    {:ok, image} =
      Inventory.upsert_image(
        %{digest: digest, repository: repository, tag: tag, description: description},
        now
      )

    image
  end

  defp placement!(image, namespace, owner, environment, now) do
    {:ok, _} =
      Inventory.upsert_placement(
        image,
        %{namespace: namespace, owner: owner, environment: environment},
        now
      )

    :ok
  end

  defp finding!(
         image,
         cve,
         package,
         version,
         severity,
         fix,
         description,
         opts
       ) do
    now = Keyword.fetch!(opts, :now)
    suppressed = Keyword.get(opts, :suppressed, false)

    {:ok, finding} =
      Inventory.upsert_finding(
        image,
        %{
          cve: cve,
          package_name: package,
          package_version: version,
          severity: severity,
          fix: fix,
          description: description,
          url: "https://nvd.nist.gov/vuln/detail/" <> cve,
          suppressed: suppressed
        },
        now,
        reopen: false
      )

    finding
  end

  defp seed_exposure!(image, namespace, owner, environment, exposure, source, now) do
    placement = placement_for!(image, namespace, owner, environment)

    unless Repo.exists?(
             from(e in Triage.Exposure.Evidence, where: e.placement_id == ^placement.id)
           ) do
      {:ok, _} = Triage.Exposure.record(placement.id, exposure, source, now)
    end

    :ok
  end

  # Impact and decisions are demo history: seeded once, never rewritten.
  defp seed_impact!(image, namespace, owner, environment, impact, source, now) do
    placement = placement_for!(image, namespace, owner, environment)

    unless Repo.exists?(from(e in Triage.Impact.Evidence, where: e.placement_id == ^placement.id)) do
      {:ok, _} = Triage.Impact.record(placement.id, impact, source, now)
    end

    :ok
  end

  defp seed_decision!(attrs) do
    unless Repo.exists?(from(d in Triage.Decisions.Decision, where: d.cve == ^attrs.cve)) do
      {:ok, _} = Triage.Decisions.record(Map.put_new(attrs, :placement_id, nil))
    end

    :ok
  end

  defp placement_for!(image, namespace, owner, environment) do
    Repo.one!(
      from(p in Inventory.ImagePlacement,
        where:
          p.image_id == ^image.id and p.namespace == ^namespace and p.owner == ^owner and
            p.environment == ^environment
      )
    )
  end

  # Demo-only intel cache: two notices, never network-sourced.
  defp seed_intel!(now) do
    unless Repo.exists?(Triage.Intel.NewsItem) do
      {:ok, _} =
        Triage.Intel.replace_news("synthetic", [
          %{
            item_id: "demo-1",
            title: "Demo notice: new exploitation reporting for a public library CVE",
            summary:
              "Demonstration row. Public notices concern the world at large and are not statements about this estate; a match in Findings is needed before action.",
            link: "https://example.invalid/demo-1",
            published_at: now
          },
          %{
            item_id: "demo-2",
            title: "Demo notice: vendor advisory for a container runtime",
            summary:
              "Demonstration row. Scanner severity is unchanged by exposure; review priority may rise when evidence shows exposure.",
            link: "https://example.invalid/demo-2",
            published_at: now
          }
        ])
        |> elem_ok()

      {:ok, _} = Triage.Intel.record_receipt("synthetic", true, 2, "seeded demo rows")
    end

    :ok
  end

  defp elem_ok({:ok, value}), do: {:ok, value}
  defp elem_ok(other), do: other

  defp pin_history!(_finding, nil), do: :ok

  defp pin_history!(finding, %{events: events} = history) do
    existing_events =
      Repo.all(
        from e in Inventory.FindingEvent, where: e.finding_id == ^finding.id, select: e.event
      )

    if "resolved" not in existing_events do
      Inventory.set_lifecycle(
        finding.id,
        Map.take(history, [:first_seen, :resolved_at, :reopen_count])
      )

      Enum.each(events, fn {event_name, at} ->
        # `appeared` is already recorded by upsert_finding for a new row; never
        # duplicate an event kind, so replaying seeds never invents history.
        if event_name not in existing_events do
          Inventory.record_event(finding.id, event_name, at, "seeded demo history")
        end
      end)

      # Align the pre-recorded `appeared` event with the pinned history so the
      # timeline sorts by observation time, not by seed-run time.
      with {"appeared", appeared_at} <- List.keyfind(events, "appeared", 0) do
        appeared_event =
          Repo.one!(
            from e in Inventory.FindingEvent,
              where: e.finding_id == ^finding.id and e.event == "appeared"
          )

        if appeared_event.occurred_at != appeared_at do
          appeared_event
          |> Inventory.FindingEvent.changeset(%{occurred_at: appeared_at})
          |> Repo.update!()
        end
      end
    end

    :ok
  end
end
