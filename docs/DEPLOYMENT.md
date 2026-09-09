# Deployment guide

## Local reference

Run the README quick start on Windows, macOS or Linux. This exercises the Python policy and handoff code only. No external messages, cloud resources or workloads are created by the demo.

## Linux gVisor worker

1. Provision a dedicated patched Linux execution node. Install Docker and register the `runsc` runtime following [gVisor's official installation instructions](https://gvisor.dev/docs/user_guide/install/). Verify cgroup limits work on that node.
2. Build and scan a minimal image containing Python 3 and optionally Bash. Remove secrets and unnecessary packages; pin its registry digest. Pre-pull it through an operator-controlled image pipeline. Do not let a model choose the image.
3. Call `secure_agent_sandbox.sandbox.gvisor.execute(source_bytes, approved_image_digest)` only from the trusted execution service after authorization of a separately registered execution tool. The local demo deliberately does not register that tool. A return value is an exit status, not trusted tool content.
4. Install an independent watchdog/reaper with a hard TTL. The template supplies `uv run python -m secure_agent_sandbox.sandbox.reaper --max-age-seconds 2400`, which only removes expired containers carrying the adapter's exact `secure-agent-sandbox.managed=1` label. Run it under a distinct supervisor identity, record its output externally, and alert on any error. Confirm cleanup after worker termination and Docker CLI timeout. Keep concurrency bounded and reserve controller resources outside workload cgroups.
5. Complete the runtime acceptance tests in DESIGN.md before processing hostile workloads. The adapter has not been integration-tested on this Windows workspace.

The adapter has no network and produces no output. Network-enabled workloads require a separate reviewed adapter and firewall/proxy deployment. Do not simply remove `--network=none`.

## MicroVM and component services

Implement the `sandbox/profiles.json` contracts in dedicated services with authenticated, tenant-bound APIs: `create(profile, artifact_digest, run_id)`, `execute(job_id)`, `status(job_id)`, and idempotent `destroy(job_id)`. Profiles and runtime selection are operator-owned. Admission fails when enforcement capabilities or audit health are missing. Retry execution only with an idempotency key and known effect status.

For Firecracker, provision KVM, jailer, approved kernel/rootfs images, per-job disk overlays, host watchdogs and external network rules. For E2B, verify provider-side limits and network guarantees using the pinned SDK and selected plan; do not assume local timeout alone kills remote compute. WASI requires a component-capable host that validates imports, installs only the WIT capability implementation and bounds both guest and host calls. These backends are not implemented in this template.

## Kubernetes baseline

After selecting a CNI with enforced ingress and egress policy and configuring runsc on dedicated nodes:

```sh
kubectl apply -f deploy/kubernetes/isolation.yaml
```

This creates a restricted namespace, default-deny network policy and runtime declaration only. It does not deploy an agent, proxy or sandbox worker. Workload manifests must set `runtimeClassName: gvisor`, non-root UID, read-only root filesystem, disabled service-account automount, dropped capabilities, seccomp RuntimeDefault, CPU/memory/ephemeral-storage limits, bounded emptyDir, no hostPath/hostNetwork, and active job deadlines. Pin the Pod Security version to your validated cluster version for releases. RuntimeClass existence alone does not install gVisor.

Place the credential broker outside the sandbox namespace and grant only explicit broker ingress and sandbox-to-broker egress. Test actual pod routing, including IPv6 and node endpoints. A NetworkPolicy file is not evidence the CNI enforces it.

## Production completion checklist

- Separate Q, P, monitor, worker and broker identities; authenticated RPC with quotas and fixed schemas.
- Trusted user intent and tenant resource mapping; no raw tool/error text in P context.
- Operator-owned immutable policy storage; authenticated new-run approval workflow.
- Runtime health checks, pinned images, resource accounting, independent cleanup.
- Broker vendor configuration translated from `proxy/contract.json` and bypass-tested.
- Secret rotation/revocation and tenant-specific credentials; no secrets in guest env or logs.
- eBPF coverage validated per runtime; remote retention-locked audit and failure policy.
- End-to-end adversarial tests, dependency scanning, SBOM/signatures and external review.

Do not label a deployment production-ready until these items have evidence attached. The repository supplies essential boilerplate, not a replacement for provisioning and operating these services.
