# Browser SPICE feasibility spike

Date: 2026-09-16
Status: In progress; do not start Task 1 yet.

## Scope and evidence

This is Task 0 of the browser SPICE console plan. No production application
code, terminal routes, or source VM configuration was changed. The existing
vm-lab suite passed: **228 tests**, using `python3 -m pytest -q -p no:cacheprovider`.
The probe scripts are throwaway investigation code, not a gateway implementation.

## Descriptor and transport

Live results are recorded below following verified cleanup. Source inspection on the deployed
Proxmox host independently established:

- `PVE/API2/Qemu.pm` calls `remote_viewer_config`, sets the VM's SPICE password,
  and sets its expiration to 30 seconds.
- `PVE/AccessControl.pm::remote_viewer_config` returns `proxy` on port 3128,
  `tls-port`, `host-subject`, `ca`, and `password`.
- **`host` is also a credential**: it contains the signed proxy ticket, not a
  DNS hostname. Redact it. The original plan's descriptor-printing recipe
  redacts only `password` and `ticket` and must be corrected before reuse.
- The CA field uses literal `\\n` sequences. Decode those before loading the PEM.
- The transport must issue HTTP CONNECT to the proxy using the descriptor's
  host and TLS port, then perform TLS with the descriptor CA and verify the
  expected certificate subject. The signed `host` is unsuitable for DNS
  hostname verification. Do not solve this by disabling certificate validation.

## The byte-relay design misses SPICE authentication

Verified in upstream `spice-html5/src/spiceconn.js`: after receiving the SPICE
link reply, the browser encrypts `this.password` with the server's public key
and sends the authentication ticket. The plan's page passes no password to
`SpiceMainConn`; a protocol-blind byte relay cannot substitute the gateway's
secret for that missing password.

**Inference:** keeping the SPICE ticket exclusively inside the gateway requires
an authentication-aware adapter before byte relay, or a different server-side
SPICE client architecture. HTTP CONNECT and TLS alone are insufficient. This
is separate from whether Proxmox needs custom per-clone ports.

Any adapter must preserve channel IDs and connection IDs, handle partial frames,
authenticate every channel, bound frame sizes and timeouts, and never expose
either ticket. New descriptor requests rotate the VM password; opening multiple
channels must be tested against that lifecycle rather than blindly minting a
new descriptor for every WebSocket.

## Clipboard

**Source support exists; live behavior remains unverified.** Current upstream
`src/main.js` implements clipboard grab/request/release, reads browser text via
`navigator.clipboard.readText`, writes it via `navigator.clipboard.writeText`,
and advertises clipboard-selection and clipboard-by-demand capabilities.
Older prose documentation and the TODO file are not sufficient evidence that
clipboard is absent.

No browser-to-guest or guest-to-browser clipboard test has passed in this spike.
Those tests need a graphical guest session with its SPICE agent, a secure
browser context, and actual clipboard permissions/user gestures. Test both
directions using distinctive text; verify the pasted result, not merely that
an API call returns. Computer Use reported that permissions were not granted
in this session, so browser verification is still a separate gate.

## Recommendation

Do not implement Tasks 1–9 from the current snippets unchanged. Retain SPICE
as the candidate, resolve the gateway authentication design, and finish the
live clipboard test first. Source support alone does not justify switching to
noVNC, and the missing authentication step is not evidence that custom SPICE
ports are required.

## Sources inspected

- Deployed `/usr/share/perl5/PVE/API2/Qemu.pm`, SPICE endpoint near line 3160.
- Deployed `/usr/share/perl5/PVE/AccessControl.pm`, `remote_viewer_config` near line 615.
- Deployed `/usr/share/perl5/PVE/APIServer/AnyEvent.pm`, proxy request handling near line 1505.
- [SPICE browser authentication source](https://gitlab.freedesktop.org/spice/spice-html5/-/blob/master/src/spiceconn.js).
- [SPICE browser clipboard source](https://gitlab.freedesktop.org/spice/spice-html5/-/blob/master/src/main.js).

Upstream HEAD observed: `f3d6692f2e827bde7b41812b83a7012ff472e7b6`.
SHA-256 of retrieved files:

- `spiceconn.js`: `c792aaf4718da6b1458c53229fba3ab7330d1dcee84a9869f21b7bf04c4ea7ae`
- `main.js`: `b8c3cdf23f39062095f006bf9c69b579093af2d2bf0826c9ae32c86b7c96daca`

## Live result

A full clone of VM 500 was created as VM **104**, named
`spice-spike-20260916`, configured with `vga=qxl`, 2 GiB RAM, and its virtual
network link disconnected. It ran only for the probe and was stopped and
**deleted successfully** afterward. The source VM and production routes were
not modified.

Descriptor, with both credentials redacted:

```json
{
  "delete-this-file": 1,
  "host-subject": "OU=PVE Cluster Node,O=Proxmox Virtual Environment,CN=pve.pm.itdivision.org",
  "type": "spice",
  "proxy": "http://pve.pm.itdivision.org:3128",
  "title": "VM 104 - spice-spike-20260916",
  "release-cursor": "Ctrl+Alt+R",
  "ca": "[CA CERTIFICATE OMITTED]",
  "secure-attention": "Ctrl+Alt+Ins",
  "toggle-fullscreen": "Shift+F11",
  "password": "[REDACTED]",
  "host": "[REDACTED PROXY TICKET]",
  "tls-port": 61000
}
```

From the existing lab-api container on the lab Docker network:

1. TCP connection to the proxy succeeded.
2. `CONNECT <descriptor.host>:61000 HTTP/1.0`, with the same authority in
   `Host`, returned **HTTP/1.0 200 OK**.
3. TLS succeeded with CA validation and exact comparison against the
   descriptor's expected certificate subject.
4. A SPICE main-channel link request returned magic `REDQ`, protocol 2.2,
   link error **0**, and a 186-byte link reply.
5. The RSA ticket-authentication probe did **not** run: `cryptography` is not
   installed in the lab-api container. No dependencies were installed there.
   This is not a successful authenticated display or clipboard test.

**Conclusion supported by this test:** the Proxmox CONNECT/TLS transport works
from the lab network, so custom per-clone SPICE ports are unnecessary for that
transport. A gateway still needs the authentication handling described above.

The full disk clone took longer than the original five-minute probe timeout.
Its task was allowed to finalize, then the same VM was resumed after checking
its name. Starting it produced a nonfatal warning about using a temporary EFI
variables disk because the source has no efidisk. The final run handled that
known warning, completed the transport probe, and removed the clone. Do not
clear a clone lock or force-delete an incompletely identified VM on timeout.

## Next executable checkpoint

1. Revise the authentication portion of the design and plan; retain server-only
   tickets. Prove successful and refused authentication, including all channels,
   before attaching a browser.
2. Run the live browser clipboard test against a fresh disposable clone with a
   graphical session and SPICE guest agent. Browser automation access must be
   enabled or the test must be performed interactively by the operator.
3. Only then mark Task 0 complete and begin the production gateway tasks.

Mutation testing is not claimed: this checkpoint changes documentation only.
