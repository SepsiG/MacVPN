// node --test: the editor's DNS section (macOS root layer 15): where it is shown, the modes, the override rule and
// the list parsing. The backend validates again on save.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  type Dns,
  modes,
  overrideProblem,
  splitList,
  joinList,
  targetedNote,
  visible,
} from "./dnsFields.ts";

const tr = (key: string, ...args: (string | number)[]) =>
  args.length ? `<${key}|${args.join("|")}>` : `<${key}>`;
const dns = (d: Partial<Dns> = {}): Dns => ({
  mode: "automatic",
  servers: [],
  domains: [],
  overrideVpn: false,
  ...d,
});

test("visible only on macOS for openvpn/wireguard/sstp", () => {
  for (const kind of ["openvpn", "wireguard", "sstp"]) {
    assert.equal(visible("macos", kind, dns()), true, kind);
    assert.equal(visible("linux", kind, dns()), false, kind);
    assert.equal(visible("windows", kind, dns()), false, kind);
  }
  assert.equal(visible("macos", "strongswan", dns()), false);
  assert.equal(
    visible("macos", "openvpn", undefined),
    false,
    "no DNS fields from the backend",
  );
});

test("targeted hidden when full_tunnel_hint is true", () => {
  assert.deepEqual(
    modes(tr, undefined).map((m) => m.id),
    ["automatic", "full", "targeted", "strict"],
  );
  assert.deepEqual(
    modes(tr, true).map((m) => m.id),
    ["automatic", "full", "strict"],
  );
  assert.equal(modes(tr, false).length, 4);
  assert.equal(modes(tr, undefined)[0].label, "<Automatic (recommended)>");
  assert.equal(
    targetedNote(tr, dns({ mode: "targeted" }), undefined),
    "<If the server sends all traffic through the VPN, Targeted works like Automatic.>",
  );
  assert.equal(targetedNote(tr, dns({ mode: "targeted" }), false), null);
  assert.equal(targetedNote(tr, dns(), undefined), null);
});

test("override needs servers", () => {
  assert.notEqual(overrideProblem(tr, dns({ overrideVpn: true })), null);
  assert.equal(
    overrideProblem(tr, dns({ overrideVpn: true, servers: ["10.0.0.53"] })),
    null,
  );
  assert.equal(overrideProblem(tr, dns()), null);
});

test("servers and domains split on commas/spaces/newlines", () => {
  assert.deepEqual(splitList(" 10.0.0.53, fd00::53\n\n10.0.0.54 "), [
    "10.0.0.53",
    "fd00::53",
    "10.0.0.54",
  ]);
  assert.deepEqual(splitList(""), []);
  assert.equal(joinList(["a.example", "b.example"]), "a.example\nb.example");
});
