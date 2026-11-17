import { generateSecretKey, getPublicKey, finalizeEvent } from "nostr-tools";
import * as nip44 from "nostr-tools/nip44";
import { describe, it, expect } from "vitest";

import { LocalSigner } from "../signer/LocalSigner.js";

import { unwrapEvent, wrapEvent, wrapManyEvents } from "./nip59.js";

describe("nip59 wrapEvent", () => {
  it("round-trips a rumor through wrap → unwrap", async () => {
    const sender = new LocalSigner(generateSecretKey());
    const recipient = new LocalSigner(generateSecretKey());
    const recipientPk = await recipient.getPublicKey();

    const wrap = await wrapEvent({ kind: 14, content: "hello", tags: [] }, sender, recipientPk);

    const rumor = await unwrapEvent(wrap, recipient);
    expect(rumor.kind).toBe(14);
    expect(rumor.content).toBe("hello");
    expect(rumor.pubkey).toBe(await sender.getPublicKey());
  });
});

describe("nip59 wrapManyEvents — per-recipient seal regression", () => {
  it("produces wraps that each recipient can unwrap to the same rumor", async () => {
    const sender = new LocalSigner(generateSecretKey());
    const r1 = new LocalSigner(generateSecretKey());
    const r2 = new LocalSigner(generateSecretKey());
    const r3 = new LocalSigner(generateSecretKey());
    const pks = await Promise.all([r1, r2, r3].map((s) => s.getPublicKey()));

    const wraps = await wrapManyEvents(
      { kind: 14, content: "shared secret", tags: [] },
      sender,
      pks,
    );

    expect(wraps).toHaveLength(3);

    const rumor1 = await unwrapEvent(wraps[0], r1);
    const rumor2 = await unwrapEvent(wraps[1], r2);
    const rumor3 = await unwrapEvent(wraps[2], r3);

    for (const rumor of [rumor1, rumor2, rumor3]) {
      expect(rumor.content).toBe("shared secret");
      expect(rumor.kind).toBe(14);
    }
  });
});

describe("nip59 unwrapEvent — forged seal rejection", () => {
  it("rejects an unsigned 'seal' that anyone could encrypt to the recipient", async () => {
    const victim = new LocalSigner(generateSecretKey());
    const victimPk = await victim.getPublicKey();
    const attacker = new LocalSigner(generateSecretKey());
    const attackerPk = await attacker.getPublicKey();

    const enc = (obj: unknown, from: LocalSigner, toPk: string) =>
      nip44.encrypt(JSON.stringify(obj), nip44.getConversationKey(from.secretKey, toPk));

    const forgedRumor = { kind: 14, pubkey: attackerPk, created_at: 1, tags: [["ClientKey", "ATTACKER-KEY"]], content: "phishing grant" };
    const forgedSeal = { kind: 13, pubkey: attackerPk, created_at: 1, tags: [], content: enc(forgedRumor, attacker, victimPk) };
    const wrapSk = generateSecretKey();
    const wrap = {
      kind: 1059,
      pubkey: getPublicKey(wrapSk),
      created_at: 1,
      tags: [["p", victimPk]],
      content: enc(forgedSeal, new LocalSigner(wrapSk), victimPk),
    };

    await expect(unwrapEvent(wrap as Event, victim)).rejects.toThrow();
  });

  it("rejects a validly-signed seal whose rumor claims a different author", async () => {
    const sender = new LocalSigner(generateSecretKey());
    const impostor = new LocalSigner(generateSecretKey());
    const victim = new LocalSigner(generateSecretKey());
    const victimPk = await victim.getPublicKey();

    const rumor = { kind: 14, pubkey: await impostor.getPublicKey(), created_at: 1, tags: [], content: "spoofed" };
    const sealContent = nip44.encrypt(JSON.stringify(rumor), nip44.getConversationKey(sender.secretKey, victimPk));
    // A properly-signed seal (kind 13) from the sender…
    const seal = await finalizeEvent(
      { kind: 13, created_at: 1, tags: [], content: sealContent },
      sender.secretKey,
    );
    const wrapSk = generateSecretKey();
    const wrap = {
      kind: 1059,
      pubkey: getPublicKey(wrapSk),
      created_at: 1,
      tags: [["p", victimPk]],
      content: nip44.encrypt(JSON.stringify(seal), nip44.getConversationKey(wrapSk, victimPk)),
    };

    await expect(unwrapEvent(wrap as Event, victim)).rejects.toThrow(/author/);
  });
});
