import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createMemoryReplayStore } from "./agent-identity-replay-store";

describe("createMemoryReplayStore", () => {
  it("reports a jti as seen only after it has been added", () => {
    const store = createMemoryReplayStore();
    assert.equal(store.has("a"), false);
    store.add("a", Math.floor(Date.now() / 1000) + 60);
    assert.equal(store.has("a"), true);
    assert.equal(store.has("b"), false);
    assert.equal(store.size(), 1);
  });

  it("forgets an entry once its expiry has passed", () => {
    let clock = 1000;
    const store = createMemoryReplayStore({ now: () => clock });
    store.add("a", 1010);
    assert.equal(store.has("a"), true);
    clock = 1010; // exactly at expiry — still live (token itself is accepted at exp + skew)
    assert.equal(store.has("a"), true);
    clock = 1011;
    assert.equal(store.has("a"), false);
    assert.equal(store.size(), 0, "expired entry is removed on lookup");
  });

  it("ignores an add whose expiry is already in the past", () => {
    const store = createMemoryReplayStore({ now: () => 1000 });
    store.add("dead", 999);
    assert.equal(store.size(), 0);
    assert.equal(store.has("dead"), false);
  });

  it("sweeps expired entries before evicting when full", () => {
    let clock = 1000;
    const store = createMemoryReplayStore({ maxEntries: 2, now: () => clock });
    store.add("old", 1005);
    store.add("live", 2000);
    clock = 1006; // "old" is now expired but not yet swept
    store.add("new", 2000);
    assert.equal(store.size(), 2);
    assert.equal(store.has("old"), false);
    assert.equal(store.has("live"), true, "live entry survives because the expired one was swept instead");
    assert.equal(store.has("new"), true);
  });

  it("evicts the oldest live entry when full and nothing has expired", () => {
    const store = createMemoryReplayStore({ maxEntries: 2, now: () => 1000 });
    store.add("first", 2000);
    store.add("second", 2000);
    store.add("third", 2000);
    assert.equal(store.size(), 2);
    assert.equal(store.has("first"), false);
    assert.equal(store.has("second"), true);
    assert.equal(store.has("third"), true);
  });

  it("re-adding a jti moves it to the newest position", () => {
    const store = createMemoryReplayStore({ maxEntries: 2, now: () => 1000 });
    store.add("first", 2000);
    store.add("second", 2000);
    store.add("first", 2000); // refresh
    store.add("third", 2000); // evicts "second", the now-oldest
    assert.equal(store.has("first"), true);
    assert.equal(store.has("second"), false);
    assert.equal(store.has("third"), true);
  });

  it("clear() drops everything", () => {
    const store = createMemoryReplayStore();
    store.add("a", Math.floor(Date.now() / 1000) + 60);
    store.clear();
    assert.equal(store.size(), 0);
    assert.equal(store.has("a"), false);
  });

  it("rejects a non-positive or non-integer maxEntries", () => {
    assert.throws(() => createMemoryReplayStore({ maxEntries: 0 }), /positive integer/);
    assert.throws(() => createMemoryReplayStore({ maxEntries: 1.5 }), /positive integer/);
    assert.throws(() => createMemoryReplayStore({ maxEntries: -3 }), /positive integer/);
  });
});
