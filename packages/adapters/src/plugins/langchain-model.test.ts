import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createGovernance,
  inputBlocklist,
  maskOutputPattern,
} from "governance-sdk";
import { wrapChatModel } from "./langchain-model.js";
import type { LangChainMessage, LangChainChatModel } from "./langchain-model.js";
import { GovernanceBlockedError } from "./outcome-handler.js";

class FakeHumanMessage implements LangChainMessage {
  constructor(public content: string) {}
  _getType() { return "human"; }
}

class FakeAIMessage implements LangChainMessage {
  constructor(public content: string) {}
  _getType() { return "ai"; }
}

function fakeModel(reply: string): LangChainChatModel & { received?: LangChainMessage[] | string } {
  const model: LangChainChatModel & { received?: LangChainMessage[] | string } = {
    invoke: async (input: LangChainMessage[] | string) => {
      model.received = input;
      return new FakeAIMessage(reply);
    },
  };
  return model;
}

async function registerAgent(rules: Parameters<typeof createGovernance>[0]["rules"] = []) {
  const gov = createGovernance({ rules });
  const { id } = await gov.register({
    name: "langchain-test", framework: "langchain", owner: "t",
  });
  return { gov, agentId: id };
}

describe("langchain-model — preprocess", () => {
  it("allow: forwards input unchanged to underlying model", async () => {
    const { gov, agentId } = await registerAgent();
    const model = fakeModel("ok");
    const guarded = wrapChatModel(model, gov, { agentId });

    await guarded.invoke([new FakeHumanMessage("hello world")]);
    const received = model.received as LangChainMessage[];
    assert.equal(received[0].content, "hello world");
  });

  it("block: throws before model.invoke runs", async () => {
    const { gov, agentId } = await registerAgent([inputBlocklist(["forbidden"])]);
    let called = false;
    const model: LangChainChatModel = {
      invoke: async () => { called = true; return new FakeAIMessage("x"); },
    };
    const guarded = wrapChatModel(model, gov, { agentId });

    await assert.rejects(
      () => guarded.invoke([new FakeHumanMessage("please do forbidden now")]),
      GovernanceBlockedError,
    );
    assert.equal(called, false);
  });

  // The message array comes from user code; a hole in it used to throw a
  // TypeError out of `_getType()` before the human turn was reached.
  it("skips holes in a ragged message array", async () => {
    const { gov, agentId } = await registerAgent([inputBlocklist(["forbidden"])]);
    const model = fakeModel("x");
    const guarded = wrapChatModel(model, gov, { agentId });

    const messages: LangChainMessage[] = [];
    messages[0] = new FakeHumanMessage("please do forbidden now");
    messages[2] = new FakeAIMessage("sure"); // index 1 is a hole

    await assert.rejects(() => guarded.invoke(messages), GovernanceBlockedError);
  });

  it("accepts raw string input", async () => {
    const { gov, agentId } = await registerAgent([inputBlocklist(["nope"])]);
    const model = fakeModel("x");
    const guarded = wrapChatModel(model, gov, { agentId });

    await assert.rejects(
      () => guarded.invoke("please say nope"),
      GovernanceBlockedError,
    );
  });
});

describe("langchain-model — postprocess", () => {
  it("mask: replaces model response content with masked version", async () => {
    const { gov, agentId } = await registerAgent([
      maskOutputPattern("\\d{3}-\\d{2}-\\d{4}", "g"),
    ]);
    const model = fakeModel("ssn 123-45-6789 here");
    const guarded = wrapChatModel(model, gov, { agentId });

    const res = await guarded.invoke([new FakeHumanMessage("hi")]);
    assert.notEqual(res.content, "ssn 123-45-6789 here");
  });

  it("allow: passes response through untouched", async () => {
    const { gov, agentId } = await registerAgent();
    const model = fakeModel("nothing to mask");
    const guarded = wrapChatModel(model, gov, { agentId });

    const res = await guarded.invoke([new FakeHumanMessage("hi")]);
    assert.equal(res.content, "nothing to mask");
  });
});

describe("langchain-model — flags", () => {
  it("preprocess: false skips input scan", async () => {
    const { gov, agentId } = await registerAgent([inputBlocklist(["forbidden"])]);
    const model = fakeModel("ok");
    const guarded = wrapChatModel(model, gov, { agentId, preprocess: false });

    const res = await guarded.invoke([new FakeHumanMessage("do forbidden stuff")]);
    assert.equal(res.content, "ok");
  });

  it("postprocess: false skips output scan", async () => {
    const { gov, agentId } = await registerAgent([
      maskOutputPattern("\\d{3}-\\d{2}-\\d{4}", "g"),
    ]);
    const model = fakeModel("ssn 123-45-6789 leak");
    const guarded = wrapChatModel(model, gov, { agentId, postprocess: false });

    const res = await guarded.invoke([new FakeHumanMessage("hi")]);
    assert.equal(res.content, "ssn 123-45-6789 leak");
  });
});

describe("langchain-model — prototype preservation", () => {
  it("wrapped model keeps prototype of original (bindTools etc. still work)", async () => {
    const { gov, agentId } = await registerAgent();
    class CustomModel implements LangChainChatModel {
      invoke = async () => new FakeAIMessage("x");
      bindTools() { return this; }
    }
    const original = new CustomModel();
    const guarded = wrapChatModel(original, gov, { agentId });

    assert.ok(guarded instanceof CustomModel);
    assert.equal(typeof guarded.bindTools, "function");
  });
});
