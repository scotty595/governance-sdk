/**
 * Message-text extraction, once.
 *
 * Six adapters carried their own `contentToText` and `extractLastUserText`.
 * The shapes they handle are the same three every chat API uses — a plain
 * string, an array of parts, or an object wrapping parts — so they are handled
 * here and the adapters map their own message type onto `TextMessage`.
 */

/** The minimum an adapter must expose for these helpers to work. */
export interface TextMessage {
  role: string;
  content: unknown;
}

/**
 * Flatten a message content payload to plain text.
 *
 * Handles: a plain string; an array of parts (`{ type: "text", text }`, or
 * bare strings); and an object carrying `parts` and/or a flat `content`
 * string (the shape message stores read back). Anything else yields "".
 */
export function contentToText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return partsToText(content);
  if (content && typeof content === "object") {
    const obj = content as Record<string, unknown>;
    if (Array.isArray(obj.parts)) return partsToText(obj.parts);
    if (typeof obj.content === "string") return obj.content;
    if (typeof obj.text === "string") return obj.text;
  }
  return "";
}

/**
 * Flatten an array of content parts to newline-joined text.
 *
 * A part counts as text when it says so (`type: "text"`, or the
 * `input_text` / `output_text` the OpenAI Agents SDK uses) or when it carries
 * a `text` string and no type at all — Genkit, LlamaIndex and the OpenAI
 * Agents SDK all emit that untagged shape, and requiring the discriminator
 * pushed a re-tagging step into three adapters.
 */
export function partsToText(parts: unknown[]): string {
  const out: string[] = [];
  for (const part of parts) {
    if (typeof part === "string") {
      if (part) out.push(part);
      continue;
    }
    if (part && typeof part === "object") {
      const p = part as { type?: unknown; text?: unknown };
      if (typeof p.text !== "string" || p.text === "") continue;
      const tagged = p.type === undefined || p.type === "text" || p.type === "input_text" || p.type === "output_text";
      if (tagged) out.push(p.text);
    }
  }
  return out.join("\n");
}

/** Text of the last message with the given role (default "user"). */
export function extractLastText(messages: readonly TextMessage[], role = "user"): string {
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg?.role !== role) continue;
    return contentToText(msg.content);
  }
  return "";
}

/**
 * Return a copy of `messages` with the last message of `role` replaced by
 * `text`, preserving the original content shape where it can (string stays a
 * string; a parts array keeps its non-text parts and rewrites the first text
 * part). Returns the input unchanged when there is no such message.
 */
export function replaceLastText<M extends TextMessage>(
  messages: readonly M[],
  text: string,
  role = "user",
): M[] {
  const out = [...messages];
  for (let i = out.length - 1; i >= 0; i--) {
    const msg = out[i];
    if (msg?.role !== role) continue;
    out[i] = { ...msg, content: replaceContentText(msg.content, text) } as M;
    return out;
  }
  return out;
}

/**
 * The single-payload form of {@link replaceLastText}: rewrite one message's
 * content, preserving its shape. Adapters that hold a lone assistant message
 * (a response envelope, a LangChain instance) use this instead of wrapping it
 * in a one-element array and unwrapping the result.
 */
export function replaceContentText(content: unknown, text: string): unknown {
  if (typeof content === "string") return text;
  if (Array.isArray(content)) return replaceInParts(content, text);
  if (content && typeof content === "object") {
    const obj = content as Record<string, unknown>;
    if (Array.isArray(obj.parts)) {
      const parts = replaceInParts(obj.parts, text);
      return { ...obj, parts, ...(typeof obj.content === "string" ? { content: text } : {}) };
    }
    if (typeof obj.content === "string") return { ...obj, content: text };
    if (typeof obj.text === "string") return { ...obj, text };
  }
  return text;
}

function replaceInParts(parts: unknown[], text: string): unknown[] {
  let replaced = false;
  const out = parts.map((part) => {
    if (replaced) return part;
    if (typeof part === "string") { replaced = true; return text; }
    if (part && typeof part === "object") {
      const p = part as { type?: unknown; text?: unknown };
      const isText = typeof p.text === "string"
        && (p.type === undefined || p.type === "text" || p.type === "input_text" || p.type === "output_text");
      if (isText) {
        replaced = true;
        return { ...(part as Record<string, unknown>), text };
      }
    }
    return part;
  });
  // No text part to rewrite — prepend one rather than silently dropping the
  // replacement, so a masked or blocked rewrite is never lost.
  return replaced ? out : [{ type: "text", text }, ...out];
}
