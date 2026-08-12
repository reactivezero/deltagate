// Anthropic Messages API over raw fetch — no SDK dependency (DeltaGate ships
// zero deps on purpose). Returns the model's structured JSON, or throws.
//
// Model is configurable: DELTAGATE_MODEL env var, default claude-haiku-4-5
// (the design's cheap tier-1 triage model; raise to a Sonnet/Opus tier for the
// adjudication pass). Key from ANTHROPIC_API_KEY. Note: an Anthropic *API key*
// is required — a Claude.ai / Claude Max subscription is billed separately and
// does not grant API access.

const ENDPOINT = 'https://api.anthropic.com/v1/messages';
const DEFAULT_MODEL = 'claude-haiku-4-5';

export function defaultModel() {
  return process.env.DELTAGATE_MODEL || DEFAULT_MODEL;
}

export function hasApiKey() {
  return !!process.env.ANTHROPIC_API_KEY;
}

/**
 * @param {{system:string, userText:string, schema:object, model?:string}} req
 * @returns {Promise<object>} the parsed structured-output JSON
 */
export async function callAnthropic({ system, userText, schema, model }) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('ANTHROPIC_API_KEY is not set (an Anthropic API key, not a Claude.ai subscription)');

  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: model || defaultModel(),
      max_tokens: 2048,
      system,
      output_config: { format: { type: 'json_schema', schema } },
      messages: [{ role: 'user', content: userText }],
    }),
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`anthropic ${res.status}: ${detail.slice(0, 300)}`);
  }
  const body = await res.json();
  if (body.stop_reason === 'refusal') throw new Error('model refused to analyze this diff');
  const text = (body.content || []).find((b) => b.type === 'text')?.text;
  if (!text) throw new Error('model returned no text block');
  return JSON.parse(text);
}
