// The closed capability taxonomy the LLM may emit, and how each maps to score.
// The model NEVER emits a score — it emits typed, evidence-anchored findings,
// and this table turns them into caps/penalties. Everything here only LOWERS the
// score (caps are ceilings; penalties are deductions), preserving monotonicity.

export const CAPABILITIES = [
  'NET_OUTBOUND_NEW_HOST',   // new network call to a new host
  'NET_COVERT_CHANNEL',      // DNS TXT / blockchain / pastebin-style exfil
  'EXEC_SUBPROCESS',         // child_process / os.system / spawn
  'EXEC_DYNAMIC_CODE',       // eval / Function / exec of a computed string
  'ENV_CREDENTIAL_ACCESS',   // reads env vars with credential-shaped names
  'FS_READ_SENSITIVE',       // reads ~/.ssh, .npmrc, wallets, cloud creds
  'CRYPTO_DECRYPT_BLOB',     // decrypts then runs/loads the result
  'PERSISTENCE',             // writes crontab / rc files / autostart
  'DESER_UNSAFE',            // pickle/Marshal/etc. on external data
  'OBFUSCATION',             // packed / string-array / charcode-assembled
  'DATA_FLOW_CRED_TO_NET',   // credential-shaped read flows to an outbound call
  'CAP_MISMATCH_UTILITY',    // a trivial lib suddenly gains net/exec/fs powers
  'SELF_MODIFYING',          // rewrites its own files at runtime
  'ANALYZER_DIRECTED_TEXT',  // text addressing the analyzer/AI (prompt injection)
  'NONE',
];

// cap = hard ceiling; penalty = deduction from 100. Both only lower the score.
export const SCORING = {
  ANALYZER_DIRECTED_TEXT: { cap: 5,  severity: 'critical', label: 'text tries to manipulate the analyzer (prompt injection)' },
  DATA_FLOW_CRED_TO_NET:  { cap: 15, severity: 'critical', label: 'credential-shaped data flows to an outbound network call' },
  CRYPTO_DECRYPT_BLOB:    { penalty: 30, severity: 'high', label: 'decrypts a blob and executes/loads the result' },
  NET_COVERT_CHANNEL:     { penalty: 30, severity: 'high', label: 'uses a covert channel (DNS/blockchain/paste) for network I/O' },
  FS_READ_SENSITIVE:      { penalty: 35, severity: 'high', label: 'reads sensitive files (ssh keys, npmrc, wallets, cloud creds)' },
  ENV_CREDENTIAL_ACCESS:  { penalty: 25, severity: 'high', label: 'reads credential-shaped environment variables' },
  EXEC_DYNAMIC_CODE:      { penalty: 25, severity: 'high', label: 'executes dynamically constructed code' },
  DESER_UNSAFE:           { penalty: 20, severity: 'medium', label: 'unsafe deserialization of external data' },
  PERSISTENCE:            { penalty: 20, severity: 'medium', label: 'installs persistence (crontab/rc/autostart)' },
  OBFUSCATION:            { penalty: 20, severity: 'medium', label: 'newly obfuscated code' },
  SELF_MODIFYING:         { penalty: 20, severity: 'medium', label: 'rewrites its own files at runtime' },
  NET_OUTBOUND_NEW_HOST:  { penalty: 15, severity: 'medium', label: 'new outbound network call to a new host' },
  CAP_MISMATCH_UTILITY:   { penalty: 15, severity: 'medium', label: 'capabilities unrelated to the package’s stated purpose' },
  EXEC_SUBPROCESS:        { penalty: 12, severity: 'medium', label: 'spawns a subprocess' },
  NONE:                   {},
};

// JSON Schema for the structured-output contract. The model returns ONLY this.
export function findingsSchema(nonceField) {
  return {
    type: 'object',
    additionalProperties: false,
    required: ['attn', 'findings'],
    properties: {
      attn: { type: 'string', description: 'echo the verification token exactly' },
      findings: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['capability', 'file', 'evidence', 'confidence'],
          properties: {
            capability: { type: 'string', enum: CAPABILITIES },
            file: { type: 'string', description: 'the hunk id or file path the evidence is in' },
            evidence: { type: 'string', description: 'the literal token/line that justifies the finding' },
            confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
          },
        },
      },
    },
    // nonceField documents which token must be echoed; enforced by the harness.
    'x-nonce-field': nonceField || 'attn',
  };
}
