import type { ParamRule, PolicyResponse, ServerTool } from '../api/types'

export interface PolicyPreset {
  id: string
  label: string
  description: string
  apply: (draft: PolicyResponse, tools: ServerTool[]) => PolicyResponse
}

const READ_ONLY_TOOLS = [
  'read_file',
  'read_multiple_files',
  'list_directory',
  'directory_tree',
  'search_files',
  'get_file_info',
]

function paramRule(overrides: Partial<ParamRule>): ParamRule {
  return {
    max_length: null,
    block_patterns: [],
    max_value: null,
    min_value: null,
    denied: false,
    ...overrides,
  }
}

// Transcribed verbatim from docs/policy-cookbook.md — keep these two in sync.
export const POLICY_PRESETS: PolicyPreset[] = [
  {
    id: 'read-only-filesystem',
    label: 'Read-only filesystem',
    description:
      "Allows only read tools (read_file, list_directory, etc.) — write/create/move tools aren't in the list, so any call to them is blocked before it reaches the upstream.",
    apply: (draft, tools) => {
      const available = new Set(tools.map((t) => t.name))
      const allowed = READ_ONLY_TOOLS.filter((name) => available.has(name))
      return { ...draft, mode: 'allowlist', allowed, denied: [] }
    },
  },
  {
    id: 'shell-with-safety-net',
    label: 'Shell access with a safety net',
    description:
      'Allowlists shell_run with a rate limit and a param rule on its command argument: a 200-character cap plus a blocklist of destructive/exfiltration patterns.',
    apply: (draft) => ({
      ...draft,
      mode: 'allowlist',
      allowed: ['shell_run'],
      denied: [],
      rate_limit: '5/minute',
      param_rules: {
        ...draft.param_rules,
        shell_run: {
          ...draft.param_rules.shell_run,
          command: paramRule({
            max_length: 200,
            block_patterns: ['rm\\s+-rf', 'sudo', 'curl.+\\|.+sh', 'wget.+\\|.+sh'],
          }),
        },
      },
    }),
  },
  {
    id: 'block-path-traversal',
    label: 'Block path traversal',
    description:
      "Allowlists read_file and list_directory, and blocks '../'-style traversal and direct reads from /etc/ on read_file's path argument.",
    apply: (draft, tools) => {
      const available = new Set(tools.map((t) => t.name))
      const allowed = ['read_file', 'list_directory'].filter((name) => available.has(name))
      return {
        ...draft,
        mode: 'allowlist',
        allowed,
        denied: [],
        param_rules: {
          ...draft.param_rules,
          read_file: {
            ...draft.param_rules.read_file,
            path: paramRule({ block_patterns: ['\\.\\./', '^/etc/'] }),
          },
        },
      }
    },
  },
  {
    id: 'deny-parameter-ssrf',
    label: 'Deny a parameter outright (SSRF)',
    description:
      "Allowlists search_jobs and denies its proxies argument entirely — any call that includes a proxies value at all is blocked, regardless of what it is.",
    apply: (draft) => ({
      ...draft,
      mode: 'allowlist',
      allowed: ['search_jobs'],
      denied: [],
      param_rules: {
        ...draft.param_rules,
        search_jobs: {
          ...draft.param_rules.search_jobs,
          proxies: paramRule({ denied: true }),
        },
      },
    }),
  },
  {
    id: 'numeric-bounds',
    label: 'Numeric bounds',
    description:
      "Caps search_jobs' results_wanted argument at 50, in passthrough mode — useful for bounding a 'how many results' argument without restricting which tools can be called.",
    apply: (draft) => ({
      ...draft,
      mode: 'passthrough',
      param_rules: {
        ...draft.param_rules,
        search_jobs: {
          ...draft.param_rules.search_jobs,
          results_wanted: paramRule({ max_value: 50 }),
        },
      },
    }),
  },
]
