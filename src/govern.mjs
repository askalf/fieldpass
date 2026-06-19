/**
 * GovernedBrowser — the orchestrator that ties the three planes together:
 *
 *   perception (page -> agent): capture -> detect -> policy -> safe view
 *   action     (agent -> page): act() gate (allowlist + step-up on danger)
 *   identity   (secrets)       : login() leases from keeper, fills at CDP layer
 *
 * For the prototype, KeeperStub and the context broker are in-memory but the
 * seams are real: swap KeeperStub for the @askalf/keeper client and `policy`
 * for a warden-wired WardenClient and this becomes the production object.
 */

import { captureFromHtml, captureFromBridge } from './capture.mjs';
import { detect } from './detect.mjs';
import { applyEscalations } from './judge.mjs';
import { buildSafeObservation } from './neutralize.mjs';
import { makePolicy } from './policy.mjs';
import { DANGEROUS_ACTION, CREDENTIAL_FIELD, SENSITIVE, matchAny, hostOf } from './patterns.mjs';

/** Action types the gate knows how to reason about; anything else is denied. */
const KNOWN_ACTIONS = new Set(['navigate', 'click', 'type', 'submit']);

/**
 * Stands in for @askalf/keeper. The agent calls login(persona); the credential
 * value is fetched here and written into the page at the CDP layer. The agent
 * receives only an opaque lease handle — the secret never enters its context,
 * its script, or any log. That property is the whole point; keep it when wiring
 * the real keeper.
 */
export class KeeperStub {
  constructor(secrets = {}) {
    this._secrets = secrets; // { persona: { user, pass } }
    this.leases = new Map();
    this._seq = 0;
  }
  lease(persona, ttlMs = 60000) {
    if (!this._secrets[persona]) throw new Error(`keeper: no secret for persona "${persona}"`);
    const id = `lease_${persona}_${++this._seq}`;
    this.leases.set(id, { persona, expiresIn: ttlMs });
    return { id, persona }; // NB: no secret material in the returned handle
  }
  /** Resolve a lease to its secret — only ever called inside the CDP fill. */
  _resolve(leaseId) {
    const l = this.leases.get(leaseId);
    if (!l) throw new Error('keeper: unknown or expired lease');
    return this._secrets[l.persona];
  }
}

export class GovernedBrowser {
  /**
   * @param {Object} opts
   * @param {string[]} [opts.allowlist]  host suffixes the agent may navigate to
   * @param {KeeperStub} [opts.keeper]
   * @param {*} [opts.policy]            WardenClient (defaults to local-only)
   * @param {string} [opts.task]         trusted task string, fenced into the safe view
   */
  constructor(opts = {}) {
    this.allowlist = opts.allowlist || [];
    this.keeper = opts.keeper || new KeeperStub();
    this.policy = opts.policy || makePolicy();
    this.judge = opts.judge || null; // optional LLMJudge for novel-phrasing escalation
    this.task = opts.task || '';
    this.audit = [];
  }

  _log(entry) { this.audit.push({ ...entry }); return entry; }

  /**
   * Perception plane. Accepts either static HTML or a live bridge target, runs
   * it through the firewall, and returns the safe, model-facing view.
   * @returns {Promise<{observation, detection, decision, safe}>}
   */
  async observe(input) {
    // Prefer the live CDP bridge whenever one is reachable — even for inline
    // `html`, which captureFromBridge renders via page.setContent so real
    // computed styles resolve class-based hiding. The static parser is the
    // browserless fallback (CI, offline demos), not a silent override that
    // would bypass the whole reason the bridge exists on a hostile page.
    const hasBridge = input.browserWSEndpoint != null || input.browserURL != null;
    const observation = hasBridge
      ? await captureFromBridge(input)
      : captureFromHtml(input.html, { url: input.url });
    const deterministic = detect(observation);

    // Optional second line: escalate the ambiguous residue to an LLM judge.
    let escalation = null;
    let detection = deterministic;
    if (this.judge) {
      escalation = await this.judge.review(observation, deterministic, { url: observation.url, task: this.task });
      if (escalation.escalations.length) detection = applyEscalations(deterministic, escalation.escalations, observation);
    }

    const decision = await this.policy.decide(detection, { url: observation.url });
    const safe = buildSafeObservation(observation, detection, { task: this.task });
    this._log({
      plane: 'perception', url: observation.url, verdict: detection.verdict,
      decision: decision.action, redactions: safe.redactions.length,
      escalated: escalation ? escalation.escalations.length : 0,
    });
    return { observation, detection, decision, safe, escalation };
  }

  /**
   * Action plane. Gate an outbound action before it touches the page.
   * @param {{type:'navigate'|'click'|'type'|'submit', url?, selector?, text?, intent?, credential?}} action
   * @returns {{allowed:boolean, reason:string, requireApproval?:boolean}}
   */
  gate(action = {}) {
    // Default-deny: the gate only passes action types it can positively reason
    // about. An unrecognized (or missing) type is refused, never waved through.
    if (!KNOWN_ACTIONS.has(action.type)) {
      return this._log({ plane: 'action', action, allowed: false, reason: `unrecognized action type "${action.type}" — denied (gate is default-deny)` });
    }
    if (action.type === 'navigate') {
      const host = hostOf(action.url);
      const ok = this.allowlist.length === 0 ||
        this.allowlist.some((d) => host === d || (host && host.endsWith('.' + d)));
      if (!ok) return this._log({ plane: 'action', action, allowed: false, reason: `navigation to ${host || action.url} is off-allowlist` });
    }
    if (action.type === 'type') {
      // Refuse to key a secret into a field whether or not the caller flagged
      // it: infer from a credential-shaped target or a secret-looking value.
      // The agent obtaining and typing a secret defeats the whole identity plane.
      const looksCredential =
        action.credential ||
        CREDENTIAL_FIELD.test(action.selector || '') ||
        matchAny(action.text || '', SENSITIVE);
      if (looksCredential) {
        return this._log({ plane: 'action', action: { ...action, text: '<redacted>' }, allowed: false, reason: 'credential-shaped field/value — must be injected via login(), never typed by the agent' });
      }
    }
    if (action.type === 'click' || action.type === 'submit') {
      const blob = `${action.selector || ''} ${action.text || ''} ${action.intent || ''}`;
      if (matchAny(blob, DANGEROUS_ACTION)) {
        return this._log({ plane: 'action', action, allowed: false, requireApproval: true, reason: 'high-authority action — step-up approval required' });
      }
    }
    return this._log({ plane: 'action', action: action.credential ? { ...action, text: '<redacted>' } : action, allowed: true, reason: 'ok' });
  }

  /**
   * Identity plane. Lease a credential from keeper and fill it at the CDP layer.
   * The agent gets the lease handle back, not the secret.
   * @param {string} persona
   * @param {{page?, userSelector?, passSelector?}} [target] live page for real fills
   */
  async login(persona, target = {}) {
    const handle = this.keeper.lease(persona);
    if (target.page) {
      const { user, pass } = this.keeper._resolve(handle.id);
      // CDP-layer fill: value is set on the element, never surfaced to the agent.
      if (target.userSelector) await target.page.type(target.userSelector, user);
      if (target.passSelector) await target.page.type(target.passSelector, pass);
    }
    this._log({ plane: 'identity', persona, lease: handle.id, filled: !!target.page });
    return handle; // opaque
  }
}

export { detect, captureFromHtml, captureFromBridge, buildSafeObservation };
