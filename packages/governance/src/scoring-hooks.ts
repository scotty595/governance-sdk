/**
 * Re-scoring an agent, and the fleet, from what they have actually done.
 *
 * `assessAgent()` scores the posture an agent *declares* — auth, guardrails,
 * observability, audit. These hooks adjust that against its audit history
 * (block rate, injection hits, approval misses) so a well-configured agent
 * that misbehaves does not keep its score. Split out of the instance because
 * the only instance state they need is storage.
 */

import { assessAgent, assessFleet, getGovernanceLevel, computeCompositeScore } from "./scorer.js";
import { computeBehavioralAdjustments, applyBehavioralAdjustments } from "./behavioral-scorer.js";
import type { AgentStatus, GovernanceAssessment, FleetSummary } from "./types.js";
import type { GovernanceStorage, StoredAgent } from "./storage.js";
import type { AgentRegistration } from "./types.js";

/** How many audit events to weigh when adjusting a score. */
const BEHAVIORAL_WINDOW = 200;

export interface ScoringHooks {
  scoreAgent(agentId: string): Promise<GovernanceAssessment | null>;
  scoreFleet(): Promise<{ assessments: GovernanceAssessment[]; summary: FleetSummary }>;
}

export function createScoringHooks(
  storage: GovernanceStorage,
  storedToRegistration: (agent: StoredAgent) => AgentRegistration,
): ScoringHooks {
  async function scoreAgent(agentId: string): Promise<GovernanceAssessment | null> {
    const agent = await storage.getAgent(agentId);
    if (!agent) return null;

    const registration = storedToRegistration(agent);
    const assessment = assessAgent(agentId, registration);

    // Apply behavioral adjustments from audit history
    const auditEvents = await storage.queryAuditEvents({ agentId, limit: BEHAVIORAL_WINDOW });
    if (auditEvents.length > 0) {
      const behavioral = computeBehavioralAdjustments({
        events: auditEvents,
        declaredTools: agent.tools,
      });
      assessment.dimensions = applyBehavioralAdjustments(
        assessment.dimensions, behavioral.adjustments,
      );
    }

    // Recompute composite score from adjusted dimensions
    const newScore = computeCompositeScore(assessment.dimensions);
    const newLevel = getGovernanceLevel(newScore);
    assessment.compositeScore = newScore;
    assessment.level = newLevel;
    assessment.status = newScore >= 60 ? "approved" : newScore > 0 ? "flagged" : "registered";

    await storage.updateAgent(agentId, {
      compositeScore: newScore,
      governanceLevel: newLevel.level,
      status: assessment.status,
    });
    return assessment;
  }

  async function scoreFleet() {
    const agents = await storage.listAgents();
    const registrations = agents.map((a) => ({
      id: a.id,
      registration: storedToRegistration(a),
    }));
    const fleet = assessFleet(registrations);

    // Apply behavioral adjustments to each agent assessment
    for (const assessment of fleet.assessments) {
      const agent = agents.find((a) => a.id === assessment.agentId);
      if (!agent) continue;

      const auditEvents = await storage.queryAuditEvents({ agentId: agent.id, limit: BEHAVIORAL_WINDOW });
      if (auditEvents.length > 0) {
        const behavioral = computeBehavioralAdjustments({
          events: auditEvents,
          declaredTools: agent.tools,
        });
        assessment.dimensions = applyBehavioralAdjustments(
          assessment.dimensions, behavioral.adjustments,
        );
      }

      const newScore = computeCompositeScore(assessment.dimensions);
      const newLevel = getGovernanceLevel(newScore);
      assessment.compositeScore = newScore;
      assessment.level = newLevel;
      assessment.status = newScore >= 60 ? "approved" : newScore > 0 ? "flagged" : "registered";
    }

    // Recompute fleet summary with adjusted scores
    const scores = fleet.assessments.map((a) => a.compositeScore);
    const avgScore = scores.length > 0
      ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
      : 0;
    fleet.summary.averageScore = avgScore;
    fleet.summary.fleetLevel = getGovernanceLevel(avgScore);

    const sorted = [...fleet.assessments].sort((a, b) => b.compositeScore - a.compositeScore);
    const highest = sorted[0];
    const lowest = sorted[sorted.length - 1];
    fleet.summary.highestScoring = highest
      ? { name: highest.agentName, score: highest.compositeScore } : null;
    fleet.summary.lowestScoring = lowest
      ? { name: lowest.agentName, score: lowest.compositeScore } : null;

    // Recount by status and level
    const byStatus: Record<AgentStatus, number> = {
      registered: 0, assessed: 0, approved: 0, flagged: 0, deprecated: 0, quarantined: 0,
    };
    const byLevel: Record<number, number> = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };
    for (const a of fleet.assessments) {
      byStatus[a.status] += 1;
      byLevel[a.level.level] = (byLevel[a.level.level] || 0) + 1;
    }
    fleet.summary.byStatus = byStatus;
    fleet.summary.byLevel = byLevel;

    // Update fleet recommendations
    const recs: string[] = [];
    if (byStatus.flagged > 0) recs.push(`${byStatus.flagged} agent(s) below governance threshold — review immediately`);
    // `byLevel` is keyed by number, so it carries an index signature; level 0
    // is seeded above, the fallback only makes that visible to the compiler.
    const unregistered = byLevel[0] ?? 0;
    if (unregistered > 0) recs.push(`${unregistered} agent(s) at Level 0 (Unregistered) — complete registration`);
    if (avgScore < 60) recs.push("Fleet average below 60 — prioritize governance improvements before scaling");
    fleet.summary.recommendations = recs;

    return fleet;
  }

  return { scoreAgent, scoreFleet };
}
