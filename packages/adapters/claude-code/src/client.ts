/**
 * The HTTP client lives in @vera/adapter-core so every adapter shares one implementation of the
 * security-critical parts (error classification and offline token verification). Re-exported here so
 * existing imports from this package keep working.
 */
export {
  type ClientOptions,
  type DecisionStatus,
  DecisionStatusSchema,
  VeraClient,
  VeraRejected,
  VeraUnreachable,
} from '@vera/adapter-core';
