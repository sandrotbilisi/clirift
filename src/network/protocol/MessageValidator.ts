import { z } from 'zod';
import { MessageType } from './Message';
import { ValidationError } from '../../utils/errors';

const messageSchema = z.object({
  id: z.string().uuid(),
  type: z.nativeEnum(MessageType),
  timestamp: z.number().int().positive(),
  nonce: z.string().min(1),
  payload: z.unknown(),
});

/** Validate message envelope structure */
export function validateMessage(data: unknown): void {
  try {
    messageSchema.parse(data);
  } catch (error) {
    throw new ValidationError(`Invalid message structure: ${error}`);
  }
}

/**
 * Validate message timestamp is within an acceptable window.
 * Default tolerance is 30 seconds (stricter than original 5 min for cloud use).
 */
export function validateTimestamp(
  timestamp: number,
  toleranceMs: number = 30_000
): void {
  const diff = Math.abs(Date.now() - timestamp);
  if (diff > toleranceMs) {
    throw new ValidationError(
      `Timestamp out of tolerance: ${diff}ms (max: ${toleranceMs}ms)`
    );
  }
}
