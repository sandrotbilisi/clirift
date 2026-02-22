import { v4 as uuidv4 } from 'uuid';
import { Message, MessageType } from './Message';
import { generateToken } from '../../crypto/password';

/**
 * Create a new message
 * @param type Message type
 * @param payload Message payload
 * @returns Message object
 */
export function createMessage<T>(type: MessageType, payload: T): Message<T> {
  return {
    id: uuidv4(),
    type,
    timestamp: Date.now(),
    nonce: generateToken(16), // 16-byte nonce
    payload,
  };
}

/**
 * Serialize message to JSON string
 * @param message Message object
 * @returns JSON string
 */
export function serializeMessage(message: Message): string {
  return JSON.stringify(message);
}

/**
 * Deserialize JSON string to message
 * @param data JSON string
 * @returns Message object
 */
export function deserializeMessage(data: string): Message {
  return JSON.parse(data);
}
