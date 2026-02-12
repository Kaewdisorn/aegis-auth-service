import { v4 as uuidv4, v5 as uuidv5, validate as uuidValidate } from 'uuid';

// /**
//  * Application-wide namespace UUID for generating deterministic UUIDs
//  * This should NEVER be changed in production as it will affect all existing UUIDs
//  */
// export const APP_NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'; // DNS namespace

// /**
//  * Generates a random UUID v4
//  * @returns A random UUID string
//  */
export function generateUUID(): string {
    return uuidv4();
}

// /**
//  * Generates a deterministic UUID v5 from a string
//  * Same input string will always produce the same UUID
//  * @param value - The string to convert to UUID
//  * @param namespace - Optional custom namespace UUID (defaults to APP_NAMESPACE)
//  * @returns A deterministic UUID string
//  */
// export function generateUUIDFromString(
//     value: string,
//     namespace: string = APP_NAMESPACE,
// ): string {
//     // Normalize the string (trim and lowercase) for consistency
//     const normalizedValue = value.trim().toLowerCase();
//     return uuidv5(normalizedValue, namespace);
// }

// /**
//  * Generates a deterministic UUID from an email address
//  * @param email - The email address
//  * @returns A deterministic UUID string
//  */
// export function generateUUIDFromEmail(email: string): string {
//     return generateUUIDFromString(email);
// }

// /**
//  * Validates if a string is a valid UUID
//  * @param uuid - The string to validate
//  * @returns true if the string is a valid UUID
//  */
// export function isValidUUID(uuid: string): boolean {
//     return uuidValidate(uuid);
// }

// /**
//  * Validates and returns the UUID, or throws an error
//  * @param uuid - The UUID string to validate
//  * @returns The validated UUID string
//  * @throws Error if the UUID is invalid
//  */
// export function validateUUID(uuid: string): string {
//     if (!isValidUUID(uuid)) {
//         throw new Error(`Invalid UUID format: ${uuid}`);
//     }
//     return uuid;
// }
