export class Password {
    private static readonly MIN_LENGTH = 8;
    private static readonly MAX_LENGTH = 128;

    private constructor(public readonly value: string) { }

    static create(plainPassword: string): Password {
        const errors = Password.validate(plainPassword);
        if (errors.length > 0) {
            throw new Error(`Invalid password: ${errors.join(', ')}`);
        }

        return new Password(plainPassword);
    }

    private static validate(password: string): string[] {
        const errors: string[] = [];

        if (!password) {
            errors.push('Password is required');
            return errors;
        }

        if (password.length < Password.MIN_LENGTH) {
            errors.push(`Password must be at least ${Password.MIN_LENGTH} characters`);
        }

        if (password.length > Password.MAX_LENGTH) {
            errors.push(`Password must be at most ${Password.MAX_LENGTH} characters`);
        }

        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }

        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }

        if (!/[0-9]/.test(password)) {
            errors.push('Password must contain at least one number');
        }

        return errors;
    }

}

