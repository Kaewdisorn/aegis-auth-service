export class Email {
    private static readonly EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    private constructor(public readonly value: string) { }

    static create(email: string): Email {
        if (!email || !Email.EMAIL_REGEX.test(email)) {
            throw new Error('Invalid email format');
        }
        return new Email(email.toLowerCase().trim());
    }

    equals(other: Email): boolean {
        return this.value === other.value;
    }

    toString(): string {
        return this.value;
    }
}