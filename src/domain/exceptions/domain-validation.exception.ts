export class DomainValidationException extends Error {
    public readonly errors: string[];

    constructor(errors: string | string[]) {
        const errorArray = Array.isArray(errors) ? errors : [errors];
        super(errorArray.join(', '));
        this.name = 'DomainValidationException';
        this.errors = errorArray;
    }
}
