export class SecurityBlockException extends Error {
    public details: any;

    constructor(message: string, details: any = {}) {
        super(message);
        this.name = 'SecurityBlockException';
        this.details = details;
    }
}
