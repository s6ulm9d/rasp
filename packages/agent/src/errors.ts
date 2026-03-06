export class RASPBlockError extends Error {
    public result: any;
    constructor(result: any) {
        super(`ShieldRASP Blocked: ${result.attack_type}`);
        this.name = 'RASPBlockError';
        this.result = result;
    }
}
