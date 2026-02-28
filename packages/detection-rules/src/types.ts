export interface Rule {
    id: string;
    name: string;
    type: string;
    pattern: string;
    action: 'block' | 'log';
    severity: 'low' | 'medium' | 'high' | 'critical';
    enabled: boolean;
}
