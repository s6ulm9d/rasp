import { create } from 'zustand';

export interface AttackEvent {
  requestId?: string;
  type: string;
  attackType: string;
  score: number;
  payload: string;
  path: string;
  timestamp: number;
  blocked: boolean;
  action: 'blocked' | 'logged';
  chain?: any[];
  behavioralChain?: string[];
  normalizationLog?: string[];
  method?: string;
  ip?: string;
}

interface AttackStore {
  attacks: AttackEvent[];
  selectedAttack: AttackEvent | null;
  addAttack: (attack: AttackEvent) => void;
  setSelectedAttack: (attack: AttackEvent | null) => void;
  clearAttacks: () => void;
}

export const useAttackStore = create<AttackStore>((set) => ({
  attacks: [],
  selectedAttack: null,
  addAttack: (attack) =>
    set((state) => {
      // Keep max 1000 events to maintain performance
      const newAttacks = [attack, ...state.attacks].slice(0, 1000);
      return { attacks: newAttacks };
    }),
  setSelectedAttack: (attack) => set({ selectedAttack: attack }),
  clearAttacks: () => set({ attacks: [], selectedAttack: null }),
}));
