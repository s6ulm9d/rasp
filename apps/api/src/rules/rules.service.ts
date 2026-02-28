import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';

@Injectable()
export class RulesService {
  constructor(private prisma: PrismaService) {}

  async findAll() { return this.prisma.detectionRule.findMany(); }

  async setStatus(id: string, enabled: boolean) {
    return this.prisma.detectionRule.update({
      where: { id },
      data: { enabled }
    });
  }

  async markFalsePositive(id: string) {
    return this.prisma.falsePositive.create({
      data: { ruleId: id, hash: 'generated_hash_' + Date.now() }
    });
  }
}