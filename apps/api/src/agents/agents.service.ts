import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';

@Injectable()
export class AgentsService {
  constructor(private prisma: PrismaService) {}

  async findAll() { return this.prisma.agent.findMany(); }
  
  async create(data: any) {
    return this.prisma.agent.create({
      data: {
        name: data.name,
        organizationId: data.organizationId
      }
    });
  }

  async delete(id: string) { return this.prisma.agent.delete({ where: { id } }); }

  async rotateKey(id: string) {
    // Generate new key logic here
    return { success: true, newKey: 'rotated_key_' + Math.random().toString(36).substr(2, 9) };
  }
}