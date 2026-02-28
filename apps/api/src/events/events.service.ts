import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';

@Injectable()
export class EventsService {
    constructor(private prisma: PrismaService) { }

    async getRecentEvents(limit: number) {
        return this.prisma.attackEvent.findMany({
            take: limit,
            orderBy: { timestamp: 'desc' }
        });
    }

    async getById(id: string) {
        return this.prisma.attackEvent.findUnique({
            where: { id },
            include: { agent: true }
        });
    }
}
