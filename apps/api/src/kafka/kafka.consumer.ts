import { Injectable, OnModuleInit } from '@nestjs/common';
import { Kafka } from 'kafkajs';
import { EventsGateway } from '../websocket/events.gateway';
import { PrismaService } from '../database/prisma.service';

@Injectable()
export class KafkaConsumer implements OnModuleInit {
    private kafka = new Kafka({
        clientId: 'api-consumer',
        brokers: [process.env.KAFKA_BROKERS || 'localhost:9092']
    });
    private consumer = this.kafka.consumer({ groupId: 'api-group' });

    constructor(
        private eventsGateway: EventsGateway,
        private prisma: PrismaService
    ) { }

    async onModuleInit() {
        await this.consumer.connect();
        await this.consumer.subscribe({ topic: 'rasp.events.raw', fromBeginning: false });

        await this.consumer.run({
            eachMessage: async ({ topic, partition, message }) => {
                if (!message.value) return;
                try {
                    const event = JSON.parse(message.value.toString());
                    // 1. Save to DB
                    await this.prisma.attackEvent.create({
                        data: {
                            id: event.event_id,
                            agentId: event.agent_id,
                            timestamp: new Date(event.timestamp_ns / 1000000),
                            attackType: event.attack_type,
                            attackSubtype: event.attack_subtype,
                            confidenceScore: event.confidence_score,
                            severity: event.severity,
                            serviceName: event.service_name,
                            environment: event.environment,
                            sourceIp: event.source_ip,
                            wasBlocked: event.was_blocked
                        }
                    });
                    // 2. Broadcast to UI
                    this.eventsGateway.broadcastAttackEvent(event);
                } catch (err) {
                    console.error('Failed processing Kafka message', err);
                }
            },
        });
    }
}
