import { Module } from '@nestjs/common';
import { EventsModule } from './events/events.module';
import { AgentsModule } from './agents/agents.module';
import { RulesModule } from './rules/rules.module';
import { DatabaseModule } from './database/database.module';
import { WebsocketModule } from './websocket/websocket.module';

@Module({
  imports: [
    DatabaseModule,
    EventsModule,
    AgentsModule,
    RulesModule,
    WebsocketModule
  ],
})
export class AppModule {}