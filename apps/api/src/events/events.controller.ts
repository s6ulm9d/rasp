import { Controller, Get, Param, Query } from '@nestjs/common';
import { EventsService } from './events.service';

@Controller('events')
export class EventsController {
    constructor(private readonly eventsService: EventsService) { }

    @Get()
    async getEvents(@Query('limit') limit = 50) {
        return this.eventsService.getRecentEvents(Number(limit));
    }

    @Get(':id')
    async getEventDetail(@Param('id') id: string) {
        return this.eventsService.getById(id);
    }
}
