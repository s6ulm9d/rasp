import { Controller, Get, Post, Delete, Param, Body } from '@nestjs/common';
import { AgentsService } from './agents.service';

@Controller('agents')
export class AgentsController {
  constructor(private agentsService: AgentsService) {}

  @Get()
  async list() { return this.agentsService.findAll(); }

  @Post()
  async register(@Body() body: any) { return this.agentsService.create(body); }

  @Delete(':id')
  async deregister(@Param('id') id: string) { return this.agentsService.delete(id); }

  @Post(':id/rotate-key')
  async rotateKey(@Param('id') id: string) { return this.agentsService.rotateKey(id); }
}