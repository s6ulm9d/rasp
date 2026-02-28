import { Controller, Get, Put, Post, Param } from '@nestjs/common';
import { RulesService } from './rules.service';

@Controller('rules')
export class RulesController {
  constructor(private rulesService: RulesService) {}

  @Get()
  async list() { return this.rulesService.findAll(); }

  @Put(':id/enable')
  async enable(@Param('id') id: string) { return this.rulesService.setStatus(id, true); }

  @Put(':id/disable')
  async disable(@Param('id') id: string) { return this.rulesService.setStatus(id, false); }

  @Post(':id/false-positive')
  async falsePositive(@Param('id') id: string) { return this.rulesService.markFalsePositive(id); }
}