// src/auth/jwt.service.ts

import { Injectable } from '@nestjs/common';
import { JwtService as NestJwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';

@Injectable()
export class JwtService {
  constructor(private readonly nestJwtService: NestJwtService) {}

  generateToken(payload: User): string {
    return this.nestJwtService.sign(payload);
  }

  verifyToken(token: string): any {
    try {
      return this.nestJwtService.verify(token);
    } catch (error) {
      return null;
    }
  }
}
