import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Prisma, User } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { JwtService } from './auth/jwt.service';
import { v4 as uuidv4 } from 'uuid';
@Injectable()
export class UserService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async createUser(data: Prisma.UserCreateInput) {
    try {
      const oldUser = await this.prisma.user.findUnique({
        where: { email: data.email },
      });
      if (oldUser) {
        throw new ConflictException('User already exists');
      }
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = (await bcrypt.hash(data.password, salt)) as string;
      data.password = hashedPassword;
      return await this.prisma.user.create({ data });
    } catch (error) {
      throw error;
    }
  }
  async login(data: Prisma.UserCreateInput) {
    try {
      const user = await this.prisma.user.findUnique({
        where: { email: data.email },
      });
      if (!user) {
        throw new BadRequestException('User not found');
      }
      const isPassword = await bcrypt.compare(data.password, user.password);
      if (!isPassword) {
        throw new BadRequestException('Password is incorrect');
      }
      const token = this.jwtService.generateToken(user);
      return { ...user, token };
    } catch (error) {
      throw error;
    }
  }

  async findAll() {
    try {
      return await this.prisma.user.findMany();
    } catch (error) {
      console.log(error);
    }
  }

  async findOne(id: number) {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: id },
      });
      if (!user) {
        throw new NotFoundException('User not found');
      }
      return user;
    } catch (error) {
      throw error;
    }
  }

  update(id: number, updateUserDto: Partial<Prisma.UserUpdateInput>) {
    try {
      return this.prisma.user.update({
        where: { id: id },
        data: updateUserDto,
      });
    } catch (error) {
      console.log(error);
    }
  }

  deleteUser(id: number) {
    try {
      const user = this.prisma.user.findUnique({
        where: { id: id },
      });
      if (!user) {
        throw new BadRequestException('User not found');
      }
      return this.prisma.user.delete({
        where: { id: id },
      });
    } catch (error) {
      console.log(error);
    }
  }
  async changePassword(
    userId: number,
    currentPassword: string,
    newPassword: string,
  ) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password,
    );
    if (!isPasswordValid) {
      throw new BadRequestException('Invalid current password');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword },
    });

    return {
      message: 'Password Changed successfully',
    };
  }
  async generatePasswordResetToken(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    const resetToken = uuidv4();
    const hashedResetToken = await bcrypt.hash(resetToken, 10);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { passwordResetToken: hashedResetToken },
    });
    // TODO : send notification to user
    return {
      message: 'Password reset token sent to your email',
    };
  }

  async resetPassword(email: string, token: string, newPassword: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    const isTokenValid = await bcrypt.compare(token, user.passwordResetToken);
    if (!isTokenValid) {
      throw new BadRequestException('Invalid reset token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await this.prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword, passwordResetToken: null },
    });
    return {
      message: ' Password reset successfully',
    };
  }
}
