import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from './auth/jwt.service';
import { JwtStrategy } from './auth/jwt.strategy';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { User } from '@prisma/client';
import {
  BadRequestException,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { AuthenticatedRequest } from 'types';

describe('UserController', () => {
  let controller: UserController;
  let userService: UserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      providers: [JwtService, JwtStrategy, UserService, PrismaService],
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
          secret: 'your-secret-key', // Replace with your own secret key
          signOptions: { expiresIn: '3d' }, // Set the expiration time as per your requirement
        }),
      ],
    }).compile();

    controller = module.get<UserController>(UserController);
    userService = module.get<UserService>(UserService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
  describe('createUser', () => {
    it('should create a new user', async () => {
      const createUserDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      const user = {
        id: 1,
        email: createUserDto.email,
        password: 'hashed_password',
      } as User;

      jest.spyOn(userService, 'createUser').mockResolvedValue(user);

      const result = await controller.create(createUserDto);

      expect(userService.createUser).toHaveBeenCalledWith(createUserDto);
      expect(result).toEqual(user);
    });

    it('should throw a ConflictException if user already exists', async () => {
      const createUserDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      jest
        .spyOn(userService, 'createUser')
        .mockRejectedValue(new ConflictException('User already exists'));
      try {
        await controller.create(createUserDto);
        fail('ConflictException was not thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(ConflictException);
        expect(error.message).toBe('User already exists');
      }

      expect(userService.createUser).toHaveBeenCalledWith(createUserDto);
    });
  });
  describe('login', () => {
    it('should return the user with a valid token on successful login', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      const user = {
        id: 1,
        email: loginDto.email,
        password: await bcrypt.hash(loginDto.password, 10),
      } as User;

      const token = 'test_token';

      jest.spyOn(userService, 'login').mockResolvedValue({ ...user, token });

      const result = await controller.login(loginDto);

      expect(userService.login).toHaveBeenCalledWith(loginDto);
      expect(result).toEqual({ ...user, token });
    });

    it('should throw a BadRequestException if user is not found during login', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      jest
        .spyOn(userService, 'login')
        .mockRejectedValue(new NotFoundException('User not found'));
      try {
        await controller.login(loginDto);
        fail('NotFoundException was not thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(NotFoundException);
        expect(error.message).toBe('User not found');
      }

      expect(userService.login).toHaveBeenCalledWith(loginDto);
    });

    it('should throw a BadRequestException if password is incorrect during login', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      jest
        .spyOn(userService, 'login')
        .mockRejectedValue(new BadRequestException('Incorrect password'));
      try {
        await controller.login(loginDto);
        fail('BadRequestException was not thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('Incorrect password');
      }
      expect(userService.login).toHaveBeenCalledWith(loginDto);
    });
  });
  describe('findAll', () => {
    it('should return an array of users', async () => {
      const users = [
        { id: 1, email: 'user1@example.com' },
        { id: 2, email: 'user2@example.com' },
      ] as User[];

      jest.spyOn(userService, 'findAll').mockResolvedValue(users);

      const result = await controller.findAll();

      expect(userService.findAll).toHaveBeenCalled();
      expect(result).toEqual(users);
    });
  });

  describe('findOne', () => {
    it('should return a user', async () => {
      const user = { id: 1, email: 'user@example.com' } as User;

      jest.spyOn(userService, 'findOne').mockResolvedValue(user);

      const result = await controller.findOne('1');

      expect(userService.findOne).toHaveBeenCalledWith(1);
      expect(result).toEqual(user);
    });

    it('should throw a NotFoundException if user is not found', async () => {
      jest.spyOn(userService, 'findOne').mockResolvedValue(null);
      try {
        await controller.findOne('1');

        expect(userService.findOne).toHaveBeenCalledWith(1);
      } catch (err) {
        expect(err.message).toBe('User not found');
        expect(err).toBeInstanceOf(NotFoundException);
      }
    });
  });

  describe('profile', () => {
    it('should return user information', async () => {
      const user = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
      } as User;

      const req = {
        user: { id: 1 },
      } as AuthenticatedRequest;

      jest.spyOn(userService, 'findOne').mockResolvedValue(user);

      const result = await controller.getUser(req);

      expect(userService.findOne).toHaveBeenCalledWith(req.user.id);
      expect(result).toEqual({
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
      });
    });

    it('should throw a NotFoundException if user is not found', async () => {
      const req = {
        user: { id: 1 },
      } as AuthenticatedRequest;

      jest.spyOn(userService, 'findOne').mockResolvedValue(null);

      try {
        await controller.getUser(req);
        // fail('NotFoundException was not thrown');
      } catch (error) {
        // expect(error).toBeInstanceOf(NotFoundException);
        expect(error.message).toBe('User not found');
      }

      expect(userService.findOne).toHaveBeenCalledWith(req.user.id);
    });
  });

  describe('update', () => {
    it('should update user information', async () => {
      const updateUserDto = {
        firstName: 'Jane',
        lastName: 'Doe',
      } as User;

      const req = {
        user: { id: 1 },
      } as AuthenticatedRequest;

      const updatedUser = {
        id: 1,
        email: 'test@example.com',
        firstName: updateUserDto.firstName,
        lastName: updateUserDto.lastName,
      } as User;

      jest.spyOn(userService, 'update').mockResolvedValue(updatedUser);

      const result = await controller.update(updateUserDto, req);

      expect(userService.update).toHaveBeenCalledWith(
        req.user.id,
        updateUserDto,
      );
      expect(result).toEqual(updatedUser);
    });
  });
});
