import { Test, TestingModule } from '@nestjs/testing';
import { UserService } from './user.service';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from './auth/jwt.service';
import {
  BadRequestException,
  ConflictException,
  HttpStatus,
  NotFoundException,
} from '@nestjs/common';
import { User } from '@prisma/client';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
describe('UserService', () => {
  let service: UserService;
  let prismaService: PrismaService;
  let jwtService: JwtService;
  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [UserService, PrismaService, JwtService],
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
          secret: 'your-secret-key', // Replace with your own secret key
          signOptions: { expiresIn: '3d' }, // Set the expiration time as per your requirement
        }),
      ],
    }).compile();

    service = module.get<UserService>(UserService);
    prismaService = module.get<PrismaService>(PrismaService);
    jwtService = module.get(JwtService);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createUser', () => {
    it('should create a new user', async () => {
      const createUserDto = {
        email: 'test@example.com',
        password: 'test1234',
      } as User;

      const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

      jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue(null);
      jest.spyOn(prismaService.user, 'create').mockResolvedValue({
        id: 1,
        ...createUserDto,
        password: hashedPassword,
      });

      const result = await service.createUser(createUserDto);

      expect(prismaService.user.findUnique).toHaveBeenCalledWith({
        where: { email: createUserDto.email },
      });
      expect(prismaService.user.create).toHaveBeenCalledWith({
        data: createUserDto,
      });
      expect(result.id).toEqual(1);
      expect(result.email).toEqual(createUserDto.email);
    });

    it('should throw BadRequestException if user already exists', async () => {
      const createUserDto = {
        email: 'test@example.com',
        password: 'test1234',
        id: 1,
      } as User;

      jest
        .spyOn(prismaService.user, 'findUnique')
        .mockResolvedValue(createUserDto);

      await expect(service.createUser(createUserDto)).rejects.toThrow(
        ConflictException,
      );
      expect(prismaService.user.findUnique).toHaveBeenCalledWith({
        where: { email: createUserDto.email },
      });
    });
  });

  describe('findOne', () => {
    it('should return the user with the given ID', async () => {
      const userId = 1;
      const user = { id: userId, email: 'test@example.com' } as User;

      jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue(user);

      const result = await service.findOne(userId);

      expect(prismaService.user.findUnique).toHaveBeenCalledWith({
        where: { id: userId },
      });
      expect(result).toEqual(user);
    });

    it('should throw NotFoundException if user is not found', async () => {
      const userId = 49999;

      jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue(null);

      try {
        await service.findOne(userId);
        fail('NotFoundException was not thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(NotFoundException);
        expect(error.message).toBe('User not found');
      }

      expect(prismaService.user.findUnique).toHaveBeenCalledWith({
        where: { id: userId },
      });
    });
  });

  describe('login', () => {
    it('should return the user with a valid token on successful login', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'test1234',
      };

      const user = {
        id: 1,
        email: loginDto.email,
        password: await bcrypt.hash(loginDto.password, 10),
      } as User;

      jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue(user);
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true as never);
      jest.spyOn(jwtService, 'generateToken').mockReturnValue('test_token');

      const result = await service.login(loginDto);

      expect(prismaService.user.findUnique).toHaveBeenCalledWith({
        where: { email: loginDto.email },
      });
      expect(bcrypt.compare).toHaveBeenCalledWith(
        loginDto.password,
        user.password,
      );
      expect(jwtService.generateToken).toHaveBeenCalledWith(user);
      expect(result).toEqual({ ...user, token: 'test_token' });
    });

    it('should throw BadRequestException if user is not found during login', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'test1234',
      } as User;

      jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue(null);

      try {
        await service.login(loginDto);
        fail('BadRequestException was not thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('User not found');
      }
      // expect(result).toEqual(user);
    });

    it('should throw BadRequestException if password is incorrect during login', async () => {
      const loginDto = {
        email: 'test@example.com',
        password: 'test1234',
      } as User;
      const createUserDto = {
        email: 'test@example.com',
        password: 'test1234',
        id: 1,
      } as User;

      jest.spyOn(prismaService.user, 'create').mockResolvedValue(createUserDto);

      await service.createUser(createUserDto);

      const user = {
        id: 1,
        email: loginDto.email,
        password: await bcrypt.hash('different_password', 10),
      } as User;

      jest.spyOn(prismaService.user, 'findUnique').mockResolvedValue(user);
      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false as never);
      try {
        await service.login(loginDto);
        fail('BadRequestException was not thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('Password is incorrect');
      }
    });
  });
  describe('findAll', () => {
    it('should return an array of users', async () => {
      const users = [
        { id: 1, email: 'user1@example.com', password: 'password1' },
        { id: 2, email: 'user2@example.com', password: 'password2' },
      ] as User[];

      jest.spyOn(prismaService.user, 'findMany').mockResolvedValue(users);

      const result = await service.findAll();

      expect(prismaService.user.findMany).toHaveBeenCalled();
      expect(result).toEqual(users);
    });

    it('should list empty array if no users are found', async () => {
      jest.spyOn(prismaService.user, 'findMany').mockResolvedValue([]);
      const result = await service.findAll();
      expect(prismaService.user.findMany).toHaveBeenCalled();

      expect(result).toEqual([]);
    });
  });

  // Add more test cases for other methods
});
