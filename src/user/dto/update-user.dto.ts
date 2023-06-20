import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';
import { CreateUserDto } from './create-user.dto';
import { PartialType } from '@nestjs/mapped-types';

export class UpdateUserDto extends PartialType(CreateUserDto) {}
export class ChangeUserPasswordDto {
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  password: string;
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  newPassword: string;
}

export class GeneratePasswordResetTokenDto {
  @IsEmail()
  email: string;
}

export class PasswordResetDto {
  @IsEmail()
  email: string;
  @IsNotEmpty()
  @IsString()
  newPassword: string;
  @IsNotEmpty()
  @IsString()
  token: string;
}
