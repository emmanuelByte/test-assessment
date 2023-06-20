import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  HttpCode,
  Req,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto, LoginDto } from './dto/create-user.dto';
import {
  ChangeUserPasswordDto,
  UpdateUserDto,
  GeneratePasswordResetTokenDto,
  PasswordResetDto,
} from './dto/update-user.dto';
import { AuthGuard } from '@nestjs/passport';
import { AuthenticatedRequest } from 'types';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('/create-user')
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.createUser(createUserDto);
  }
  @HttpCode(200)
  @Post('/login')
  login(@Body() loginDto: LoginDto) {
    return this.userService.login(loginDto);
  }

  @Get()
  findAll() {
    return this.userService.findAll();
  }

  @Get('profile')
  @UseGuards(AuthGuard('jwt'))
  async getUser(@Req() req: AuthenticatedRequest) {
    return await this.userService.findOne(req.user.id);
  }
  @UseGuards(AuthGuard('jwt'))
  @Patch('update')
  update(
    @Body() updateUserDto: UpdateUserDto,
    @Req() req: AuthenticatedRequest,
  ) {
    return this.userService.update(req.user.id, updateUserDto);
  }
  @UseGuards(AuthGuard('jwt'))
  @Patch('change-password')
  changePassword(
    @Body() changeUserPasswordDto: ChangeUserPasswordDto,
    @Req() req: AuthenticatedRequest,
  ) {
    return this.userService.changePassword(
      req.user.id,
      changeUserPasswordDto.password,
      changeUserPasswordDto.newPassword,
    );
  }

  @Post('generate-reset-token')
  generateResetPassword(@Body() data: GeneratePasswordResetTokenDto) {
    return this.userService.generatePasswordResetToken(data.email);
  }

  @Patch('reset-password')
  resetPassword(@Body() data: PasswordResetDto) {
    return this.userService.resetPassword(
      data.email,
      data.token,
      data.newPassword,
    );
  }
  @UseGuards(AuthGuard('jwt'))
  @Delete('delete')
  remove(@Req() req: AuthenticatedRequest) {
    return this.userService.deleteUser(req.user.id);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get(':id')
  async findOne(@Param('id') id: string) {
    return await this.userService.findOne(+id);
  }
}
