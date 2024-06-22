import { Controller, Get, Post, Body, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';

import { CreateUserDto, RegisterDto, LoginDto } from './dto';
import { AuthGuard } from './guards/auth.guard';
import { LoginResponse } from './interfaces/login-response.interface';
import { User } from './entities/user.entity';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  login( @Body() loginDto: LoginDto ){
    return this.authService.login( loginDto )
  }

  @Post('/register')
  async register( @Body() registerDto: RegisterDto ){
    return await this.authService.register( registerDto )
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll( @Request() req: Request ) {
    const user = req['user'];

    return user;
  }

  @UseGuards(AuthGuard)
  @Get('check-token')
  async checkToken( @Request() req: Request ): Promise<LoginResponse>{
    const user = req['user'] as User;

    return {
      user,
      token: await this.authService.getJWT({ id: user['id'] })
    }
  }

  // @Get(':id')
  // findOne(@Param('id') id: string) {
  //   return this.authService.findOne(+id);
  // }

  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
  //   return this.authService.update(+id, updateAuthDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.authService.remove(+id);
  // }
}
