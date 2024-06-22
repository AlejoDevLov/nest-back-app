import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto, RegisterDto, UpdateAuthDto, LoginDto } from './dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';

import { JwtService } from '@nestjs/jwt';

import { JwtPayload } from './interfaces/JWT-payload.interface';
import { LoginResponse } from './interfaces/login-response.interface';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ) {}


  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      // 1- Encriptar password
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      });

      // 2- Guardar el usuario
      await newUser.save();

      const { password:_, ...user } = newUser.toJSON();
      return user;

    } catch (error) {
      if( error.code === 11000 ){
        throw new BadRequestException(`${ createUserDto.email } already exist!`);
      }
      throw new InternalServerErrorException(`Something bad happened`);
    }
  }

  async login( loginDto: LoginDto ): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    if( !user ){
      throw new UnauthorizedException('Not valid credentials - email')
    }

    if( !bcryptjs.compareSync( password, user.password ) ) {
      throw new  UnauthorizedException('Not valid credentials - password');
    }

    const { password:_, ...rest } = user.toJSON();

    return {
      user: rest,
      token: await this.getJWT({ id: user.id })
    };
  }

  async register( registerDto: RegisterDto ): Promise<LoginResponse> {
    try {
      const { email } = await this.create(registerDto);

      const user = await this.userModel.findOne({ email });

      return {
        user,
        token: await this.getJWT({ id: user.id })
      }

    } catch(error){
      throw new UnauthorizedException(error.message);
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( userId: string ) {
    const user = await this.userModel.findById(userId);
    const { password, ...rest } = user.toJSON();
    return { ...rest };
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  async getJWT( payload: JwtPayload ){
    const token = await this.jwtService.signAsync(payload);
    return token;
  }
}
