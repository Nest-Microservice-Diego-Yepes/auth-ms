import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

import { RpcException } from '@nestjs/microservices';

import * as bcrypt from 'bcrypt';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwtPayload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');
  constructor(private readonly jwtService: JwtService) {
    super();
  }
  async onModuleInit() {
    this.logger.log('MongoDb connected');
    await this.$connect();
  }
  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where: { email },
      });
      if (!user) {
        throw new RpcException({
          status: HttpStatus.UNAUTHORIZED,
          message: 'Email/Password not valid (Email)',
        });
      }

      const paswwordCompare = bcrypt.compareSync(password, user.password);

      if (!paswwordCompare) {
        throw new RpcException({
          status: HttpStatus.UNAUTHORIZED,
          message: 'Email/Password not valid (Password)',
        });
      }

      const { password: __, ...rest } = user;

      return {
        rest,
        token: await this.jwtToken(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: error.message,
      });
    }
  }
  async registerUser(registerUserDto: RegisterUserDto) {
    const { name, email, password } = registerUserDto;

    try {
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });

      if (user)
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'User already exists',
        });

      const newUser = await this.user.create({
        data: {
          name,
          email,
          password: bcrypt.hashSync(password, 10),
        },
      });
      const { password: __, ...rest } = newUser;
      return {
        rest,
        token: await this.jwtToken(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: error.message,
      });
    }
  }

  async validateToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user: user,
        token: await this.jwtToken(user),
      };
    } catch (error) {

      console.log(error)

      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid Token'
      })
    }
  }

  async jwtToken(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }
}
