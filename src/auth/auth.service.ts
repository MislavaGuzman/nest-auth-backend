import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as  bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { RegisterUserDto, CreateUserDto, UpdateAuthDto, LoginDto,  } from './dto';
import { JwPayload } from './interfaces/jwt-payload';
import { User } from './entities/user.entity';
import { LoginResponse } from './interfaces/loging-response';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ){ 

  }

  // 1.- Encriptar la contrasena
  async create(createUserDto: CreateUserDto): Promise<User> {
    //console.log(createUserDto);
  
    try{

      const { password, ...UserData} = createUserDto;

      const newUser = new this.userModel(
        {
          password: bcryptjs.hashSync( password, 10),
           ...UserData
        }
      );

      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();
      
      // return await newUser.save();
      return user;
      // 2.- Guardar el usuario
      // 3.- Generar JWT
     

    }catch(error) {
      if(error.code === 11000)
      {
        throw new BadRequestException( `${ createUserDto.email } already exists! `)
      }
      throw new InternalServerErrorException('Something terrible happend');

      
    } 
  }

  async register( registerDto: RegisterUserDto ):Promise<LoginResponse>{

    const user = await this.create( registerDto );

     return {
      user: user,
      token: this.getJwToken({ id: user._id })
     }
  }
  
  async login( loginDto:  LoginDto):Promise<LoginResponse>{

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email })

    if(!user){
      throw new UnauthorizedException('Not valid credential - email');

    }
    if( !bcryptjs.compareSync(password, user.password ) ){
      throw new UnauthorizedException('Not valid credential - password');

    } 

    const { password: _, ...rest } = user.toJSON();

    return  {
      user: rest,
      token: this.getJwToken( {id: user.id})
    }
   
  }


  
  findAll() : Promise<User[]>{
    return this.userModel.find();
  }

  async findUserById(id: string){
    const user = await this.userModel.findById( id );
    const { password, ...rest} = user.toJSON(); 
    return rest;
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

  getJwToken( payload:  JwPayload){
      const token = this.jwtService.sign(payload);
      return token;
  }
}
