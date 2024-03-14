import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { AuthService } from 'src/auth/auth.service';
import { JwPayload } from 'src/auth/interfaces/jwt-payload';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private authServic: AuthService
  ){

  }


  async canActivate(context: ExecutionContext ): Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('No hay token en la peticion');
    }

    try{
      
      const payload = await this.jwtService.verifyAsync<JwPayload>(
      token,
      { secret: process.env.JWT_SEED }
      );

      const user = await this.authServic.findUserById( payload.id );
        if(!user) throw new UnauthorizedException('User does not exist');
        if(!user.isActive) throw new UnauthorizedException('User is not active');
        request['user'] = user;

  }catch(error){
    throw new UnauthorizedException();
  }
    


    
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
