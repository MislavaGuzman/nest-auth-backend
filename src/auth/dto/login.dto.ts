import { IsEmail, MaxLength } from "class-validator";

export class LoginDto{

    @IsEmail()
    email: string;

    @MaxLength(6)
    password: string;

}