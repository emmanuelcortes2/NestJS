import { ForbiddenException, Injectable } from "@nestjs/common";
// import { User, Bookmark } from "@prisma/client";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) { }
    async signup(dto: AuthDto) {
        const hashedPassword = await argon.hash(dto.password)

        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hashedPassword
                },
                select: {
                    id: true,
                    email: true,
                    createdAt: true
                }
            })
            return user
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credentials taken')
                }
            }
            throw error
        }

    }

    async singin(dto: AuthDto) {

        const user = await this.prisma.user.findFirst({
            where: {
                email: dto.email
            }
        })
        if(!user) {
            throw new ForbiddenException('Credentials incorrect')
        }

        const pwMatches = await argon.verify(user.hashedPassword, dto.password)

        if(!pwMatches) {
            throw new ForbiddenException('Credentials incorrect')
        }

        delete user.hashedPassword

        return user
    }
}