import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import Hash from '@ioc:Adonis/Core/Hash'
import User from 'App/Models/User'
import auth from 'Config/auth'



export default class UsersController {
    public async RegisterUser(ctx: HttpContextContract){
        const user = await User.create({
            username: ctx.request.input("username"),
            email: ctx.request.input("email"),
            password: await Hash.make(ctx.request.input("password"))
        })

        //user.save()
        const body = ctx.request.body()

        ctx.response.json(user)
    }

    public async LoginUser(ctx: HttpContextContract){

            const user = await User
            .query()
            .where('email',ctx.request.input('email'))
            .whereNull('is_deleted')
            .firstOrFail()

            if(!(await Hash.verify(user.password,ctx.request.input('password')))){
                return ctx.response.badRequest('Invalid credentials')
            }

        
            try{ 
                const token = await ctx.auth.use('api').generate(user,{
                    expiresIn: '10min'
                })
                return token
            }catch{
                return ctx.response.badRequest('Invalid credentials')
            }
            /*if(await User.findByOrFail('email', ctx.request.input('email')) || await User.findByOrFail('username', ctx.request.input('username'))){
            const user = await User.findByOrFail('email', ctx.request.input('email')) || await User.findByOrFail('username',ctx.request.input('username'))
            if(await Hash.verify(user.password,ctx.request.input('password'))){
                const token = await ctx.auth.use('api').attempt(ctx.request.input('email'),ctx.request.input('password'){
                    expiresIn:'30mins'
                })
                ctx.response.status(200).json(token)
            }else{
                ctx.response.status(401).json({msg:'Credenciales incorrectas'})
            }
            }else{
                ctx.response.json({msg:'correo incorrecto'})
            }*/
    }

    public async Logout(ctx: HttpContextContract){
        await ctx.auth.use('api').revoke()
        return { 
            revoked: true
        }
    }

    public async isLogin(ctx: HttpContextContract){
        await ctx.auth.use('api').authenticate()
        ctx.auth.isLoggedIn
    }
}
