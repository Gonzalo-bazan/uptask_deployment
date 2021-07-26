const passport = require('passport');
const Sequelize = require('sequelize');
const Usuarios = require('../models/Usuarios');
const Op = Sequelize.Op;
const crypto = require('crypto');
const bcrypt = require('bcrypt-nodejs');
const enviarEmail = require('../handler/email');
// const { Sequelize } = require('sequelize/types');



exports.autenticarUsuario= passport.authenticate('local',{
    successRedirect: '/',
    failureRedirect: '/',
    failureFlash: true,
    badRequestMessage: 'Ambos campos son obligatorios'
});

//Funcion para revisar si el usuario esta logueado o no

exports.usuarioAutenticado = (req,res,next)=>{
    //Si el usuario está autenticado, adelante

    if(req.isAuthenticated()){
        return next();
    }

    //Sino está autenticado, redigir al formulario  

    return res.redirect('/');
}

//funcion para cerrar sesion

exports.cerrarSesion=(req,res)=>{
    req.session.destroy(()=>{
        res.redirect('/iniciar-sesion'); //Al cerrar sesión nos lleva al login
    })  
}

//Genera un token si el usuario es válido

exports.enviarToken=async(req,res)=>{
    // Verificar que el usuario existe
    const {email} = req.body
    const usuario = await Usuarios.findOne({where:{ email }});

    //Si no existe el usuario

    if(!usuario){
        req.flash('error','No existe esa cuenta');
        res.redirect('/reestablecer');
    }

    //Usuario existe

    usuario.token = crypto.randomBytes(20).toString('hex');
    usuario.expiracion = Date.now()+3600000;

    //Guardar en la base de datos

    await usuario.save();

    //url de reset

    const resetUrl = `hhtp://${req.headers.host}/reestablecer/${usuario.token}`;

    //Envia el correo con el token

    await enviarEmail.enviar({
        usuario,
        subject: 'Password Reset',
        resetUrl,
        archivo: 'restablecerPassword'
    });

    //Terminar

    req.flash('correcto','Se envió un mensaje a tu correo');
    res.redirect('/iniciar-sesion');

}

exports.validarToken= async (req,res)=>{
    const usuario = await Usuarios.findOne({
        where: {
            token: req.params.token
        }
    });

    //Si no encuentra el usuario

    if(!usuario){
        req.flash('error','No válido');
        res.redirect('/reestablecer');
    }

    //Formulario para generar el password

    res.render('resetPassword',{
        nombrePagina: 'Reestablecer contraseña'
    })

    
}

//Cambiar el password 

exports.actualizarPassword=async(req,res)=>{
    

    //Verificar el token valido y la fecha de expiración
    const usuario = await Usuarios.findOne({
        where:{
            token: req.params.token,
            expiracion: {
                [Op.gte] : Date.now()
            }
        }
    });

    //Verificamos si el usuario existe

    if(!usuario){
        req.flash('error','No válid');
        res.redirect('/reestablecer');
    }

    //hashear el nuevo password

    usuario.password= bcrypt.hashSync(req.body.password,bcrypt.genSaltSync(10));
    usuario.token = null;
    usuario.expiracion = null;

    //Guardamos el nuevo password

    await usuario.save();

    req.flash('correcto','Tu password se ha modificado correctamente');
    res.redirect('/iniciar-sesion');

    
}

