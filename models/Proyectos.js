const Sequelize = require('sequelize');
const slug = require('slug');
const db=require('../config/db');
const shortid = require('shortid');

const Proyectos = db.define('proyectos',{

    id : {
        type: Sequelize.INTEGER, 

        primaryKey: true,
        autoIncrement: true,
        
    },

    nombre : {
        type: Sequelize.STRING,
   
    },
    url : {
        type: Sequelize.STRING
    }
},{
    hooks: {
        beforeCreate(proyecto){
            const url = slug(proyecto.nombre).toLowerCase();

            proyecto.url = `${url}-${shortid.generate()}`;
        }

        
    }
});

module.exports= Proyectos;