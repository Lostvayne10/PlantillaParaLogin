const passport = require('passport');
const Strategy = require('passport-local');
const db = require('../database');
const helpers = require('../lib/helpers');

passport.use('local.signin', new Strategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, username, password, done) =>{
    console.log(req.body);
    const rows = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    console.log(rows.length);
    if(rows.length > 0){
        const user = rows [0];
        const validPassword = await helpers.matchPassword(password, user.password);

        if(validPassword){
            done(null, user, req.flash('success','Welcome ' + user.username));
        }
        else{
            done(null, false, req.flash('message','Incorrect Password'));
        }
    }else{
        return done(null, false, req.flash('message','Incorrect Username'));
    }
}));


passport.use('local.signup', new Strategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, username, password, done) => {
    const {fullname} = req.body;
    const newUSer = {
        username,
        password,
        fullname
    };
    newUSer.password = await helpers.encryptPassword(password);

    const result = await db.query('INSERT INTO users SET ?', [newUSer]);
    newUSer.id = result.insertId;
    return done(null, newUSer);

}));

passport.serializeUser((user, done) =>{
    done(null, user.id);

});

passport.deserializeUser(async (id, done) =>{
    const rows = await db.query('SELECT * FROM users WHERE id = ?', [id]);
    done(null, rows[0]);
});