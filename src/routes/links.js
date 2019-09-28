const express = require('express');
const router =  express.Router();
const {isLoggedIn} = require('../lib/auth');
const pool = require('../database');


router.get('/add', isLoggedIn, (req, res) => {
    res.render('links/add');
});

router.post('/add', isLoggedIn, async (req,res) => {
    const { title, url, description} = req.body;
    const newLink = {
        title, 
        url,
        description,
        user_id: req.user.id
    };
    await pool.query('INSERT INTO links set ?', [newLink]);
    req.flash('success', 'Link Agregado Correctamente');
    res.redirect('/links');
});

router.get('/delete/:id', isLoggedIn, async (req, res) =>{
    const { id } = req.params;
    await pool.query('DELETE FROM links WHERE ID =?', [id]);
    req.flash('success', 'Link removido satisfactoriamente');
    res.redirect('/links');
});

router.get('/edit/:id', isLoggedIn, async (req, res) =>{
    const { id } = req.params;
    const links = await pool.query('SELECT * FROM links WHERE id = ?', [id]);
    res.render('links/edit', {links: links[0]});
});

router.post('/edit/:id', isLoggedIn, async (req, res) =>{
    const { id } = req.params;
    const {title, description, url} = req.body;
    const newlink ={
        title,
        description,
        url
    };
    await pool.query('UPDATE links SET ?  WHERE id = ?', [newlink, id]);
    req.flash('success', 'Link Editado Correctamente');
    res.redirect('/links');
});


router.get('/', isLoggedIn, async (req,res) => {
    const links = await pool.query('SELECT * FROM links WHERE user_id = ?', [req.user.id]);
    console.log(links);
    res.render('links/list', {links: links});
});



module.exports = router;