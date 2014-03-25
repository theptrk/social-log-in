module.exports = function (app, passport) {


	// ====================================
	// HOME PAGE (with login links) =======
	// ====================================
	app.get('/', function (req, res) {
		res.render('index.ejs'); // load index.ejs file
	})


	// ====================================
	// LOGIN ==============================
	// ====================================
	app.get('/login', function (req,res) {
		// render the page and pass in any flash data if it exists
		res.render('login.ejs', { message: req.flash('loginMessage') });
			//'loginMessage' set up in passport config
	})

	// process the login form
	app.post('/login', passport.authenticate('local-login', {
		successRedirect: '/profile', 
		failureRedirect: '/login', // redirects back to login page if error
		failureFlash: true 
	}));


	// ====================================
	// PROFILE SECTION ====================
	// ====================================
	// we will want this protected so you have to be logged in to visit
	// we will use route middleware to verify this (the isLoggedIn function)
	app.get('/profile', isLoggedIn, function (req, res) {
		res.render('profile.ejs', {
			user : req.user // get the user out of session and pass to template
		});
	});


	// ====================================
	// LOGOUT =============================
	// ====================================
	app.get('/logout', function (req, res) {
		req.logout(); // logout() provided by passport
		res.redirect('/');
	});




	// ====================================
	// INIT SIGN UPS ======================
	// ====================================

	// init local -------------------------
		app.get('/signup', function (req, res) {
			// render the page and pass in any flash data if it exists
			res.render('signup.ejs', { message: req.flash('signupMessage')})
		});

		// process the signup form
		app.post('/signup', passport.authenticate('local-signup', {
			successRedirect : '/profile', // redirect to the secure profile section
			failureRedirect : '/signup', // redirect back to the signup page if there is an error
			failureFlash : true // allow flash messages 
		})); // heavy lifting is in 'config/passport.js'

	// init facebook -----------------------
		app.get('/auth/facebook', passport.authenticate('facebook', {scope : 'email'}));

		// handle the callbook after facebook has authenticated the user
		// *** remember where you set the callback URL at the dev portal
		app.get('/auth/facebook/callback', 
			passport.authenticate('facebook', {
				successRedirect : '/profile',
				failureRedirect : '/'
			}));

	// init twitter -------------------------
		// route for twitter authentication and login
		app.get('/auth/twitter', passport.authenticate('twitter'));

		//handle the callback after twitter has authenticated the user
		app.get('/auth/twitter/callback', 
			passport.authenticate('twitter', {
				successRedirect: '/profile', 
				failureRedirect: '/', 
			}));

	// init google -------------------------
		// send to google, profile gets us basic info including name
		// email gets their email
		app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

		//handle the callback after google has authenticated the user
		app.get('/auth/google/callback', 
			passport.authenticate('google', {
				successRedirect: '/profile', 
				failureRedirect: '/', 
			}));

	// init linkedin -------------------------
		// send to linkedin, profile gets us basic info including name
		app.get('/auth/linkedin', passport.authenticate('linkedin'));

		//handle the callback after linkedin has authenticated the user
		app.get('/auth/linkedin/callback', 
			passport.authenticate('linkedin', {
				successRedirect: '/profile', 
				failureRedirect: '/', 
			}));

	// ====================================
	// LINK ACCOUNTS ======================
	// ====================================
 
	// link locally --------------------------------
		app.get('/connect/local', function(req, res) {
			res.render('connect-local.ejs', { message: req.flash('signupMessage') });
		});
		app.post('/connect/local', passport.authenticate('local-signup', {
			successRedirect : '/profile', // redirect to the secure profile section
			failureRedirect : '/connect/local', // redirect back to the signup page if there is an error
			failureFlash : true // allow flash messages
		}));

	// link facebook -------------------------------

		// send to facebook to do the authentication
		app.get('/connect/facebook', passport.authorize('facebook', { scope : 'email' }));

		// handle the callback after facebook has authorized the user
		app.get('/connect/facebook/callback',
			passport.authorize('facebook', {
				successRedirect : '/profile',
				failureRedirect : '/'
			}));

	// link twitter --------------------------------

		// send to twitter to do the authentication
		app.get('/connect/twitter', passport.authorize('twitter', { scope : 'email' }));

		// handle the callback after twitter has authorized the user
		app.get('/connect/twitter/callback',
			passport.authorize('twitter', {
				successRedirect : '/profile',
				failureRedirect : '/'
			}));


	// link google ---------------------------------

		// send to google to do the authentication
		app.get('/connect/google', passport.authorize('google', { scope : ['profile', 'email'] }));

		// the callback after google has authorized the user
		app.get('/connect/google/callback',
			passport.authorize('google', {
				successRedirect : '/profile',
				failureRedirect : '/'
			}));

	// link linkedin ---------------------------------

		// send to google to do the authentication
		app.get('/connect/linkedin', passport.authorize('linkedin'));

		// the callback after google has authorized the user
		app.get('/connect/linked/callback',
			passport.authorize('linkedin', {
				successRedirect : '/profile',
				failureRedirect : '/'
			}));


	// =============================================================================
	// UNLINK ACCOUNTS =============================================================
	// =============================================================================
	// used to unlink accounts. for social accounts, just remove the token
	// for local account, remove email and password
	// user account will stay active in case they want to reconnect in the future

	    // unlink local -----------------------------------
	    app.get('/unlink/local', function(req, res) {
	        var user            = req.user;
	        user.local.email    = undefined;
	        user.local.password = undefined;
	        user.save(function(err) {
	            res.redirect('/profile');
	        });
	    });

	    // unlink facebook -------------------------------
	    app.get('/unlink/facebook', function(req, res) {
	        var user            = req.user;
	        user.facebook.token = undefined;
	        user.save(function(err) {
	            res.redirect('/profile');
	        });
	    });

	    // unlink twitter --------------------------------
	    app.get('/unlink/twitter', function(req, res) {
	        var user           = req.user;
	        user.twitter.token = undefined;
	        user.save(function(err) {
	           res.redirect('/profile');
	        });
	    });

	    // unlink google ---------------------------------
	    app.get('/unlink/google', function(req, res) {
	        var user          = req.user;
	        user.google.token = undefined;
	        user.save(function(err) {
	           res.redirect('/profile');
	        });
	    });

	    // unlink linkedin ---------------------------------
	    app.get('/unlink/linkedin', function(req, res) {
	        var user            = req.user;
	        user.linkedin.token = undefined;
	        user.save(function(err) {
	           res.redirect('/profile');
	        });
	    });

};

// route middleware to make sure a user is logged in 
function isLoggedIn (req, res, next) {

	// if user is authenticated in the session, carry on
	if (req.isAuthenticated())
		return next();

	// if they aren't redirect them to the home page
	res.redirect('/');
}


