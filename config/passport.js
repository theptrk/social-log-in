var LocalStrategy 		= require('passport-local').Strategy;
var FacebookStrategy	= require('passport-facebook').Strategy;
var TwitterStrategy 	= require('passport-twitter').Strategy;
var GoogleStrategy 		= require('passport-google-oauth').OAuth2Strategy;
var LinkedInStrategy 	= require('passport-linkedin').Strategy;
var GithubStrategy 	  = require('passport-github').Strategy;

// load user model that is hooked to mongoose 
var User 				= require('../app/models/user');

// load your app api keys and secrets 
var configAuth 			= require('./auth');

// expose this function to our app using module.exports
// * remember, you were passed passport in server.js
module.exports = function(passport) {

	// ==========================================
	// PASSPORT SESSION SETUP ===================
	// ==========================================
	// required for persistent login sessions
	// passport needs ability to serialize and unserialize users out of a session

	// used to serialize the user for the session
	passport.serializeUser(function(user, done) {
		done(null, user.id);
	});

	// used to deserialize the user
	passport.deserializeUser(function(id, done) {
		User.findById(id, function(err, user) {
			done(err, user);
		});
	});


	// ==========================================
	// LOCAL SIGNUP =============================
	// ==========================================
	// we are using named strategies since we have on for login and one for signup 
	// by default, if there was no name, it would just be called 'local'

	passport.use('local-signup', new LocalStrategy({
		// be default, local strategy uses username and password, we will override
		usernameField: 'email', 
		passwordField: 'password',
		passReqToCallback: true // allows us to pass back the entire requst to the callback
	}, 
	function(req, email, password, done) {

		// asynchronos 
		// User.findOne wont fire unless data is sent back
		process.nextTick(function(){

			if (!req.user) {
				// find a user whose email is the same as the forms email
				// we are check to see fi the user trying to login already exists
				User.findOne({ 'local.email': email }, function(err,user) {
					// if there are any errors, return the error
					if (err)
						return done(err);

					// check to see if theres already a user with that email
					if (user) {
						return done(null, false, req.flash('signupMessage', 'That email is already taken.'))
					} else {

						// if there is no user with that email
						// create the user
						var newUser 			= new User();

						// set the user's local credentials
						newUser.local.email 	= email;
						newUser.local.password 	= newUser.generateHash(password);

						// save the user
						newUser.save(function(err) {
							if (err)
								throw err;
							return done(null, newUser);
						});
					}
				});
			} else {
				User.findOne({ 'local.email': email }, function(err,user) {
					// if there are any errors, return the error
					if (err)
						return done(err);

					// check to see if theres already a user with that email
					if (user) {
						return done(null, false, req.flash('signupMessage', 'That email is already taken.'))
					} else {

						// if there is no user with that email
						// create the user
						var user 				= req.user;

						// set the user's local credentials
						user.local.email 		= email;
						user.local.password 	= user.generateHash(password);

						// save the user
						user.save(function(err) {
							if (err)
								throw err;
							return done(null, user);
						});
					}
				
				});
			}
		});
	}));

	
	// ==========================================
	// LOCAL LOGIN ==============================
	// ==========================================
	// we are using name strategies since we have one for login and one for signup
	// by default, if there was no name, it would just be called local'

	passport.use('local-login', new LocalStrategy({
		// be default, local strategy uses username and password, we will override
		usernameField: 'email',
		passwordField: 'password',
		passReqToCallback: true // allows us to pass back the entire request to the callback
	},
	function(req, email, password, done) { //calback with email and password from our form

		// find a user whose email is the same as the forms email
		// we are checking to see if the user trying to login already exists
		User.findOne( {'local.email' : email }, function(err, user) {
			// if there are any errors, return the error before anything else
			if (err)
				return done(err);

			// if no user is found, return the message 
			if (!user)
				return done(null, false, req.flash('loginMessage', 'No user found'));

			if (!user.validPassword(password))
				return done(null, false, req.flash('loginMessage', 'Oops! Wrong password'));

			// all is well, return sucessful user
			return done(null, user);
		});
	}));


	// ==========================================
	// FACEBOOK =================================
	// ==========================================
	passport.use(new FacebookStrategy({

		// pull in our app id and secret from our auth.js file
		clientID 			: configAuth.facebookAuth.clientID,
		clientSecret 		: configAuth.facebookAuth.clientSecret,
		callbackURL 		: configAuth.facebookAuth.callbackURL,
		passReqToCallback 	: true // from passport docs. allows us to pass req
	},

	// facebook will send back the token and profile
	function(req, token, refreshToken, profile, done) {
		console.log(profile);
		// asynchronous
		process.nextTick(function() {

			if (!req.user) {
				User.findOne({ 'facebook.id' : profile.id }, function(err, user) {

					// if there is an error, stop everything and return that
					// ie an error connecting to database
					if (err)
						return done(err);

					// if the user is found, then log them in
					if (user) {

						// if there is a user id already but no token (user was linked at one point and then removed)
	                	// just add our token and profile information
	                    if (!user.facebook.token) {
	                        user.facebook.token = token;
	                        user.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
	                        user.facebook.email = profile.emails[0].value;

	                        user.save(function(err) {
	                            if (err)
	                                throw err;
	                            return done(null, user);
	                        });
	                    }

						return done(null, user);
					} else {
						// if there is no user found with that facebook id, create them
						var newUser 			= new User();

						// set all of the facebook information in our user model
						newUser.facebook.id 	= profile.id; // set the users facebook id
						newUser.facebook.token 	= token // we will save the token that facebook provides
						newUser.facebook.name 	= profile.name.givenName + ' ' + profile.name.familyName; // look at the passport user profile to see how names are returned
						newUser.facebook.email 	= profile.emails[0].value; // facebook can return multiple emails, take the first

						// save our user to the database
						newUser.save(function(err) {
							if (err)
								throw err;

							// if successful, return the new user
							return done(null, newUser);
						});
					};
				});	
			} else {
				// user already exists and is logged in, link accounts now
	            var user            = req.user; // pull the user out of the session

				// add facebook info 
	            user.facebook.id    = profile.id;
	            user.facebook.token = token;
	            user.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
	            user.facebook.email = profile.emails[0].value;

				// save the user
	            user.save(function(err) {
	                if (err)
	                    throw err;
	                return done(null, user);
	            });
			}
			
		});
	}));

	
	// ==========================================
	// TWITTER ==================================
	// ==========================================

	passport.use(new TwitterStrategy({

		// pull in our app id and secret from our auth.js file
		consumerKey 		: configAuth.twitterAuth.consumerKey,
		consumerSecret 		: configAuth.twitterAuth.consumerSecret,
		callbackURL 		: configAuth.twitterAuth.callbackURL,
		passReqToCallback	: true

	}, // ?why is twitter tokenSecret and facebook refreshToken?
	function(req, token, tokenSecret, profile, done) {
		console.log(profile);
		// make the code asynchronous
		process.nextTick(function() {

			if (!req.user) {
				User.findOne({ 'twitter.id' : profile.id }, function(err, user) {

					// if there is an error, stop everything and return that
					if (err) 
						return done(err);

					if (user) {
						return done(null, user); // user found, return user
					} else {
						// if no user by this profile id, create new one
						var newUser 			= new User();

						// set all of the data given to us
						newUser.twitter.id 			= profile.id;
						newUser.twitter.token 		= token;
						newUser.twitter.username 	= profile.username;
						newUser.twitter.displayName = profile.displayName; 

						// save our user into the database
						newUser.save(function(err) {
							if (err)
								throw err;
							return done(null, newUser);
						});
					}
				});
			} else {
				// user found, create add credentials
				var user 		= req.user; 
				user.twitter.id 			= profile.id;
				user.twitter.token 			= token;
				user.twitter.username 		= profile.username;
				user.twitter.displayName 	= profile.displayName;

				// save the user
	            user.save(function(err) {
	                if (err)
	                    throw err;
	                return done(null, user);
	            });
			};
			
		});
	}));


	// ==========================================
	// GOOGLE ===================================
	// ==========================================
	passport.use(new GoogleStrategy({

		clientID 			: configAuth.googleAuth.clientID,
		clientSecret 		: configAuth.googleAuth.clientSecret,
		callbackURL			: configAuth.googleAuth.callbackURL,
		passReqToCallback	: true 

	},
	function(req, token, refreshToken, profile, done) {
		console.log(profile);
		//async, User.findOne won't fire until we have all our data from Google
		process.nextTick(function(){

			if (!req.user) {
				User.findOne({ 'google.id' : profile.id }, function(err, user) {
					if (err)
						return done(err);

					if (user) {
						// if a user is found, log them in
						return done(null, user);
					} else {
						// user not found, create new User
						var newUser = new User();

						// set all relevant information
						newUser.google.id 		= profile.id;
						newUser.google.token 	= token;
						newUser.google.name 	= profile.displayName;
						newUser.google.email 	= profile.emails[0].value; // pull the first email

						// save the user
						newUser.save(function(err) {
							if (err) 
								throw err;
							return done(null, newUser);
						});
					}
				});
			} else {
				// user found, create add credentials
				var user = req.user;
				user.google.id 		= profile.id;
				user.google.token 	= token;
				user.google.name 	= profile.displayName;
				user.google.email 	= profile.emails[0].value; // pull the first email

				// save the user
				user.save(function(err) {
					if (err) 
						throw err;
					return done(null, user);
				});
			};

		})
	}));



	// ==========================================
	// GITHUB ===================================
	// ==========================================
	passport.use(new GithubStrategy({

		clientID 				: configAuth.githubAuth.clientID,
		clientSecret 		: configAuth.githubAuth.clientSecret,
		callbackURL			: configAuth.githubAuth.callbackURL,
		passReqToCallback	: true 

	},
	function(req, token, refreshToken, profile, done) {
		//async, User.findOne won't fire until we have all our data from Google
		process.nextTick(function(){
			console.log(profile);
			if (!req.user) {
				User.findOne({ 'github.id' : profile.id }, function(err, user) {
					if (err)
						return done(err);

					if (user) {
						// if a user is found, log them in
						return done(null, user);
					} else {
						// user not found, create new User
						var newUser = new User();

						// set all relevant information
						newUser.github.id 				= profile.id;
						newUser.github.name 	= profile.username;
						newUser.github.picture 	= profile._json.avatar_url;
						newUser.github.token 	= token;
						// newUser.github.email 	= profile.emails[0].value; // pull the first email

						// save the user
						newUser.save(function(err) {
							if (err) 
								throw err;
							return done(null, newUser);
						});
					}
				});
			} else {
				// user found, create add credentials
				var user = req.user;
				user.github.id 		= profile.id;
				user.github.name 	= profile.username;
				user.github.token 	= token;
				user.github.picture 	= profile._json.avatar_url;
				// user.github.email 	= profile.emails[0].value; // pull the first email

				// save the user
				user.save(function(err) {
					if (err) 
						throw err;
					return done(null, user);
				});
			};

		})
	}));








	// ==========================================
	// LINKEDIN =================================
	// ==========================================

	passport.use(new LinkedInStrategy({

		// these are authorization keys
		consumerKey 	: configAuth.linkedinAuth.apiKey,
		consumerSecret 	: configAuth.linkedinAuth.secretKey,
		callbackURL 	: configAuth.linkedinAuth.callbackURL,
		// specifying the profile fields we want access to 
		profileFields	: ['id', 'first-name', 'last-name', 'email-address', 'headline', 'picture-url', 'positions','industry','picture-urls::(original)'],
		passReqToCallback : true 
	},
	function(req, token, tokenSecret, profile, done) {
		console.log('profile.id: '+ profile.id)
		console.log('profile.displayName: '+ profile.displayName)
		console.log('profile.emails[0].value: '+ profile.emails[0].value)
		console.log('profile._json.headline: '+ profile._json.headline);
		console.log('profile._json.pictureUrl: '+ profile._json.pictureUrl)
		console.log('profile._json.industry: ' + profile._json.industry);
		console.log(profile._json.positions.values);
		console.log(profile);
		console.log('==================');
		console.log(profile._json.pictureUrls.values[0]);
		//async
		process.nextTick(function(){
			
			if (!req.user) {
				User.findOne({ 'linkedin.id' : profile.id }, function(err, user) {
					if (err)
						return done(err);

					if (user) {
						// if a user is found, log them in
						return done(null, user);
					} else {
						console.log('User not found')
						// user not found, create new User
						var newUser = new User();

						// set all relevant information
						newUser.linkedin.id 		= profile.id;
						newUser.linkedin.token 		= token;
						newUser.linkedin.name 		= profile.displayName;
						newUser.linkedin.email 		= profile.emails[0].value; // pull the first email
						newUser.linkedin.headline 	= profile._json.headline;
						newUser.linkedin.picture 	= profile._json.pictureUrls.values[0];

						// save the user
						newUser.save(function(err) {
							if (err) 
								throw err;
							return done(null, newUser);
						});
					}
				});
			} else {
				// user found, create add credentials
				var user = req.user;
				user.linkedin.id 		= profile.id;
				user.linkedin.token 	= token;
				user.linkedin.name 		= profile.displayName;
				user.linkedin.email 	= profile.emails[0].value; // pull the first email
				user.linkedin.headline 	= profile._json.headline;
				user.linkedin.picture 	= profile._json.pictureUrls.values[0];

				// save the user
				user.save(function(err) {
					if (err) 
						throw err;
					return done(null, user);
				});
			};

		})
	}));
};