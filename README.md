Social Log In
=========
Facebook, Twitter, Google, LinkedIn and Local log in capabilities

On sign in, a local user is created and saved to mongodb. The social services is then linked to the local user.
Once the user is logged in there is the choice to link or unlink social services to this user.

----
### API keys ###
  
  * config/private_auth.js

  Make sure to keep these keys secret if you decide to fork this repo

### Database ###
  
  * config/private_database

	This file holds routing information for the database. MongoHQ and Azure hosted Mongo databases are perfect for this.