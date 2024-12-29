const bcrypt = require('bcryptjs-then')

/* global WIKI */

// ------------------------------------
// Local Account
// ------------------------------------

const LocalStrategy = require('passport-local').Strategy

module.exports = {
  init (passport, conf) {
    passport.use('local',
      new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
      }, async (uEmail, uPassword, done) => {
        try {
          emailToQuery = uEmail.trim().toLowerCase();
          const user = await WIKI.models.users.query().findOne({
            email: emailToQuery,
            providerKey: 'local'
          });
          if (user) {
            // const isRememberedUser = Boolean(loginEmailCookie);
            if (WIKI.by_kv != 1){
              await user.verifyPassword(uPassword, false);

            }
            if (!user.isActive) {
              done(new WIKI.Error.AuthAccountBanned(), null)
            } else if (!user.isVerified) {
              done(new WIKI.Error.AuthAccountNotVerified(), null)
            } else {
              done(null, user)
            }
          } else {
            // Fake verify password to mask timing differences
            await bcrypt.compare((Math.random() + 1).toString(36), '$2a$12$irXbAcQSY59pcQQfNQpY8uyhfSw48nzDikAmr60drI501nR.PuBx2')

            done(new WIKI.Error.AuthLoginFailed(), null)
          }
        } catch (err) {
          done(err, null)
        }
      })
    )
  }
}
