// @flow
import passport from "@outlinewiki/koa-passport";
// import fetch from "fetch-with-proxy";
import Router from "koa-router";
import { Strategy as GitlabStrategy } from "passport-gitlab2";
import accountProvisioner from "../../commands/accountProvisioner";
import env from "../../env";
import passportMiddleware from "../../middlewares/passport";

const router = new Router();
const providerName = "gitlab";

const GITLAB_APP_ID = process.env.GITLAB_APP_ID;
const GITLAB_APP_SECRET = process.env.GITLAB_APP_SECRET;
const GITLAB_BASE_URL = process.env.GITLAB_BASE_URL || "https://gitlab.com/";

const GITLAB_TEAM_NAME = "taliox GmbH";
const GITLAB_TEAM_DOMAIN = "taliox.io";
const GITLAB_TEAM_SUBDOMAIN = "taliox.io";

const scopes = [];

export const config = {
  name: "Gitlab",
  enabled: !!GITLAB_APP_ID,
};

export async function request(endpoint: string, accessToken: string) {
  const response = await fetch(endpoint, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  });
  return response.json();
}

if (GITLAB_APP_ID) {
  let strategyOptions = {
    clientID: GITLAB_APP_ID,
    clientSecret: GITLAB_APP_SECRET,
    baseURL: GITLAB_BASE_URL,
    callbackURL: `${env.URL}/auth/gitlab.callback`,
  };

  passport.use(
    new GitlabStrategy(strategyOptions, async function (
      req,
      accessToken,
      refreshToken,
      profile,
      cb
    ) {
      try {
        const result = await accountProvisioner({
          ip: req.ip,
          team: {
            name: GITLAB_TEAM_NAME,
            domain: GITLAB_TEAM_DOMAIN,
            subdomain: GITLAB_TEAM_SUBDOMAIN,
          },
          user: {
            name: profile._json.username,
            email: profile.emails[0]["value"],
            avatarUrl: profile.avatarUrl,
          },
          authenticationProvider: {
            name: providerName,
            providerId: `${GITLAB_TEAM_DOMAIN}-${providerName}`,
          },
          authentication: {
            providerId: profile.id,
            accessToken,
            refreshToken,
            scopes,
          },
        });
        return cb(null, result.user, result);
      } catch (err) {
        return cb(err, null);
      }
    })
  );

  router.get("gitlab", passport.authenticate(providerName));
  router.get("gitlab.callback", passportMiddleware(providerName));
}

export default router;
