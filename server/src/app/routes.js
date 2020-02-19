import path from "path";
import cookieParser from "cookie-parser";
import {
  AGPayload,
  ContentItem,
  JWTPayload,
  NRPayload,
  GroupsPayload,
  SetupParameters
} from "../common/restTypes";
import config from "../config/config";
import assignGrades from "./assign-grades";
import * as content_item from "./content-item";
import eventstore from './eventstore';
import {
  deepLink,
  deepLinkContent
} from "./deep-linking";
import * as lti from "./lti";
import ltiAdv from "./lti-adv";
import namesRoles from "./names-roles";
import groups from "./groups";
import redisUtil from "./redisutil";
const fs = require('fs')
const blackboard = require('../../../blackboardsetup.json');
const toolKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3V7B2nSgWdeWH
ueJBYdygUfyJ7fD0SLYa+PwjMbUqDnRXi4uc90FOInEsd4HkPVVlinYNZcfHsLKF
vylMNRyHNEA+ok8HUPoXm76ovD5K44EslINWE5BQA8Bmuu6uvc3tB9FuXpd72kK/
qt1dFT6Nt3JTnp/baQ5ov6nDNAaSHHpLii96JUzwS4zNzD7xmFuY9ACcFXAgs01v
zIBPWCsp1Y0jh+NNNKL/qI/uCJbMX25p89fPj0wg1V4uVLSTapO84/hPkAvcOVgC
GQybXNv+e4lgtnOWqM70++Thwwa3wk1A7ZtZTS3qoDhFXOC3OO33u3kqFWv8YNGK
6w5ptjsfAgMBAAECggEAd9XlDWJjVWrx/+jLrhic8F0mR7EykTkFblPX2dkfpMGV
4bLgKlSiZsO0XXAvglNkgd4ik1c3YZpo1WrBP4Jnhyfr5gSIyytujAfMctW3kZNq
Vw0rWxOme+Y31+3PHIALHSbDCPTi5p0ei9DOp4y/OjnxjB5eNjdQp76+40waD11a
ZmHnFd+ARaEMVCR4UJFfOsMz9Z3NDnuk7ZFelW9zEDJudgk6Y3f6dM2qNr/itUND
TT8AK3W6GIYsChyRsskrbjozxsj5i28GKtY5ZcGtCgjFXJG0H7CEMw29f44aZfb2
5fCPaN9QZaIp7p0pOePg7GEsR9MLmzstGfQ1mwV2IQKBgQDfvCEQGYzGC2dRH8Jj
/lPqu1khOa6Htl+chUDuBPZVHB2OHgolqNwlHdifKOnFY+mOPzS/PL9S4WypNiHN
VvTei5/QRxXLF4cIqJ0Pte5qynn08QsPG48FZudr+f8hsIQRZMnu6GEz6+tn+V17
hASyPQn/CG0dbk8I7vzSFrVKAwKBgQDRyFnQhAH7yI5arXvhR2c/ehLJ0Sr2NPdr
uj48yf/etZhzDdwdnezJofwfgIYmsdZglRAN34lZPLrjra7UHa1AA1vPe41mJ01A
4DYWf6w+gIohKF24eaOBY1N1gMjIlK58tYkqrO5oQ31tloPtIVceNHQVszhEVXgq
1BmN6sJNtQKBgE8+Jse5BO8wIsvM3+Dit34wFQV7lKFkqsCZQcIL5+OFLcKkSRvF
jxNmWs8kgofzN0m2gUwqi+kjBoV4Msizv88CzPvL8aAZGS6r6dUirusMA94Jcc1M
CX/0Tosj5IVeK6itdgg0LhlhueL9o2qX+8HVdLDrnxoJc9zKKKmQeW1ZAoGASjYm
D62jRf7c3RciC7/Gtp3op5xnJlH2dRWdjsOm0JJNK+ZrR87mRS4YksxUqLugquoQ
k9fQLtFdC84VWtRkxZBqmiuLCeg9XAX1HGBt/m5abwBopyngvZT1oUu9u7ddQqC1
tXMXo6q8ZFgqs2hn+Td1GXgdH49cw0nlAF9b/UECgYEAlQTpUHOuto76IE6pnfLs
GGnP9k31TPnj9jOARoBiQaNF3Oma+0G9BouCaoJvJart0tfl6OHzjjRowvYyHuYg
5e1YZWCIENBarEnP8e43r44VIOXAlJ42cKINGFr+HfhXWQnCCCR3DoEomH6a86dP
MqfFsudcmeGpI/1weA5BDs0=
-----END PRIVATE KEY-----`

let jwk2pem = require('pem-jwk').jwk2pem

const contentitem_key = "contentItemData";

const FULL_KEYS = "{\n" +
  "  \"kty\": \"RSA\",\n" +
  "  \"d\": \"o_OPanHKvMvkM1D0_u52AHhZDRCMyxsDTHW-6rCmi7DhXNcfLGJMpL05pLiGSz3OGZN7uI83IP748f-WgRxc5H5nyXYe-7fEMue1T6ZF1p5-e1rBZ_ukXULHaiLff834YOMuMa0t8X7sKLMI4eInKH2SK_uSqxCT12hh3IukhxS1wbB9kSvE1v7PNXAU1enXC3M1wFRmmKPMuK_AKbtqKv-y2UG1GeisWg7HLuOYHINga8gY60KJDBp-wDsJOpIrMCRDP99OnkJWMbC-k8gWzDGCtdQHTGQnfgGxJVmKVUG-7JOCnlu-S21yofvj1K_aTAtAS8ByJHBLBzIjUBotuQ\",\n" +
  "  \"e\": \"AQAB\",\n" +
  "  \"use\": \"sig\",\n" +
  "  \"kid\": \"12345\",\n" +
  "  \"alg\": \"RS256\",\n" +
  "  \"n\": \"sB3jz6IZBOuerqkZ-RUpCoZuNeaL2A2ODOC4W9dJcL649-dYGzJMR6R8chuOL5EQAEZyzbxGU49rkLCa0d0yt4PIJE_k86Ib9PBZhhyj1WuIPHYuJqzPlwdHXJDSA6pEdSsOS5fWCLs75IETnbmPtV0wM8C32QHd6U8M2iZSmy5XFut5H-DisplW7rTaeCzVIqZXEnvBp0ZsxVyXkYJj1emnhX0TqgsdQy8H7evVvM2--dIBIENbKmxNQQH8pwTdRgMWJqAFjo8Tkj2PKLb075aEE-wEtlF0Ms7Y2ASo22Jya57E-CPfeCPE5vIJ_SyC0B8GeIE41qdra-lfzVi_zQ\"\n" +
  "}";

const PUBLIC_KEY_SET = "{\n" +
  "  \"keys\": [\n" +
  "    {\n" +
  "      \"kty\": \"RSA\",\n" +
  "      \"e\": \"AQAB\",\n" +
  "      \"use\": \"sig\",\n" +
  "      \"kid\": \"12345\",\n" +
  "      \"alg\": \"RS256\",\n" +
  "      \"n\": \"sB3jz6IZBOuerqkZ-RUpCoZuNeaL2A2ODOC4W9dJcL649-dYGzJMR6R8chuOL5EQAEZyzbxGU49rkLCa0d0yt4PIJE_k86Ib9PBZhhyj1WuIPHYuJqzPlwdHXJDSA6pEdSsOS5fWCLs75IETnbmPtV0wM8C32QHd6U8M2iZSmy5XFut5H-DisplW7rTaeCzVIqZXEnvBp0ZsxVyXkYJj1emnhX0TqgsdQy8H7evVvM2--dIBIENbKmxNQQH8pwTdRgMWJqAFjo8Tkj2PKLb075aEE-wEtlF0Ms7Y2ASo22Jya57E-CPfeCPE5vIJ_SyC0B8GeIE41qdra-lfzVi_zQ\"\n" +
  "    }\n" +
  "  ]\n" +
  "}";

module.exports = function (app) {
  app.use(cookieParser());

  let provider =
    config.provider_domain +
    (config.provider_port !== "NA" ? ":" + config.provider_port : "");

  let contentItemData = new ContentItem();
  let ciLoaded = false;
  let privateKey = jwk2pem(JSON.parse(FULL_KEYS));
  //=======================================================
  let setupLoaded = false;
  let setup = new SetupParameters();
  // let setup_key = "setupParameters";
  setup = {
    ...blackboard,
    privateKey: toolKey
  }
  // if (!setupLoaded) {
  //   redisUtil.redisGet(setup_key).then(setupData => {
  //     if (setupData !== null) {
  //       setup = setupData;

  //       if (setup.privateKey === "") {
  //         // use our generated one that goes with our generated public key and jwks URL
  //         setup.privateKey = privateKey;
  //         console.log("Using generated private key...");
  //       }

  //       setupLoaded = true;
  //     }
  //   });
  // }

  //=======================================================
  // LTI 1 provider and caliper stuff
  app.post('/caliper/send', (req, res) => {
    lti.caliper_send(req, res);
  });
  app.post('/caliper/register', (req, res) => {
    lti.caliper(req, res);
  });
  app.post('/caliper', (req, res) => {
    eventstore.got_caliper(req, res);
  });
  app.get('/caliper', (req, res) => {
    eventstore.show_events(req, res);
  });
  app.post("/rest/auth", (req, res) => {
    lti.rest_auth(req, res);
  });
  app.post("/rest/user", (req, res) => {
    lti.rest_getuser(req, res);
  });
  app.post("/rest/course", (req, res) => {
    lti.rest_getcourse(req, res);
  });
  app.post("/lti/outcomes", (req, res) => {
    lti.outcomes(req, res);
  });
  app.post("/lti/send_outcomes", (req, res) => {
    lti.send_outcomes(req, res);
  });
  app.get("/lti/membership", (req, res) => {
    lti.get_membership(req, res);
  });
  app.post("/lti", (req, res) => {
    console.log("--------------------\nlti");
    if (req.body.lti_message_type === "ContentItemSelectionRequest") {
      content_item.got_launch(req, res, contentItemData).then(() => {
        redisUtil.redisSave(contentitem_key, contentItemData);
        ciLoaded = true;

        let redirectUrl = provider + "/content_item";
        console.log("Redirecting to : " + redirectUrl);
        res.redirect(redirectUrl);
      });
    }

    if (req.body.lti_message_type === "basic-lti-launch-request") {
      lti.got_launch(req, res);
    }

    if (req.body.id_token) {
      console.log("Redirecting to LTI 1.3");
      jwtPayload = new JWTPayload();
      ltiAdv.verifyToken(req.body.id_token, jwtPayload, setup);
      res.redirect("/lti_adv_view");
    }
  });

  //=======================================================
  // Content Item Message processing
  let passthru_req;
  let passthru_res;
  let passthru = false;

  app.post("/CIMRequest", (req, res) => {
    console.log("--------------------\nCIMRequest Provider URL in routes: " + provider);

    if (req.body.custom_option === undefined) {
      // no custom_option set so go to CIM request menu and save req and res to pass through
      // after custom_option has been selected
      passthru_req = req;
      passthru_res = res;
      passthru = true;
      res.redirect("/cim_request");
    } else {
      if (!passthru) {
        // custom_option was set in call from TC so use current req and res
        passthru_req = req;
        passthru_res = res;
        passthru = false;
      } else {
        // custom_option was set from menu so add option and content (if available) to passthru_req
        passthru_req.body.custom_option = req.body.custom_option;
        passthru_req.body.custom_content = req.body.custom_content;
      }
      content_item
        .got_launch(passthru_req, passthru_res, contentItemData)
        .then(() => {
          redisUtil.redisSave(contentitem_key, contentItemData);
          ciLoaded = true;

          let redirectUrl = provider + "/content_item";
          console.log("Redirecting to : " + redirectUrl);
          res.redirect(redirectUrl);
        });
    }
  });

  app.get("/contentitemdata", (req, res) => {
    if (!ciLoaded) {
      redisUtil.redisGet(contentitem_key).then(contentData => {
        contentItemData = contentData;
        res.send(contentItemData);
      });
    } else {
      res.send(contentItemData);
    }
  });

  //=======================================================
  // LTI Advantage Message processing
  let jwtPayload;
  let users = {
    name: "Fyodor",
    age: "77"
  };

  app.post("/lti13", (req, res) => {
    console.log("--------------------\nltiAdvantage");
    // console.log(req.params)
    jwtPayload = new JWTPayload();
    // console.log(jwtPayload)
    ltiAdv.verifyToken(req.body.id_token, jwtPayload, setup);
    res.cookie("userData-legacy", users);
    res.cookie("userData", users, {
      sameSite: 'none',
      secure: true
    });
    res.redirect("/lti_adv_view");
  });

  app.post("/ltiAdv", (req, res) => {
    console.log("--------------------\nltiAdvantage");
    jwtPayload = new JWTPayload();
    ltiAdv.verifyToken(req.body.id_token, jwtPayload, setup);
    res.cookie("userData-legacy", users);
    res.cookie("userData", users, {
      sameSite: 'none',
      secure: true
    });
    res.redirect("/lti_adv_view");
  });

  app.get("/jwtPayloadData", (req, res) => {
    res.send(jwtPayload);
  });

  app.get("/login", (req, res) => {
    console.log("--------------------\nlogin");
    ltiAdv.security1(req, res, jwtPayload, setup);
  });

  //=======================================================
  // Deep Linking
  let dlPayload;

  app.post("/deepLink", (req, res) => {
    console.log("--------------------\ndeepLink");
    dlPayload = new JWTPayload();
    ltiAdv.verifyToken(req.body.id_token, dlPayload, setup);
    deepLink(req, res, dlPayload, setup);
    res.redirect("/deep_link");
  });

  app.get("/dlPayloadData", (req, res) => {
    res.send(dlPayload);
  });

  app.post("/deepLinkOptions", (req, res) => {
    console.log("--------------------\ndeepLinkOptions");
    dlPayload = new JWTPayload();
    ltiAdv.verifyToken(req.body.id_token, dlPayload, setup);
    res.redirect("/deep_link_options");
  });

  app.post("/deepLinkContent", (req, res) => {
    console.log("--------------------\ndeepLinkContent");
    deepLinkContent(req, res, dlPayload, setup);
    res.redirect("/deep_link");
  });

  //=======================================================
  // Names and Roles
  let nrPayload;

  app.post("/namesAndRoles", (req, res) => {
    console.log(req.body)
    console.log("--------------------\nnamesAndRoles");
    nrPayload = new NRPayload();
    namesRoles.namesRoles(req, res, nrPayload, setup);
  });

  app.post("/namesAndRoles2", (req, res) => {
    nrPayload.url = req.body.url;
    namesRoles.namesRoles(req, res, nrPayload, setup);
  });

  app.get("/nrPayloadData", (req, res) => {
    res.send(nrPayload);
  });

  //=======================================================
  // Groups
  let groupsPayload;

  app.post("/groups", (req, res) => {
    console.log("--------------------\ngroups");
    groupsPayload = new GroupsPayload();
    groups.groups(req, res, groupsPayload, setup);
    res.redirect("/groups_view");
  });

  app.get("/groupsPayloadData", (req, res) => {
    res.send(groupsPayload);
  });

  app.post("/getgroups", (req, res) => {
    console.log("--------------------\ngroups");
    groupsPayload.form = req.body;
    groups.getGroups(req, res, groupsPayload, setup);
  });

  let groupSetsPayload;

  app.post("/groupsets", (req, res) => {
    console.log("--------------------\ngroupsets");
    groupSetsPayload = new GroupsPayload();
    groups.groupSets(req, res, groupSetsPayload, setup);
  });

  app.get("/groupSetsPayloadData", (req, res) => {
    res.send(groupSetsPayload);
  });

  //=======================================================
  // Assignments and Grades
  let agPayload;

  app.post("/assignAndGrades", (req, res) => {
    console.log("--------------------\nassignAndGrades");
    agPayload = new AGPayload();
    assignGrades.assignGrades(req, res, agPayload);
    res.redirect("/assign_grades_view");
  });

  app.post("/agsReadCols", (req, res) => {
    console.log("--------------------\nagsReadCols");
    agPayload.url = req.body.url;
    assignGrades.readCols(req, res, agPayload, setup);
  });

  app.post("/agsAddcol", (req, res) => {
    console.log("--------------------\nagsAddCol");
    agPayload.form = req.body;
    assignGrades.addCol(req, res, agPayload, setup);
  });

  app.post("/agsDeleteCol", (req, res) => {
    console.log("--------------------\nagsDeleteCol");
    agPayload.form = req.body;
    assignGrades.delCol(req, res, agPayload, setup);
  });

  app.post("/agsResults", (req, res) => {
    console.log("--------------------\nagsResults");
    agPayload.form = req.body;
    assignGrades.results(req, res, agPayload, setup);
  });

  app.post("/agsScores", (req, res) => {
    console.log("--------------------\nagsScores");
    agPayload.form = req.body;
    assignGrades.scores(req, res, agPayload, setup, "score");
  });

  app.post("/agsClearScores", (req, res) => {
    console.log("--------------------\nagsClearScores");
    agPayload.form = req.body;
    assignGrades.scores(req, res, agPayload, setup, "clear");
  });

  app.post("/agsSubmitAttempt", (req, res) => {
    console.log("--------------------\nagsSubmitAttempt");
    agPayload.form = req.body;
    assignGrades.scores(req, res, agPayload, setup, "submit");
  });

  app.get("/agPayloadData", (req, res) => {
    res.send(agPayload);
  });

  app.get("/config", (req, res) => {
    res.send(config);
  });

  app.get("/.well-known/jwks.json", (req, res) => {
    res.send(PUBLIC_KEY_SET);
  });

  //=======================================================
  // Grab a token and display it

  app.get("/tokenGrab", (req, res) => {
    console.log("--------------------\ntokenGrab");
    ltiAdv.tokenGrab(req, res, jwtPayload, setup);
  });

  //=======================================================
  // Setup processing

  app.get("/setup_page", (req, res) => {
    console.log("--------------------\nsetup");
    res.redirect("/setup");
  });

  app.get("/setupData", (req, res) => {
    setup.cookies = req.cookies;
    setup.host = req.header('Host');
    res.send(setup);
  });

  app.post("/saveSetup", (req, res) => {
    console.log(process.env.TOOL, "ENV VALUE")
    console.log(setup, "before")
    // setup.privateKey = req.body.privateKey;
    // setup.tokenEndPoint = req.body.tokenEndPoint;
    // setup.oidcAuthUrl = req.body.oidcAuthUrl;
    // setup.issuer = req.body.issuer;
    // setup.applicationId = req.body.applicationId;
    // setup.devPortalHost = req.body.devPortalHost;
    console.log(setup, "after")
    // redisUtil.redisSave(setup_key, setup);
    res.redirect("/setup");
  });

  //=======================================================
  // Test REDIS

  app.get("/testRedis", (req, res) => {
    console.log("--------------------\ntestRedis");

    redisUtil.redisSave("key", "value");
    redisUtil.redisGet("key").then((value) => {
      console.log("Redis value for key: " + value);
    });

    res.send('<html lang=""><body>1</body></html>');
  });

  //=======================================================
  // Catch all
  app.get("*", (req, res) => {
    console.log("catchall - (" + req.url + ")");
    res.sendFile(path.resolve("./public", "index.html"));
  });
};