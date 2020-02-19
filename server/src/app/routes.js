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
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQClAbXD6LF+LbQy
Zy578q8J1BJaKmkXoVRejN0pN4PVgFEhalqOCcnfdqd2InIfspo+OKC4aDngRdoT
33/YZb6ZQ++92wyHauSLqBQpcpLrZ0HWHdGgW/PrGhfPVrbX+28iT70YQWXKkMxW
P7+hgZ+iILI99fSnJNL1vxE08aDUoLq7CLSIXQgRTcsr1NsbCxc+78D/BQbBXfgZ
OJZDMHP9Zb4GEGFv4c0J4Ip7IUWXDweRjtY5NJdecxxOdOlw0iK1R1Asso1gIjTw
I4wHTXWCJRZwETi/nIt/Bd4l6920Qjm9D/4gsT4oVSu4rcD48dOSqSFIL63Xtn4w
Kuvs/vYLAgMBAAECggEAYWEp+U1ZeqLUZq6YM1Qc0wsSLZ472VM/rHErkEiQCC8r
MjJG8O578eJfoAtiGKzZ9ICM8WepSF9Q/Ut4cqhRHLiIQx6EPWLrMDRoebGBXWXZ
59g/P4kk4YnLpXSCgeKEStaOPUNTJIHh5cDHgjQylob/SiveT8oeqiMxr3IuPW0P
P3ySFrl7aD4oiSEqvb5oGkfgCMKcpgyPIpV5fCiyz68X/IZn5KHeP2dJFHGb+jAq
TtOIO5CZXy3N3xHtdS/eIfLTkkDJWLQyFU4gmxsICZrSZLXe2/oRcmY0na7Huvzd
04sPwIYz5FusRM2NaHelaFhSGEJkM+u8w0gV2lMgqQKBgQDSPU90MYG2Ep61iUSu
HM3FRpXRFz2e5eJxH4EcgPXaq/5Ujpd8i4khW9ifJtjFr7kdZE/HQsskI9pRpnyf
ihgjV7UriI+qP4yv9EuhvjNf+eDtb1DOl0Nzl2fSAr4NTOhaT4NWWUa+ZMg04JCV
V8BrJxqLXk+oCzd+3oc8CjIetwKBgQDI6/79t8fJd9wAgWk2BZyuFMKG+K+dVXfF
6fCVTW4iTqhg/Ykv52maRS8G+m7z6H/lMVgwqlrh3ZmPIFsr/wkjSaDagjtXFLZ2
l0YuLJ3QG9zMkqMznLIl7VoGUEH/wctvUF4LAYYY445WOe+oRux+FXx/8rpdU0px
+ML0NdkPTQKBgEaoiG2aved9do24praFw7qLsIpnbzRaOrKeTfxQc1CdAYtVqSAY
nWvyvGkw2yYFmwd/0Tg9AJ0S16sdc0EDXn1yWtdYvEARv6zbRBgGHqohBzGFefkU
6XyN5Dy24z0BHg5MLu30b0xJ/ueWmcE3jtn0eH1iow7tRieDjpvlKVcdAoGAZ7P3
HrlWsxPcR56D0VBAOFGavdNpwQk2Er7WYBlg+PAkVDtILaOBjBCdXzqvPdEJAiDf
5e5njiC0e3010ZWG/+Gm1mFVg3K7YqZdoMOCiMF4y1X8Sk1cXdsOFigiiIFcIQ4Y
HBIjRoFdHAA3RGGm+sTYR6neqwCscfr1lNqeOBkCgYB9YwJi/JwMDzva0VplEb+f
TLP5VeiR9ChvjiR9syXhYoO5uZwdwwuFrhgqd9JHG7Gai4R9xRStky66YX8fflMr
m7Wxh2F+LUgCubR+ojWRD2D9wMsP29yn8qOF6Kps4FE1AVPv90ctMSAOFWagza8k
r+eq/xTLQ5iZjn8uAcDSog==
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