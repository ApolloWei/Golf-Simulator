"use strict";

const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");

admin.initializeApp();

const SUPPORTER_PASSWORD = defineSecret("SUPPORTER_PASSWORD");
const SUPPORTER_PLUS_PASSWORD = defineSecret("SUPPORTER_PLUS_PASSWORD");
const SUPPORTER_MAX_PASSWORD = defineSecret("SUPPORTER_MAX_PASSWORD");
const SUPPORTER_CREATOR_PASSWORD = defineSecret("SUPPORTER_CREATOR_PASSWORD");

function supporterFlagsForTier(tier) {
  if (tier === "5") return { normal: true, future: true, max: true, creator: true };
  if (tier === "3") return { normal: true, future: true, max: true, creator: false };
  if (tier === "2") return { normal: true, future: true, max: false, creator: false };
  if (tier === "1") return { normal: true, future: false, max: false, creator: false };
  return null;
}

function expectedPasswordForTier(tier) {
  if (tier === "5") return SUPPORTER_CREATOR_PASSWORD.value();
  if (tier === "3") return SUPPORTER_MAX_PASSWORD.value();
  if (tier === "2") return SUPPORTER_PLUS_PASSWORD.value();
  if (tier === "1") return SUPPORTER_PASSWORD.value();
  return "";
}

exports.verifySupporterCode = onCall(
  {
    secrets: [
      SUPPORTER_PASSWORD,
      SUPPORTER_PLUS_PASSWORD,
      SUPPORTER_MAX_PASSWORD,
      SUPPORTER_CREATOR_PASSWORD
    ]
  },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "Sign in before unlocking supporter access.");
    }

    const tier = String(request.data?.tier || "").trim();
    const password = String(request.data?.password || "");
    const supporter = supporterFlagsForTier(tier);
    const expected = expectedPasswordForTier(tier);

    if (!supporter || !expected || password !== expected) {
      throw new HttpsError("permission-denied", "Incorrect supporter password.");
    }

    await admin
      .firestore()
      .doc(`users/${request.auth.uid}/serverProfile/progress`)
      .set(
        {
          supporter,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        },
        { merge: true }
      );

    return { ok: true, supporter };
  }
);
