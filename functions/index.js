"use strict";

const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");
const crypto = require("node:crypto");

admin.initializeApp();

const db = admin.firestore();
const SESSION_TTL_MS = 90000;

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

function normalizeNickname(nickname) {
  const displayName = String(nickname || "").trim().replace(/\s+/g, " ");
  if (displayName.length < 2 || displayName.length > 24 || displayName.includes("/")) {
    throw new HttpsError("invalid-argument", "Nickname must be 2-24 characters and cannot contain /.");
  }
  const accountId = crypto.createHash("sha256").update(displayName.toLocaleLowerCase()).digest("hex");
  return { accountId, displayName };
}

function requirePassword(password) {
  const value = String(password || "");
  if (value.length < 4 || value.length > 64) {
    throw new HttpsError("invalid-argument", "Password must be 4-64 characters.");
  }
  return value;
}

function hashPassword(password, salt) {
  return crypto.createHash("sha256").update(`${salt}:${password}`).digest("hex");
}

function accountPayload(accountId, displayName, sessionId) {
  return { accountId, displayName, sessionId };
}

function assertAccountSession(account = {}, uid) {
  if (!uid) throw new HttpsError("unauthenticated", "Sign in first.");
  const accountId = String(account.accountId || "");
  const sessionId = String(account.sessionId || "");
  if (!accountId || !sessionId) throw new HttpsError("invalid-argument", "Missing account session.");
  return { accountId, sessionId };
}

async function takeAccountSession({ accountRef, sessionRef, uid, sessionId }) {
  const now = admin.firestore.Timestamp.now();
  await db.runTransaction(async (tx) => {
    const accountSnap = await tx.get(accountRef);
    if (!accountSnap.exists) throw new HttpsError("not-found", "Account not found.");
    const account = accountSnap.data() || {};
    const activeAt = account.activeAt?.toMillis ? account.activeAt.toMillis() : 0;
    const activeFresh = Date.now() - activeAt < SESSION_TTL_MS;
    if (account.activeUid && account.activeUid !== uid && activeFresh) {
      throw new HttpsError("failed-precondition", "account-busy");
    }
    tx.set(accountRef, {
      activeUid: uid,
      activeSessionId: sessionId,
      activeAt: now
    }, { merge: true });
    tx.set(sessionRef, {
      accountId: accountRef.id,
      sessionId,
      active: true,
      updatedAt: now
    }, { merge: true });
  });
}

exports.createGameAccount = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Sign in first.");
  const { accountId, displayName } = normalizeNickname(request.data?.nickname);
  const password = requirePassword(request.data?.password);
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(password, salt);
  const sessionId = crypto.randomUUID();
  const now = admin.firestore.Timestamp.now();
  const accountRef = db.doc(`gameAccounts/${accountId}`);
  const sessionRef = db.doc(`accountSessions/${request.auth.uid}`);
  const profileRef = db.doc(`accountProfiles/${accountId}/clientMirror/profile`);

  await db.runTransaction(async (tx) => {
    const existing = await tx.get(accountRef);
    if (existing.exists) throw new HttpsError("already-exists", "Account already exists.");
    tx.set(accountRef, {
      displayName,
      passwordHash,
      salt,
      activeUid: request.auth.uid,
      activeSessionId: sessionId,
      activeAt: now,
      createdAt: now
    });
    tx.set(sessionRef, {
      accountId,
      sessionId,
      active: true,
      updatedAt: now
    }, { merge: true });
    tx.set(profileRef, {
      ...(request.data?.profile || {}),
      updatedAt: now
    }, { merge: true });
  });

  return { ok: true, account: accountPayload(accountId, displayName, sessionId) };
});

exports.loginGameAccount = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Sign in first.");
  const { accountId } = normalizeNickname(request.data?.nickname);
  const password = requirePassword(request.data?.password);
  const accountRef = db.doc(`gameAccounts/${accountId}`);
  const accountSnap = await accountRef.get();
  if (!accountSnap.exists) throw new HttpsError("permission-denied", "Incorrect nickname or password.");
  const account = accountSnap.data() || {};
  const passwordHash = hashPassword(password, account.salt || "");
  if (passwordHash !== account.passwordHash) {
    throw new HttpsError("permission-denied", "Incorrect nickname or password.");
  }

  const sessionId = crypto.randomUUID();
  await takeAccountSession({
    accountRef,
    sessionRef: db.doc(`accountSessions/${request.auth.uid}`),
    uid: request.auth.uid,
    sessionId
  });

  return { ok: true, account: accountPayload(accountId, account.displayName, sessionId) };
});

exports.resumeGameAccount = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Sign in first.");
  const { accountId, sessionId } = assertAccountSession(request.data, request.auth.uid);
  const accountRef = db.doc(`gameAccounts/${accountId}`);
  const accountSnap = await accountRef.get();
  if (!accountSnap.exists) return { ok: false };
  const account = accountSnap.data() || {};
  if (account.activeUid !== request.auth.uid || account.activeSessionId !== sessionId) {
    return { ok: false };
  }
  await takeAccountSession({
    accountRef,
    sessionRef: db.doc(`accountSessions/${request.auth.uid}`),
    uid: request.auth.uid,
    sessionId
  });
  return { ok: true, account: accountPayload(accountId, account.displayName, sessionId) };
});

exports.accountHeartbeat = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Sign in first.");
  const { accountId, sessionId } = assertAccountSession(request.data, request.auth.uid);
  const accountRef = db.doc(`gameAccounts/${accountId}`);
  const accountSnap = await accountRef.get();
  if (!accountSnap.exists) return { ok: false };
  const account = accountSnap.data() || {};
  if (account.activeUid !== request.auth.uid || account.activeSessionId !== sessionId) {
    return { ok: false };
  }
  await accountRef.set({ activeAt: admin.firestore.Timestamp.now() }, { merge: true });
  await db.doc(`accountSessions/${request.auth.uid}`).set({
    accountId,
    sessionId,
    active: true,
    updatedAt: admin.firestore.Timestamp.now()
  }, { merge: true });
  return { ok: true };
});

exports.logoutGameAccount = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Sign in first.");
  const { accountId, sessionId } = assertAccountSession(request.data, request.auth.uid);
  const accountRef = db.doc(`gameAccounts/${accountId}`);
  const sessionRef = db.doc(`accountSessions/${request.auth.uid}`);
  await db.runTransaction(async (tx) => {
    const accountSnap = await tx.get(accountRef);
    if (accountSnap.exists) {
      const account = accountSnap.data() || {};
      if (account.activeUid === request.auth.uid && account.activeSessionId === sessionId) {
        tx.set(accountRef, {
          activeUid: admin.firestore.FieldValue.delete(),
          activeSessionId: admin.firestore.FieldValue.delete(),
          activeAt: admin.firestore.FieldValue.delete()
        }, { merge: true });
      }
    }
    tx.set(sessionRef, {
      accountId,
      sessionId,
      active: false,
      updatedAt: admin.firestore.Timestamp.now()
    }, { merge: true });
  });
  return { ok: true };
});

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
