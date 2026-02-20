require("dotenv").config(); // Load .env variables

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const admin = require("firebase-admin");
const axios = require("axios");

/* ==============================
   🔐 FIREBASE INITIALIZATION
============================== */
const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();
const app = express();

/* ==============================
   🛡 SECURITY MIDDLEWARE
============================== */
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "10kb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                  // max requests per IP
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

/* ==============================
   🔐 VERIFY USER MIDDLEWARE
============================== */
const verifyUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const idToken = authHeader.split("Bearer ")[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

/* ==============================
   👑 REQUIRE ADMIN MIDDLEWARE
============================== */
const requireAdmin = (req, res, next) => {
  if (!req.user.admin) {
    return res.status(403).json({ message: "Access denied (Admin only)" });
  }
  next();
};

/* ==============================
   🔗 LINKEDIN AUTH ROUTES
============================== */
app.get("/auth/linkedin", (req, res) => {
  const scope = "r_liteprofile r_emailaddress";
  const linkedinAuthUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${process.env.LINKEDIN_REDIRECT_URI}&scope=${scope}`;
  res.redirect(linkedinAuthUrl);
});

app.get("/auth/linkedin/callback", async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send("No code received from LinkedIn");

    const tokenResponse = await axios.post(
      "https://www.linkedin.com/oauth/v2/accessToken",
      null,
      {
        params: {
          grant_type: "authorization_code",
          code,
          redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
          client_id: process.env.LINKEDIN_CLIENT_ID,
          client_secret: process.env.LINKEDIN_CLIENT_SECRET,
        },
      }
    );

    const accessToken = tokenResponse.data.access_token;

    const profileResponse = await axios.get("https://api.linkedin.com/v2/me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const emailResponse = await axios.get(
      "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const userEmail = emailResponse.data.elements[0]["handle~"].emailAddress;
    const userName = `${profileResponse.data.localizedFirstName} ${profileResponse.data.localizedLastName}`;

    const firebaseToken = await admin.auth().createCustomToken(userEmail, {
      displayName: userName,
    });

    res.send(`
      <script>
        window.opener.postMessage({ firebaseToken: "${firebaseToken}" }, "*");
        window.close();
      </script>
    `);
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).send("LinkedIn login failed");
  }
});

/* ==============================
   🗳 VOTE API
============================== */
app.post("/api/vote", verifyUser, async (req, res) => {
  try {
    const userId = req.user.uid;
    const name = req.user.displayName || "Anonymous";
    const { candidateId, linkedInProfile } = req.body;

    if (!candidateId) return res.status(400).json({ message: "Candidate ID required" });

    const voterRef = db.collection("voters").doc(userId);
    const candidateRef = db.collection("candidates").doc(candidateId);

    await db.runTransaction(async (transaction) => {
      const voterDoc = await transaction.get(voterRef);
      if (voterDoc.exists) throw new Error("You have already voted");

      const candidateDoc = await transaction.get(candidateRef);
      if (!candidateDoc.exists) throw new Error("Candidate not found");

      transaction.set(voterRef, {
        name,
        candidateId,
        linkedInProfile: linkedInProfile || null,
        votedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      transaction.update(candidateRef, {
        votes: admin.firestore.FieldValue.increment(1),
      });
    });

    res.status(200).json({ message: "Vote successful!" });
  } catch (error) {
    res.status(400).json({ message: error.message || "Voting failed" });
  }
});

/* ==============================
   👥 GET ALL CANDIDATES
============================== */
app.get("/api/candidates", async (req, res) => {
  try {
    const snapshot = await db.collection("candidates").get();
    const candidates = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    res.status(200).json(candidates);
  } catch (error) {
    res.status(500).json({ message: "Error fetching candidates", error: error.message });
  }
});

/* ==============================
   📋 GET ALL VOTERS (ANY LOGGED-IN USER)
============================== */
app.get("/api/voters", verifyUser, async (req, res) => {
  try {
    const snapshot = await db.collection("voters").get();
    const voters = snapshot.docs.map((doc) => {
      const data = doc.data();
      return {
        userId: doc.id,
        name: data.name,
        linkedInProfile: data.linkedInProfile,
        candidateId: data.candidateId,
        votedAt: data.votedAt ? data.votedAt.toDate().toISOString() : null,
      };
    });
    res.status(200).json(voters);
  } catch (error) {
    res.status(500).json({ message: "Error fetching voters", error: error.message });
  }
});

/* ==============================
   👑 MAKE USER ADMIN
============================== */
app.post("/make-admin", verifyUser, requireAdmin, async (req, res) => {
  try {
    const { uid } = req.body;
    if (!uid) return res.status(400).json({ message: "UID required" });

    await admin.auth().setCustomUserClaims(uid, { admin: true });
    res.status(200).json({ message: "User is now admin!" });
  } catch (error) {
    res.status(500).json({ message: "Error setting admin", error: error.message });
  }
});

/* ==============================
   ❤️ HEALTH CHECK
============================== */
app.get("/", (req, res) => res.send("Voting Backend Running ✅"));

/* ==============================
   🚀 START SERVER
============================== */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));