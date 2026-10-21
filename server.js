const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();

app.use(express.json());

const JWT_SECRET = "super_secret_key_afl3_ariiq";

// --- DUMMY DATABASE ---
const users = [
  { id: 1, username: "admin", role: "Admin", department: "IT", subStatus: "Premium" },
  { id: 2, username: "dr_budi", role: "Doctor", department: "Kardiologi", subStatus: "Premium" },
  { id: 3, username: "dr_siti", role: "Doctor", department: "Neurologi", subStatus: "Basic" },
  { id: 4, username: "patient_ariiq", role: "Patient", patientId: "P100", department: "Kardiologi", subStatus: "Premium" },
];

const medicalRecords = [
  { id: 101, title: "Rekam Jantung Ariiq", department: "Kardiologi", ownerPatientId: "P100", isConfidential: true },
  { id: 102, title: "Rekam Saraf Anna", department: "Neurologi", ownerPatientId: "P200", isConfidential: false },
];

// --- MIDDLEWARE 1: VERIFIKASI JWT (#1 Access Token) ---
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Access Token Required" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid or Expired Token" });
    req.user = user;
    next();
  });
}

// --- MIDDLEWARE 2: RBAC CHECK (#2 RBAC) ---
function checkRBAC(allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: `Access Denied: Role '${req.user.role}' is not authorized.` });
    }
    next();
  };
}

// --- MIDDLEWARE 3: ABAC CHECK (#3 ABAC) ---
function checkABAC_Ownership(req, res, next) {
  const recordId = parseInt(req.params.id);
  const record = medicalRecords.find((r) => r.id === recordId);

  if (!record) return res.status(404).json({ message: "Record not found" });

  // Atribut Pengguna vs Atribut Resource
  if (req.user.role === "Patient" && req.user.patientId !== record.ownerPatientId) {
    return res.status(403).json({ message: "ABAC Denied: You do not own this medical record." });
  }

  req.record = record;
  next();
}

// --- MIDDLEWARE 4: GABUNGAN RBAC + ABAC (#4 Combined) ---
function checkCombined_RBAC_ABAC(req, res, next) {
  const recordId = parseInt(req.params.id);
  const record = medicalRecords.find((r) => r.id === recordId);

  if (!record) return res.status(404).json({ message: "Record not found" });

  // 1. RBAC Check: Harus Doctor atau Admin
  if (!["Admin", "Doctor"].includes(req.user.role)) {
    return res.status(403).json({ message: "Combined Check Failed: Role not authorized" });
  }

  // 2. ABAC Check: Jika Doctor, Departemen Pengguna HARUS SAMA dengan Departemen Record
  if (req.user.role === "Doctor" && req.user.department !== record.department) {
    return res.status(403).json({ 
      message: `Combined Check Failed: Doctor department (${req.user.department}) does not match Record department (${record.department})` 
    });
  }

  next();
}

// ================= ROUTE ENDPOINTS =================

// 1. LOGIN (JWT Generation)
app.post("/api/auth/login", (req, res) => {
  const { username } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user) return res.status(400).json({ message: "User not found" });

  const accessToken = jwt.sign(user, JWT_SECRET, { expiresIn: "1h" });
  res.json({ accessToken, user });
});

// Mock Google OAuth Callback Endpoint (#1 Access Token)
app.get("/api/auth/google/callback", (req, res) => {
  const googleUser = { id: 99, username: "ariiq_google", role: "Patient", patientId: "P100", subStatus: "Premium" };
  const accessToken = jwt.sign(googleUser, JWT_SECRET, { expiresIn: "1h" });
  res.json({ message: "Google OAuth Successful", accessToken });
});

// 2. ENDPOINT RBAC (#2)
app.get("/api/admin/dashboard", authenticateJWT, checkRBAC(["Admin"]), (res_req, res) => {
  res.json({ message: "Welcome Admin! Access Granted to System Management." });
});

// 3. ENDPOINT ABAC (#3)
app.get("/api/records/my-record/:id", authenticateJWT, checkABAC_Ownership, (req, res) => {
  res.json({ message: "ABAC Granted: Viewing Owned Record", record: req.record });
});

// 4. ENDPOINT GABUNGAN RBAC + ABAC (#4)
app.delete("/api/records/delete/:id", authenticateJWT, checkCombined_RBAC_ABAC, (req, res) => {
  res.json({ message: `Success: Record ${req.params.id} deleted via Combined RBAC+ABAC authorization.` });
});

app.listen(3000, () => console.log("MediAccess Server running on port 3000"));