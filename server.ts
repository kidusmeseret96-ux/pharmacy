import 'dotenv/config';
import crypto from 'node:crypto';
import path from 'node:path';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import {
  hashPassword,
  issueToken,
  requireAuth,
  requireManagerOrOwner,
  requireOwner,
  verifyConstantTimeSecret,
  verifyPassword,
  type AuthedRequest,
} from './server/auth.ts';
import {
  appendAuditLog,
  buildPayrollStatuses,
  computeAttendanceSummary,
  getClinicNow,
  loadDatabase,
  saveDatabase,
  syncAlertForDrug,
  verifyAuditChain,
} from './server/store.ts';
import type {
  Drug,
  DrugKindIconKey,
  ExpenseCategory,
  OverviewAnalytics,
  PaymentMethod,
  PayrollMethod,
  SaleUnitTier,
  ShiftCloseReport,
  StorageRequirement,
  Transaction,
  TransactionItem,
  UserRole,
} from './src/types/pharmacy.ts';

const PORT = Number(process.env.PORT || 3000);
const MASTER_RECOVERY_PASSCODE = '0945206759';
const VALID_STORAGE: StorageRequirement[] = ['room_temp', 'refrigerated', 'controlled'];
const VALID_PAYMENTS: PaymentMethod[] = ['cash', 'transfer', 'card', 'split'];
const VALID_PAYROLL_METHODS: PayrollMethod[] = ['cash', 'telebirr', 'cbe_birr', 'bank_transfer', 'check'];
const VALID_EXPENSE_CATS: ExpenseCategory[] = ['rent', 'utilities', 'supplies', 'maintenance', 'license', 'other'];
const VALID_ICON_KEYS: DrugKindIconKey[] = [
  'tablet',
  'capsule',
  'injection',
  'syrup',
  'inhaler',
  'cream',
  'drops',
  'suppository',
  'box',
];

function sanitizeDrugForRole(drug: Drug, role: UserRole): Drug {
  if (role === 'owner' || role === 'manager') return drug;
  const { buyingPrice: _omit, ...publicDrug } = drug;
  return publicDrug as Drug;
}

function sanitizeTransactionForRole(txn: Transaction, role: UserRole): Transaction {
  if (role === 'owner' || role === 'manager') return txn;
  const { totalCost: _c, totalProfit: _p, ...rest } = txn;
  return {
    ...rest,
    items: txn.items.map(({ unitBuyingPrice: _b, ...itemRest }) => itemRest),
  };
}

function sanitizeShiftCloseForRole(report: ShiftCloseReport, role: UserRole): ShiftCloseReport {
  if (role === 'owner' || role === 'manager') return report;
  const { expectedCash: _e, variance: _v, status: _s, ...blindCopy } = report;
  return blindCopy;
}

function isValidImageString(val: unknown): val is string {
  if (typeof val !== 'string') return false;
  if (val === '') return true;
  if (val.startsWith('/src/assets/')) return true;
  if (/^data:image\/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$/.test(val)) return true;
  return false;
}

function isValidHhMm(val: unknown): val is string {
  return typeof val === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(val.trim());
}

function resolveDrugUnit(
  drug: Drug,
  tier: SaleUnitTier
): { multiplier: number; sellingPrice: number; unitLabel: string } {
  const unitsPerPack = Math.max(1, Math.floor(drug.unitsPerPack ?? 1));
  const packsPerBox = Math.max(1, Math.floor(drug.packsPerBox ?? 1));

  if (tier === 'box' && packsPerBox > 1) {
    const multiplier = unitsPerPack * packsPerBox;
    const price =
      drug.boxSellingPrice && drug.boxSellingPrice > 0
        ? drug.boxSellingPrice
        : Number((drug.sellingPrice * multiplier).toFixed(2));
    return { multiplier, sellingPrice: price, unitLabel: drug.boxUnitName || 'Box' };
  }
  if (tier === 'pack' && unitsPerPack > 1) {
    const price =
      drug.packSellingPrice && drug.packSellingPrice > 0
        ? drug.packSellingPrice
        : Number((drug.sellingPrice * unitsPerPack).toFixed(2));
    return { multiplier: unitsPerPack, sellingPrice: price, unitLabel: drug.packUnitName || 'Strip' };
  }
  return { multiplier: 1, sellingPrice: drug.sellingPrice, unitLabel: drug.baseUnitName || 'Unit' };
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '15mb' }));

  // Auth status
  app.get('/api/auth/status', (_req, res) => {
    const db = loadDatabase();
    const envPasscodeActive = Boolean(process.env.OWNER_PASSCODE && process.env.OWNER_PASSCODE.trim().length > 0);
    res.json({
      ownerClaimed: envPasscodeActive || Boolean(db.ownerPasswordHash),
      envPasscodeActive,
      clinicName: db.settings.clinicName,
      currencySymbol: db.settings.currencySymbol,
      taxRatePercent: db.settings.taxRatePercent,
    });
  });

  // One-time owner claim
  app.post('/api/auth/owner/claim', async (req, res) => {
    const db = loadDatabase();
    const envPasscode = process.env.OWNER_PASSCODE?.trim();
    if (envPasscode) {
      return res.status(403).json({ error: 'Owner passcode is managed by environment configuration.' });
    }
    if (db.ownerPasswordHash) {
      return res.status(409).json({ error: 'Owner account has already been claimed. Please sign in.' });
    }

    const { username, password, ownerName, clinicName } = req.body ?? {};
    const cleanUsername = typeof username === 'string' && username.trim() ? username.trim().toLowerCase() : 'owner';
    if (!/^[a-zA-Z0-9._-]{3,32}$/.test(cleanUsername)) {
      return res.status(400).json({ error: 'Username must be 3–32 characters (letters, numbers, ., _, -).' });
    }
    if (typeof password !== 'string' || password.length < 6 || password.length > 128) {
      return res.status(400).json({ error: 'Password must be between 6 and 128 characters.' });
    }

    db.ownerUsername = cleanUsername;
    db.ownerPasswordHash = hashPassword(password);
    if (typeof ownerName === 'string' && ownerName.trim()) {
      db.settings.ownerName = ownerName.trim().slice(0, 80);
    }
    if (typeof clinicName === 'string' && clinicName.trim()) {
      db.settings.clinicName = clinicName.trim().slice(0, 100);
    }

    appendAuditLog(db, {
      actorId: 'owner_primary',
      actorName: db.settings.ownerName,
      actorRole: 'owner',
      action: 'OWNER_ACCOUNT_CLAIMED',
      targetType: 'account',
      targetName: db.ownerUsername,
      afterSummary: `Owner account claimed (${db.settings.clinicName})`,
    });

    await saveDatabase(db);

    const user = {
      id: 'owner_primary',
      role: 'owner' as const,
      name: db.settings.ownerName,
      username: db.ownerUsername,
    };
    const token = issueToken(user);
    res.status(201).json({ token, user });
  });

  // Unified Username + Password Sign-In (Owner, Manager, or Seller)
  app.post('/api/auth/login', async (req, res) => {
    const db = loadDatabase();
    const { username, password } = req.body ?? {};
    if (typeof username !== 'string' || typeof password !== 'string' || !username.trim() || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    const normalized = username.trim().toLowerCase();
    const ownerUser = (db.ownerUsername || 'owner').toLowerCase();
    const envPasscode = process.env.OWNER_PASSCODE?.trim();

    if (normalized === ownerUser) {
      let valid = false;
      if (envPasscode) {
        valid = verifyConstantTimeSecret(password, envPasscode);
      } else if (db.ownerPasswordHash) {
        valid = verifyPassword(password, db.ownerPasswordHash);
      }
      if (!valid) {
        return res.status(401).json({ error: 'Invalid username or password.' });
      }
      const user = {
        id: 'owner_primary',
        role: 'owner' as const,
        name: db.settings.ownerName,
        username: db.ownerUsername || 'owner',
      };
      const token = issueToken(user);
      return res.json({ token, user });
    }

    const staffMember = db.staff.find((s) => s.username.toLowerCase() === normalized);
    if (!staffMember || !verifyPassword(password, staffMember.passwordHash)) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
    if (!staffMember.active) {
      return res.status(403).json({ error: 'This account has been suspended by the pharmacy owner.' });
    }

    staffMember.lastLoginAt = getClinicNow(db.settings).toISOString();
    await saveDatabase(db);

    const user = {
      id: staffMember.id,
      role: staffMember.role,
      name: staffMember.name,
      username: staffMember.username,
      shift: staffMember.shift,
      jobTitle: staffMember.jobTitle,
      photoImage: staffMember.photoImage,
      scheduledClockIn: staffMember.scheduledClockIn,
      scheduledClockOut: staffMember.scheduledClockOut,
    };
    const token = issueToken(user);
    res.json({ token, user });
  });

  // Owner Forgot-Password Recovery using unchangeable server-side master passcode
  app.post('/api/auth/owner/recover', async (req, res) => {
    const db = loadDatabase();
    const envPasscode = process.env.OWNER_PASSCODE?.trim();
    if (envPasscode) {
      return res.status(403).json({ error: 'Owner passcode is managed by environment configuration.' });
    }
    if (!db.ownerPasswordHash) {
      return res.status(400).json({ error: 'Owner account has not been claimed yet.' });
    }

    const { masterPasscode, newUsername, newPassword } = req.body ?? {};
    if (
      typeof masterPasscode !== 'string' ||
      !verifyConstantTimeSecret(masterPasscode.trim(), MASTER_RECOVERY_PASSCODE)
    ) {
      return res.status(403).json({ error: 'Invalid master recovery passcode.' });
    }

    if (typeof newPassword !== 'string' || newPassword.length < 6 || newPassword.length > 128) {
      return res.status(400).json({ error: 'New password must be between 6 and 128 characters.' });
    }

    if (typeof newUsername === 'string' && newUsername.trim().length > 0) {
      const cleanUsername = newUsername.trim().toLowerCase();
      if (!/^[a-zA-Z0-9._-]{3,32}$/.test(cleanUsername)) {
        return res.status(400).json({ error: 'Username must be 3–32 characters (letters, numbers, ., _, -).' });
      }
      if (db.staff.some((s) => s.username.toLowerCase() === cleanUsername)) {
        return res.status(409).json({ error: 'That username is already used by a staff member.' });
      }
      db.ownerUsername = cleanUsername;
    }

    db.ownerPasswordHash = hashPassword(newPassword);

    appendAuditLog(db, {
      actorId: 'owner_primary',
      actorName: db.settings.ownerName,
      actorRole: 'owner',
      action: 'OWNER_PASSWORD_RECOVERED',
      targetType: 'account',
      targetName: db.ownerUsername,
      afterSummary: 'Owner password reset via master recovery passcode',
    });

    await saveDatabase(db);

    const user = {
      id: 'owner_primary',
      role: 'owner' as const,
      name: db.settings.ownerName,
      username: db.ownerUsername || 'owner',
    };
    const token = issueToken(user);
    res.json({ token, user });
  });

  // Owner In-App Username / Password Change
  app.post('/api/auth/owner/credentials', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const envPasscode = process.env.OWNER_PASSCODE?.trim();
    if (envPasscode) {
      return res.status(403).json({ error: 'Owner passcode is managed by environment configuration.' });
    }
    if (!db.ownerPasswordHash) {
      return res.status(400).json({ error: 'Owner password is not configured.' });
    }

    const { currentPassword, newUsername, newPassword } = req.body ?? {};
    if (typeof currentPassword !== 'string' || !verifyPassword(currentPassword, db.ownerPasswordHash)) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    const hasNewUsername = typeof newUsername === 'string' && newUsername.trim().length > 0;
    const hasNewPassword = typeof newPassword === 'string' && newPassword.length > 0;
    if (!hasNewUsername && !hasNewPassword) {
      return res.status(400).json({ error: 'Enter a new username or a new password to update.' });
    }

    const prevUsername = db.ownerUsername;
    if (hasNewUsername) {
      const cleanUsername = newUsername.trim().toLowerCase();
      if (!/^[a-zA-Z0-9._-]{3,32}$/.test(cleanUsername)) {
        return res.status(400).json({ error: 'Username must be 3–32 characters (letters, numbers, ., _, -).' });
      }
      if (db.staff.some((s) => s.username.toLowerCase() === cleanUsername)) {
        return res.status(409).json({ error: 'That username is already used by a staff member.' });
      }
      db.ownerUsername = cleanUsername;
    }

    if (hasNewPassword) {
      if (newPassword.length < 6 || newPassword.length > 128) {
        return res.status(400).json({ error: 'New password must be between 6 and 128 characters.' });
      }
      db.ownerPasswordHash = hashPassword(newPassword);
    }

    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'OWNER_CREDENTIALS_UPDATED',
      targetType: 'account',
      targetName: db.ownerUsername,
      beforeSummary: `Username=${prevUsername}`,
      afterSummary: `Username=${db.ownerUsername}${hasNewPassword ? ', Password updated' : ''}`,
    });

    await saveDatabase(db);

    const user = {
      id: 'owner_primary',
      role: 'owner' as const,
      name: db.settings.ownerName,
      username: db.ownerUsername || 'owner',
    };
    const token = issueToken(user);
    res.json({ token, user });
  });

  app.get('/api/auth/me', requireAuth, (req: AuthedRequest, res) => {
    res.json({ user: req.authUser });
  });

  // Settings
  app.get('/api/settings', requireAuth, (_req, res) => {
    const db = loadDatabase();
    res.json(db.settings);
  });

  app.put('/api/settings', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const body = req.body ?? {};
    const prevDateOffset = db.settings.dateOffsetDays;
    const prevCalendarMode = db.settings.calendarMode;

    if (typeof body.clinicName === 'string' && body.clinicName.trim()) {
      db.settings.clinicName = body.clinicName.trim().slice(0, 100);
    }
    if (typeof body.ownerName === 'string' && body.ownerName.trim()) {
      db.settings.ownerName = body.ownerName.trim().slice(0, 80);
    }
    if (typeof body.licenseNumber === 'string') {
      db.settings.licenseNumber = body.licenseNumber.trim().slice(0, 60);
    }
    if (typeof body.currencySymbol === 'string' && body.currencySymbol.trim()) {
      db.settings.currencySymbol = body.currencySymbol.trim().slice(0, 6);
    }
    if (typeof body.taxRatePercent === 'number' && Number.isFinite(body.taxRatePercent)) {
      db.settings.taxRatePercent = Math.max(0, Math.min(30, body.taxRatePercent));
    }
    if (typeof body.receiptFooter === 'string') {
      db.settings.receiptFooter = body.receiptFooter.trim().slice(0, 280);
    }
    if (typeof body.alertSoundEnabled === 'boolean') {
      db.settings.alertSoundEnabled = body.alertSoundEnabled;
    }
    if (body.calendarMode === 'ethiopian' || body.calendarMode === 'gregorian' || body.calendarMode === 'both') {
      db.settings.calendarMode = body.calendarMode;
    }
    if (body.dateOffsetDays !== undefined && Number.isFinite(Number(body.dateOffsetDays))) {
      db.settings.dateOffsetDays = Math.max(-3650, Math.min(3650, Math.round(Number(body.dateOffsetDays))));
    }

    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'SETTINGS_UPDATED',
      targetType: 'settings',
      targetName: db.settings.clinicName,
      beforeSummary: `Cal=${prevCalendarMode}, Offset=${prevDateOffset}d`,
      afterSummary: `Cal=${db.settings.calendarMode}, Offset=${db.settings.dateOffsetDays}d`,
    });

    await saveDatabase(db);
    res.json(db.settings);
  });

  // Drug Kinds (Dosage Forms)
  app.get('/api/drug-kinds', requireAuth, (_req, res) => {
    const db = loadDatabase();
    res.json(db.drugKinds);
  });

  app.post('/api/drug-kinds', requireAuth, requireManagerOrOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const { label, unitLabel, iconKey } = req.body ?? {};
    if (typeof label !== 'string' || !label.trim() || label.trim().length > 48) {
      return res.status(400).json({ error: 'Valid drug kind name is required.' });
    }
    const slug =
      label
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '') || `kind_${Date.now()}`;

    if (db.drugKinds.some((k) => k.id === slug || k.label.toLowerCase() === label.trim().toLowerCase())) {
      return res.status(409).json({ error: 'This drug kind already exists.' });
    }

    const kind = {
      id: slug,
      label: label.trim(),
      unitLabel: typeof unitLabel === 'string' && unitLabel.trim() ? unitLabel.trim().slice(0, 32) : 'Units',
      iconKey: VALID_ICON_KEYS.includes(iconKey) ? (iconKey as DrugKindIconKey) : 'box',
    };
    db.drugKinds.push(kind);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'DRUG_KIND_CREATED',
      targetType: 'drug_kind',
      targetName: kind.label,
    });
    await saveDatabase(db);
    res.status(201).json(kind);
  });

  app.patch('/api/drug-kinds/:id', requireAuth, requireManagerOrOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const kind = db.drugKinds.find((k) => k.id === req.params.id);
    if (!kind) {
      return res.status(404).json({ error: 'Drug kind not found.' });
    }
    const { label, unitLabel, iconKey } = req.body ?? {};
    const prevLabel = kind.label;
    if (typeof label === 'string' && label.trim()) {
      const cleanLabel = label.trim().slice(0, 48);
      if (db.drugKinds.some((k) => k.id !== kind.id && k.label.toLowerCase() === cleanLabel.toLowerCase())) {
        return res.status(409).json({ error: 'Another drug kind already uses that name.' });
      }
      kind.label = cleanLabel;
    }
    if (typeof unitLabel === 'string' && unitLabel.trim()) {
      kind.unitLabel = unitLabel.trim().slice(0, 32);
    }
    if (VALID_ICON_KEYS.includes(iconKey)) {
      kind.iconKey = iconKey as DrugKindIconKey;
    }

    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'DRUG_KIND_UPDATED',
      targetType: 'drug_kind',
      targetName: kind.label,
      beforeSummary: prevLabel,
      afterSummary: `${kind.label} (${kind.unitLabel})`,
    });
    await saveDatabase(db);
    res.json(kind);
  });

  app.delete('/api/drug-kinds/:id', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const idx = db.drugKinds.findIndex((k) => k.id === req.params.id);
    if (idx === -1) {
      return res.status(404).json({ error: 'Drug kind not found.' });
    }
    if (db.drugKinds.length <= 1) {
      return res.status(400).json({ error: 'At least one drug kind must remain.' });
    }
    const inUse = db.drugs.some((d) => d.dosageForm === req.params.id);
    if (inUse) {
      return res.status(409).json({ error: 'Cannot delete a drug kind currently assigned to medicines.' });
    }
    const [removed] = db.drugKinds.splice(idx, 1);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'DRUG_KIND_DELETED',
      targetType: 'drug_kind',
      targetName: removed.label,
    });
    await saveDatabase(db);
    res.json({ deleted: true });
  });

  // Drugs Inventory (Seller can ONLY read sanitized stock; Manager/Owner can create/edit/restock)
  app.get('/api/drugs', requireAuth, (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const role = req.authUser!.role;
    res.json(db.drugs.map((d) => sanitizeDrugForRole(d, role)));
  });

  app.post('/api/drugs', requireAuth, requireManagerOrOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const body = req.body ?? {};

    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const genericName = typeof body.genericName === 'string' ? body.genericName.trim() : '';
    const strength = typeof body.strength === 'string' ? body.strength.trim() : '';
    const category = typeof body.category === 'string' ? body.category.trim() : 'General';
    const rawForm = typeof body.dosageForm === 'string' ? body.dosageForm.trim() : 'tablet';
    const dosageForm = db.drugKinds.some((k) => k.id === rawForm) ? rawForm : 'tablet';
    const buyingPrice = Number(body.buyingPrice);
    const sellingPrice = Number(body.sellingPrice);
    const stock = Math.floor(Number(body.stock));
    const lowStockThreshold = Math.floor(Number(body.lowStockThreshold ?? 10));
    const requiresPrescription = Boolean(body.requiresPrescription);
    const batchNumber = typeof body.batchNumber === 'string' ? body.batchNumber.trim() : '';
    const expiryDate = typeof body.expiryDate === 'string' ? body.expiryDate.trim() : '';
    const manufacturer = typeof body.manufacturer === 'string' ? body.manufacturer.trim() : '';
    const barcode = typeof body.barcode === 'string' ? body.barcode.trim() : '';
    const shelfLocation = typeof body.shelfLocation === 'string' ? body.shelfLocation.trim().slice(0, 40) : '';
    const storageRequirement = VALID_STORAGE.includes(body.storageRequirement)
      ? (body.storageRequirement as StorageRequirement)
      : 'room_temp';
    const imageUrl = isValidImageString(body.imageUrl) ? body.imageUrl : '';
    const notes = typeof body.notes === 'string' ? body.notes.trim().slice(0, 400) : '';

    const unitsPerPack = Math.max(1, Math.floor(Number(body.unitsPerPack ?? 1) || 1));
    const packsPerBox = Math.max(1, Math.floor(Number(body.packsPerBox ?? 1) || 1));
    const baseUnitName = typeof body.baseUnitName === 'string' && body.baseUnitName.trim()
      ? body.baseUnitName.trim().slice(0, 24)
      : 'Unit';
    const packUnitName = typeof body.packUnitName === 'string' && body.packUnitName.trim()
      ? body.packUnitName.trim().slice(0, 24)
      : 'Strip';
    const boxUnitName = typeof body.boxUnitName === 'string' && body.boxUnitName.trim()
      ? body.boxUnitName.trim().slice(0, 24)
      : 'Box';
    const packSellingPrice =
      body.packSellingPrice !== undefined && Number(body.packSellingPrice) > 0
        ? Number(Number(body.packSellingPrice).toFixed(2))
        : undefined;
    const boxSellingPrice =
      body.boxSellingPrice !== undefined && Number(body.boxSellingPrice) > 0
        ? Number(Number(body.boxSellingPrice).toFixed(2))
        : undefined;

    if (!name || name.length > 120) {
      return res.status(400).json({ error: 'Valid medicine name is required.' });
    }
    if (!Number.isFinite(buyingPrice) || buyingPrice < 0 || !Number.isFinite(sellingPrice) || sellingPrice <= 0) {
      return res.status(400).json({ error: 'Buying and selling prices must be valid numbers.' });
    }
    if (!Number.isFinite(stock) || stock < 0 || !Number.isFinite(lowStockThreshold) || lowStockThreshold < 0) {
      return res.status(400).json({ error: 'Stock and low-stock threshold must be non-negative integers.' });
    }

    const now = getClinicNow(db.settings).toISOString();
    const drug: Drug = {
      id: `drg_${crypto.randomUUID().slice(0, 8)}`,
      name,
      genericName: genericName || name,
      strength: strength || 'Standard',
      category: category || 'General',
      dosageForm,
      buyingPrice: Number(buyingPrice.toFixed(2)),
      sellingPrice: Number(sellingPrice.toFixed(2)),
      baseUnitName,
      packUnitName,
      boxUnitName,
      unitsPerPack,
      packsPerBox,
      packSellingPrice,
      boxSellingPrice,
      stock,
      lowStockThreshold,
      requiresPrescription,
      batchNumber: batchNumber || `LOT-${Date.now().toString().slice(-6)}`,
      expiryDate: /^\d{4}-\d{2}-\d{2}$/.test(expiryDate) ? expiryDate : '2028-12-31',
      manufacturer: manufacturer || 'Independent Supplier',
      barcode: barcode || `${Math.floor(1000000000000 + Math.random() * 8999999999999)}`,
      shelfLocation,
      storageRequirement,
      imageUrl,
      notes,
      createdAt: now,
      updatedAt: now,
    };

    db.drugs.unshift(drug);
    syncAlertForDrug(db, drug);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'DRUG_CREATED',
      targetType: 'drug',
      targetName: drug.name,
      afterSummary: `Price=${drug.sellingPrice} Br, Stock=${drug.stock} ${baseUnitName}`,
    });
    await saveDatabase(db);
    res.status(201).json(drug);
  });

  app.put('/api/drugs/:id', requireAuth, requireManagerOrOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const drug = db.drugs.find((d) => d.id === req.params.id);
    if (!drug) {
      return res.status(404).json({ error: 'Medicine not found.' });
    }

    const beforeSummary = `Buy=${drug.buyingPrice ?? 0}, Sell=${drug.sellingPrice}, Stock=${drug.stock}`;
    const body = req.body ?? {};
    if (typeof body.name === 'string' && body.name.trim()) drug.name = body.name.trim().slice(0, 120);
    if (typeof body.genericName === 'string') drug.genericName = body.genericName.trim().slice(0, 120);
    if (typeof body.strength === 'string') drug.strength = body.strength.trim().slice(0, 60);
    if (typeof body.category === 'string' && body.category.trim()) drug.category = body.category.trim().slice(0, 60);
    if (typeof body.dosageForm === 'string' && db.drugKinds.some((k) => k.id === body.dosageForm)) {
      drug.dosageForm = body.dosageForm;
    }
    if (body.buyingPrice !== undefined && Number.isFinite(Number(body.buyingPrice)) && Number(body.buyingPrice) >= 0) {
      drug.buyingPrice = Number(Number(body.buyingPrice).toFixed(2));
    }
    if (body.sellingPrice !== undefined && Number.isFinite(Number(body.sellingPrice)) && Number(body.sellingPrice) > 0) {
      drug.sellingPrice = Number(Number(body.sellingPrice).toFixed(2));
    }
    if (body.unitsPerPack !== undefined && Number.isFinite(Number(body.unitsPerPack))) {
      drug.unitsPerPack = Math.max(1, Math.floor(Number(body.unitsPerPack)));
    }
    if (body.packsPerBox !== undefined && Number.isFinite(Number(body.packsPerBox))) {
      drug.packsPerBox = Math.max(1, Math.floor(Number(body.packsPerBox)));
    }
    if (typeof body.baseUnitName === 'string' && body.baseUnitName.trim()) {
      drug.baseUnitName = body.baseUnitName.trim().slice(0, 24);
    }
    if (typeof body.packUnitName === 'string' && body.packUnitName.trim()) {
      drug.packUnitName = body.packUnitName.trim().slice(0, 24);
    }
    if (typeof body.boxUnitName === 'string' && body.boxUnitName.trim()) {
      drug.boxUnitName = body.boxUnitName.trim().slice(0, 24);
    }
    if (body.packSellingPrice !== undefined) {
      drug.packSellingPrice = Number(body.packSellingPrice) > 0 ? Number(Number(body.packSellingPrice).toFixed(2)) : undefined;
    }
    if (body.boxSellingPrice !== undefined) {
      drug.boxSellingPrice = Number(body.boxSellingPrice) > 0 ? Number(Number(body.boxSellingPrice).toFixed(2)) : undefined;
    }
    if (body.stock !== undefined && Number.isFinite(Number(body.stock)) && Number(body.stock) >= 0) {
      drug.stock = Math.floor(Number(body.stock));
    }
    if (
      body.lowStockThreshold !== undefined &&
      Number.isFinite(Number(body.lowStockThreshold)) &&
      Number(body.lowStockThreshold) >= 0
    ) {
      drug.lowStockThreshold = Math.floor(Number(body.lowStockThreshold));
    }
    if (typeof body.requiresPrescription === 'boolean') {
      drug.requiresPrescription = body.requiresPrescription;
    }
    if (typeof body.batchNumber === 'string') drug.batchNumber = body.batchNumber.trim().slice(0, 60);
    if (typeof body.expiryDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(body.expiryDate.trim())) {
      drug.expiryDate = body.expiryDate.trim();
    }
    if (typeof body.manufacturer === 'string') drug.manufacturer = body.manufacturer.trim().slice(0, 80);
    if (typeof body.barcode === 'string') drug.barcode = body.barcode.trim().slice(0, 40);
    if (typeof body.shelfLocation === 'string') drug.shelfLocation = body.shelfLocation.trim().slice(0, 40);
    if (VALID_STORAGE.includes(body.storageRequirement)) {
      drug.storageRequirement = body.storageRequirement;
    }
    if (body.imageUrl !== undefined && isValidImageString(body.imageUrl)) {
      drug.imageUrl = body.imageUrl;
    }
    if (typeof body.notes === 'string') drug.notes = body.notes.trim().slice(0, 400);

    drug.updatedAt = getClinicNow(db.settings).toISOString();
    syncAlertForDrug(db, drug);

    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'DRUG_UPDATED',
      targetType: 'drug',
      targetName: drug.name,
      beforeSummary,
      afterSummary: `Buy=${drug.buyingPrice ?? 0}, Sell=${drug.sellingPrice}, Stock=${drug.stock}`,
    });

    await saveDatabase(db);
    res.json(drug);
  });

  app.post('/api/drugs/:id/restock', requireAuth, requireManagerOrOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const drug = db.drugs.find((d) => d.id === req.params.id);
    if (!drug) {
      return res.status(404).json({ error: 'Medicine not found.' });
    }
    const quantity = Math.floor(Number(req.body?.quantity));
    const unitTier: SaleUnitTier =
      req.body?.unitTier === 'box' || req.body?.unitTier === 'pack' ? req.body.unitTier : 'base';
    const { multiplier } = resolveDrugUnit(drug, unitTier);
    const addedBaseUnits = quantity * multiplier;

    if (!Number.isFinite(quantity) || quantity <= 0 || addedBaseUnits > 500000) {
      return res.status(400).json({ error: 'Restock quantity must be a positive integer.' });
    }

    const prevStock = drug.stock;
    drug.stock += addedBaseUnits;
    if (typeof req.body?.batchNumber === 'string' && req.body.batchNumber.trim()) {
      drug.batchNumber = req.body.batchNumber.trim().slice(0, 60);
    }
    if (typeof req.body?.expiryDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(req.body.expiryDate.trim())) {
      drug.expiryDate = req.body.expiryDate.trim();
    }
    if (
      req.body?.buyingPrice !== undefined &&
      Number.isFinite(Number(req.body.buyingPrice)) &&
      Number(req.body.buyingPrice) >= 0
    ) {
      drug.buyingPrice = Number(Number(req.body.buyingPrice).toFixed(2));
    }
    if (
      req.body?.sellingPrice !== undefined &&
      Number.isFinite(Number(req.body.sellingPrice)) &&
      Number(req.body.sellingPrice) > 0
    ) {
      drug.sellingPrice = Number(Number(req.body.sellingPrice).toFixed(2));
    }
    drug.updatedAt = getClinicNow(db.settings).toISOString();
    syncAlertForDrug(db, drug);

    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'DRUG_RESTOCKED',
      targetType: 'drug',
      targetName: drug.name,
      beforeSummary: `Stock=${prevStock}`,
      afterSummary: `Added=${addedBaseUnits} (${quantity} ${unitTier}) -> Stock=${drug.stock}`,
    });

    await saveDatabase(db);
    res.json({ drug, alerts: db.alerts });
  });

  app.delete('/api/drugs/:id', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const idx = db.drugs.findIndex((d) => d.id === req.params.id);
    if (idx === -1) {
      return res.status(404).json({ error: 'Medicine not found.' });
    }
    const [removed] = db.drugs.splice(idx, 1);
    db.alerts = db.alerts.filter((a) => a.drugId !== req.params.id);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'DRUG_DELETED',
      targetType: 'drug',
      targetName: removed.name,
      beforeSummary: `Stock=${removed.stock}, Price=${removed.sellingPrice} Br`,
    });
    await saveDatabase(db);
    res.json({ deleted: true });
  });

  // Alerts (Owner & Manager)
  app.get('/api/alerts', requireAuth, requireManagerOrOwner, (_req, res) => {
    const db = loadDatabase();
    res.json(db.alerts);
  });

  app.post('/api/alerts/:id/acknowledge', requireAuth, requireManagerOrOwner, async (req, res) => {
    const db = loadDatabase();
    const alert = db.alerts.find((a) => a.id === req.params.id);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found.' });
    }
    alert.acknowledged = true;
    await saveDatabase(db);
    res.json(alert);
  });

  // Staff / Users Management (Owner only — includes scheduled clock-in/out & Fayda ID)
  app.get('/api/staff', requireAuth, requireOwner, (_req, res) => {
    const db = loadDatabase();
    res.json(db.staff.map(({ passwordHash: _ph, ...safe }) => safe));
  });

  app.post('/api/staff', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const {
      name,
      phone,
      role,
      username,
      password,
      jobTitle,
      shift,
      scheduledClockIn,
      scheduledClockOut,
      graceMinutes,
      photoImage,
      faydaFrontImage,
      faydaBackImage,
    } = req.body ?? {};

    if (typeof name !== 'string' || !name.trim() || name.trim().length > 80) {
      return res.status(400).json({ error: 'Full name is required.' });
    }
    if (typeof username !== 'string' || !/^[a-zA-Z0-9._-]{3,32}$/.test(username.trim())) {
      return res.status(400).json({ error: 'Username must be 3–32 characters (letters, numbers, ., _, -).' });
    }
    if (typeof password !== 'string' || password.length < 4 || password.length > 128) {
      return res.status(400).json({ error: 'Password must be 4–128 characters.' });
    }

    const normalized = username.trim().toLowerCase();
    if (normalized === (db.ownerUsername || 'owner').toLowerCase()) {
      return res.status(409).json({ error: 'That username is reserved for the owner.' });
    }
    if (db.staff.some((s) => s.username.toLowerCase() === normalized)) {
      return res.status(409).json({ error: 'Username already exists.' });
    }

    const staffRole = role === 'manager' ? 'manager' : 'seller';
    const clockInStr = isValidHhMm(scheduledClockIn) ? scheduledClockIn.trim() : '08:30';
    const clockOutStr = isValidHhMm(scheduledClockOut) ? scheduledClockOut.trim() : '17:30';
    const graceNum = Number.isFinite(Number(graceMinutes))
      ? Math.max(0, Math.min(60, Math.floor(Number(graceMinutes))))
      : 5;

    const newStaff = {
      id: `stf_${crypto.randomUUID().slice(0, 8)}`,
      role: staffRole as 'manager' | 'seller',
      name: name.trim(),
      phone: typeof phone === 'string' ? phone.trim().slice(0, 32) : '',
      username: username.trim(),
      jobTitle:
        typeof jobTitle === 'string' && jobTitle.trim()
          ? jobTitle.trim().slice(0, 60)
          : staffRole === 'manager'
            ? 'Pharmacy Manager'
            : 'Counter Seller',
      shift: typeof shift === 'string' && shift.trim() ? shift.trim().slice(0, 40) : 'Full-Time',
      scheduledClockIn: clockInStr,
      scheduledClockOut: clockOutStr,
      graceMinutes: graceNum,
      active: true,
      photoImage: isValidImageString(photoImage) ? photoImage : undefined,
      faydaFrontImage: isValidImageString(faydaFrontImage) ? faydaFrontImage : undefined,
      faydaBackImage: isValidImageString(faydaBackImage) ? faydaBackImage : undefined,
      passwordHash: hashPassword(password),
      createdAt: getClinicNow(db.settings).toISOString(),
    };

    db.staff.push(newStaff);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'STAFF_CREATED',
      targetType: 'staff',
      targetName: newStaff.name,
      afterSummary: `Role=${newStaff.role}, Schedule=${clockInStr}-${clockOutStr}`,
    });
    await saveDatabase(db);

    const { passwordHash: _ph, ...safe } = newStaff;
    res.status(201).json(safe);
  });

  app.patch('/api/staff/:id', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const member = db.staff.find((s) => s.id === req.params.id);
    if (!member) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const beforeSummary = `Role=${member.role}, Active=${member.active}, Schedule=${member.scheduledClockIn}-${member.scheduledClockOut}`;
    const {
      active,
      password,
      shift,
      name,
      phone,
      role,
      username,
      jobTitle,
      scheduledClockIn,
      scheduledClockOut,
      graceMinutes,
      photoImage,
      faydaFrontImage,
      faydaBackImage,
    } = req.body ?? {};

    if (typeof active === 'boolean') member.active = active;
    if (role === 'manager' || role === 'seller') member.role = role;
    if (typeof name === 'string' && name.trim()) member.name = name.trim().slice(0, 80);
    if (typeof phone === 'string') member.phone = phone.trim().slice(0, 32);
    if (typeof jobTitle === 'string' && jobTitle.trim()) member.jobTitle = jobTitle.trim().slice(0, 60);
    if (typeof shift === 'string' && shift.trim()) member.shift = shift.trim().slice(0, 40);
    if (isValidHhMm(scheduledClockIn)) member.scheduledClockIn = scheduledClockIn.trim();
    if (isValidHhMm(scheduledClockOut)) member.scheduledClockOut = scheduledClockOut.trim();
    if (graceMinutes !== undefined && Number.isFinite(Number(graceMinutes))) {
      member.graceMinutes = Math.max(0, Math.min(60, Math.floor(Number(graceMinutes))));
    }
    if (typeof username === 'string' && /^[a-zA-Z0-9._-]{3,32}$/.test(username.trim())) {
      const normalized = username.trim().toLowerCase();
      const collision =
        normalized === (db.ownerUsername || 'owner').toLowerCase() ||
        db.staff.some((s) => s.id !== member.id && s.username.toLowerCase() === normalized);
      if (collision) {
        return res.status(409).json({ error: 'Username already in use.' });
      }
      member.username = username.trim();
    }
    if (typeof password === 'string' && password.trim().length > 0) {
      if (password.length < 4) {
        return res.status(400).json({ error: 'Password must be at least 4 characters.' });
      }
      member.passwordHash = hashPassword(password);
    }
    if (photoImage !== undefined && isValidImageString(photoImage)) {
      member.photoImage = photoImage || undefined;
    }
    if (faydaFrontImage !== undefined && isValidImageString(faydaFrontImage)) {
      member.faydaFrontImage = faydaFrontImage || undefined;
    }
    if (faydaBackImage !== undefined && isValidImageString(faydaBackImage)) {
      member.faydaBackImage = faydaBackImage || undefined;
    }

    for (const p of db.payrollProfiles) {
      if (p.workerId === member.id) {
        p.workerName = member.name;
      }
    }

    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'STAFF_UPDATED',
      targetType: 'staff',
      targetName: member.name,
      beforeSummary,
      afterSummary: `Role=${member.role}, Active=${member.active}, Schedule=${member.scheduledClockIn}-${member.scheduledClockOut}`,
    });

    await saveDatabase(db);
    const { passwordHash: _ph, ...safe } = member;
    res.json(safe);
  });

  app.delete('/api/staff/:id', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const idx = db.staff.findIndex((s) => s.id === req.params.id);
    if (idx === -1) {
      return res.status(404).json({ error: 'User not found.' });
    }
    const [removed] = db.staff.splice(idx, 1);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'STAFF_DELETED',
      targetType: 'staff',
      targetName: removed.name,
    });
    await saveDatabase(db);
    res.json({ deleted: true });
  });

  // Attendance & Dual QR Codes + Lateness calculation
  app.get('/api/attendance/qr', requireAuth, requireManagerOrOwner, (_req, res) => {
    const db = loadDatabase();
    res.json(db.attendanceQr);
  });

  app.get('/api/attendance', requireAuth, (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const user = req.authUser!;
    if (user.role === 'owner' || user.role === 'manager') {
      return res.json(db.attendance);
    }
    res.json(db.attendance.filter((a) => a.workerId === user.id));
  });

  app.get('/api/attendance/my-summary', requireAuth, (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const user = req.authUser!;
    const summary = computeAttendanceSummary(db.attendance, user.id);
    const staffMember = db.staff.find((s) => s.id === user.id);
    res.json({
      summary,
      scheduledClockIn: staffMember?.scheduledClockIn ?? '08:30',
      scheduledClockOut: staffMember?.scheduledClockOut ?? '17:30',
      graceMinutes: staffMember?.graceMinutes ?? 5,
    });
  });

  app.post('/api/attendance/punch', requireAuth, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const user = req.authUser!;
    const { type, qrToken, source, clientSyncId, offlineCreatedAt } = req.body ?? {};

    if (typeof clientSyncId === 'string' && clientSyncId.trim()) {
      const existing = db.attendance.find((a) => a.clientSyncId === clientSyncId.trim());
      if (existing) {
        return res.status(200).json(existing);
      }
    }

    if (type !== 'clock_in' && type !== 'clock_out') {
      return res.status(400).json({ error: 'Attendance type must be clock_in or clock_out.' });
    }

    const isQr = source === 'qr_scan' || Boolean(qrToken);
    if (isQr) {
      const expected =
        type === 'clock_in' ? db.attendanceQr.clockInToken : db.attendanceQr.clockOutToken;
      if (typeof qrToken !== 'string' || !verifyConstantTimeSecret(qrToken, expected)) {
        return res.status(403).json({ error: 'Invalid or expired pharmacy attendance QR code.' });
      }
    }

    const punchTime =
      typeof offlineCreatedAt === 'string' && !Number.isNaN(new Date(offlineCreatedAt).getTime())
        ? new Date(offlineCreatedAt)
        : getClinicNow(db.settings);

    const staffMember = db.staff.find((s) => s.id === user.id);
    let scheduledTime: string | undefined;
    let attendanceStatus: 'on_time' | 'late' | 'early_leave' | 'completed' =
      type === 'clock_in' ? 'on_time' : 'completed';
    let lateMinutes = 0;

    if (staffMember) {
      const punchMinutes = punchTime.getHours() * 60 + punchTime.getMinutes();
      if (type === 'clock_in') {
        scheduledTime = staffMember.scheduledClockIn || '08:30';
        const [sh, sm] = scheduledTime.split(':').map(Number);
        const schedMinutes = sh * 60 + sm;
        const diff = punchMinutes - schedMinutes;
        if (diff > (staffMember.graceMinutes ?? 5)) {
          attendanceStatus = 'late';
          lateMinutes = diff;
        } else {
          attendanceStatus = 'on_time';
        }
      } else {
        scheduledTime = staffMember.scheduledClockOut || '17:30';
        const [eh, em] = scheduledTime.split(':').map(Number);
        const schedMinutes = eh * 60 + em;
        if (punchMinutes < schedMinutes - 5) {
          attendanceStatus = 'early_leave';
          lateMinutes = schedMinutes - punchMinutes;
        } else {
          attendanceStatus = 'completed';
        }
      }
    }

    const record = {
      id: `att_${crypto.randomUUID().slice(0, 8)}`,
      workerId: user.id,
      workerName: user.name,
      workerRole: user.role,
      type,
      timestamp: punchTime.toISOString(),
      source: isQr ? ('qr_scan' as const) : ('portal' as const),
      scheduledTime,
      attendanceStatus,
      lateMinutes: lateMinutes > 0 ? lateMinutes : undefined,
      clientSyncId: typeof clientSyncId === 'string' && clientSyncId.trim() ? clientSyncId.trim() : undefined,
    };

    db.attendance.unshift(record);
    await saveDatabase(db);
    res.status(201).json(record);
  });

  // Payroll & Salaries (Owner manages; Workers view their own)
  app.get('/api/payroll', requireAuth, requireOwner, (_req, res) => {
    const db = loadDatabase();
    res.json({
      entries: buildPayrollStatuses(db),
      payments: db.payrollPayments,
    });
  });

  app.get('/api/payroll/my', requireAuth, (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const user = req.authUser!;
    const allEntries = buildPayrollStatuses(db);
    const myEntries = allEntries.filter((e) => e.profile.workerId === user.id);
    const myPayments = db.payrollPayments.filter((p) => p.workerId === user.id);
    res.json({
      entries: myEntries,
      payments: myPayments,
    });
  });

  app.post('/api/payroll', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const { workerId, workDescription, monthlySalary, paydayDay } = req.body ?? {};
    const worker = db.staff.find((s) => s.id === workerId);
    if (!worker) {
      return res.status(400).json({ error: 'Select a valid pharmacy staff member.' });
    }
    const salaryNum = Number(monthlySalary);
    const dayNum = Math.floor(Number(paydayDay));
    if (!Number.isFinite(salaryNum) || salaryNum <= 0) {
      return res.status(400).json({ error: 'Monthly salary must be greater than 0.' });
    }
    if (!Number.isFinite(dayNum) || dayNum < 1 || dayNum > 31) {
      return res.status(400).json({ error: 'Payday must be between day 1 and 31.' });
    }

    const existing = db.payrollProfiles.find((p) => p.workerId === worker.id);
    const now = getClinicNow(db.settings).toISOString();
    if (existing) {
      existing.workDescription =
        typeof workDescription === 'string' && workDescription.trim()
          ? workDescription.trim().slice(0, 120)
          : worker.jobTitle;
      existing.monthlySalary = Number(salaryNum.toFixed(2));
      existing.paydayDay = dayNum;
      existing.workerName = worker.name;
      existing.updatedAt = now;
      appendAuditLog(db, {
        actorId: req.authUser!.id,
        actorName: req.authUser!.name,
        actorRole: req.authUser!.role,
        action: 'PAYROLL_UPDATED',
        targetType: 'payroll',
        targetName: worker.name,
        afterSummary: `Salary=${existing.monthlySalary} Br, Day=${dayNum}`,
      });
      await saveDatabase(db);
      return res.json(existing);
    }

    const profile = {
      id: `payp_${crypto.randomUUID().slice(0, 8)}`,
      workerId: worker.id,
      workerName: worker.name,
      workDescription:
        typeof workDescription === 'string' && workDescription.trim()
          ? workDescription.trim().slice(0, 120)
          : worker.jobTitle,
      monthlySalary: Number(salaryNum.toFixed(2)),
      paydayDay: dayNum,
      createdAt: now,
      updatedAt: now,
    };
    db.payrollProfiles.push(profile);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'PAYROLL_CREATED',
      targetType: 'payroll',
      targetName: worker.name,
      afterSummary: `Salary=${profile.monthlySalary} Br, Day=${dayNum}`,
    });
    await saveDatabase(db);
    res.status(201).json(profile);
  });

  app.delete('/api/payroll/:id', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const idx = db.payrollProfiles.findIndex((p) => p.id === req.params.id);
    if (idx === -1) {
      return res.status(404).json({ error: 'Payroll schedule not found.' });
    }
    const [removed] = db.payrollProfiles.splice(idx, 1);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'PAYROLL_DELETED',
      targetType: 'payroll',
      targetName: removed.workerName,
    });
    await saveDatabase(db);
    res.json({ deleted: true });
  });

  app.post('/api/payroll/:id/pay', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const profile = db.payrollProfiles.find((p) => p.id === req.params.id);
    if (!profile) {
      return res.status(404).json({ error: 'Payroll schedule not found.' });
    }

    const { paymentMethod, monthKey, amount, reference } = req.body ?? {};
    const method = VALID_PAYROLL_METHODS.includes(paymentMethod)
      ? (paymentMethod as PayrollMethod)
      : 'telebirr';
    const now = getClinicNow(db.settings);
    const targetMonth =
      typeof monthKey === 'string' && /^\d{4}-\d{2}$/.test(monthKey)
        ? monthKey
        : `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

    const alreadyPaid = db.payrollPayments.find(
      (p) => p.payrollProfileId === profile.id && p.monthKey === targetMonth
    );
    if (alreadyPaid) {
      return res.status(409).json({ error: `Salary for ${targetMonth} is already confirmed paid.` });
    }

    const paidAmount =
      amount !== undefined && Number.isFinite(Number(amount)) && Number(amount) > 0
        ? Number(Number(amount).toFixed(2))
        : profile.monthlySalary;

    const payment = {
      id: `pay_${crypto.randomUUID().slice(0, 8)}`,
      payrollProfileId: profile.id,
      workerId: profile.workerId,
      workerName: profile.workerName,
      monthKey: targetMonth,
      amount: paidAmount,
      paymentMethod: method,
      reference: typeof reference === 'string' && reference.trim() ? reference.trim().slice(0, 80) : undefined,
      paidAt: now.toISOString(),
      confirmedBy: req.authUser!.name,
    };

    db.payrollPayments.unshift(payment);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'PAYROLL_PAID',
      targetType: 'payroll',
      targetName: `${profile.workerName} (${targetMonth})`,
      afterSummary: `${paidAmount} Br via ${method}`,
    });
    await saveDatabase(db);
    res.status(201).json(payment);
  });

  // Blind End-of-Shift Cash Count (Z-Reports)
  app.get('/api/shifts', requireAuth, (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const user = req.authUser!;
    if (user.role === 'owner' || user.role === 'manager') {
      return res.json(db.shiftCloses);
    }
    res.json(
      db.shiftCloses
        .filter((s) => s.workerId === user.id)
        .map((s) => sanitizeShiftCloseForRole(s, 'seller'))
    );
  });

  app.post('/api/shifts/close', requireAuth, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const user = req.authUser!;
    const countedCash = Number(req.body?.countedCash);
    if (!Number.isFinite(countedCash) || countedCash < 0) {
      return res.status(400).json({ error: 'Counted cash amount must be 0 or greater.' });
    }

    const lastClose = db.shiftCloses.find((s) => s.workerId === user.id);
    const now = getClinicNow(db.settings);
    const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const periodStart = lastClose ? lastClose.closedAt : startOfDay;
    const periodStartMs = new Date(periodStart).getTime();

    const workerTxns = db.transactions.filter(
      (t) => t.cashierId === user.id && new Date(t.createdAt).getTime() > periodStartMs
    );

    let expectedCash = 0;
    for (const txn of workerTxns) {
      if (txn.paymentMethod === 'cash') {
        expectedCash += txn.totalAmount;
      } else if (txn.paymentMethod === 'split') {
        expectedCash += txn.splitCashAmount ?? 0;
      }
    }
    expectedCash = Number(expectedCash.toFixed(2));
    const roundedCounted = Number(countedCash.toFixed(2));
    const variance = Number((roundedCounted - expectedCash).toFixed(2));
    const status: ShiftCloseReport['status'] =
      Math.abs(variance) < 0.01 ? 'exact' : variance > 0 ? 'over' : 'short';

    const report: ShiftCloseReport = {
      id: `shf_${crypto.randomUUID().slice(0, 8)}`,
      workerId: user.id,
      workerName: user.name,
      workerRole: user.role,
      countedCash: roundedCounted,
      expectedCash,
      variance,
      status,
      transactionCount: workerTxns.length,
      periodStart,
      closedAt: now.toISOString(),
      notes: typeof req.body?.notes === 'string' && req.body.notes.trim() ? req.body.notes.trim().slice(0, 240) : undefined,
    };

    db.shiftCloses.unshift(report);
    appendAuditLog(db, {
      actorId: user.id,
      actorName: user.name,
      actorRole: user.role,
      action: 'BLIND_SHIFT_CLOSED',
      targetType: 'shift',
      targetName: user.name,
      afterSummary: `Counted=${roundedCounted} Br, Expected=${expectedCash} Br, Variance=${variance} Br (${status})`,
    });

    await saveDatabase(db);
    res.status(201).json(sanitizeShiftCloseForRole(report, user.role));
  });

  // Expense Tracker (Owner only)
  app.get('/api/expenses', requireAuth, requireOwner, (_req, res) => {
    const db = loadDatabase();
    res.json(db.expenses);
  });

  app.post('/api/expenses', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const { title, category, amount, paymentMethod, date, notes } = req.body ?? {};
    if (typeof title !== 'string' || !title.trim() || title.trim().length > 100) {
      return res.status(400).json({ error: 'Expense title is required.' });
    }
    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0) {
      return res.status(400).json({ error: 'Expense amount must be greater than 0.' });
    }
    const cat = VALID_EXPENSE_CATS.includes(category) ? (category as ExpenseCategory) : 'other';
    const method = VALID_PAYROLL_METHODS.includes(paymentMethod)
      ? (paymentMethod as PayrollMethod)
      : 'cash';
    const now = getClinicNow(db.settings);
    const expense = {
      id: `exp_${crypto.randomUUID().slice(0, 8)}`,
      title: title.trim(),
      category: cat,
      amount: Number(amt.toFixed(2)),
      paymentMethod: method,
      date: typeof date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(date.trim()) ? date.trim() : now.toISOString().slice(0, 10),
      notes: typeof notes === 'string' && notes.trim() ? notes.trim().slice(0, 200) : undefined,
      recordedBy: req.authUser!.name,
      createdAt: now.toISOString(),
    };
    db.expenses.unshift(expense);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'EXPENSE_RECORDED',
      targetType: 'expense',
      targetName: expense.title,
      afterSummary: `${expense.amount} Br (${expense.category})`,
    });
    await saveDatabase(db);
    res.status(201).json(expense);
  });

  app.patch('/api/expenses/:id', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const expense = db.expenses.find((e) => e.id === req.params.id);
    if (!expense) return res.status(404).json({ error: 'Expense not found.' });

    const beforeSummary = `${expense.title}: ${expense.amount} Br`;
    const { title, category, amount, paymentMethod, date, notes } = req.body ?? {};
    if (typeof title === 'string' && title.trim()) {
      expense.title = title.trim().slice(0, 100);
    }
    if (VALID_EXPENSE_CATS.includes(category)) {
      expense.category = category as ExpenseCategory;
    }
    if (amount !== undefined && Number.isFinite(Number(amount)) && Number(amount) > 0) {
      expense.amount = Number(Number(amount).toFixed(2));
    }
    if (VALID_PAYROLL_METHODS.includes(paymentMethod)) {
      expense.paymentMethod = paymentMethod as PayrollMethod;
    }
    if (typeof date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(date.trim())) {
      expense.date = date.trim();
    }
    if (notes !== undefined) {
      expense.notes = typeof notes === 'string' && notes.trim() ? notes.trim().slice(0, 200) : undefined;
    }

    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'EXPENSE_UPDATED',
      targetType: 'expense',
      targetName: expense.title,
      beforeSummary,
      afterSummary: `${expense.title}: ${expense.amount} Br (${expense.category})`,
    });
    await saveDatabase(db);
    res.json(expense);
  });

  app.delete('/api/expenses/:id', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const idx = db.expenses.findIndex((e) => e.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Expense not found.' });
    const [removed] = db.expenses.splice(idx, 1);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'EXPENSE_DELETED',
      targetType: 'expense',
      targetName: removed.title,
      beforeSummary: `${removed.amount} Br`,
    });
    await saveDatabase(db);
    res.json({ deleted: true });
  });

  // Suppliers & Wholesale Credit Invoices (Owner only)
  app.get('/api/suppliers', requireAuth, requireOwner, (_req, res) => {
    const db = loadDatabase();
    const todayStr = getClinicNow(db.settings).toISOString().slice(0, 10);
    const invoices = db.supplierInvoices.map((inv) => {
      let status = inv.status;
      if (inv.paidAmount >= inv.totalAmount) {
        status = 'paid';
      } else if (inv.dueDate < todayStr) {
        status = 'overdue';
      } else if (inv.paidAmount > 0) {
        status = 'partial';
      } else {
        status = 'unpaid';
      }
      return { ...inv, status };
    });
    res.json({ suppliers: db.suppliers, invoices });
  });

  app.post('/api/suppliers', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const { name, phone, tinNumber, address, notes } = req.body ?? {};
    if (typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({ error: 'Supplier name is required.' });
    }
    const supplier = {
      id: `sup_${crypto.randomUUID().slice(0, 8)}`,
      name: name.trim().slice(0, 100),
      phone: typeof phone === 'string' ? phone.trim().slice(0, 32) : '',
      tinNumber: typeof tinNumber === 'string' && tinNumber.trim() ? tinNumber.trim().slice(0, 32) : undefined,
      address: typeof address === 'string' && address.trim() ? address.trim().slice(0, 120) : undefined,
      notes: typeof notes === 'string' && notes.trim() ? notes.trim().slice(0, 200) : undefined,
      createdAt: getClinicNow(db.settings).toISOString(),
    };
    db.suppliers.unshift(supplier);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'SUPPLIER_ADDED',
      targetType: 'supplier',
      targetName: supplier.name,
    });
    await saveDatabase(db);
    res.status(201).json(supplier);
  });

  app.patch('/api/suppliers/:id', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const supplier = db.suppliers.find((s) => s.id === req.params.id);
    if (!supplier) return res.status(404).json({ error: 'Supplier not found.' });

    const prevName = supplier.name;
    const { name, phone, tinNumber, address, notes } = req.body ?? {};
    if (typeof name === 'string' && name.trim()) {
      supplier.name = name.trim().slice(0, 100);
      for (const inv of db.supplierInvoices) {
        if (inv.supplierId === supplier.id) {
          inv.supplierName = supplier.name;
        }
      }
    }
    if (typeof phone === 'string') supplier.phone = phone.trim().slice(0, 32);
    if (tinNumber !== undefined) {
      supplier.tinNumber = typeof tinNumber === 'string' && tinNumber.trim() ? tinNumber.trim().slice(0, 32) : undefined;
    }
    if (address !== undefined) {
      supplier.address = typeof address === 'string' && address.trim() ? address.trim().slice(0, 120) : undefined;
    }
    if (notes !== undefined) {
      supplier.notes = typeof notes === 'string' && notes.trim() ? notes.trim().slice(0, 200) : undefined;
    }

    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'SUPPLIER_UPDATED',
      targetType: 'supplier',
      targetName: supplier.name,
      beforeSummary: prevName,
      afterSummary: `${supplier.name} (${supplier.phone || 'No phone'})`,
    });
    await saveDatabase(db);
    res.json(supplier);
  });

  app.delete('/api/suppliers/:id', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const idx = db.suppliers.findIndex((s) => s.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Supplier not found.' });
    if (db.supplierInvoices.some((inv) => inv.supplierId === req.params.id)) {
      return res.status(409).json({ error: 'Cannot delete supplier with recorded credit invoices.' });
    }
    const [removed] = db.suppliers.splice(idx, 1);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'SUPPLIER_DELETED',
      targetType: 'supplier',
      targetName: removed.name,
    });
    await saveDatabase(db);
    res.json({ deleted: true });
  });

  app.post('/api/suppliers/invoices', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const { supplierId, invoiceNumber, itemsSummary, totalAmount, paidAmount, dueDate } = req.body ?? {};
    const supplier = db.suppliers.find((s) => s.id === supplierId);
    if (!supplier) {
      return res.status(400).json({ error: 'Select a valid supplier.' });
    }
    const totalNum = Number(totalAmount);
    const paidNum = Math.max(0, Number(paidAmount ?? 0) || 0);
    if (!Number.isFinite(totalNum) || totalNum <= 0) {
      return res.status(400).json({ error: 'Invoice total must be greater than 0.' });
    }
    const now = getClinicNow(db.settings);
    const clampedPaid = Math.min(totalNum, Number(paidNum.toFixed(2)));
    const due = typeof dueDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(dueDate.trim())
      ? dueDate.trim()
      : new Date(now.getTime() + 30 * 86400000).toISOString().slice(0, 10);

    const inv = {
      id: `inv_${crypto.randomUUID().slice(0, 8)}`,
      supplierId: supplier.id,
      supplierName: supplier.name,
      invoiceNumber: typeof invoiceNumber === 'string' && invoiceNumber.trim()
        ? invoiceNumber.trim().slice(0, 48)
        : `INV-${Date.now().toString().slice(-6)}`,
      itemsSummary: typeof itemsSummary === 'string' && itemsSummary.trim()
        ? itemsSummary.trim().slice(0, 200)
        : 'Wholesale medicine delivery',
      totalAmount: Number(totalNum.toFixed(2)),
      paidAmount: clampedPaid,
      dueDate: due,
      status: (clampedPaid >= totalNum ? 'paid' : clampedPaid > 0 ? 'partial' : 'unpaid') as
        | 'paid'
        | 'partial'
        | 'unpaid'
        | 'overdue',
      payments:
        clampedPaid > 0
          ? [
              {
                id: `spay_${crypto.randomUUID().slice(0, 8)}`,
                amount: clampedPaid,
                method: 'cash' as const,
                paidAt: now.toISOString(),
                recordedBy: req.authUser!.name,
              },
            ]
          : [],
      createdAt: now.toISOString(),
    };
    db.supplierInvoices.unshift(inv);
    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'SUPPLIER_INVOICE_ADDED',
      targetType: 'supplier_invoice',
      targetName: `${supplier.name} (${inv.invoiceNumber})`,
      afterSummary: `Total=${inv.totalAmount} Br, Paid=${inv.paidAmount} Br`,
    });
    await saveDatabase(db);
    res.status(201).json(inv);
  });

  app.post('/api/suppliers/invoices/:id/pay', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const inv = db.supplierInvoices.find((i) => i.id === req.params.id);
    if (!inv) return res.status(404).json({ error: 'Supplier invoice not found.' });
    const payAmt = Number(req.body?.amount);
    const remaining = Number((inv.totalAmount - inv.paidAmount).toFixed(2));
    if (!Number.isFinite(payAmt) || payAmt <= 0 || payAmt > remaining + 0.01) {
      return res.status(400).json({ error: `Enter a valid payment up to ${remaining} Br.` });
    }
    const method = VALID_PAYROLL_METHODS.includes(req.body?.method)
      ? (req.body.method as PayrollMethod)
      : 'bank_transfer';

    const actualPay = Math.min(remaining, Number(payAmt.toFixed(2)));
    inv.paidAmount = Number((inv.paidAmount + actualPay).toFixed(2));
    inv.status = inv.paidAmount >= inv.totalAmount ? 'paid' : 'partial';
    inv.payments.unshift({
      id: `spay_${crypto.randomUUID().slice(0, 8)}`,
      amount: actualPay,
      method,
      reference: typeof req.body?.reference === 'string' && req.body.reference.trim()
        ? req.body.reference.trim().slice(0, 80)
        : undefined,
      paidAt: getClinicNow(db.settings).toISOString(),
      recordedBy: req.authUser!.name,
    });

    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'SUPPLIER_PAYMENT_RECORDED',
      targetType: 'supplier_invoice',
      targetName: `${inv.supplierName} (${inv.invoiceNumber})`,
      afterSummary: `Paid +${actualPay} Br via ${method} (Total Paid=${inv.paidAmount}/${inv.totalAmount})`,
    });
    await saveDatabase(db);
    res.json(inv);
  });

  app.patch('/api/suppliers/invoices/:id', requireAuth, requireOwner, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const inv = db.supplierInvoices.find((i) => i.id === req.params.id);
    if (!inv) return res.status(404).json({ error: 'Supplier invoice not found.' });

    const { supplierId, invoiceNumber, itemsSummary, totalAmount, dueDate } = req.body ?? {};
    const beforeSummary = `${inv.invoiceNumber}: Total=${inv.totalAmount} Br`;
    if (typeof supplierId === 'string' && supplierId.trim()) {
      const sup = db.suppliers.find((s) => s.id === supplierId);
      if (!sup) return res.status(400).json({ error: 'Select a valid supplier.' });
      inv.supplierId = sup.id;
      inv.supplierName = sup.name;
    }
    if (typeof invoiceNumber === 'string' && invoiceNumber.trim()) {
      inv.invoiceNumber = invoiceNumber.trim().slice(0, 48);
    }
    if (typeof itemsSummary === 'string' && itemsSummary.trim()) {
      inv.itemsSummary = itemsSummary.trim().slice(0, 200);
    }
    if (totalAmount !== undefined) {
      const totalNum = Number(totalAmount);
      if (!Number.isFinite(totalNum) || totalNum <= 0) {
        return res.status(400).json({ error: 'Invoice total must be greater than 0.' });
      }
      if (totalNum < inv.paidAmount) {
        return res.status(400).json({ error: `Invoice total cannot be less than already paid amount (${inv.paidAmount} Br).` });
      }
      inv.totalAmount = Number(totalNum.toFixed(2));
    }
    if (typeof dueDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(dueDate.trim())) {
      inv.dueDate = dueDate.trim();
    }

    const todayStr = getClinicNow(db.settings).toISOString().slice(0, 10);
    inv.status =
      inv.paidAmount >= inv.totalAmount
        ? 'paid'
        : inv.dueDate < todayStr
          ? 'overdue'
          : inv.paidAmount > 0
            ? 'partial'
            : 'unpaid';

    appendAuditLog(db, {
      actorId: req.authUser!.id,
      actorName: req.authUser!.name,
      actorRole: req.authUser!.role,
      action: 'SUPPLIER_INVOICE_UPDATED',
      targetType: 'supplier_invoice',
      targetName: `${inv.supplierName} (${inv.invoiceNumber})`,
      beforeSummary,
      afterSummary: `${inv.invoiceNumber}: Total=${inv.totalAmount} Br, Due=${inv.dueDate}`,
    });
    await saveDatabase(db);
    res.json(inv);
  });

  // Tamper-Proof Audit Log (Owner only)
  app.get('/api/audit-log', requireAuth, requireOwner, (_req, res) => {
    const db = loadDatabase();
    res.json({
      chainValid: verifyAuditChain(db.auditLog),
      entries: db.auditLog,
    });
  });

  // Transactions / POS Sale Execution (Supports Box/Strip/Base conversion, Split Pay, Offline Idempotency)
  app.get('/api/transactions', requireAuth, (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const user = req.authUser!;
    if (user.role === 'owner' || user.role === 'manager') {
      return res.json(db.transactions.map((t) => sanitizeTransactionForRole(t, user.role)));
    }
    const ownTxns = db.transactions
      .filter((t) => t.cashierId === user.id)
      .map((t) => sanitizeTransactionForRole(t, 'seller'));
    res.json(ownTxns);
  });

  app.post('/api/transactions', requireAuth, async (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const user = req.authUser!;
    const body = req.body ?? {};

    // Idempotent check for offline sync retries
    const clientSyncId =
      typeof body.clientSyncId === 'string' && body.clientSyncId.trim()
        ? body.clientSyncId.trim().slice(0, 80)
        : undefined;
    if (clientSyncId && db.processedSyncIds.includes(clientSyncId)) {
      const existingTxn = db.transactions.find((t) => t.clientSyncId === clientSyncId);
      if (existingTxn) {
        return res.status(200).json({
          transaction: sanitizeTransactionForRole(existingTxn, user.role),
          triggeredLowStock: [],
        });
      }
    }

    const rawItems = Array.isArray(body.items) ? body.items : [];
    if (rawItems.length === 0) {
      return res.status(400).json({ error: 'Cart cannot be empty.' });
    }

    const paymentMethod = VALID_PAYMENTS.includes(body.paymentMethod)
      ? (body.paymentMethod as PaymentMethod)
      : null;
    if (!paymentMethod) {
      return res.status(400).json({ error: 'Select a valid payment method.' });
    }

    const paymentProofImage =
      typeof body.paymentProofImage === 'string' ? body.paymentProofImage : '';
    const prescriptionImage =
      typeof body.prescriptionImage === 'string' ? body.prescriptionImage : '';

    if (paymentMethod !== 'cash') {
      if (!paymentProofImage || !isValidImageString(paymentProofImage)) {
        return res.status(400).json({
          error:
            'A photo or screenshot of the payment confirmation message is required for transfer, card, or split payments.',
        });
      }
    }

    // Aggregate base unit deductions per drug to verify stock cleanly
    const baseDeductByDrug = new Map<string, number>();
    const normalizedLines: { drugId: string; quantity: number; unitTier: SaleUnitTier }[] = [];

    for (const entry of rawItems) {
      const drugId = typeof entry?.drugId === 'string' ? entry.drugId : '';
      const qty = Math.floor(Number(entry?.quantity));
      const tier: SaleUnitTier =
        entry?.unitTier === 'box' || entry?.unitTier === 'pack' ? entry.unitTier : 'base';

      if (!drugId || !Number.isFinite(qty) || qty <= 0) {
        return res.status(400).json({ error: 'Invalid item or quantity in cart.' });
      }
      const drug = db.drugs.find((d) => d.id === drugId);
      if (!drug) {
        return res.status(404).json({ error: `Medicine (${drugId}) is no longer in inventory.` });
      }
      const { multiplier } = resolveDrugUnit(drug, tier);
      const baseNeeded = qty * multiplier;
      baseDeductByDrug.set(drugId, (baseDeductByDrug.get(drugId) ?? 0) + baseNeeded);
      normalizedLines.push({ drugId, quantity: qty, unitTier: tier });
    }

    for (const [drugId, totalBaseNeeded] of baseDeductByDrug.entries()) {
      const drug = db.drugs.find((d) => d.id === drugId)!;
      if (drug.stock < totalBaseNeeded) {
        return res.status(409).json({
          error: `Insufficient stock for ${drug.name}. Only ${drug.stock} ${drug.baseUnitName || 'units'} remaining.`,
        });
      }
    }

    let requiresPrescription = false;
    const verifiedItems: TransactionItem[] = [];
    let subtotal = 0;
    let totalCost = 0;

    for (const line of normalizedLines) {
      const drug = db.drugs.find((d) => d.id === line.drugId)!;
      if (drug.requiresPrescription) {
        requiresPrescription = true;
      }
      const { multiplier, sellingPrice, unitLabel } = resolveDrugUnit(drug, line.unitTier);
      const baseUnitsDeducted = line.quantity * multiplier;
      const lineTotal = Number((sellingPrice * line.quantity).toFixed(2));
      const unitBuyingBase = drug.buyingPrice ?? 0;

      subtotal += lineTotal;
      totalCost += unitBuyingBase * baseUnitsDeducted;

      verifiedItems.push({
        drugId: drug.id,
        drugName: drug.name,
        dosageForm: drug.dosageForm,
        strength: drug.strength,
        quantity: line.quantity,
        unitTier: line.unitTier,
        unitLabel,
        baseUnitsDeducted,
        unitSellingPrice: sellingPrice,
        unitBuyingPrice: unitBuyingBase,
        lineTotal,
        requiresPrescription: drug.requiresPrescription,
      });
    }

    if (requiresPrescription) {
      if (!prescriptionImage || !isValidImageString(prescriptionImage)) {
        return res.status(400).json({
          error: 'Prescription image verification is required before dispensing Rx medicines.',
        });
      }
    }

    const roundedSubtotal = Number(subtotal.toFixed(2));
    const taxAmount = Number(((roundedSubtotal * db.settings.taxRatePercent) / 100).toFixed(2));
    const totalAmount = Number((roundedSubtotal + taxAmount).toFixed(2));
    const roundedCost = Number(totalCost.toFixed(2));
    const totalProfit = Number((roundedSubtotal - roundedCost).toFixed(2));

    let splitCashAmount: number | undefined;
    let splitNonCashAmount: number | undefined;
    let splitSecondMethod: 'transfer' | 'card' | undefined;

    if (paymentMethod === 'split') {
      const cashPart = Number(body.splitCashAmount);
      if (!Number.isFinite(cashPart) || cashPart <= 0 || cashPart >= totalAmount) {
        return res.status(400).json({
          error: `Split payment cash portion must be between 1 and ${(totalAmount - 0.01).toFixed(2)} ${db.settings.currencySymbol}.`,
        });
      }
      splitCashAmount = Number(cashPart.toFixed(2));
      splitNonCashAmount = Number((totalAmount - splitCashAmount).toFixed(2));
      splitSecondMethod = body.splitSecondMethod === 'card' ? 'card' : 'transfer';
    }

    let cashTendered: number | undefined;
    let changeDue: number | undefined;
    if (paymentMethod === 'cash' && body.cashTendered !== undefined) {
      const tendered = Number(body.cashTendered);
      if (Number.isFinite(tendered) && tendered >= totalAmount) {
        cashTendered = Number(tendered.toFixed(2));
        changeDue = Number((tendered - totalAmount).toFixed(2));
      }
    }

    // Deduct stock atomically
    const newlyTriggeredAlerts: string[] = [];
    for (const [drugId, totalBaseNeeded] of baseDeductByDrug.entries()) {
      const drug = db.drugs.find((d) => d.id === drugId)!;
      const prevStock = drug.stock;
      drug.stock -= totalBaseNeeded;
      drug.updatedAt = getClinicNow(db.settings).toISOString();
      syncAlertForDrug(db, drug);
      if (prevStock > drug.lowStockThreshold && drug.stock <= drug.lowStockThreshold) {
        newlyTriggeredAlerts.push(drug.name);
      }
    }

    const saleTime =
      typeof body.offlineCreatedAt === 'string' && !Number.isNaN(new Date(body.offlineCreatedAt).getTime())
        ? new Date(body.offlineCreatedAt)
        : getClinicNow(db.settings);

    const receiptNumber = `RX-${saleTime.toISOString().slice(2, 10).replace(/-/g, '')}-${String(
      db.transactions.length + 101
    ).padStart(4, '0')}`;

    const transaction: Transaction = {
      id: `txn_${crypto.randomUUID().slice(0, 8)}`,
      receiptNumber,
      cashierId: user.id,
      cashierName: user.name,
      items: verifiedItems,
      subtotal: roundedSubtotal,
      taxAmount,
      totalAmount,
      totalCost: roundedCost,
      totalProfit,
      paymentMethod,
      cashTendered,
      changeDue,
      splitCashAmount,
      splitNonCashAmount,
      splitSecondMethod,
      paymentProofImage: paymentMethod !== 'cash' ? paymentProofImage : undefined,
      prescriptionImage: requiresPrescription ? prescriptionImage : undefined,
      patientReference:
        typeof body.patientReference === 'string' && body.patientReference.trim()
          ? body.patientReference.trim().slice(0, 100)
          : undefined,
      notes:
        typeof body.notes === 'string' && body.notes.trim()
          ? body.notes.trim().slice(0, 240)
          : undefined,
      clientSyncId,
      syncedFromOffline: Boolean(clientSyncId),
      createdAt: saleTime.toISOString(),
    };

    db.transactions.unshift(transaction);
    if (clientSyncId) {
      db.processedSyncIds.unshift(clientSyncId);
      if (db.processedSyncIds.length > 1000) {
        db.processedSyncIds = db.processedSyncIds.slice(0, 1000);
      }
    }

    appendAuditLog(db, {
      actorId: user.id,
      actorName: user.name,
      actorRole: user.role,
      action: clientSyncId ? 'SALE_OFFLINE_SYNCED' : 'SALE_COMPLETED',
      targetType: 'transaction',
      targetName: transaction.receiptNumber,
      afterSummary: `${totalAmount} Br (${paymentMethod}), ${verifiedItems.length} line(s)`,
    });

    await saveDatabase(db);

    res.status(201).json({
      transaction: sanitizeTransactionForRole(transaction, user.role),
      triggeredLowStock: newlyTriggeredAlerts,
    });
  });

  // Owner Analytics Overview (includes Expenses, Payroll & True Net Profit)
  app.get('/api/overview', requireAuth, requireOwner, (req: AuthedRequest, res) => {
    const db = loadDatabase();
    const period = typeof req.query.period === 'string' ? req.query.period : '30d';
    const nowDate = getClinicNow(db.settings);
    const nowMs = nowDate.getTime();

    let cutoffMs = 0;
    if (period === 'today') {
      const startOfDay = new Date(nowDate.getFullYear(), nowDate.getMonth(), nowDate.getDate());
      cutoffMs = startOfDay.getTime();
    } else if (period === '7d') {
      cutoffMs = nowMs - 7 * 24 * 60 * 60 * 1000;
    } else if (period === '30d') {
      cutoffMs = nowMs - 30 * 24 * 60 * 60 * 1000;
    }

    const filteredTxns = db.transactions.filter(
      (t) => new Date(t.createdAt).getTime() >= cutoffMs
    );
    const filteredExpenses = db.expenses.filter(
      (e) => new Date(`${e.date}T12:00:00`).getTime() >= cutoffMs
    );
    const filteredPayroll = db.payrollPayments.filter(
      (p) => new Date(p.paidAt).getTime() >= cutoffMs
    );

    let totalRevenue = 0;
    let totalCost = 0;
    let totalProfit = 0;
    let unitsSold = 0;

    const paymentMap = new Map<'cash' | 'transfer' | 'card', { count: number; amount: number }>([
      ['cash', { count: 0, amount: 0 }],
      ['transfer', { count: 0, amount: 0 }],
      ['card', { count: 0, amount: 0 }],
    ]);

    const drugSalesMap = new Map<
      string,
      {
        drugId: string;
        drugName: string;
        dosageForm: string;
        unitsSold: number;
        revenue: number;
        profit: number;
      }
    >();

    const cashierMap = new Map<
      string,
      {
        cashierId: string;
        cashierName: string;
        transactions: number;
        revenue: number;
        cashTotal: number;
        nonCashTotal: number;
      }
    >();

    const dailyMap = new Map<
      string,
      { date: string; label: string; revenue: number; profit: number; transactions: number }
    >();

    for (let i = 6; i >= 0; i--) {
      const d = new Date(nowMs - i * 24 * 60 * 60 * 1000);
      const key = d.toISOString().slice(0, 10);
      const label = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      dailyMap.set(key, { date: key, label, revenue: 0, profit: 0, transactions: 0 });
    }

    for (const txn of filteredTxns) {
      totalRevenue += txn.totalAmount;
      const txnCost = txn.totalCost ?? 0;
      const txnProfit = txn.totalProfit ?? txn.subtotal - txnCost;
      totalCost += txnCost;
      totalProfit += txnProfit;

      if (txn.paymentMethod === 'split') {
        const cashEntry = paymentMap.get('cash')!;
        cashEntry.count += 1;
        cashEntry.amount = Number((cashEntry.amount + (txn.splitCashAmount ?? 0)).toFixed(2));
        const secondKey = txn.splitSecondMethod === 'card' ? 'card' : 'transfer';
        const secondEntry = paymentMap.get(secondKey)!;
        secondEntry.count += 1;
        secondEntry.amount = Number((secondEntry.amount + (txn.splitNonCashAmount ?? 0)).toFixed(2));
      } else {
        const payEntry = paymentMap.get(txn.paymentMethod);
        if (payEntry) {
          payEntry.count += 1;
          payEntry.amount = Number((payEntry.amount + txn.totalAmount).toFixed(2));
        }
      }

      const dayKey = txn.createdAt.slice(0, 10);
      const dayEntry = dailyMap.get(dayKey);
      if (dayEntry) {
        dayEntry.revenue = Number((dayEntry.revenue + txn.totalAmount).toFixed(2));
        dayEntry.profit = Number((dayEntry.profit + txnProfit).toFixed(2));
        dayEntry.transactions += 1;
      }

      const cEntry = cashierMap.get(txn.cashierId) ?? {
        cashierId: txn.cashierId,
        cashierName: txn.cashierName,
        transactions: 0,
        revenue: 0,
        cashTotal: 0,
        nonCashTotal: 0,
      };
      cEntry.transactions += 1;
      cEntry.revenue = Number((cEntry.revenue + txn.totalAmount).toFixed(2));
      if (txn.paymentMethod === 'cash') {
        cEntry.cashTotal = Number((cEntry.cashTotal + txn.totalAmount).toFixed(2));
      } else if (txn.paymentMethod === 'split') {
        cEntry.cashTotal = Number((cEntry.cashTotal + (txn.splitCashAmount ?? 0)).toFixed(2));
        cEntry.nonCashTotal = Number((cEntry.nonCashTotal + (txn.splitNonCashAmount ?? 0)).toFixed(2));
      } else {
        cEntry.nonCashTotal = Number((cEntry.nonCashTotal + txn.totalAmount).toFixed(2));
      }
      cashierMap.set(txn.cashierId, cEntry);

      for (const item of txn.items) {
        const baseUnits = item.baseUnitsDeducted ?? item.quantity;
        unitsSold += baseUnits;
        const existing = drugSalesMap.get(item.drugId) ?? {
          drugId: item.drugId,
          drugName: item.drugName,
          dosageForm: item.dosageForm,
          unitsSold: 0,
          revenue: 0,
          profit: 0,
        };
        const itemCost = (item.unitBuyingPrice ?? 0) * baseUnits;
        existing.unitsSold += baseUnits;
        existing.revenue = Number((existing.revenue + item.lineTotal).toFixed(2));
        existing.profit = Number((existing.profit + (item.lineTotal - itemCost)).toFixed(2));
        drugSalesMap.set(item.drugId, existing);
      }
    }

    const totalExpenses = Number(
      filteredExpenses.reduce((acc, e) => acc + e.amount, 0).toFixed(2)
    );
    const totalPayrollPaid = Number(
      filteredPayroll.reduce((acc, p) => acc + p.amount, 0).toFixed(2)
    );
    const trueNetProfit = Number((totalProfit - totalExpenses - totalPayrollPaid).toFixed(2));
    const unpaidSupplierBalance = Number(
      db.supplierInvoices
        .reduce((acc, inv) => acc + Math.max(0, inv.totalAmount - inv.paidAmount), 0)
        .toFixed(2)
    );

    const thirtyDaysMs = nowMs + 30 * 24 * 60 * 60 * 1000;
    const expiringSoonCount = db.drugs.filter(
      (d) => new Date(d.expiryDate).getTime() <= thirtyDaysMs
    ).length;

    const activeLowStockCount = db.drugs.filter((d) => d.stock <= d.lowStockThreshold).length;
    const netRevenueExTax = filteredTxns.reduce((acc, t) => acc + t.subtotal, 0);
    const profitMarginPercent =
      netRevenueExTax > 0 ? Number(((totalProfit / netRevenueExTax) * 100).toFixed(1)) : 0;

    const overview: OverviewAnalytics = {
      totalRevenue: Number(totalRevenue.toFixed(2)),
      totalCost: Number(totalCost.toFixed(2)),
      netProfit: Number(totalProfit.toFixed(2)),
      totalExpenses,
      totalPayrollPaid,
      trueNetProfit,
      unpaidSupplierBalance,
      profitMarginPercent,
      transactionCount: filteredTxns.length,
      unitsSold,
      averageBasket:
        filteredTxns.length > 0 ? Number((totalRevenue / filteredTxns.length).toFixed(2)) : 0,
      activeLowStockCount,
      expiringSoonCount,
      paymentBreakdown: Array.from(paymentMap.entries()).map(([method, stats]) => ({
        method,
        count: stats.count,
        amount: stats.amount,
      })),
      dailySeries: Array.from(dailyMap.values()),
      topDrugs: Array.from(drugSalesMap.values())
        .sort((a, b) => b.unitsSold - a.unitsSold)
        .slice(0, 6),
      cashierPerformance: Array.from(cashierMap.values()).sort((a, b) => b.revenue - a.revenue),
    };

    res.json(overview);
  });

  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`YOYA Pharmacy server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
