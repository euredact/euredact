function clean(candidate: string, chars = /[\s.\-]/g): string {
  return candidate.replace(chars, "");
}

export function validateIban(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "").toUpperCase();
  if (c.length < 5 || !/^[A-Z]{2}/.test(c) || !/^\d{2}$/.test(c.slice(2, 4))) return false;

  const ibanLengths: Record<string, number> = {
    AL:28,AD:24,AT:20,AZ:28,BH:22,BY:28,BE:16,BA:20,BR:29,BG:22,CR:22,HR:21,
    CY:28,CZ:24,DK:18,DO:28,TL:23,EE:20,FO:18,FI:18,FR:27,GE:22,DE:22,GI:23,
    GR:27,GL:18,GT:28,HU:28,IS:26,IQ:23,IE:22,IL:23,IT:27,JO:30,KZ:20,XK:20,
    KW:30,LV:21,LB:28,LI:21,LT:20,LU:20,MT:31,MR:27,MU:30,MC:27,MD:24,ME:22,
    NL:18,MK:19,NO:15,PK:24,PS:29,PL:28,PT:25,QA:29,RO:24,LC:32,SM:27,SA:24,
    RS:22,SC:31,SK:24,SI:19,ES:24,SE:24,CH:21,TN:24,TR:26,UA:29,AE:23,GB:22,
    VA:22,VG:24,
  };
  const country = c.slice(0, 2);
  const expected = ibanLengths[country];
  if (expected !== undefined && c.length !== expected) return false;

  const rearranged = c.slice(4) + c.slice(0, 4);
  let numeric = "";
  for (const ch of rearranged) {
    if (/\d/.test(ch)) numeric += ch;
    else if (/[A-Z]/.test(ch)) numeric += (ch.charCodeAt(0) - 55).toString();
    else return false;
  }
  // BigInt mod 97
  let remainder = 0n;
  for (let i = 0; i < numeric.length; i += 7) {
    const chunk = remainder.toString() + numeric.slice(i, i + 7);
    remainder = BigInt(chunk) % 97n;
  }
  return remainder === 1n;
}

export function validateBsn(candidate: string): boolean {
  const c = clean(candidate);
  if (c.length !== 9 || !/^\d{9}$/.test(c) || c === "000000000") return false;
  const weights = [9,8,7,6,5,4,3,2,-1];
  let total = 0;
  for (let i = 0; i < 9; i++) total += parseInt(c[i]) * weights[i];
  return total % 11 === 0 && total !== 0;
}

export function validateBelgianNn(candidate: string): boolean {
  const c = clean(candidate);
  if (c.length !== 11 || !/^\d{11}$/.test(c)) return false;
  const firstNine = parseInt(c.slice(0, 9));
  const check = parseInt(c.slice(9, 11));
  if (97 - (firstNine % 97) === check) return true;
  const firstNine2000 = parseInt("2" + c.slice(0, 9));
  return 97 - (firstNine2000 % 97) === check;
}

export function validateLuhn(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (!/^\d+$/.test(c) || c.length < 12) return false;
  let total = 0;
  for (let i = c.length - 1; i >= 0; i--) {
    let n = parseInt(c[i]);
    if ((c.length - 1 - i) % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    total += n;
  }
  return total % 10 === 0;
}

export function validateBelgianVat(candidate: string): boolean {
  let c = clean(candidate).toUpperCase();
  if (c.startsWith("BE")) c = c.slice(2);
  if (c.length !== 10 || !/^\d{10}$/.test(c) || c[0] !== "0") return false;
  const firstPart = parseInt(c.slice(0, 8));
  const check = parseInt(c.slice(8, 10));
  return (firstPart % 97) === (97 - check) || (97 - (firstPart % 97)) === check;
}

export function validateVatNl(candidate: string): boolean {
  let c = clean(candidate).toUpperCase();
  if (c.startsWith("NL")) c = c.slice(2);
  if (c.length !== 12) return false;
  return /^\d{9}B\d{2}$/.test(c);
}

export function validateVatDe(candidate: string): boolean {
  let c = clean(candidate).toUpperCase();
  if (c.startsWith("DE")) c = c.slice(2);
  return c.length === 9 && /^\d{9}$/.test(c);
}

export function validateVatFr(candidate: string): boolean {
  let c = clean(candidate).toUpperCase();
  if (c.startsWith("FR")) c = c.slice(2);
  if (c.length !== 11) return false;
  for (const ch of c.slice(0, 2)) {
    if (!(/\d/.test(ch) || (/[A-Z]/.test(ch) && ch !== "O" && ch !== "I"))) return false;
  }
  return /^\d{9}$/.test(c.slice(2));
}

export function validateVatLu(candidate: string): boolean {
  let c = clean(candidate).toUpperCase();
  if (c.startsWith("LU")) c = c.slice(2);
  return c.length === 8 && /^\d{8}$/.test(c);
}

export function validateGermanTaxId(candidate: string): boolean {
  const c = candidate.replace(/[\s.\-/]/g, "");
  if (c.length !== 11 || !/^\d{11}$/.test(c) || c[0] === "0") return false;
  let product = 10;
  for (let i = 0; i < 10; i++) {
    let total = (parseInt(c[i]) + product) % 10;
    if (total === 0) total = 10;
    product = (total * 2) % 11;
  }
  const check = (11 - product) % 10;
  return check === parseInt(c[10]);
}

export function validateFrenchNir(candidate: string): boolean {
  const c = clean(candidate);
  if (c.length !== 15) return false;
  let numeric = c;
  const upper = c.toUpperCase();
  if (!/^\d+$/.test(c)) {
    if (upper.includes("A")) numeric = upper.replace(/A/g, "0");
    else if (upper.includes("B")) numeric = upper.replace(/B/g, "0");
    else return false;
  }
  if (!/^\d+$/.test(numeric)) return false;
  let first13 = parseInt(numeric.slice(0, 13));
  if (upper.includes("A")) {
    first13 = parseInt(upper.slice(0, 7).replace(/A/g, "0") + c.slice(7, 13)) - 1000000;
  } else if (upper.includes("B")) {
    first13 = parseInt(upper.slice(0, 7).replace(/B/g, "0") + c.slice(7, 13)) - 2000000;
  }
  const check = parseInt(numeric.slice(13, 15));
  return (97 - (first13 % 97)) === check;
}

export function validateVin(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "").toUpperCase();
  if (c.length !== 17) return false;
  return !/[IOQ]/.test(c);
}

export function validateBic(candidate: string): boolean {
  const c = candidate.replace(/ /g, "").toUpperCase();
  if (c.length !== 8 && c.length !== 11) return false;
  if (!/^[A-Z]{4}/.test(c)) return false;
  if (!/^[A-Z]{2}$/.test(c.slice(4, 6))) return false;
  if (!/^[A-Z0-9]{2}$/.test(c.slice(6, 8))) return false;
  if (c.length === 11 && !/^[A-Z0-9]{3}$/.test(c.slice(8, 11))) return false;
  return true;
}

export function validateKvk(candidate: string): boolean {
  const c = clean(candidate);
  return c.length === 8 && /^\d{8}$/.test(c);
}

export function validateSwedishPnr(candidate: string): boolean {
  let c = candidate.replace(/[\s\-+]/g, "");
  if (c.length === 12) c = c.slice(2);
  if (c.length !== 10 || !/^\d{10}$/.test(c)) return false;
  const month = parseInt(c.slice(2, 4));
  const day = parseInt(c.slice(4, 6));
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;
  let total = 0;
  for (let i = 0; i < 10; i++) {
    let n = parseInt(c[i]) * (i % 2 === 0 ? 2 : 1);
    total += Math.floor(n / 10) + (n % 10);
  }
  return total % 10 === 0;
}

export function validateNorwegianFnr(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 11 || !/^\d{11}$/.test(c)) return false;
  const d = c.split("").map(Number);
  const w1 = [3,7,6,1,8,9,4,5,2];
  let s1 = 0; for (let i = 0; i < 9; i++) s1 += d[i] * w1[i];
  let c1 = 11 - (s1 % 11); if (c1 === 11) c1 = 0; if (c1 === 10) return false;
  if (d[9] !== c1) return false;
  const w2 = [5,4,3,2,7,6,5,4,3,2];
  let s2 = 0; for (let i = 0; i < 10; i++) s2 += d[i] * w2[i];
  let c2 = 11 - (s2 % 11); if (c2 === 11) c2 = 0; if (c2 === 10) return false;
  return d[10] === c2;
}

export function validateFinnishHetu(candidate: string): boolean {
  const c = candidate.trim();
  if (c.length !== 11) return false;
  const digits = c.slice(0, 6);
  const sep = c[6];
  const individual = c.slice(7, 10);
  const checkChar = c[10];
  if (!/^\d{6}$/.test(digits) || !/^\d{3}$/.test(individual)) return false;
  if (!"-+ABCDEFYXWVU".includes(sep)) return false;
  const lookup = "0123456789ABCDEFHJKLMNPRSTUVWXY";
  const num = parseInt(digits + individual);
  return checkChar === lookup[num % 31];
}

export function validateIcelandicKt(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 10 || !/^\d{10}$/.test(c)) return false;
  const d = c.split("").map(Number);
  const w = [3,2,7,6,5,4,3,2];
  let s = 0; for (let i = 0; i < 8; i++) s += d[i] * w[i];
  const check = (11 - (s % 11)) % 11;
  if (check === 10) return false;
  return d[8] === check;
}

export function validateDanishVat(candidate: string): boolean {
  let c = candidate.replace(/[\s\-]/g, "").toUpperCase();
  if (c.startsWith("DK")) c = c.slice(2);
  if (c.length !== 8 || !/^\d{8}$/.test(c)) return false;
  const d = c.split("").map(Number);
  const w = [2,7,6,5,4,3,2,1];
  let total = 0; for (let i = 0; i < 8; i++) total += d[i] * w[i];
  return total % 11 === 0;
}

export function validateFinnishBusinessId(candidate: string): boolean {
  let c = candidate.replace(/\s/g, "");
  if (c.includes("-")) {
    const parts = c.split("-");
    if (parts.length !== 2) return false;
    c = parts[0] + parts[1];
  }
  if (c.length !== 8 || !/^\d{8}$/.test(c)) return false;
  const d = c.split("").map(Number);
  const w = [7,9,10,5,8,4,2];
  let s = 0; for (let i = 0; i < 7; i++) s += d[i] * w[i];
  const remainder = s % 11;
  let check: number;
  if (remainder === 0) check = 0;
  else if (remainder === 1) return false;
  else check = 11 - remainder;
  return d[7] === check;
}

export function validateImei(candidate: string): boolean {
  const c = candidate.replace(/[\s\-/]/g, "");
  if (c.length !== 15 || !/^\d{15}$/.test(c)) return false;
  if (c.slice(0, 8) === "00000000") return false;
  let total = 0;
  for (let i = 0; i < 15; i++) {
    let n = parseInt(c[i]);
    if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    total += n;
  }
  return total % 10 === 0;
}

export function validateDanishCpr(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 10 || !/^\d{10}$/.test(c)) return false;
  const day = parseInt(c.slice(0, 2));
  const month = parseInt(c.slice(2, 4));
  return day >= 1 && day <= 31 && month >= 1 && month <= 12;
}

export function validateNorwegianOrg(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 9 || !/^\d{9}$/.test(c) || !("89".includes(c[0]))) return false;
  const d = c.split("").map(Number);
  const w = [3,2,7,6,5,4,3,2];
  let s = 0; for (let i = 0; i < 8; i++) s += d[i] * w[i];
  const remainder = s % 11;
  let check: number;
  if (remainder === 0) check = 0;
  else if (remainder === 1) return false;
  else check = 11 - remainder;
  return d[8] === check;
}

export function validateAustrianSvnr(candidate: string): boolean {
  const c = candidate.replace(/\s/g, "");
  if (c.length !== 10 || !/^\d{10}$/.test(c)) return false;
  const d = c.split("").map(Number);
  const weights = [3,7,9,0,5,8,4,2,1,6];
  let total = 0; for (let i = 0; i < 10; i++) total += d[i] * weights[i];
  return total % 11 === d[3];
}

export function validateSwissAhv(candidate: string): boolean {
  const c = clean(candidate);
  if (c.length !== 13 || !/^\d{13}$/.test(c) || !c.startsWith("756")) return false;
  let total = 0;
  for (let i = 0; i < 12; i++) total += parseInt(c[i]) * (i % 2 === 0 ? 1 : 3);
  const check = (10 - (total % 10)) % 10;
  return check === parseInt(c[12]);
}

export function validateItalianCf(candidate: string): boolean {
  const c = candidate.toUpperCase().trim();
  if (c.length !== 16) return false;
  if (!/^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$/.test(c)) return false;
  const oddMap: Record<string, number> = {
    "0":1,"1":0,"2":5,"3":7,"4":9,"5":13,"6":15,"7":17,"8":19,"9":21,
    A:1,B:0,C:5,D:7,E:9,F:13,G:15,H:17,I:19,J:21,K:2,L:4,M:18,N:20,O:11,
    P:3,Q:6,R:8,S:12,T:14,U:16,V:10,W:22,X:25,Y:24,Z:23,
  };
  const evenMap: Record<string, number> = {
    "0":0,"1":1,"2":2,"3":3,"4":4,"5":5,"6":6,"7":7,"8":8,"9":9,
    A:0,B:1,C:2,D:3,E:4,F:5,G:6,H:7,I:8,J:9,K:10,L:11,M:12,N:13,O:14,
    P:15,Q:16,R:17,S:18,T:19,U:20,V:21,W:22,X:23,Y:24,Z:25,
  };
  let total = 0;
  for (let i = 0; i < 15; i++) {
    total += i % 2 === 0 ? (oddMap[c[i]] ?? 0) : (evenMap[c[i]] ?? 0);
  }
  return c[15] === String.fromCharCode(65 + (total % 26));
}

export function validateSpanishDni(candidate: string): boolean {
  const c = candidate.toUpperCase().trim();
  if (!/^\d{8}[A-Z]$/.test(c)) return false;
  const lookup = "TRWAGMYFPDXBNJZSQVHLCKE";
  return c[8] === lookup[parseInt(c.slice(0, 8)) % 23];
}

export function validateSpanishNie(candidate: string): boolean {
  const c = candidate.toUpperCase().trim();
  if (!/^[XYZ]\d{7}[A-Z]$/.test(c)) return false;
  const prefixMap: Record<string, string> = { X: "0", Y: "1", Z: "2" };
  const num = parseInt(prefixMap[c[0]] + c.slice(1, 8));
  const lookup = "TRWAGMYFPDXBNJZSQVHLCKE";
  return c[8] === lookup[num % 23];
}

export function validatePortugueseNif(candidate: string): boolean {
  const c = clean(candidate);
  if (c.length !== 9 || !/^\d{9}$/.test(c) || "04".includes(c[0])) return false;
  const weights = [9,8,7,6,5,4,3,2];
  let total = 0; for (let i = 0; i < 8; i++) total += parseInt(c[i]) * weights[i];
  const remainder = total % 11;
  const check = remainder < 2 ? 0 : 11 - remainder;
  return parseInt(c[8]) === check;
}

export function validatePolishPesel(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 11 || !/^\d{11}$/.test(c)) return false;
  const d = c.split("").map(Number);
  const weights = [1,3,7,9,1,3,7,9,1,3];
  let total = 0; for (let i = 0; i < 10; i++) total += d[i] * weights[i];
  return d[10] === (10 - (total % 10)) % 10;
}

export function validatePolishNip(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 10 || !/^\d{10}$/.test(c)) return false;
  const d = c.split("").map(Number);
  const weights = [6,5,7,2,3,4,5,6,7];
  let total = 0; for (let i = 0; i < 9; i++) total += d[i] * weights[i];
  return total % 11 === d[9];
}

export function validateCzechBirthNumber(candidate: string): boolean {
  const c = candidate.replace(/[/\s]/g, "");
  if (!/^\d+$/.test(c) || (c.length !== 9 && c.length !== 10)) return false;
  if (c.length === 10) return parseInt(c) % 11 === 0;
  return true;
}

export function validateRomanianCnp(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 13 || !/^\d{13}$/.test(c) || !"12345678".includes(c[0])) return false;
  const key = "279146358279";
  let total = 0; for (let i = 0; i < 12; i++) total += parseInt(c[i]) * parseInt(key[i]);
  const remainder = total % 11;
  const check = remainder === 10 ? 1 : remainder;
  return parseInt(c[12]) === check;
}

export function validateHungarianTaj(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 9 || !/^\d{9}$/.test(c)) return false;
  const d = c.split("").map(Number);
  let total = 0;
  for (let i = 0; i < 8; i++) total += d[i] * (i % 2 === 0 ? 3 : 7);
  return total % 10 === d[8];
}

export function validateBulgarianEgn(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 10 || !/^\d{10}$/.test(c)) return false;
  const d = c.split("").map(Number);
  const weights = [2,4,8,5,10,9,7,3,6];
  let total = 0; for (let i = 0; i < 9; i++) total += d[i] * weights[i];
  let check = total % 11; if (check === 10) check = 0;
  return d[9] === check;
}

export function validateCroatianOib(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 11 || !/^\d{11}$/.test(c)) return false;
  let product = 10;
  for (let i = 0; i < 10; i++) {
    let total = (parseInt(c[i]) + product) % 10;
    if (total === 0) total = 10;
    product = (total * 2) % 11;
  }
  const check = (11 - product) % 10;
  return check === parseInt(c[10]);
}

export function validateSlovenianEmso(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 13 || !/^\d{13}$/.test(c)) return false;
  const d = c.split("").map(Number);
  const weights = [7,6,5,4,3,2,7,6,5,4,3,2];
  let total = 0; for (let i = 0; i < 12; i++) total += d[i] * weights[i];
  const remainder = total % 11;
  let check = remainder === 0 ? 0 : 11 - remainder;
  if (check === 10) return false;
  return d[12] === check;
}

export function validateIrishPps(candidate: string): boolean {
  const c = candidate.toUpperCase().trim();
  if (!/^\d{7}[A-W][ABWTXZ]?$/.test(c)) return false;
  const weights = [8,7,6,5,4,3,2];
  let total = 0;
  for (let i = 0; i < 7; i++) total += parseInt(c[i]) * weights[i];
  if (c.length === 9 && /[A-Z]/.test(c[8])) total += (c.charCodeAt(8) - 64) * 9;
  const expected = total % 23;
  const check = expected > 0 ? String.fromCharCode(64 + expected) : "W";
  return c[7] === check;
}

export function validateEstonianId(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 11 || !/^\d{11}$/.test(c) || !"123456".includes(c[0])) return false;
  const d = c.split("").map(Number);
  const w1 = [1,2,3,4,5,6,7,8,9,1];
  let s1 = 0; for (let i = 0; i < 10; i++) s1 += d[i] * w1[i];
  s1 = s1 % 11;
  if (s1 !== 10) return d[10] === s1;
  const w2 = [3,4,5,6,7,8,9,1,2,3];
  let s2 = 0; for (let i = 0; i < 10; i++) s2 += d[i] * w2[i];
  s2 = s2 % 11; if (s2 === 10) s2 = 0;
  return d[10] === s2;
}

export function validateUkNhs(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 10 || !/^\d{10}$/.test(c)) return false;
  const weights = [10,9,8,7,6,5,4,3,2];
  let total = 0; for (let i = 0; i < 9; i++) total += parseInt(c[i]) * weights[i];
  let check = 11 - (total % 11);
  if (check === 11) check = 0;
  if (check === 10) return false;
  return parseInt(c[9]) === check;
}

export function validateGreekAfm(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 9 || !/^\d{9}$/.test(c)) return false;
  const d = c.split("").map(Number);
  let total = 0;
  for (let i = 0; i < 8; i++) total += d[i] * Math.pow(2, 8 - i);
  return d[8] === (total % 11) % 10;
}

export function validateGreekAmka(candidate: string): boolean {
  const c = candidate.replace(/[\s\-]/g, "");
  if (c.length !== 11 || !/^\d{11}$/.test(c)) return false;
  let total = 0;
  for (let i = c.length - 1; i >= 0; i--) {
    let n = parseInt(c[i]);
    if ((c.length - 1 - i) % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    total += n;
  }
  return total % 10 === 0;
}

function validateHighEntropy(candidate: string): boolean {
  const clean = candidate.trim();
  if (clean.length < 8) return false;
  // Short passwords (< 24 chars): require at least 1 letter, 1 digit, 1 special char
  if (clean.length < 24) {
    const hasLetter = /[a-zA-Z]/.test(clean);
    const hasDigit = /\d/.test(clean);
    const hasSpecial = /[^a-zA-Z0-9]/.test(clean);
    if (hasLetter && hasDigit && hasSpecial) return true;
    // For short tokens without special chars, require entropy check
    if (!hasSpecial && clean.length < 16) return false;
  }
  const freq = new Map<string, number>();
  for (const ch of clean) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  const len = clean.length;
  let entropy = 0;
  for (const c of freq.values()) {
    const p = c / len;
    entropy -= p * Math.log2(p);
  }
  // Hex-only strings have max ~4.0 bits entropy, use lower threshold
  const isHex = /^[a-fA-F0-9]+$/.test(clean);
  const threshold = isHex ? 3.0 : clean.length < 24 ? 3.0 : 3.5;
  return entropy >= threshold;
}

export const VALIDATORS: Record<string, (candidate: string) => boolean> = {
  iban: validateIban,
  bsn: validateBsn,
  belgian_nn: validateBelgianNn,
  luhn: validateLuhn,
  belgian_vat: validateBelgianVat,
  vat_nl: validateVatNl,
  vat_de: validateVatDe,
  vat_fr: validateVatFr,
  vat_lu: validateVatLu,
  german_tax_id: validateGermanTaxId,
  french_nir: validateFrenchNir,
  vin: validateVin,
  bic: validateBic,
  kvk: validateKvk,
  swedish_pnr: validateSwedishPnr,
  norwegian_fnr: validateNorwegianFnr,
  finnish_hetu: validateFinnishHetu,
  icelandic_kt: validateIcelandicKt,
  danish_vat: validateDanishVat,
  finnish_business_id: validateFinnishBusinessId,
  norwegian_org: validateNorwegianOrg,
  danish_cpr: validateDanishCpr,
  imei: validateImei,
  austrian_svnr: validateAustrianSvnr,
  swiss_ahv: validateSwissAhv,
  italian_cf: validateItalianCf,
  spanish_dni: validateSpanishDni,
  spanish_nie: validateSpanishNie,
  portuguese_nif: validatePortugueseNif,
  polish_pesel: validatePolishPesel,
  polish_nip: validatePolishNip,
  czech_birth_number: validateCzechBirthNumber,
  romanian_cnp: validateRomanianCnp,
  hungarian_taj: validateHungarianTaj,
  bulgarian_egn: validateBulgarianEgn,
  croatian_oib: validateCroatianOib,
  slovenian_emso: validateSlovenianEmso,
  irish_pps: validateIrishPps,
  estonian_id: validateEstonianId,
  uk_nhs: validateUkNhs,
  greek_afm: validateGreekAfm,
  greek_amka: validateGreekAmka,
  high_entropy: validateHighEntropy,
};
