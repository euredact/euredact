/**
 * BIC registry — tier-1 membership testing for ISO 9362 bank identifier codes.
 *
 * BIC is the only bank identifier in the supported set with **no check digit**
 * (IBAN has mod-97, VAT has country-specific checksums). Structure alone cannot
 * separate a genuine BIC from an ordinary 8- or 11-character uppercase word,
 * because characters 5-6 of everyday words are frequently valid ISO 3166
 * country codes (`DRINGEND` -> `GE`, `HOSPITAL` -> `IT`). Registry membership
 * is therefore the strongest precision signal available.
 *
 * Two sources are consulted, in order:
 *
 * 1. A deployment-supplied registry, installed via {@link setBicRegistry}.
 *    This is the path for anyone holding a licensed directory (SWIFTRef).
 * 2. {@link SEED_BIC6_PREFIXES} — a small bundled set of institution+country
 *    prefixes for major European banks, compiled from publicly published bank
 *    data. No licensed directory is bundled.
 *
 * Matching is on the **BIC6 prefix** (4-letter institution + 2-letter country),
 * so any location and branch code on a known institution is accepted. The
 * prefix is the stable part of a BIC; branch codes churn as branches open and
 * close.
 *
 * The registry is used as an *accept* signal, never as a filter: a candidate
 * that misses it falls through to the context gate in `suppressors.ts` and is
 * still detected when banking context is present. A stale list therefore costs
 * a little recall on bare, contextless BICs — it never causes a leak. Annual
 * review is sufficient.
 */

// BIC6 prefixes (institution + country) of major European institutions,
// compiled from publicly published bank data — not from a licensed directory.
// Kept deliberately small: this covers the banks that appear bare and
// contextless in real documents. Anything outside this list is still detected
// via the context gate.
export const SEED_BIC6_PREFIXES: ReadonlySet<string> = new Set([

  // --- Netherlands ---
  "ABNANL",  // ABN AMRO
  "INGBNL",  // ING
  "RABONL",  // Rabobank
  "SNSBNL",  // SNS Bank
  "TRIONL",  // Triodos
  "BUNQNL",  // bunq
  "KNABNL",  // Knab
  "ASNBNL",  // ASN Bank
  "RBRBNL",  // RegioBank
  "FVLBNL",  // Van Lanschot
  "BITSNL",  // BinckBank
  "DEUTNL",  // Deutsche Bank NL
  // --- Belgium ---
  "BBRUBE",  // BNP Paribas Fortis
  "GEBABE",  // BNP Paribas Fortis (legacy)
  "KREDBE",  // KBC
  "GKCCBE",  // Belfius
  "BPOTBE",  // bpost bank
  "ARSPBE",  // Argenta
  "AXABBE",  // AXA Bank Belgium
  "CREGBE",  // Belfius (legacy)
  "NICABE",  // Crelan
  "TRIOBE",  // Triodos Belgium
  "CTBKBE",  // Banca Monte Paschi Belgio
  "JVBABE",  // Van Breda
  // --- Germany ---
  "DEUTDE",  // Deutsche Bank
  "COBADE",  // Commerzbank
  "PBNKDE",  // Postbank
  "GENODE",  // Volksbanken / Raiffeisen
  "MALADE",  // Sparkassen
  "HELADE",  // Helaba / Sparkassen
  "BYLADE",  // BayernLB / Sparkassen
  "SOLADE",  // Sparkassen (Baden-Wurttemberg)
  "WELADE",  // Sparkassen (Westfalen)
  "NOLADE",  // Norddeutsche Landesbank
  "SPKKDE",  // Sparkasse
  "HYVEDE",  // UniCredit / HypoVereinsbank
  "DRESDE",  // Dresdner (legacy Commerzbank)
  "INGDDE",  // ING-DiBa
  "NTSBDE",  // N26
  "SFRTDE",  // Sutor / fintech BaaS
  "TEDADE",  // Telda / BaaS
  // --- France ---
  "BNPAFR",  // BNP Paribas
  "SOGEFR",  // Societe Generale
  "AGRIFR",  // Credit Agricole
  "CCBPFR",  // Banque Populaire
  "CEPAFR",  // Caisse d'Epargne
  "CMCIFR",  // Credit Mutuel / CIC
  "PSSTFR",  // La Banque Postale
  "BREDFR",  // BRED Banque Populaire
  "CRLYFR",  // LCL
  "HSBCFR",  // HSBC France
  "TRZOFR",  // Treezor
  "QNTOFR",  // Qonto
  // --- Austria ---
  "GIBAAT",  // Erste Bank / Sparkassen
  "BKAUAT",  // UniCredit Bank Austria
  "RZBAAT",  // Raiffeisen Bank International
  "RLNWAT",  // Raiffeisen NO-Wien
  "OBKLAT",  // Oberbank
  "BAWAAT",  // BAWAG P.S.K.
  "VBOEAT",  // Volksbank
  "HYPTAT",  // Hypo Tirol
  "SPIHAT",  // Sparkasse
  // --- Luxembourg ---
  "BCEELU",  // Banque et Caisse d'Epargne de l'Etat
  "BILLLU",  // Banque Internationale a Luxembourg
  "BGLLLU",  // BGL BNP Paribas
  "CCRALU",  // Banque Raiffeisen
  "BLUXLU",  // Banque de Luxembourg
  // --- Ireland / UK ---
  "AIBKIE",  // Allied Irish Banks
  "BOFIIE",  // Bank of Ireland
  "ULSBIE",  // Ulster Bank
  "CITIIE",  // Citibank Ireland
  "BARCGB",  // Barclays
  "HBUKGB",  // HSBC UK
  "MIDLGB",  // HSBC (legacy Midland)
  "LOYDGB",  // Lloyds
  "NWBKGB",  // NatWest
  "RBOSGB",  // Royal Bank of Scotland
  "TSBSGB",  // TSB
  "REVOGB",  // Revolut
  "MONZGB",  // Monzo
  "STARGB",  // Starling
  "CHASGB",  // JP Morgan Chase UK
  // --- Nordics ---
  "NDEADK",  // Nordea Denmark
  "DABADK",  // Danske Bank
  "JYBADK",  // Jyske Bank
  "SYBKDK",  // Sydbank
  "NDEASE",  // Nordea Sweden
  "ESSESE",  // SEB
  "HANDSE",  // Handelsbanken
  "SWEDSE",  // Swedbank
  "DNBANO",  // DNB
  "NDEANO",  // Nordea Norway
  "NDEAFI",  // Nordea Finland
  "OKOYFI",  // OP Corporate Bank
  "HELSFI",  // Aktia
  "NBIIIS",  // Landsbankinn (NBIIISRE)
  "ESJAIS",  // Arion Bank (ESJAISRE)
  "GLITIS",  // Islandsbanki (GLITISRE)
  "MPBAIS",  // Kvika banki (MPBAISRE)
  "KBNONO",  // BNbank ASA (KBNONO22)
  "PRBONO",  // Boligbanken ASA (PRBONO22)
  "AARBDE",  // Aareal Bank AG (AARBDE5W)
  // --- Southern / Central Europe ---
  "UNCRIT",  // UniCredit Italy
  "BCITIT",  // Intesa Sanpaolo
  "PASCIT",  // Monte dei Paschi
  "BPMOIT",  // Banco BPM
  "CRPPIT",  // Cassa di Risparmio
  "BSCHES",  // Banco Santander
  "BBVAES",  // BBVA
  "CAIXES",  // CaixaBank
  "SABBES",  // Banco Sabadell
  "BKBKES",  // Bankinter
  "BCOMPT",  // Millennium BCP
  "CGDIPT",  // Caixa Geral de Depositos
  "BPIPPT",  // Banco BPI
  "NOVBPT",  // Novo Banco
  "BPKOPL",  // PKO Bank Polski
  "BREXPL",  // mBank
  "INGBPL",  // ING Bank Slaski
  "WBKPPL",  // Santander Bank Polska
  "KOMBCZ",  // Komercni banka
  "CEKOCZ",  // CSOB
  "GIBACZ",  // Ceska sporitelna
  "TATRSK",  // Tatra banka
  "SUBASK",  // Vseobecna uverova banka
  "GIBASK",  // Slovenska sporitelna
  "OTPVHU",  // OTP Bank
  "BUDAHU",  // Budapest Bank
  "MKKBHU",  // MKB Bank
  // --- Switzerland ---
  "UBSWCH",  // UBS
  "CRESCH",  // Credit Suisse
  "POFICH",  // PostFinance
  "ZKBKCH",  // Zurcher Kantonalbank
  "RAIFCH",  // Raiffeisen Switzerland
  "MIGRCH",  // Migros Bank
]);

/** A membership test over BIC8/BIC11 codes or bare BIC6 prefixes. */
export type BicRegistryProvider = (bic: string) => boolean;

let provider: BicRegistryProvider | null = null;

/**
 * Install a deployment-supplied BIC registry, consulted ahead of the seed list.
 *
 * Accepts a membership callable, any iterable of BIC strings, or `null` to
 * remove a previously installed registry. Entries may be full BIC8/BIC11 codes
 * or bare BIC6 prefixes; both are matched, case-insensitively and ignoring
 * spaces.
 */
export function setBicRegistry(
  registry: BicRegistryProvider | Iterable<string> | null,
): void {
  if (registry === null) {
    provider = null;
    return;
  }
  if (typeof registry === "function") {
    provider = registry;
    return;
  }
  const known = new Set<string>();
  for (const entry of registry) {
    const e = String(entry).trim();
    if (e && !e.startsWith("#")) known.add(e.replace(/ /g, "").toUpperCase());
  }
  provider = (bic: string) => known.has(bic);
}

/** Return the installed registry provider, or null if none is installed. */
export function getBicRegistry(): BicRegistryProvider | null {
  return provider;
}

/**
 * Tier 1: is `candidate` a BIC of a known institution?
 *
 * Checks the deployment-supplied registry first (full code, then BIC6 prefix),
 * then the bundled seed prefixes.
 */
export function isRegisteredBic(candidate: string): boolean {
  const c = candidate.replace(/ /g, "").toUpperCase();
  if (c.length !== 8 && c.length !== 11) return false;
  const prefix = c.slice(0, 6);
  if (provider !== null) {
    try {
      if (provider(c) || provider(prefix)) return true;
    } catch {
      // a broken provider must not break detection
    }
  }
  return SEED_BIC6_PREFIXES.has(prefix);
}
