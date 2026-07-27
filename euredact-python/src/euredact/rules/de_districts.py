"""German vehicle registration district codes (Unterscheidungszeichen).

The set is closed: codes are fixed by the Fahrzeug-Zulassungsverordnung and
maintained by the Kraftfahrt-Bundesamt, changing only when a district is
created, merged, or a historic code is reinstated. That makes membership a
usable precision signal — unlike the open-ended blocklist of standards
prefixes it replaces, which only ever catches acronyms someone thought of.

Used as a **tier**, not a filter (see
:func:`euredact.rules.suppressors.suppress_de_plate_unknown_district`):

* code on this list -> emit, no cue needed;
* code absent but a plate cue nearby (``Kennzeichen``, ``Kfz``...) -> emit;
* neither -> reject.

So a code missing from this list costs recall only where there is also no cue,
rather than silently dropping a plate. Note that some entries are also
standards prefixes — ``DIN`` is Dinslaken as well as the German standards body
— which is why the standards guard is kept alongside this one.
"""

from __future__ import annotations

DE_DISTRICT_CODES: frozenset[str] = frozenset({
    "A", "AA", "AB", "ABG", "AC", "AE", "AH", "AIB", "AIC", "AK", "AL",
    "ALF", "ALS", "ALZ", "AM", "AN", "ANA", "ANG", "ANK", "AP", "APD", "AR",
    "ARN", "ART", "AS", "ASD", "ASL", "ASZ", "AT", "AU", "AUR", "AW", "AZ",
    "AZE", "AÖ", "B", "BA", "BAD", "BAR", "BB", "BBG", "BBL", "BC", "BCH",
    "BD", "BE", "BED", "BEI", "BEL", "BER", "BF", "BG", "BGD", "BGL", "BH",
    "BI", "BID", "BIN", "BIR", "BIT", "BIW", "BK", "BKS", "BL", "BLB",
    "BLK", "BM", "BN", "BNA", "BO", "BOG", "BOH", "BOR", "BOT", "BP", "BR",
    "BRA", "BRB", "BRG", "BRI", "BRK", "BRL", "BRV", "BS", "BSB", "BSK",
    "BT", "BTF", "BU", "BUL", "BUR", "BW", "BWL", "BYL", "BZ", "BZA", "BÖ",
    "BÜD", "BÜS", "BÜZ", "C", "CA", "CAS", "CB", "CE", "CHA", "CHL", "CLP",
    "CLZ", "CO", "COC", "COE", "CR", "CT", "CUX", "CW", "D", "DA", "DAH",
    "DAN", "DAU", "DB", "DBR", "DD", "DE", "DEG", "DEL", "DG", "DGF", "DH",
    "DI", "DIL", "DIN", "DIZ", "DKB", "DL", "DLG", "DM", "DN", "DO", "DON",
    "DS", "DT", "DU", "DUD", "DW", "DZ", "DÜW", "E", "EA", "EB", "EBE",
    "EBN", "EBS", "ECK", "ED", "EE", "EF", "EG", "EH", "EHI", "EI", "EIC",
    "EIH", "EIL", "EIN", "EIS", "EL", "EM", "EMD", "EMS", "EN", "ER", "ERB",
    "ERH", "ERK", "ES", "ESA", "ESB", "ESW", "EU", "EUT", "EW", "F", "FAL",
    "FB", "FD", "FDB", "FDS", "FEU", "FF", "FFB", "FG", "FH", "FI", "FKB",
    "FL", "FLÖ", "FN", "FO", "FOR", "FR", "FRG", "FRI", "FRW", "FS", "FT",
    "FTL", "FW", "FZ", "FÜ", "FÜS", "G", "GA", "GAN", "GAP", "GC", "GD",
    "GDB", "GE", "GEL", "GEM", "GEO", "GER", "GF", "GG", "GHA", "GHC", "GI",
    "GK", "GL", "GLA", "GM", "GMN", "GN", "GNT", "GOA", "GOH", "GP", "GR",
    "GRA", "GRH", "GRI", "GRM", "GRS", "GRZ", "GS", "GT", "GTH", "GUB",
    "GUN", "GV", "GVM", "GW", "GZ", "GÖ", "GÜ", "H", "HA", "HAB", "HAL",
    "HAM", "HAS", "HB", "HBN", "HBS", "HC", "HCH", "HD", "HDH", "HDL", "HE",
    "HEB", "HEF", "HEI", "HEL", "HER", "HET", "HF", "HG", "HGN", "HGW",
    "HH", "HHM", "HI", "HIG", "HIP", "HK", "HL", "HM", "HMU", "HN", "HO",
    "HOG", "HOH", "HOL", "HOM", "HOR", "HOT", "HP", "HR", "HRO", "HS",
    "HSK", "HST", "HU", "HUS", "HV", "HVL", "HW", "HWI", "HX", "HY", "HZ",
    "HÖS", "HÜN", "IGB", "IK", "IL", "ILL", "IN", "IS", "IZ", "J", "JB",
    "JE", "JEV", "JL", "JÜL", "K", "KA", "KAR", "KB", "KC", "KE", "KEH",
    "KEL", "KEM", "KF", "KG", "KH", "KI", "KIB", "KK", "KL", "KLE", "KLT",
    "KLZ", "KM", "KN", "KO", "KOZ", "KR", "KRU", "KS", "KT", "KU", "KUS",
    "KW", "KY", "KYF", "KÖN", "KÖT", "KÜN", "L", "LA", "LAN", "LAT", "LAU",
    "LB", "LBS", "LBZ", "LC", "LD", "LDK", "LDS", "LE", "LEO", "LER", "LEV",
    "LF", "LG", "LH", "LI", "LIB", "LIF", "LIN", "LIP", "LK", "LL", "LM",
    "LN", "LOH", "LOS", "LP", "LR", "LS", "LSA", "LSN", "LSZ", "LU", "LUK",
    "LWL", "LÖ", "LÖB", "LÜD", "LÜN", "M", "MA", "MAB", "MAI", "MAK", "MAL",
    "MAR", "MB", "MC", "MD", "ME", "MED", "MEG", "MEI", "MEK", "MEL", "MEP",
    "MER", "MES", "MET", "MG", "MGH", "MGN", "MH", "MHL", "MI", "MIL", "MK",
    "MKK", "ML", "MM", "MN", "MO", "MOD", "MOL", "MON", "MOS", "MQ", "MR",
    "MS", "MSP", "MST", "MT", "MTK", "MTL", "MVL", "MW", "MY", "MYK", "MZ",
    "MZG", "MÜ", "MÜB", "MÜL", "MÜN", "MÜR", "N", "NAB", "NAI", "NAU", "NB",
    "ND", "NDH", "NE", "NEA", "NEB", "NEC", "NEN", "NES", "NEU", "NEW",
    "NF", "NH", "NI", "NIB", "NK", "NL", "NM", "NMB", "NMS", "NOH", "NOL",
    "NOM", "NOR", "NP", "NR", "NRW", "NRÜ", "NT", "NU", "NVP", "NW", "NWM",
    "NY", "NZ", "NÖ", "OA", "OAL", "OB", "OBB", "OBG", "OC", "OCH", "OD",
    "OE", "OF", "OG", "OH", "OHA", "OHV", "OHZ", "OK", "OL", "OLD", "OP",
    "OPR", "OR", "OS", "OSL", "OTT", "OTW", "OVI", "OVL", "OVP", "OZ", "P",
    "PA", "PAF", "PAN", "PAR", "PB", "PCH", "PE", "PEG", "PER", "PF", "PI",
    "PIR", "PK", "PL", "PLÖ", "PM", "PN", "PR", "PRÜ", "PS", "PW", "PZ",
    "QFT", "QLB", "R", "RA", "RC", "RD", "RDG", "RE", "REG", "REH", "REI",
    "RG", "RH", "RI", "RID", "RIE", "RL", "RM", "RN", "RO", "ROD", "ROF",
    "ROH", "ROK", "ROL", "ROS", "ROT", "ROW", "RPL", "RS", "RSL", "RT",
    "RU", "RV", "RW", "RWL", "RY", "RZ", "RÜD", "RÜG", "S", "SA", "SAB",
    "SAD", "SAL", "SAN", "SAO", "SAW", "SB", "SBG", "SBK", "SC", "SCZ",
    "SDH", "SDL", "SDT", "SE", "SEB", "SEE", "SEF", "SEL", "SF", "SFA",
    "SFB", "SFT", "SG", "SGH", "SH", "SHA", "SHG", "SHK", "SHL", "SHS",
    "SI", "SIG", "SIM", "SK", "SL", "SLE", "SLF", "SLG", "SLK", "SLN",
    "SLS", "SLZ", "SLÜ", "SM", "SMÜ", "SN", "SNH", "SO", "SOB", "SOG",
    "SOK", "SOL", "SON", "SP", "SPB", "SPN", "SPR", "SR", "SRB", "SRO",
    "ST", "STA", "STB", "STD", "STE", "STH", "STL", "STO", "SU", "SUL",
    "SW", "SWA", "SWZ", "SY", "SZ", "SZB", "SÄK", "SÖM", "SÜW", "TBB", "TE",
    "TF", "TG", "TGO", "THL", "THW", "TIR", "TO", "TP", "TR", "TS", "TT",
    "TUT", "TÖL", "TÖN", "TÜ", "UE", "UEM", "UER", "UFF", "UH", "UL", "UM",
    "UN", "USI", "V", "VAI", "VB", "VEC", "VER", "VIB", "VIE", "VIT", "VK",
    "VL", "VOF", "VOH", "VR", "VS", "W", "WA", "WAF", "WAK", "WAM", "WAN",
    "WAR", "WAT", "WB", "WBS", "WD", "WDA", "WE", "WEB", "WEG", "WEI",
    "WEL", "WEM", "WEN", "WER", "WES", "WF", "WG", "WHV", "WI", "WIL",
    "WIS", "WIT", "WIZ", "WK", "WL", "WLG", "WM", "WMS", "WN", "WND", "WO",
    "WOB", "WOH", "WOL", "WOR", "WOS", "WR", "WRN", "WS", "WSF", "WST",
    "WSW", "WT", "WTL", "WTM", "WUG", "WUM", "WUN", "WUR", "WW", "WZ",
    "WZL", "WÜ", "X", "Y", "Z", "ZE", "ZEL", "ZI", "ZIG", "ZP", "ZR", "ZS",
    "ZW", "ZZ", "ÖHR", "ÜB",
})
