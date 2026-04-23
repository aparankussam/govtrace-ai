import hashlib
import json
import math
import os
import re
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional

try:
    from .models import Finding, RegulatoryReference, SafeHarborBlock
except ImportError:
    from models import Finding, RegulatoryReference, SafeHarborBlock

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# NANP-aware: area code must start with 2-9, which rules out 10-digit runs
# that begin with 0 or 1 (e.g. `0111222333` bank account) but still matches
# real US phone numbers with or without separators.
_PHONE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?[2-9]\d{2}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)")
_DOB = re.compile(
    r"\b(?:dob|date of birth|born)\s*[:\-]?\s*(?:"
    r"\d{4}-\d{1,2}-\d{1,2}|"                                    # ISO 8601 YYYY-MM-DD
    r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|"                            # US-style MM/DD/YYYY or MM-DD-YY
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\s+\d{1,2},?\s+\d{4}"
    r")\b",
    re.IGNORECASE,
)
_NAME = re.compile(
    # Label part is case-insensitive (matches `Patient:` just as well as
    # `patient:`); captured name stays strictly TitleCase so `DOB` /
    # `SALARY` / etc. do not get pulled in.
    r"\b(?:[Nn]ame|[Cc]ustomer|[Pp]atient|[Ee]mployee|[Rr]esident|[Aa]pplicant)\s*[:\-]?\s*"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"
)
_PERSON_NAME = re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b")
_STREET_ADDRESS = re.compile(
    r"\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,4}\s+"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b",
    re.IGNORECASE,
)
_CITY_STATE_ZIP = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?\b")
_INJECTION = re.compile(
    # Instruction-override verbs with scope modifiers. Trailing noun is
    # optional but constrained to injection-relevant nouns to avoid matching
    # benign "ignore previous advice"-style prose outside the corpus.
    r"(?:ignore|disregard|forget) (?:all |the |everything |every )?"
    r"(?:previous|prior|above|preceding|earlier)"
    r"(?:\s+(?:instructions?|prompts?|rules?|context|messages?|directives?))?|"
    r"override (?:all |the )?instructions|"
    # Mode / persona aliases
    r"jailbreak|dan mode|do anything now|developer mode|"
    r"act as (?:an? )?(?:unrestricted|uncensored|unfiltered|jailbroken|evil|unethical|amoral|root)|"
    # Prompt-extraction attempts. Require an adjective qualifier
    # (system|initial|original|hidden) so benign "show me the prompt to
    # approve this PO" doesn't match.
    r"reveal (?:the )?system prompt|"
    r"(?:print|repeat|show|output|expose|leak|disclose|divulge)"
    r"(?: me| us)?(?: the| your)?\s+(?:system|initial|original|hidden)"
    r"\s+(?:prompt|instructions?|messages?|rules?)|"
    r"what (?:are|were|is) your (?:original|initial|hidden|system)"
    r"\s+(?:instructions?|prompt|rules?|guidelines?)|"
    # Safety-bypass verbs and targets
    r"(?:bypass|circumvent|disable) (?:all |the )?"
    r"(?:safety|restrictions|filters|guardrails|content polic(?:y|ies)|content filters?|safeguards)|"
    r"no longer bound by|"
    # Chat-template role-impersonation tokens
    r"<\s*/?\s*system\s*>|"
    r"<\|im_(?:start|end)\|>|"
    # End-of-prompt delimiter attacks
    r"end of (?:system )?(?:prompt|instructions)|"
    # Instruction smuggling — telling the model how to classify findings.
    # Optional modifier slot (`compliance`, `policy`, `audit`, etc.) sits
    # between the quantifier and the target noun.
    r"treat (?:(?:all|any|the|these|those)\s+)?(?:[A-Za-z]+\s+)?"
    r"(?:findings?|alerts?|flags?|violations?|results?|outputs?|warnings?|issues?)"
    r"\s+as\s+safe|"
    # Output fabrication — telling the model what to claim about the input
    r"say (?:the|this) (?:note|text|content|document|payload|input|output)"
    r"\s+(?:was|is)\s+(?:fully |already |completely )?redacted|"
    # Meta-framing as a test to disarm safety
    r"test of (?:model |safety |content |policy )?"
    r"(?:override|bypass|injection|jailbreak)(?:\s+(?:behavior|behaviour|test))?",
    re.IGNORECASE,
)
_OVERCLAIM = re.compile(
    r"\b(?:guaranteed|proven fact|always|never|no doubt|unquestionably|certainly compliant|risk free)\b",
    re.IGNORECASE,
)
_UNVERIFIED = re.compile(
    r"\b(?:tbd|to be confirmed|not yet verified|unverified|awaiting confirmation|"
    r"pending documentation|documentation unavailable|evidence pending|source not confirmed|"
    r"preliminary only|based on limited data)\b",
    re.IGNORECASE,
)
_EXTERNAL_SHARING = re.compile(
    r"\b(?:share(?:d)? with external partners|send to vendors?|distribute broadly|share with all staff|"
    r"training purposes outside controlled use|external sharing|share externally)\b",
    re.IGNORECASE,
)
_CREDIT_CARD = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
_BANK_ACCOUNT = re.compile(
    r"\b(?:"
    r"account\s+number|acct(?:ount)?|"
    r"routing(?:\s+(?:number|no\.?|#))?|"
    r"(?:direct\s+deposit|deposit|checking|savings)\s+account"
    r")\s*[:#-]?\s*\d{6,17}\b",
    re.IGNORECASE,
)
_HEALTH_DATA = re.compile(
    r"\b(?:patient|diagnosis|diagnosed|treatment|medication|prescription|mrn|medical record|phi|hipaa)\b",
    re.IGNORECASE,
)
# Clinical narrative patterns — catch PHI that keyword matching misses.
# Age phrasing: `54-year-old`, `72 yo`, `6 y/o`, `82 years old`.
_CLINICAL_AGE = re.compile(
    r"\b\d{1,3}\s*[-]?\s*(?:year[s]?[-\s]?old|y/?o|yo)\b",
    re.IGNORECASE,
)
# Diagnosis / clinical-action verbs that routinely prefix PHI in provider notes.
_CLINICAL_DIAG_VERB = re.compile(
    r"\b(?:diagnosed\s+with|presented\s+with|admitted\s+for|treated\s+for|status\s+post|s/p)\b",
    re.IGNORECASE,
)

# ----- HIPAA Safe Harbor detection patterns ----------------------------------
# Used exclusively by compute_safe_harbor() to map each of the 18 identifiers
# in 45 CFR § 164.514(b)(2) to a present/absent status on both the original
# input and the redacted preview. These do not emit findings on their own;
# they are complementary to the existing detection/redaction patterns.
_SH_CLINICAL_DATE = re.compile(
    r"\b(?:admission|admitted|discharge|discharged|death|deceased|died|"
    r"visit|visited|seen|service|procedure|surgery|appointment)"
    # Optional modifier (" date" / " on" / " dated") must be whitespace-attached,
    # but the separator to the date value allows colon/dash adjacent to the
    # keyword (e.g. "Discharged: 03/16/26"). At least one of [\s:-] is required.
    r"(?:\s+(?:date|on|dated))?[\s:\-]+"
    r"(\d{4}-\d{1,2}-\d{1,2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|"
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\s+\d{1,2},?\s+\d{4})\b",
    re.IGNORECASE,
)
_SH_FAX = re.compile(
    r"\bfax\s*(?:number|no\.?|#)?\s*[:\-]?\s*"
    r"(?:\+?1[-.\s]?)?(?:\(?[2-9]\d{2}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b",
    re.IGNORECASE,
)
# Label-to-value separators use [ \t] instead of \s so the pattern can't
# cross a newline and capture the next line's first word as the value.
# Matters when `compute_safe_harbor` strips placeholders from the redacted
# preview and leaves `Vehicle VIN:  \nEmergency contact: …` behind — a
# newline-permissive \s would roll "Emergency" into the VIN match.
_SH_LICENSE_CERT = re.compile(
    r"\b(?:license|licence|certificate|cert|npi|dea|dl|driver'?s?\s+license)"
    r"[ \t]*(?:number|no\.?|#)?[ \t]*[:\-][ \t]*[A-Z0-9][-A-Z0-9]{4,}\b",
    re.IGNORECASE,
)
_SH_VEHICLE = re.compile(
    r"\b(?:vin|license\s+plate|plate\s+(?:number|no\.?|#))"
    r"[ \t]*[:\-]?[ \t]*[A-Z0-9][-A-Z0-9]{3,}\b",
    re.IGNORECASE,
)
_SH_DEVICE = re.compile(
    r"\b(?:device\s+(?:id|identifier|serial)|serial\s+(?:number|no\.?)|imei|iccid|mac\s+address)"
    r"[ \t]*[:\-]?[ \t]*[A-Z0-9][-:A-Z0-9]{4,}\b",
    re.IGNORECASE,
)
_SH_URL = re.compile(r"\b(?:https?|hxxps?|h[*x]tps?)://[^\s<>\"']+", re.IGNORECASE)
_SH_ANY_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Redaction placeholders emitted by `build_redacted_preview` — e.g.
# `[address redacted]`, `[name redacted]`. Used by `compute_safe_harbor` to
# strip placeholders before detectors run on the preview, so label-anchored
# detectors don't mistake a correctly-masked `Home address: [address redacted]`
# for a remaining address.
_SH_PLACEHOLDER = re.compile(r"\[[a-z0-9 ]+\s+redacted\]", re.IGNORECASE)

# ----- SEC-02: Security / Credential Exposure --------------------------------
# Strict, high-signal patterns first (high severity, high confidence).
# Vendor-specific prefixes win over generic heuristics to avoid duplicate hits.
_CRED_VENDOR_KEY = re.compile(
    r"\b("
    r"sk_live_[A-Za-z0-9]{10,}|sk_test_[A-Za-z0-9]{10,}|"        # Stripe
    r"rk_live_[A-Za-z0-9]{10,}|"                                  # Stripe restricted
    r"xox[abprs]-[A-Za-z0-9-]{10,}|"                              # Slack
    r"AKIA[0-9A-Z]{16}|"                                          # AWS access key
    r"ASIA[0-9A-Z]{16}|"                                          # AWS temp
    r"AIza[0-9A-Za-z_\-]{35}|"                                    # Google API
    r"ya29\.[0-9A-Za-z_\-]{20,}|"                                 # Google OAuth
    r"ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|ghu_[A-Za-z0-9]{30,}|ghs_[A-Za-z0-9]{30,}|"  # GitHub
    r"glpat-[A-Za-z0-9_\-]{10,}"                                  # GitLab
    r")\b"
)
_CRED_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")
_CRED_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")
_CRED_PRIVATE_KEY_END = re.compile(r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")
# Full-block pattern for redaction only: masks the header, the base64 body,
# AND the end marker as a single unit so the preview never leaks key material.
_REDACT_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    r"[\s\S]*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
)
_CRED_KEY_ASSIGNMENT = re.compile(
    # Capture class includes `/`, `+`, `=` so AWS secrets and base64-style
    # values (e.g. `wJalrXUtnFEMI/K7MDENG/bPx...`) are captured as one unit
    # and the whole value gets replaced by the redaction placeholder.
    r"\b(?:api[\s_\-]?key|secret[\s_\-]?key|access[\s_\-]?token|bearer|auth[\s_\-]?token)\s*[:=]\s*([A-Za-z0-9_\-\./+=]{12,})",
    re.IGNORECASE,
)
_CRED_PASSWORD = re.compile(
    # Allows `password is VALUE`, `password: VALUE`, `password=VALUE`, AND the
    # doubled form `password is: VALUE`. Colon is excluded from the captured
    # value so a `:` right after `is` does not itself become the "value".
    r"\b(?:password|passwd|pwd)\s*(?:is|=|:)\s*:?\s*([^\s,;:]{4,})",
    re.IGNORECASE,
)
_CRED_MFA_CODE = re.compile(
    # `code[s]?` so plural phrasing (`backup codes:`) matches, and the
    # capture absorbs a comma-separated list so all codes get masked as
    # a single unit in the redaction pass.
    r"\b(?:mfa|2fa|totp|backup|recovery)\s+(?:backup\s+)?code[s]?\s*(?:is|=|:)?\s*((?:\d{4,})(?:\s*,\s*\d{4,})*)",
    re.IGNORECASE,
)
# Infrastructure exposure — medium severity. Only emit when an internal IP/CIDR
# coincides with firewall/port language in the same payload to avoid noise on
# innocuous references.
_INFRA_INTERNAL_IP = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?|"
    r"192\.168\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?"
    r")\b"
)
_INFRA_FIREWALL_HINT = re.compile(
    r"\b(?:firewall rule|acl\b|allow\s+\d+\.\d+\.\d+\.\d+|open port|port\s+\d{2,5})",
    re.IGNORECASE,
)
# Internal hostnames under private namespaces (`.internal`, `.corp`, etc.).
# Matches `api.internal.local`, `sso-prod.internal.local`, `srv.corp.example`.
_INFRA_INTERNAL_HOST = re.compile(
    r"\b(?:[a-z0-9][-a-z0-9]*\.)+(?:internal|corp|intranet|lan|intra)(?:\.[a-z]+)*\b",
    re.IGNORECASE,
)

# ----- LEG-01: Legal privilege / work-product / litigation hold --------------
# Explicit privilege markers — the presence of these phrases is itself the
# signal that the enclosing payload is protected and must not leave the tenant.
_LEG_PRIVILEGE_MARKER = re.compile(
    r"\b(?:"
    r"attorney[-\s]client\s+(?:privilege[ds]?|communications?)|"
    r"(?:attorney\s+)?work[-\s]product(?:\s+doctrine)?|"
    r"prepared\s+in\s+anticipation\s+of\s+litigation|"
    r"privileged\s+(?:and|&)\s+confidential|"
    r"privileged\s+communications?|"
    r"litigation\s+strategy|"
    r"(?:subject\s+to\s+(?:a\s+)?)?litigation\s+hold|"
    r"legal\s+hold\s+notice"
    r")\b",
    re.IGNORECASE,
)
# Softer legal signals — advice language and settlement-confidentiality phrasing
# that does not explicitly say "privileged". Confidence is lower than the strict
# markers above; severity is medium rather than high. These still contribute
# to LEGAL blocking-class because the surrounding content is protected even when
# the speaker did not label it with the canonical terminology.
_LEG_SOFT_MARKER = re.compile(
    r"\b(?:"
    r"(?:attorney|counsel|legal\s+counsel|outside\s+counsel|in[-\s]house\s+counsel)\s+(?:advised|advises|recommended|counseled|opined)|"
    r"(?:under\s+|pursuant\s+to\s+)?(?:attorney[-\s]client|legal)\s+advice|"
    r"settlement\s+(?:talks|negotiations?|discussions?|communications?)\s+(?:are|remain|shall\s+remain|must\s+remain|to\s+remain)\s+confidential|"
    r"in\s+consultation\s+with\s+(?:counsel|our\s+(?:attorneys?|lawyers?))"
    r")\b",
    re.IGNORECASE,
)
# Citations to FRE 408/501/502 and FRCP 26(b)(3). Presence typically means the
# surrounding text is settlement-protected or attorney work product.
# NB: alternatives that end in `)` carry their own anchors — an outer `\b`
# would fail after `)` (two non-word chars = no boundary) and force a
# short-match to `...26`, leaving `(b)(3)` unredacted in the preview.
_LEG_RULE_CITATION = re.compile(
    r"(?:"
    r"\bFRE\s*(?:408|501|502)\b|"
    r"\bFederal\s+Rule[s]?\s+of\s+Evidence\s+(?:408|501|502)\b|"
    r"\bFRCP\s*26(?:\(b\)\(3\))?(?!\d)|"
    r"\bFed\.\s*R\.\s*Civ\.\s*P\.\s*26(?:\(b\)\(3\))?(?!\d)|"
    r"\bRule\s+26\(b\)\(3\)"
    r")",
    re.IGNORECASE,
)

# ----- PHI-01 extensions: medications, ICD-10 codes, workflow IDs ------------
# Coverage expansion for HIPAA-adjacent signals that bare patient/treatment
# keywords miss. These produce PHI-01 findings AND are masked in the preview
# so safe_after_redaction cannot return true on a narrative that still names
# specific drugs, diagnoses, or patient-linked workflow identifiers.
#
# Medication list is intentionally narrow — common generics on the 2024 WHO
# Model List of Essential Medicines and the top-200 US dispensed generics.
# Adding arbitrary brand names would require a formulary feed; the suffix
# heuristic below covers the long tail for common drug-class suffixes.
_PHI_MEDICATION_NAME = re.compile(
    r"\b(?:"
    r"lisinopril|enalapril|ramipril|benazepril|captopril|"
    r"losartan|valsartan|irbesartan|olmesartan|telmisartan|"
    r"atorvastatin|rosuvastatin|simvastatin|pravastatin|lovastatin|pitavastatin|"
    r"metformin|glipizide|glyburide|glimepiride|pioglitazone|sitagliptin|empagliflozin|"
    r"atenolol|metoprolol|carvedilol|propranolol|bisoprolol|nebivolol|"
    r"amlodipine|nifedipine|diltiazem|verapamil|felodipine|"
    r"hydrochlorothiazide|furosemide|spironolactone|chlorthalidone|bumetanide|"
    r"omeprazole|pantoprazole|esomeprazole|lansoprazole|rabeprazole|"
    r"sertraline|fluoxetine|escitalopram|paroxetine|citalopram|duloxetine|venlafaxine|bupropion|"
    r"amoxicillin|azithromycin|ciprofloxacin|levofloxacin|doxycycline|cephalexin|"
    r"warfarin|apixaban|rivaroxaban|dabigatran|clopidogrel|ticagrelor|"
    r"levothyroxine|liothyronine|methimazole|"
    r"gabapentin|pregabalin|tramadol|oxycodone|hydrocodone|morphine|fentanyl|"
    r"insulin(?:\s+(?:glargine|aspart|lispro|detemir|regular))?|"
    r"ondansetron|metoclopramide|promethazine|"
    r"prednisone|methylprednisolone|dexamethasone|"
    r"albuterol|budesonide|montelukast|tiotropium|"
    r"methotrexate|hydroxychloroquine|adalimumab|etanercept"
    r")\b",
    re.IGNORECASE,
)
# ICD-10 code list — require at least one labeled or 2+ codes in sequence so
# that bare strings like "A23" in unrelated text do not false-positive.
# Letter set excludes U (reserved for emergency use / research) and a few
# others the WHO has not allocated, but we keep it permissive since payers
# sometimes emit non-standard codes.
_PHI_ICD10_CODES = re.compile(
    r"(?:"
    # Labeled: "Diagnosis codes: I10, E11.9" / "ICD-10: N18.31"
    r"\b(?:diagnos[ie]s\s+codes?|icd[-\s]?10(?:\s+codes?)?|dx\s+codes?)\s*:?\s*"
    r"[A-TV-Z]\d{2}(?:\.\d{1,4})?(?:\s*[,;]\s*[A-TV-Z]\d{2}(?:\.\d{1,4})?)*"
    r"|"
    # Unlabeled sequence: at least two codes separated by comma/space
    r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?(?:\s*,\s*[A-TV-Z]\d{2}(?:\.\d{1,4})?){1,}\b"
    r")",
    re.IGNORECASE,
)
# Healthcare workflow identifiers. Many are alphanumeric (CLM-77882211,
# AUTH-882194, ENC-2026-0412-7781, PA-552190, GRP-4455) which the generic
# _REDACT_INSURANCE_ID pattern (digits only) does not cover.
_PHI_HEALTHCARE_ID = re.compile(
    r"\b(?:"
    r"claim\s+(?:number|no\.?|id|#)|"
    r"encounter\s+(?:id|number|no\.?|#)|"
    r"(?:prior\s+)?authoriz(?:ation|ed)\s+(?:reference|id|number|no\.?|#)|"
    r"auth\s*(?:ref(?:erence)?|#)|"
    r"policy\s+group|group\s+id|"
    r"payer\s+id|plan\s+id|plan\s+number|"
    r"member\s+(?:id|number)|subscriber\s+(?:id|number)|"
    r"medical\s+record\s+(?:number|no\.?)|mrn|"
    r"referral\s+(?:id|number|#)"
    r")\s*[:#\-]?\s*([A-Z]{1,5}[-_][A-Za-z0-9\-_]{3,}|\d[\d\-]{3,}|[A-Z0-9]{4,})",
    re.IGNORECASE,
)

# ----- COM-01: Commercial-confidential / trade-secret signals ----------------
# Deliberately phrase-anchored (not single-word) so generic business vocabulary
# ("revenue", "customers", "pricing") does not trigger. Each alternative should
# be strong enough on its own to merit a commercial-confidential finding.
_COM_COMMERCIAL_TERMS = re.compile(
    r"\b(?:"
    r"customer\s+list|client\s+list|account\s+list|subscriber\s+list|"
    r"pricing\s+(?:strategy|tiers?|model|schedule|playbook)|"
    r"contract\s+rates?|negotiated\s+rates?|discount\s+matrix|price\s+floor|price\s+ceiling|"
    r"margin\s+(?:data|analysis|report|breakdown)|gross\s+margin\s+by\s+\w+|"
    r"revenue\s+(?:forecast|projection[s]?|pipeline)|"
    r"quarterly\s+churn|churn\s+rate\s+forecast|renewal\s+forecast|"
    r"(?:executive|exec|ceo|cfo|c-?suite)\s+(?:comp|compensation|pay|bonus)|"
    r"m&a\s+(?:targets?|pipeline)|acquisition\s+targets?|divestiture\s+targets?|"
    r"board\s+(?:deck|pack|presentation|materials?|memo)|"
    r"trade\s+secrets?|"
    r"go[-\s]to[-\s]market\s+playbook|sales\s+playbook"
    r")\b",
    re.IGNORECASE,
)

# ----- Redaction-only patterns (do not change detection coverage) ------------
# These are used exclusively by build_redacted_preview so the masked output
# stays aligned with what the engine can detect, without altering finding logic.
_REDACT_MRN = re.compile(
    r"\b(?:medical\s+record\s+(?:number|no\.?)|mrn)\s*[:#-]?\s*(\d[\d\-]{3,})\b",
    re.IGNORECASE,
)
# Accepts alphanumeric IDs (`CIG-77492013`, `GRP-11882`) in addition to the
# legacy digits-only shape. Separator is REQUIRED (colon/hash/dash) so label
# fragments like "Insurance policy number " can't have "number" captured as
# the value when the real ID has been redacted to `[id redacted]`. The value
# must also contain at least one digit, so pure-letter tokens like "NUMBER"
# cannot match.
_REDACT_INSURANCE_ID = re.compile(
    r"\b(?:insurance\s+(?:policy|id)(?:\s+(?:number|no\.?|#))?|"
    r"policy\s+(?:number|id|#)|member\s+(?:id|number)|"
    r"group\s+(?:number|id|#)|subscriber\s+(?:id|number)|"
    r"plan\s+(?:id|number))\s*[:#\-]\s*"
    r"((?=[A-Z0-9_\-]{4,})[A-Z0-9][A-Z0-9_\-]*\d[A-Z0-9_\-]*)\b",
    re.IGNORECASE,
)
# Account-style IDs: `Acct#: AC-00918273`, `Account number: 1234567`.
# Negative lookbehind prevents matching when "account" is the tail of a
# different phrase — `Name on account: Elena M.` must NOT be parsed as
# `account: Elena` (which would mask "Elena" as an ID). The lookbehind
# rejects preposition-preceded uses; `_REDACT_NAME_LABEL`'s
# `name\s+on\s+account` alternative is the correct matcher for those cases.
_REDACT_ACCOUNT_LABEL = re.compile(
    r"(?<!\bon\s)(?<!\bin\s)(?<!\bof\s)(?<!\bvia\s)"
    r"\b(?:acct|account)\s*(?:number|no\.?|#)?\s*[:#\-]\s*"
    r"([A-Z0-9][A-Z0-9_\-]{3,})\b",
    re.IGNORECASE,
)
# Government-issued identifiers: driver license, passport (incl. scan refs),
# and partial SSN ("SSN last 4: 7812"). Each has its own entry so the
# single-capture-group contract with `_mask_group1` holds.
_REDACT_DRIVER_LICENSE = re.compile(
    r"\b(?:driver'?s?\s+license|driver\s+licence|dl)"
    r"\s*(?:number|no\.?|#)?\s*[:#\-]?\s*"
    r"([A-Z0-9][A-Z0-9_\-]{3,})\b",
    re.IGNORECASE,
)
_REDACT_PASSPORT = re.compile(
    r"\bpassport(?:\s+(?:scan\s+ref|number|no\.?|#))?"
    r"\s*[:#\-]?\s*([A-Z0-9][A-Z0-9_\-]{3,})\b",
    re.IGNORECASE,
)
_REDACT_SSN_PARTIAL = re.compile(
    r"\bssn\s+last\s*\-?\s*4\s*[:#\-]?\s*(\d{4})\b",
    re.IGNORECASE,
)
# HIPAA SH #12: vehicle identifiers (VINs / plates). Separator mandatory and
# value requires ≥1 digit so plain words ("NUMBER") can't match.
_REDACT_VEHICLE_ID = re.compile(
    r"\b(?:vehicle\s+vin|vin|license\s+plate|plate\s+(?:number|no\.?|#))"
    r"\s*[:#\-]\s*"
    r"((?=[A-Z0-9_\-]{4,})[A-Z0-9][A-Z0-9_\-]*\d[A-Z0-9_\-]*)\b",
    re.IGNORECASE,
)
# HIPAA SH #13: device identifiers / serial numbers. Label set intentionally
# broader than `_SH_DEVICE` so real-world medical phrasing is covered
# (pacemaker, infusion pump, stent lot, equipment serial, implant).
_REDACT_DEVICE_ID = re.compile(
    r"\b(?:device\s+(?:id|identifier|serial)|"
    r"serial\s+(?:number|no\.?|#)|"
    r"imei|iccid|mac\s+address|"
    r"pacemaker(?:\s+(?:id|serial))?|"
    r"infusion\s+pump(?:\s+(?:serial|asset))?|"
    r"stent\s+(?:lot|serial|id)|"
    r"equipment\s+(?:serial|tag|id|asset)|"
    r"implant(?:\s+(?:id|serial|card))?|"
    # Free-form medical equipment label forms (wheelchair, O2 concentrator,
    # nebulizer, oxygen tank, …) + tag/asset/serial value. Catches the Input #3
    # device cluster without enumerating every device type.
    r"(?:wheelchair|nebulizer|oxygen\s+(?:tank|concentrator)|o2\s+concentrator|"
    r"glucose\s+meter|cpap|bipap|ventilator|iv\s+pump)"
    r"(?:\s+(?:serial|tag|id|asset))?|"
    # Ambulance run sheet / transport record IDs.
    r"ambulance\s+run\s+sheet|transport\s+record)"
    r"\s*[:#\-]\s*"
    r"((?=[A-Z0-9_\-]{4,})[A-Z0-9][A-Z0-9_\-]*\d[A-Z0-9_\-]*)\b",
    re.IGNORECASE,
)
# HIPAA SH #14: web URLs. Catches plain http(s) and common defanged forms
# (`hxxps://`, `[.]` for dots). Whole match is replaced; no capture group.
_REDACT_URL = re.compile(
    r"\b(?:https?|hxxps?|h[*x]tps?)://[^\s<>\"']+",
    re.IGNORECASE,
)
# Form / document identifiers (intake forms, consent forms, chart scans).
# Separate from _PHI_HEALTHCARE_ID because "form id" is not itself a
# healthcare-workflow ID — it's a document-tracking reference that still
# correlates to an encounter.
_REDACT_FORM_ID = re.compile(
    r"\b(?:scanned\s+(?:intake|consent|chart)\s+form\s+id|"
    r"(?:intake|consent|chart|registration)\s+form\s+id|"
    r"form\s+(?:id|number|no\.?|#))"
    r"\s*[:#\-]\s*"
    r"((?=[A-Z0-9_\-]{4,})[A-Z0-9][A-Z0-9_\-]*\d[A-Z0-9_\-]*)\b",
    re.IGNORECASE,
)
# Cryptographic hashes / digests (MD5=32, SHA1=40, SHA256=64). Label-anchored
# so we don't mask arbitrary hex strings elsewhere. Captures the hex tail only.
_REDACT_HASH_VALUE = re.compile(
    r"\b(?:(?:consent|document|record|file|form|intake|chart|digest|content)"
    r"\s+hash|hash|digest|sha\-?(?:1|256|512)|md5)"
    r"\s*[:#\-]\s*"
    r"([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b",
    re.IGNORECASE,
)
# Payment card expiry dates. `Exp: MM/YY` or `Expiry: MM/YYYY` shapes — PCI
# exposure class, not catastrophic alone but should not appear next to a
# partial PAN. Restricted to 2-digit month so random dates don't match.
_REDACT_CARD_EXPIRY = re.compile(
    r"\b(?:exp(?:ir(?:es|y|ation))?|expires|valid\s+thru)"
    r"\.?\s*[:#\-]?\s*"
    r"((?:0[1-9]|1[0-2])[/\-](?:\d{2}|\d{4}))\b",
    re.IGNORECASE,
)
# Service-account handles: `svc-foo-bar`, `srv-intake`, `service account:
# svc-…`. Label-anchored so random hyphenated tokens don't match. Masks the
# handle value only.
_REDACT_SERVICE_ACCOUNT = re.compile(
    r"\b(?:shared\s+)?(?:service|svc|system)\s+account"
    r"\s*[:#\-]\s*"
    r"((?:svc|srv|sys|sa)[-_][A-Za-z0-9_\-]{2,})\b",
    re.IGNORECASE,
)
# Vendor / business-associate labels: masks the full org-name value after
# `Contracted vendor:` / `Business associate:` etc. Bounded to 120 chars and
# terminates at newline or 2+ whitespace (same shape as _REDACT_ADDRESS_LABEL)
# so flat-text inputs do not over-mask. Capture must start with \S so a
# bare label with no value does not match.
_REDACT_VENDOR_LABEL = re.compile(
    r"\b(?:contracted\s+vendor|vendor\s+name|business\s+associate|"
    r"baa\s+vendor|subcontractor|supplier|partner\s+org)\s*[:#\-]\s*"
    r"(\S(?:.{0,119}?))(?=\n|\s{2,}|$)",
    re.IGNORECASE,
)
# Bare facility / provider-org names. TitleCase head (1-4 tokens) followed by
# a healthcare-org suffix token. Catches outside-records bullet lists like
# `- Mercy West Cardiology` that have no label in front. Deliberately narrow
# (suffix list is the anchor) so everyday capitalised phrases don't match.
_REDACT_FACILITY_NAME = re.compile(
    r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}\s+"
    r"(?:Cardiology|Nephrology|Oncology|Radiology|Pathology|Pharmacy|"
    r"Imaging\s+Center|Medical\s+(?:Center|Group|Associates|Practice)|"
    r"Hospital|Clinic|Healthcare|Health\s+(?:Services|System|Center)|"
    r"Laboratory|Urgent\s+Care|Surgical\s+Center|Rehabilitation\s+Center)\b"
)
_REDACT_ROUTING_NUM = re.compile(
    r"\brouting\s*(?:number|no\.?|#)?\s*[:#-]?\s*(\d{6,12})\b",
    re.IGNORECASE,
)
_REDACT_DD_ACCOUNT = re.compile(
    r"\b(?:direct deposit account|deposit account|checking account|savings account)\s*[:#-]?\s*(\d{6,17})\b",
    re.IGNORECASE,
)
_REDACT_CVV = re.compile(r"\bcvv\s*[:#-]?\s*(\d{3,4})\b", re.IGNORECASE)
# Redaction-only DOB: captures the value so the `DOB:` label is preserved in
# the preview (`Guarantor DOB: [date redacted]`). Detection-side `_DOB` stays
# unchanged because DATE OF BIRTH / NAME + DOB findings depend on its shape.
_REDACT_DOB_VALUE = re.compile(
    r"\b(?:dob|date of birth|born)\s*[:\-]?\s*("
    r"\d{4}-\d{1,2}-\d{1,2}|"
    r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|"
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\s+\d{1,2},?\s+\d{4}"
    r")\b",
    re.IGNORECASE,
)
# Name-label pattern for redaction only. The label part accepts either case,
# but the captured name group stays strictly TitleCase — without IGNORECASE,
# so `[A-Z][a-z]+` does not accidentally match tokens like "DOB".
_REDACT_NAME_LABEL = re.compile(
    r"\b(?:[Nn]ame|[Nn]ame\s+on\s+account|[Cc]ustomer|[Pp]atient|[Pp]t|"
    r"[Ee]mployee|[Rr]esident|[Aa]pplicant|"
    r"[Aa]ttending|[Nn]urse|[Pp]rovider|[Pp]hysician|[Dd]octor|"
    r"[Cc]ardholder(?:\s+name)?|[Ee]mergency\s+contact|[Gg]uarantor|"
    # Workforce role labels (revenue cycle, care management, ancillary).
    # Label-anchored so the TitleCase name after the colon is masked without
    # touching legitimate uses of these role words elsewhere in the text.
    r"[Rr]evenue\s+cycle\s+specialist|[Cc]ase\s+manager|[Ss]ocial\s+worker|"
    r"[Bb]illing\s+specialist|[Ss]cheduler|[Cc]linician|[Tt]herapist|"
    r"[Dd]ietitian|[Cc]are\s+coordinator|[Hh]ealth\s+coach)\s*[:\-]\s*"
    # Accept TitleCase tokens, single-letter initials (`M.`), and common
    # honorifics (`Dr.`) in any position. 1-4 tokens so "Elena M." and
    # "Dr. Priya Shah" both match without over-capturing trailing suffixes
    # like ", RN" (the comma terminates the capture). Inter-token separator
    # is horizontal whitespace only ([ \t]+), so the capture never crosses a
    # newline into the next label line (e.g. `Attending: Dr. Priya Shah\nNurse:`
    # must not roll "Nurse" into the name group).
    r"((?:Dr\.|Mr\.|Ms\.|Mrs\.|[A-Z][a-z]+|[A-Z]\.)"
    r"(?:[ \t]+(?:Dr\.|Mr\.|Ms\.|Mrs\.|[A-Z][a-z]+|[A-Z]\.)){0,3})"
)
# Broader street-suffix list for redaction (Terrace/Plaza/Circle/etc. missing
# from the detection regex). Redaction-only, does not affect findings.
_REDACT_STREET = re.compile(
    r"\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,4}\s+"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|"
    r"Place|Pl|Terrace|Ter|Plaza|Circle|Cir|Parkway|Pkwy|Highway|Hwy)\b",
    re.IGNORECASE,
)
# `Address: …` label catch — masks the value after an explicit address label.
# Terminates at newline, end-of-string, OR two-or-more whitespace characters
# (which is how PDF text extractors separate what used to be separate lines),
# and is bounded to 120 chars so flat-text inputs cannot over-mask the rest
# of the payload.
_REDACT_ADDRESS_LABEL = re.compile(
    r"\b(?:address|mailing\s+address|street\s+address|home\s+address)\s*[:#-]\s*"
    # Capture must start with a non-whitespace character so bare
    # `Home address:  ` (no value) does not match. Prevents the SH geo
    # detector from false-positiving on placeholder-stripped previews.
    r"(\S(?:.{0,119}?))(?=\n|\s{2,}|$)",
    re.IGNORECASE,
)
# Clinical/PHI value labels — mask the value after Diagnosis / Treatment Date /
# Medication / Prescription / Procedure / Lab Result. Same bounded terminator
# as _REDACT_ADDRESS_LABEL so flat-text (PDF) inputs don't over-mask.
_REDACT_CLINICAL_LABEL = re.compile(
    r"\b(?:diagnosis|diagnosed\s+with|treatment(?:\s+date)?|medication|prescription|procedure|lab\s+result)\s*[:#-]\s*"
    r"(.{1,120}?)(?=\n|\s{2,}|$)",
    re.IGNORECASE,
)
# Internal network addresses (RFC1918) — mirrors _INFRA_INTERNAL_IP.
_REDACT_INTERNAL_IP = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?|"
    r"192\.168\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?"
    r")\b"
)
# Firewall rule / port content: `allow 10.1.2.3`, `open port 22`, `port 443`.
_REDACT_FIREWALL_RULE = re.compile(
    r"\b(?:allow|deny|open\s+port|port)\s+(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|\d{2,5})\b",
    re.IGNORECASE,
)
# Bare `City, ST` without trailing ZIP — constrained to real US state codes so
# this does not fire on arbitrary two-letter capital pairs.
_REDACT_CITY_STATE_BARE = re.compile(
    r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3},\s*"
    r"(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|"
    r"MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC|PR)"
    r"\b(?!\s+\d{5})"
)

INPUT_LIMIT = 10_000

# Per-finding raw-evidence retention gate. Default OFF — `example` is always
# masked before it is persisted to the DoCR or rendered in the UI, so the audit
# artifact itself cannot become a copy of the sensitive span it flagged. When
# enabled (e.g. a dev environment that needs full fidelity for triage), the raw
# matched span is additionally retained in `example_raw`. Mirrors the pattern
# of GOVTRACE_STORE_RAW_INPUT.
STORE_RAW_EVIDENCE = os.getenv("GOVTRACE_STORE_RAW_EVIDENCE", "false").strip().lower() == "true"

PROFILE_ALIASES = {
    "general": "General",
    "public sector": "Public Sector",
    "public_sector": "Public Sector",
    "healthcare": "Healthcare",
    "finance": "Finance",
}

REASON_LABELS = {
    "PII": "PII detected",
    "FINANCIAL": "Financial data detected",
    "HEALTH": "Health data detected",
    "EXTERNAL_SHARING": "Unsafe external sharing",
    "PROMPT_INJECTION": "Prompt injection attempt",
    "UNSUPPORTED_CLAIM": "Unsupported claim",
    "INCOMPLETE_EVIDENCE": "Incomplete or unverified information",
    "CREDENTIAL": "Credential or secret exposure",
    "INFRA_CONFIG": "Internal infrastructure exposure",
    "LEGAL": "Legal privilege or work-product material",
    "COMMERCIAL": "Commercial-confidential or trade-secret material",
    "INPUT_TRUNCATION": "Input exceeded processing limit",
}

RULE_LABELS = {
    "PHI-01": "Protected health information exposure",
    "PII-01": "Personally identifiable information exposure",
    "PII-02": "Contact information detected",
    "PII-03": "Identity record exposure",
    "FIN-02": "Financial account disclosure",
    "SEC-01": "Prompt injection or instruction override attempt",
    "SEC-02": "Credential, secret, or internal infrastructure exposure",
    "LEG-01": "Attorney-client privilege or attorney work-product exposure",
    "COM-01": "Trade secret or commercial-confidential business material",
    "GEN-03": "Unsafe external sharing",
    "GEN-04": "Unsupported claim",
    "GEN-05": "Incomplete or unverified support",
    "GEN-TRUNCATED": "Input truncated beyond policy engine limit",
}

# Regulatory citation registry — keyed by rule_id.
# Each entry maps to one or more real regulatory frameworks.
# This is the foundation for the configurable rule engine (rules are
# currently hardcoded but this registry is the extraction point).
REGULATORY_CITATIONS: dict[str, list[dict[str, str]]] = {
    "PII-01": [
        {
            "citation": "GDPR Art. 4(1) — Definition of personal data",
            "body": "EU GDPR",
            "url": "https://gdpr-info.eu/art-4-gdpr/",
        },
        {
            "citation": "CCPA §1798.140(o) — Definition of personal information",
            "body": "California CCPA",
            "url": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.140",
        },
    ],
    "PII-02": [
        {
            "citation": "GDPR Art. 4(1) — Definition of personal data",
            "body": "EU GDPR",
            "url": "https://gdpr-info.eu/art-4-gdpr/",
        },
        {
            "citation": "CCPA §1798.140(o) — Definition of personal information",
            "body": "California CCPA",
            "url": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.140",
        },
    ],
    "PII-03": [
        {
            "citation": "GDPR Art. 9 — Processing of special categories of personal data",
            "body": "EU GDPR",
            "url": "https://gdpr-info.eu/art-9-gdpr/",
        },
        {
            "citation": "CCPA §1798.140(o) — Definition of personal information",
            "body": "California CCPA",
            "url": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.140",
        },
        {
            "citation": "Privacy Act of 1974, 5 U.S.C. §552a — Records maintained on individuals",
            "body": "US Federal",
            "url": "https://www.govinfo.gov/content/pkg/USCODE-2010-title5/pdf/USCODE-2010-title5-partI-chap5-subchapII-sec552a.pdf",
        },
    ],
    "PHI-01": [
        {
            "citation": "HIPAA §164.514 — De-identification of protected health information",
            "body": "HHS / HIPAA Privacy Rule",
            "url": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.514",
        },
        {
            "citation": "HIPAA §164.502 — Uses and disclosures of protected health information",
            "body": "HHS / HIPAA Privacy Rule",
            "url": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.502",
        },
        {
            "citation": "HITECH Act §13402 — Notification in the case of breach",
            "body": "HHS / HITECH",
            "url": "https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html",
        },
    ],
    "FIN-02": [
        {
            "citation": "PCI DSS v4.0 Requirement 3 — Protect stored account data",
            "body": "PCI Security Standards Council",
            "url": "https://www.pcisecuritystandards.org/document_library/",
        },
        {
            "citation": "GLBA §6802 — Obligations regarding disclosure of personal information",
            "body": "US Federal / Gramm-Leach-Bliley Act",
            "url": "https://www.govinfo.gov/content/pkg/USCODE-2018-title15/pdf/USCODE-2018-title15-chap94-subchapI-sec6802.pdf",
        },
        {
            "citation": "CCPA §1798.140(o) — Definition of personal information",
            "body": "California CCPA",
            "url": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.140",
        },
    ],
    "SEC-01": [
        {
            "citation": "NIST AI RMF — GOVERN 1.1 (AI risk policies and procedures)",
            "body": "NIST AI Risk Management Framework",
            "url": "https://airc.nist.gov/Docs/1",
        },
        {
            "citation": "OWASP LLM Top 10 — LLM01: Prompt Injection",
            "body": "OWASP",
            "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        },
        {
            "citation": "EU AI Act Art. 9 — Risk management system",
            "body": "EU AI Act",
            "url": "https://artificialintelligenceact.eu/article/9/",
        },
    ],
    "SEC-02": [
        {
            "citation": "OWASP Top 10 (2021) — A07: Identification and Authentication Failures",
            "body": "OWASP",
            "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        },
        {
            "citation": "NIST SP 800-53 Rev.5 — IA-5 Authenticator Management",
            "body": "NIST",
            "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        },
        {
            "citation": "CWE-798 — Use of Hard-coded Credentials",
            "body": "MITRE CWE",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
        },
    ],
    "LEG-01": [
        {
            "citation": "FRE 502 — Attorney-Client Privilege and Work Product; Limitations on Waiver",
            "body": "US Federal Rules of Evidence",
            "url": "https://www.law.cornell.edu/rules/fre/rule_502",
        },
        {
            "citation": "FRCP 26(b)(3) — Trial Preparation: Materials (work product)",
            "body": "US Federal Rules of Civil Procedure",
            "url": "https://www.law.cornell.edu/rules/frcp/rule_26",
        },
        {
            "citation": "FRE 408 — Compromise Offers and Negotiations",
            "body": "US Federal Rules of Evidence",
            "url": "https://www.law.cornell.edu/rules/fre/rule_408",
        },
        {
            "citation": "ABA Model Rule 1.6 — Confidentiality of Information",
            "body": "American Bar Association",
            "url": "https://www.americanbar.org/groups/professional_responsibility/publications/model_rules_of_professional_conduct/rule_1_6_confidentiality_of_information/",
        },
    ],
    "COM-01": [
        {
            "citation": "Defend Trade Secrets Act, 18 U.S.C. §1836 — Civil proceedings",
            "body": "US Federal / DTSA",
            "url": "https://www.law.cornell.edu/uscode/text/18/1836",
        },
        {
            "citation": "Uniform Trade Secrets Act §1 — Definitions of trade secret and misappropriation",
            "body": "Uniform Law Commission",
            "url": "https://www.uniformlaws.org/committees/community-home?CommunityKey=3a2538fb-e030-4e2d-a9e2-90373dc05792",
        },
        {
            "citation": "Economic Espionage Act, 18 U.S.C. §1832 — Theft of trade secrets",
            "body": "US Federal",
            "url": "https://www.law.cornell.edu/uscode/text/18/1832",
        },
        {
            "citation": "EU Trade Secrets Directive 2016/943 — Protection of undisclosed know-how",
            "body": "European Union",
            "url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016L0943",
        },
        {
            "citation": "SEC Regulation FD, 17 CFR §243 — Selective disclosure and insider trading",
            "body": "US Securities and Exchange Commission",
            "url": "https://www.ecfr.gov/current/title-17/chapter-II/part-243",
        },
    ],
    "GEN-03": [
        {
            "citation": "GDPR Art. 28 — Processor obligations and sub-processor controls",
            "body": "EU GDPR",
            "url": "https://gdpr-info.eu/art-28-gdpr/",
        },
        {
            "citation": "HIPAA §164.314 — Business associate contracts and other arrangements",
            "body": "HHS / HIPAA Security Rule",
            "url": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.314",
        },
    ],
    "GEN-04": [
        {
            "citation": "FTC Act §5 — Unfair or deceptive acts or practices",
            "body": "US Federal Trade Commission",
            "url": "https://www.ftc.gov/legal-library/browse/statutes/federal-trade-commission-act",
        },
        {
            "citation": "EU AI Act Art. 13 — Transparency and provision of information to deployers",
            "body": "EU AI Act",
            "url": "https://artificialintelligenceact.eu/article/13/",
        },
    ],
    "GEN-05": [
        {
            "citation": "EU AI Act Art. 9 — Risk management system",
            "body": "EU AI Act",
            "url": "https://artificialintelligenceact.eu/article/9/",
        },
        {
            "citation": "ISO/IEC 42001:2023 §6.1 — Actions to address risks and opportunities",
            "body": "ISO/IEC",
            "url": "https://www.iso.org/standard/81230.html",
        },
    ],
}

def _load_rule_overrides() -> dict[str, dict]:
    """Load optional per-rule overrides from rules_override.json at startup.

    The file is optional. If it is absent, malformed, or empty, defaults apply.
    Supported override keys per rule_id:
      severity           — "low" | "medium" | "high"
      confidence         — float 0.0–0.99 (base confidence before profile boost)
      rationale          — str  (replaces the built-in rationale)
      recommended_action — str  (replaces the built-in recommended action)
      regulatory_references — list[{citation, body, url}]  (appended to built-ins)
    """
    override_path = Path(__file__).parent / "rules_override.json"
    if not override_path.exists():
        return {}
    try:
        with open(override_path, encoding="utf-8") as fh:
            data = json.load(fh)
        rules = data.get("rules") if isinstance(data, dict) else None
        # Keys beginning with "_" are treated as documentation/comments and are ignored.
        return {k: v for k, v in rules.items() if isinstance(rules, dict) and not k.startswith("_")} if isinstance(rules, dict) else {}
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


_RULE_OVERRIDES: dict[str, dict] = _load_rule_overrides()


def _compute_policy_digest() -> str:
    """SHA-256 over the canonical JSON of the loaded policy bundle
    (rule labels + regulatory citations + overrides). Surfaced on every DoCR
    and on `/health` so downstream auditors can pin a known-good digest and
    detect silent rule changes."""
    bundle = {
        "rule_labels": RULE_LABELS,
        "regulatory_citations": REGULATORY_CITATIONS,
        "rule_overrides": _RULE_OVERRIDES,
    }
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


POLICY_BUNDLE_DIGEST: str = _compute_policy_digest()

# Optional operator pin. If set, the server refuses to boot with an unexpected
# policy bundle — closes the "someone swapped rules_override.json on the
# filesystem" attack for prod deployments that wire this env in their secrets.
_pinned = os.getenv("GOVTRACE_POLICY_PINNED_DIGEST", "").strip().lower()
if _pinned and _pinned != POLICY_BUNDLE_DIGEST:
    raise RuntimeError(
        f"Policy bundle digest mismatch: expected {_pinned}, loaded {POLICY_BUNDLE_DIGEST}. "
        "Refusing to start — review rules_override.json before clearing the pin."
    )

PROFILE_RULES = {
    "General": {"health_confidence_boost": 0.0, "financial_confidence_boost": 0.0},
    "Public Sector": {"health_confidence_boost": 0.0, "financial_confidence_boost": 0.0},
    "Healthcare": {"health_confidence_boost": 0.06, "financial_confidence_boost": 0.0},
    "Finance": {"health_confidence_boost": 0.0, "financial_confidence_boost": 0.06},
}


def normalize_profile(profile: Optional[str]) -> str:
    if not profile:
        return "General"

    cleaned = profile.strip().lower()
    return PROFILE_ALIASES.get(cleaned, "General")


def _clip_confidence(value: float) -> float:
    return max(0.0, min(0.99, round(value, 2)))


def _confidence_label(value: float) -> str:
    if value >= 0.93:
        return "High"
    if value >= 0.8:
        return "Medium"
    return "Low"


def _severity_rank(value: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0)


def _overall_severity(findings: list[Finding]) -> str:
    if any(f.severity == "critical" for f in findings):
        return "critical"
    if any(f.severity == "high" for f in findings):
        return "high"
    if any(f.severity == "medium" for f in findings):
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Validation helpers — Luhn, Shannon entropy, and NFKC obfuscation-stripping
# ---------------------------------------------------------------------------

def _luhn_valid(raw: str) -> bool:
    """Return True if the digit-run in `raw` satisfies the Luhn checksum.

    Accepts strings with spaces/dashes; only digits are checked. Length must
    fall within the PAN range (13–19) before Luhn is evaluated.
    """
    digits = re.sub(r"\D", "", raw)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _shannon_entropy(token: str) -> float:
    if not token:
        return 0.0
    counts = Counter(token)
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


_SECRET_CANDIDATE = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")


def _looks_like_generic_secret(token: str) -> bool:
    """Conservative heuristic for an unlabeled high-entropy credential."""
    if len(token) < 24:
        return False
    if token.startswith(("http://", "https://", "www.")):
        return False
    if token.endswith((".pdf", ".png", ".jpg", ".jpeg", ".gif", ".docx", ".xlsx", ".json", ".csv", ".xml")):
        return False
    has_digit = any(ch.isdigit() for ch in token)
    has_alpha = any(ch.isalpha() for ch in token)
    if not (has_digit and has_alpha):
        return False
    # Bare hex strings at canonical hash lengths are usually already-hashed
    # output (git SHA, MD5, SHA-1/256/512) rather than a live secret.
    if re.fullmatch(r"[a-fA-F0-9]+", token) and len(token) in {32, 40, 64, 96, 128}:
        return False
    return _shannon_entropy(token) >= 4.0


_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\ufeff"}


def _normalize_for_injection(text: str) -> str:
    """NFKC-normalize and strip zero-width / NBSP chars that enable bypass.

    Returns a string where obfuscated variants like `ign\u200core previous`
    collapse back to `ignore previous` so `_INJECTION` can match them.
    """
    cleaned_chars = []
    for ch in text:
        if ch in _ZERO_WIDTH:
            continue
        if ch == "\u00a0":
            cleaned_chars.append(" ")
        else:
            cleaned_chars.append(ch)
    return unicodedata.normalize("NFKC", "".join(cleaned_chars))


def _snippet(text: str, start: int, end: int, padding: int = 18) -> str:
    left = max(0, start - padding)
    right = min(len(text), end + padding)
    return text[left:right].strip()


def _location(text: str, start: int) -> str:
    line = text.count("\n", 0, start) + 1
    line_start = text.rfind("\n", 0, start)
    column = start + 1 if line_start == -1 else start - line_start
    return f"Line {line}, char {column}"


def _confidence_explanation(value: float, signal: str) -> str:
    label = _confidence_label(value)
    if label == "High":
        return f"High confidence because the content matched a strong {signal.lower()} signal."
    if label == "Medium":
        return f"Medium confidence because the content matched a likely {signal.lower()} signal that should be reviewed."
    return f"Low confidence because the signal is weaker and needs human validation."


def _mask_ssn(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "***-**-****"
    return f"***-**-{digits[-4:]}"


def _mask_email(value: str) -> str:
    return "[email redacted]"


def _mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        return f"***-***-{digits[-4:]}"
    return "***-***-****"


def _mask_address(value: str) -> str:
    return "[street address redacted]"


def _mask_credit_card(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "****"
    return f"**** **** **** {digits[-4:]}"


def _mask_secret(value: str) -> str:
    """Partial-reveal mask for credential-class spans: first 4 chars + asterisks."""
    if len(value) <= 4:
        return "****"
    return f"{value[:4]}…{'*' * max(4, len(value) - 4)}"


_IP_SHAPE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?")


# Per-finding masking policy. Stable (finding_type -> (mask_fn_or_placeholder,
# example_type_label)) map. `example_type` is a short, deterministic label that
# describes the kind of evidence without revealing its content, so downstream
# consumers can reason about findings without reading raw spans.
#
# Placeholder style matches build_redacted_preview() output; partial-reveal
# masks (SSN / phone / credit card last-4, secret first-4) are retained where
# they are already established in the engine's public-facing output.
_EXAMPLE_POLICY: dict[str, tuple[object, str]] = {
    # Truncation notice carries no raw data — the existing summary is safe.
    "INPUT TRUNCATED":                 (None,                                "truncation notice"),
    "EMAIL ADDRESS":                   ("[email redacted]",                  "email pattern"),
    "SOCIAL SECURITY NUMBER":          (_mask_ssn,                           "SSN pattern"),
    "PHONE NUMBER":                    (_mask_phone,                         "phone number pattern"),
    "STREET ADDRESS":                  ("[street address redacted]",         "street address pattern"),
    "LOCATION DETAIL":                 ("[address redacted]",                "city/state/ZIP pattern"),
    "NAME + DOB COMBINATION":          ("[name redacted] / [date redacted]", "NAME + DOB pattern"),
    "DATE OF BIRTH":                   ("[date redacted]",                   "date-of-birth pattern"),
    "PROMPT INJECTION":                ("[injection phrase redacted]",       "prompt injection phrase"),
    "OVERCLAIM LANGUAGE":              ("[overclaim phrase redacted]",       "overclaim phrase"),
    "UNVERIFIED OR INCOMPLETE CLAIM":  ("[unverified phrase redacted]",      "unverified claim phrase"),
    "EXTERNAL SHARING INSTRUCTION":    ("[sharing instruction redacted]",    "external sharing phrase"),
    "CREDIT CARD NUMBER":              (_mask_credit_card,                   "payment card pattern"),
    "CARD SECURITY CODE":              ("[cvv redacted]",                    "card security code"),
    "BANK ACCOUNT DETAIL":             ("[account redacted]",                "bank account / routing pattern"),
    "HEALTH DATA SIGNAL":              ("[health term redacted]",            "healthcare terminology signal"),
    "CLINICAL NARRATIVE":              ("[clinical phrase redacted]",        "clinical narrative phrase"),
    "LEGAL PRIVILEGE":                 ("[legal phrase redacted]",           "legal privilege marker"),
    "LEGAL ADVICE":                    ("[legal phrase redacted]",           "legal advice phrase"),
    "COMMERCIAL CONFIDENTIAL":         ("[commercial term redacted]",        "commercial-confidential term"),
    "MEDICATION NAME":                 ("[drug name redacted]",              "generic medication name"),
    "DIAGNOSIS CODE":                  ("[icd10 code list redacted]",        "ICD-10 code list"),
    "HEALTHCARE WORKFLOW ID":          ("[healthcare id redacted]",          "labeled healthcare workflow identifier"),
    "PRIVATE KEY":                     ("[private key redacted]",            "private key header"),
    "API KEY":                         (_mask_secret,                        "API key pattern"),
    "TOKEN":                           (_mask_secret,                        "bearer token pattern"),
    "PASSWORD":                        (_mask_secret,                        "password disclosure"),
    "MFA CODE":                        (_mask_secret,                        "MFA code disclosure"),
    "GENERIC SECRET":                  (_mask_secret,                        "high-entropy token"),
}


def _mask_example(raw: str, finding_type: str) -> tuple[str, str]:
    """Return (masked_example, example_type_label) for a finding.

    Called from _make_finding so every persisted Finding.example is masked by
    default. The raw span is retained in Finding.example_raw only when
    STORE_RAW_EVIDENCE is enabled.
    """
    # INFRA CONFIG covers two distinct shapes (hostname vs RFC1918 address),
    # so dispatch on the raw shape rather than adding another finding type.
    if finding_type == "INFRA CONFIG":
        if _IP_SHAPE.fullmatch(raw.strip()):
            return ("[internal ip redacted]", "internal network address")
        return ("[internal host redacted]", "internal hostname")

    policy = _EXAMPLE_POLICY.get(finding_type)
    if policy is None:
        # Unknown finding type — fail closed. Never let an unmapped rule leak
        # raw evidence just because someone forgot to update the policy map.
        return ("[sensitive span redacted]", "unspecified evidence")

    mask, label = policy
    if mask is None:
        # Explicit "raw is already safe" exemption (currently INPUT TRUNCATED).
        return (raw, label)
    if callable(mask):
        return (mask(raw), label)
    return (mask, label)


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    # Location is part of the dedup key because masking collapses raw spans
    # (5 different healthcare IDs all render as "[healthcare id redacted]").
    # Without location, distinct occurrences of the same finding type would
    # silently merge and auditors would lose positional evidence.
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Finding] = []

    for finding in findings:
        key = (finding.type, finding.reason_code, finding.example, finding.location)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    return sorted(unique, key=lambda finding: (-_severity_rank(finding.severity), -finding.confidence, finding.type))


def _has_clinical_context(text: str, start: int, end: int) -> bool:
    window_start = max(0, start - 80)
    window_end = min(len(text), end + 80)
    window = text[window_start:window_end]
    return bool(re.search(r"\b(?:patient|diagnosis|diagnosed|treatment|medication|prescription|mrn|medical record|phi|hipaa)\b", window, re.IGNORECASE))


def _make_finding(
    *,
    type: str,
    reason_code: str,
    rule_id: str,
    severity: str,
    confidence: float,
    signal: str,
    location: str,
    raw_example: str,
    rationale: str,
    recommended_action: str,
) -> Finding:
    # Apply customer overrides for this rule before building the Finding.
    override = _RULE_OVERRIDES.get(rule_id, {})
    if override:
        severity = override.get("severity", severity)
        if "confidence" in override:
            confidence = float(override["confidence"])
        rationale = override.get("rationale", rationale)
        recommended_action = override.get("recommended_action", recommended_action)

    confidence = _clip_confidence(confidence)
    regulatory_references = [
        RegulatoryReference(**ref)
        for ref in REGULATORY_CITATIONS.get(rule_id, [])
    ]
    # Append any extra citations declared in the override (does not replace built-ins).
    if override.get("regulatory_references"):
        try:
            extra = [RegulatoryReference(**r) for r in override["regulatory_references"]]
            regulatory_references = regulatory_references + extra
        except (TypeError, ValueError):
            pass  # Malformed override citations are silently ignored.

    masked_example, example_type = _mask_example(raw_example, type)

    return Finding(
        type=type,
        reason_code=reason_code,
        reason_label=REASON_LABELS[reason_code],
        rule_id=rule_id,
        rule_label=RULE_LABELS[rule_id],
        severity=severity,
        confidence=confidence,
        confidence_label=_confidence_label(confidence),
        confidence_explanation=_confidence_explanation(confidence, signal),
        signal=signal,
        location=location,
        example=masked_example,
        example_type=example_type,
        example_raw=raw_example if STORE_RAW_EVIDENCE else None,
        rationale=rationale,
        recommended_action=recommended_action,
        regulatory_references=regulatory_references,
    )


def analyze(text: str, profile: str = "General") -> list[Finding]:
    original_length = len(text)
    text = text[:INPUT_LIMIT]
    profile = normalize_profile(profile)
    profile_rules = PROFILE_RULES[profile]
    findings: list[Finding] = []

    # GEN-TRUNCATED: a truncated analysis cannot issue a SAFE verdict. Emit a
    # first-class finding so this shows up in the DoCR and forces review.
    if original_length > INPUT_LIMIT:
        findings.append(_make_finding(
            type="INPUT TRUNCATED",
            reason_code="INPUT_TRUNCATION",
            rule_id="GEN-TRUNCATED",
            severity="medium",
            confidence=0.99,
            signal="Input exceeded engine processing limit",
            location=f"Character {INPUT_LIMIT} (of {original_length})",
            raw_example=f"Truncated at {INPUT_LIMIT} chars; {original_length - INPUT_LIMIT} chars were not analyzed",
            rationale="The submitted content exceeded the engine's single-pass limit. Portions of the input were not analyzed, so no SAFE verdict can be issued without a re-run over the full content.",
            recommended_action="Chunk the input into segments below the engine limit and re-submit each segment, or raise the engine limit after a security review.",
        ))

    for match in _EMAIL.finditer(text):
        findings.append(_make_finding(
            type="EMAIL ADDRESS",
            reason_code="PII",
            rule_id="PII-02",
            severity="medium",
            confidence=0.96,
            signal="Email pattern",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A direct email address was detected, which is treated as sensitive contact information.",
            recommended_action="Remove or mask the email address before sending the content downstream.",
        ))

    for match in _SSN.finditer(text):
        findings.append(_make_finding(
            type="SOCIAL SECURITY NUMBER",
            reason_code="PII",
            rule_id="PII-03",
            severity="high",
            confidence=0.99,
            signal="SSN pattern",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="The content matches a Social Security number pattern.",
            recommended_action="Block the payload until the SSN is fully redacted.",
        ))

    for match in _PHONE.finditer(text):
        findings.append(_make_finding(
            type="PHONE NUMBER",
            reason_code="PII",
            rule_id="PII-02",
            severity="medium",
            confidence=0.90,
            signal="Phone number pattern",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A phone number was detected and should be reviewed before production use.",
            recommended_action="Verify the number is necessary, or redact it before sharing.",
        ))

    for match in _STREET_ADDRESS.finditer(text):
        findings.append(_make_finding(
            type="STREET ADDRESS",
            reason_code="PII",
            rule_id="PII-01",
            severity="medium",
            confidence=0.88,
            signal="Street address pattern",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A physical mailing or street address was detected.",
            recommended_action="Remove the address unless the workflow explicitly requires it.",
        ))

    for match in _CITY_STATE_ZIP.finditer(text):
        findings.append(_make_finding(
            type="LOCATION DETAIL",
            reason_code="PII",
            rule_id="PII-01",
            severity="medium",
            confidence=0.82,
            signal="City/state/ZIP pattern",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A city, state, and ZIP combination was detected.",
            recommended_action="Review whether this location detail should remain in the prompt or payload.",
        ))

    dob_matches = list(_DOB.finditer(text))
    name_match = _NAME.search(text)
    if not name_match and dob_matches:
        first_dob = dob_matches[0]
        window_start = max(0, first_dob.start() - 80)
        window_end = min(len(text), first_dob.end() + 80)
        window = text[window_start:window_end]
        person_match = _PERSON_NAME.search(window)
        if person_match:
            name_match = person_match

    standalone_dobs = list(dob_matches)
    if dob_matches and name_match:
        dob_match = dob_matches[0]
        rule_id = "PHI-01" if _has_clinical_context(text, name_match.start(1), dob_match.end()) else "PII-03"
        # PHI-01 (patient identity + DOB in clinical context) is HIPAA Safe-Harbor
        # material — escalate to critical so verdict logic always forces STOP.
        findings.append(_make_finding(
            type="NAME + DOB COMBINATION",
            reason_code="HEALTH" if rule_id == "PHI-01" else "PII",
            rule_id=rule_id,
            severity="critical" if rule_id == "PHI-01" else "high",
            confidence=0.98 if rule_id == "PHI-01" else 0.97,
            signal="Patient identity and date-of-birth pattern" if rule_id == "PHI-01" else "Name and date-of-birth pattern",
            location=_location(text, min(name_match.start(1), dob_match.start())),
            raw_example=f"{name_match.group(1)} / {dob_match.group().strip()}",
            rationale="A named individual appears alongside a date-of-birth reference, which creates a direct identifying record." if rule_id == "PII-03" else "A patient identity marker appears alongside a date-of-birth reference in clinical context, which raises PHI exposure risk.",
            recommended_action="Block or heavily redact personal identity details before proceeding." if rule_id == "PII-03" else "Block the payload and remove patient-linked clinical identity details before proceeding.",
        ))
        # First DOB consumed by the NAME+DOB combo; remaining DOBs (guarantor,
        # spouse, dependent, emergency-contact, etc.) still surface individually.
        standalone_dobs = dob_matches[1:]

    for dob_match in standalone_dobs:
        findings.append(_make_finding(
            type="DATE OF BIRTH",
            reason_code="PII",
            rule_id="PII-03",
            severity="medium",
            confidence=0.91,
            signal="Date-of-birth pattern",
            location=_location(text, dob_match.start()),
            raw_example=dob_match.group().strip(),
            rationale="A date-of-birth reference was detected and should be reviewed as personal information.",
            recommended_action="Redact or confirm that DOB data is approved for this workflow.",
        ))

    raw_injection_examples: set[str] = set()
    for match in _INJECTION.finditer(text):
        raw_injection_examples.add(match.group().lower())
        findings.append(_make_finding(
            type="PROMPT INJECTION",
            reason_code="PROMPT_INJECTION",
            rule_id="SEC-01",
            severity="high",
            confidence=0.99,
            signal="Prompt injection phrase",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="The text contains language associated with attempts to override or expose model instructions.",
            recommended_action="Block the request and remove the adversarial instruction before retrying.",
        ))

    # Obfuscation-resistant second pass: strip zero-width chars and NFKC-fold
    # so variants like `ign\u200core previous instructions` still match.
    normalized_text = _normalize_for_injection(text)
    if normalized_text != text:
        for match in _INJECTION.finditer(normalized_text):
            phrase = match.group()
            if phrase.lower() in raw_injection_examples:
                continue
            findings.append(_make_finding(
                type="PROMPT INJECTION",
                reason_code="PROMPT_INJECTION",
                rule_id="SEC-01",
                severity="high",
                confidence=0.94,
                signal="Prompt injection phrase (obfuscation-normalized)",
                location=f"Normalized offset {match.start()}",
                raw_example=phrase,
                rationale="An instruction-override phrase was detected only after NFKC normalization and zero-width-character stripping, indicating deliberate obfuscation.",
                recommended_action="Block the request; treat the payload as adversarial.",
            ))

    for match in _OVERCLAIM.finditer(text):
        findings.append(_make_finding(
            type="OVERCLAIM LANGUAGE",
            reason_code="UNSUPPORTED_CLAIM",
            rule_id="GEN-04",
            severity="medium",
            confidence=0.83,
            signal="Unsupported certainty language",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="Absolute certainty language can create policy or trust risk and should be qualified.",
            recommended_action="Route to review and replace absolute claims with evidence-backed wording.",
        ))

    for match in _UNVERIFIED.finditer(text):
        findings.append(_make_finding(
            type="UNVERIFIED OR INCOMPLETE CLAIM",
            reason_code="INCOMPLETE_EVIDENCE",
            rule_id="GEN-05",
            severity="medium",
            confidence=0.81,
            signal="Incomplete evidence phrase",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="The content explicitly signals missing verification, documentation, or incomplete evidence and should not be treated as fully cleared.",
            recommended_action="Route to review and confirm the missing support before using this content in a live workflow.",
        ))

    for match in _EXTERNAL_SHARING.finditer(text):
        findings.append(_make_finding(
            type="EXTERNAL SHARING INSTRUCTION",
            reason_code="EXTERNAL_SHARING",
            rule_id="GEN-03",
            severity="high" if any(f.reason_code in {"PII", "HEALTH", "FINANCIAL"} for f in findings) else "medium",
            confidence=0.86,
            signal="External sharing phrase",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="The content includes language suggesting broad or external sharing, which raises governance risk when sensitive material is present.",
            recommended_action="Restrict distribution to approved internal channels and remove external sharing instructions before use.",
        ))

    for match in _CREDIT_CARD.finditer(text):
        # Luhn gate — the raw regex matches any 13–16 digit run, which produces
        # heavy false positives on invoice / case / SKU numbers. Only emit when
        # the candidate passes the Luhn checksum (PCI PAN convention).
        if not _luhn_valid(match.group()):
            continue
        findings.append(_make_finding(
            type="CREDIT CARD NUMBER",
            reason_code="FINANCIAL",
            rule_id="FIN-02",
            severity="critical",
            confidence=0.97 + profile_rules["financial_confidence_boost"],
            signal="Luhn-valid payment card pattern",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A Luhn-valid payment card number was detected in the submitted content, which is PCI-regulated material.",
            recommended_action="Remove the card number or replace it with a tokenized value; rotate if already transmitted.",
        ))

    for match in _BANK_ACCOUNT.finditer(text):
        findings.append(_make_finding(
            type="BANK ACCOUNT DETAIL",
            reason_code="FINANCIAL",
            rule_id="FIN-02",
            severity="high" if profile == "Finance" else "medium",
            confidence=0.89 + profile_rules["financial_confidence_boost"],
            signal="Bank account or routing pattern",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="Banking or routing details were detected and can expose sensitive financial data.",
            recommended_action="Block or redact the account details before this content is shared.",
        ))

    # PCI-DSS prohibits CVV/CVC storage post-authorization, so a labeled CVV is
    # itself a disclosure event even without an accompanying PAN.
    for match in _REDACT_CVV.finditer(text):
        findings.append(_make_finding(
            type="CARD SECURITY CODE",
            reason_code="FINANCIAL",
            rule_id="FIN-02",
            severity="critical",
            confidence=0.95 + profile_rules["financial_confidence_boost"],
            signal="CVV / CVC label with 3-4 digit code",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A card security code (CVV/CVC) was detected in plaintext. PCI-DSS prohibits storage of CVV/CVC data after transaction authorization.",
            recommended_action="Remove the CVV immediately and confirm it has not been persisted in logs, tickets, or downstream systems.",
        ))

    for match in _HEALTH_DATA.finditer(text):
        severity = "high" if profile == "Healthcare" and match.group().lower() in {"phi", "hipaa", "medical record", "mrn"} else "medium"
        findings.append(_make_finding(
            type="HEALTH DATA SIGNAL",
            reason_code="HEALTH",
            rule_id="PHI-01",
            severity=severity,
            confidence=0.84 + profile_rules["health_confidence_boost"],
            signal="Healthcare terminology signal",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="Healthcare-oriented language suggests the content may contain patient or protected health information.",
            recommended_action="Review for PHI exposure and redact medical details before use.",
        ))

    # Clinical narrative — age phrasing. HIPAA Safe Harbor treats age > 89 as
    # PHI, and ages paired with clinical context are routinely quasi-identifying.
    for match in _CLINICAL_AGE.finditer(text):
        findings.append(_make_finding(
            type="CLINICAL NARRATIVE",
            reason_code="HEALTH",
            rule_id="PHI-01",
            severity="medium",
            confidence=0.86 + profile_rules["health_confidence_boost"],
            signal="Age phrasing in clinical context",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="Patient age phrasing (e.g. `54-year-old`, `72 y/o`) is a quasi-identifier and is treated as PHI under HIPAA Safe Harbor when paired with other clinical markers.",
            recommended_action="Redact the age phrase or generalize it (e.g. `adult patient`) before sharing externally.",
        ))

    # LEG-01: Attorney-client privilege / work product / litigation hold
    # markers. Their presence means the surrounding content is protected and
    # must not leave the tenant — redaction of the marker alone is not enough,
    # which is why LEGAL is also in _BLOCKING_REASON_CODES.
    for match in _LEG_PRIVILEGE_MARKER.finditer(text):
        findings.append(_make_finding(
            type="LEGAL PRIVILEGE",
            reason_code="LEGAL",
            rule_id="LEG-01",
            severity="high",
            confidence=0.92,
            signal="Attorney-client privilege / work-product marker",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="The text contains an explicit marker of attorney-client privilege, attorney work product, or a litigation hold. Content bearing these markers is protected and cannot be shared with external systems without risk of waiving privilege.",
            recommended_action="Block the payload and route to legal review. Do not send privileged or work-product content to external models, vendors, or shared channels.",
        ))

    for match in _LEG_RULE_CITATION.finditer(text):
        findings.append(_make_finding(
            type="LEGAL PRIVILEGE",
            reason_code="LEGAL",
            rule_id="LEG-01",
            severity="medium",
            confidence=0.78,
            signal="Citation to FRE/FRCP privilege or settlement rule",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="The text cites a Federal Rule of Evidence (408, 501, 502) or FRCP 26(b)(3). These rules govern settlement communications and attorney work product; surrounding content is likely privileged or protected.",
            recommended_action="Route the payload to legal review. Do not forward to external systems without confirming waiver or non-privileged status.",
        ))

    # Softer legal-advice signals. Lower confidence / medium severity — still
    # contribute to the LEGAL blocking class so redaction alone will not make
    # the surrounding content safe to share externally.
    for match in _LEG_SOFT_MARKER.finditer(text):
        findings.append(_make_finding(
            type="LEGAL ADVICE",
            reason_code="LEGAL",
            rule_id="LEG-01",
            severity="medium",
            confidence=0.80,
            signal="Legal-advice or settlement-confidentiality phrasing",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="Phrasing such as `attorney advised`, `counsel recommended`, or `settlement talks remain confidential` indicates legal advice or settlement-protected communications. Surrounding content is typically privileged even without an explicit privilege marker.",
            recommended_action="Route to legal review and do not forward to external systems. Confirm whether the material is truly non-privileged before sharing.",
        ))

    # COM-01: Commercial-confidential / trade-secret material. Not in
    # _BLOCKING_REASON_CODES (those are "never leaves tenant" classes) — but
    # enforcement_decisions blocks external_share for COMMERCIAL and routes
    # vendor_share to review, because leaking pricing, customer lists, or M&A
    # plans to an external model is typically a trade-secret exposure event.
    for match in _COM_COMMERCIAL_TERMS.finditer(text):
        findings.append(_make_finding(
            type="COMMERCIAL CONFIDENTIAL",
            reason_code="COMMERCIAL",
            rule_id="COM-01",
            severity="high",
            confidence=0.85,
            signal="Commercial-confidential business term",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="The text contains a phrase that typically marks trade-secret or commercial-confidential material (customer lists, pricing strategy, margin data, revenue forecasts, board materials, M&A targets, or executive compensation). Exposing this content to external systems risks waiver of trade-secret protection and, for public companies, may implicate Regulation FD.",
            recommended_action="Route to business/legal review before forwarding. Do not send commercial-confidential content to external models or vendors without a contractual confidentiality carve-out.",
        ))

    # Clinical narrative — diagnosis / disposition verbs. These verbs typically
    # sit immediately before a specific diagnosis string that is itself PHI.
    for match in _CLINICAL_DIAG_VERB.finditer(text):
        findings.append(_make_finding(
            type="CLINICAL NARRATIVE",
            reason_code="HEALTH",
            rule_id="PHI-01",
            severity="medium",
            confidence=0.84 + profile_rules["health_confidence_boost"],
            signal="Diagnosis / disposition verb",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="Clinical verbs such as `diagnosed with`, `presented with`, or `s/p` indicate a patient-linked clinical narrative that typically contains PHI.",
            recommended_action="Review the surrounding sentence for patient-specific medical detail and redact before use.",
        ))

    # Named generic medications. Drug names alone are PHI-adjacent under HIPAA
    # Safe Harbor when paired with a patient context — conservative medium
    # severity, not critical, so this doesn't escalate non-clinical prose that
    # happens to name a common drug.
    for match in _PHI_MEDICATION_NAME.finditer(text):
        findings.append(_make_finding(
            type="MEDICATION NAME",
            reason_code="HEALTH",
            rule_id="PHI-01",
            severity="medium",
            confidence=0.80 + profile_rules["health_confidence_boost"],
            signal="Named generic medication",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A named generic medication was detected. Medication lists combined with patient context are PHI under HIPAA and should not be sent to external systems without de-identification.",
            recommended_action="Remove or generalize medication names (e.g. `antihypertensive`) before sharing the narrative externally.",
        ))

    # ICD-10 diagnosis codes. A labeled list or a multi-code sequence is a
    # near-definitive PHI signal — single-code mentions could be instructional
    # (e.g. billing training), so the regex requires label or 2+ codes.
    for match in _PHI_ICD10_CODES.finditer(text):
        findings.append(_make_finding(
            type="DIAGNOSIS CODE",
            reason_code="HEALTH",
            rule_id="PHI-01",
            severity="high",
            confidence=0.90 + profile_rules["health_confidence_boost"],
            signal="ICD-10 diagnosis code list",
            location=_location(text, match.start()),
            raw_example=match.group()[:60],
            rationale="A list of ICD-10 diagnosis codes typically accompanies a specific encounter and is treated as PHI under HIPAA Safe Harbor.",
            recommended_action="Remove or generalize the diagnosis codes before routing the content outside the covered entity.",
        ))

    # Labeled healthcare workflow identifiers (claim, encounter, authorization,
    # policy group, referral, member/plan IDs). Alphanumeric values (e.g.
    # `CLM-77882211`) are not caught by the numeric-only MRN/insurance patterns.
    for match in _PHI_HEALTHCARE_ID.finditer(text):
        findings.append(_make_finding(
            type="HEALTHCARE WORKFLOW ID",
            reason_code="HEALTH",
            rule_id="PHI-01",
            severity="medium",
            confidence=0.85 + profile_rules["health_confidence_boost"],
            signal="Labeled claim / authorization / encounter / policy identifier",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="Claim numbers, authorization references, encounter IDs, and policy-group identifiers are patient-linked workflow identifiers treated as PHI by HIPAA and payer contracts.",
            recommended_action="Mask or tokenize the identifier before sharing the narrative externally.",
        ))

    # ----- SEC-02: credentials, secrets, infra exposure ---------------------
    # Track covered spans so generic heuristics do not double-flag a vendor-
    # specific secret (e.g. `api key = sk_live_...` emits API KEY once).
    sec02_spans: list[tuple[int, int]] = []

    def _overlaps(start: int, end: int) -> bool:
        return any(s < end and start < e for s, e in sec02_spans)

    for match in _CRED_PRIVATE_KEY.finditer(text):
        # Widen the covered span to the END marker so the generic-entropy pass
        # below does not re-flag the base64 body as an unlabeled secret.
        end_match = _CRED_PRIVATE_KEY_END.search(text, match.end())
        covered_end = end_match.end() if end_match else match.end()
        sec02_spans.append((match.start(), covered_end))
        findings.append(_make_finding(
            type="PRIVATE KEY",
            reason_code="CREDENTIAL",
            rule_id="SEC-02",
            severity="critical",
            confidence=0.99,
            signal="Private key header",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A private-key header was detected in plaintext.",
            recommended_action="Remove the private key and rotate the credential immediately.",
        ))

    for match in _CRED_VENDOR_KEY.finditer(text):
        if _overlaps(match.start(), match.end()):
            continue
        sec02_spans.append((match.start(), match.end()))
        findings.append(_make_finding(
            type="API KEY",
            reason_code="CREDENTIAL",
            rule_id="SEC-02",
            severity="critical",
            confidence=0.97,
            signal="Vendor API key pattern (live-credential class)",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A pattern matching a known vendor API key prefix was detected — treated as a live credential.",
            recommended_action="Remove the key from the payload and rotate it in the issuing system immediately.",
        ))

    for match in _CRED_JWT.finditer(text):
        if _overlaps(match.start(), match.end()):
            continue
        sec02_spans.append((match.start(), match.end()))
        findings.append(_make_finding(
            type="TOKEN",
            reason_code="CREDENTIAL",
            rule_id="SEC-02",
            severity="high",
            confidence=0.9,
            signal="JWT-style token pattern",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A JSON Web Token pattern was detected in the submitted content.",
            recommended_action="Strip the token and treat it as exposed; revoke if it is a live session.",
        ))

    for match in _CRED_KEY_ASSIGNMENT.finditer(text):
        if _overlaps(match.start(), match.end()):
            continue
        sec02_spans.append((match.start(), match.end()))
        findings.append(_make_finding(
            type="API KEY",
            reason_code="CREDENTIAL",
            rule_id="SEC-02",
            severity="high",
            confidence=0.88,
            signal="Key assignment heuristic",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A key or token assignment phrase was detected with a credential-like value.",
            recommended_action="Remove the key/token and rotate the credential.",
        ))

    for match in _CRED_PASSWORD.finditer(text):
        if _overlaps(match.start(), match.end()):
            continue
        sec02_spans.append((match.start(), match.end()))
        findings.append(_make_finding(
            type="PASSWORD",
            reason_code="CREDENTIAL",
            rule_id="SEC-02",
            severity="high",
            confidence=0.92,
            signal="Password disclosure phrase",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="A password was written in plaintext.",
            recommended_action="Remove the password and rotate it in the target system.",
        ))

    for match in _CRED_MFA_CODE.finditer(text):
        if _overlaps(match.start(), match.end()):
            continue
        sec02_spans.append((match.start(), match.end()))
        findings.append(_make_finding(
            type="MFA CODE",
            reason_code="CREDENTIAL",
            rule_id="SEC-02",
            severity="high",
            confidence=0.9,
            signal="MFA/backup-code disclosure",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="An MFA or backup recovery code was detected in plaintext.",
            recommended_action="Invalidate the code and regenerate backup codes.",
        ))

    # Generic high-entropy secret heuristic — catches unlabeled credentials
    # that miss the labeled/vendor patterns above (e.g. raw tokens pasted
    # without an "api key =" prefix). Skips anything already covered by a
    # stronger SEC-02 match and anything that looks like a URL / filename.
    for cand in _SECRET_CANDIDATE.finditer(text):
        if _overlaps(cand.start(), cand.end()):
            continue
        token = cand.group()
        if not _looks_like_generic_secret(token):
            continue
        sec02_spans.append((cand.start(), cand.end()))
        findings.append(_make_finding(
            type="GENERIC SECRET",
            reason_code="CREDENTIAL",
            rule_id="SEC-02",
            severity="high",
            confidence=0.8,
            signal="High-entropy token (generic-secret heuristic)",
            location=_location(text, cand.start()),
            raw_example=token,
            rationale="An unlabeled high-entropy token was detected that resembles a credential or bearer secret.",
            recommended_action="Confirm whether this is a live credential; if so, remove and rotate it.",
        ))

    # Internal hostnames: the private-namespace suffix is itself a strong
    # signal (not a public domain), so emit unconditionally rather than
    # gating on firewall-hint language.
    for match in _INFRA_INTERNAL_HOST.finditer(text):
        if _overlaps(match.start(), match.end()):
            continue
        sec02_spans.append((match.start(), match.end()))
        findings.append(_make_finding(
            type="INFRA CONFIG",
            reason_code="INFRA_CONFIG",
            rule_id="SEC-02",
            severity="medium",
            confidence=0.85,
            signal="Internal hostname (private-namespace suffix)",
            location=_location(text, match.start()),
            raw_example=match.group(),
            rationale="An internal hostname was disclosed, which leaks infrastructure topology.",
            recommended_action="Remove internal hostnames before sharing externally.",
        ))

    # Infra exposure: medium severity, and only emit ONE finding per payload,
    # anchored on the first internal-IP match, IFF firewall/port language is
    # also present. This prevents noise from incidental IP mentions.
    if _INFRA_FIREWALL_HINT.search(text):
        first_ip = _INFRA_INTERNAL_IP.search(text)
        if first_ip and not _overlaps(first_ip.start(), first_ip.end()):
            sec02_spans.append((first_ip.start(), first_ip.end()))
            findings.append(_make_finding(
                type="INFRA CONFIG",
                reason_code="INFRA_CONFIG",
                rule_id="SEC-02",
                severity="medium",
                confidence=0.82,
                signal="Internal network address + firewall/port context",
                location=_location(text, first_ip.start()),
                raw_example=first_ip.group(),
                rationale="Internal network addresses were disclosed alongside firewall or port details.",
                recommended_action="Remove internal network topology before sharing externally.",
            ))

    return _dedupe(findings)


def verdict(findings: list[Finding]) -> tuple[str, str]:
    if any(f.severity == "critical" for f in findings):
        return (
            "POLICY VIOLATION",
            "Critical policy violations were detected (live credentials, payment cards, or patient-identifying PHI). Block the payload.",
        )
    if any(f.severity == "high" for f in findings):
        return (
            "POLICY VIOLATION",
            "High-confidence policy violations were detected. Remove the flagged content before using it in a live AI workflow.",
        )

    if findings:
        return (
            "NEEDS REVIEW",
            "Potentially sensitive or unsupported content was detected. Review and resolve the flagged items before proceeding.",
        )

    return (
        "COMPLIANT",
        "No sensitive data, prompt injection, or unsupported claims were detected in this policy check.",
    )


# ---------------------------------------------------------------------------
# Enterprise-shape helpers (additive — do not rename existing verdict vocab)
# ---------------------------------------------------------------------------

_VERDICT_CODE_BY_STATUS = {
    "POLICY VIOLATION": "STOP",
    "NEEDS REVIEW": "NEEDS_REVIEW",
    "COMPLIANT": "SAFE",
}

_BLOCKING_REASON_CODES = {"CREDENTIAL", "HEALTH", "PROMPT_INJECTION", "LEGAL", "COMMERCIAL"}


def verdict_code(status: str) -> str:
    return _VERDICT_CODE_BY_STATUS.get(status, "NEEDS_REVIEW")


def input_had_blocking_class(findings: list[Finding]) -> bool:
    """True if the ORIGINAL input contained a category that must never pass
    downstream, regardless of whether redaction masked it. Used to force
    stricter downstream gating than a simple `safe_after_redaction` bool."""
    for f in findings:
        if f.severity == "critical":
            return True
        if f.reason_code in _BLOCKING_REASON_CODES:
            return True
    return False


# Finding `reason_code` (internal engine vocabulary) → external-facing class
# slug used by SOC dashboards, procurement questionnaires, and the response
# `blocking_classes` rollup. Slugs are deliberately lowercase snake_case and
# stable — consumers pin on these strings.
_CLASS_BY_REASON_CODE = {
    "HEALTH": "phi",
    "PII": "pii",
    "FINANCIAL": "financial",
    "CREDENTIAL": "credential",
    "PROMPT_INJECTION": "prompt_injection",
    "LEGAL": "legal_privilege",
    "COMMERCIAL": "commercial_confidential",
    "INFRA_CONFIG": "infra_config",
    "EXTERNAL_SHARING": "external_sharing",
    "UNSUPPORTED_CLAIM": "unsupported_claim",
    "INCOMPLETE_EVIDENCE": "incomplete_evidence",
    "INPUT_TRUNCATION": "input_truncation",
}


def compute_blocking_classes(findings: list[Finding]) -> dict[str, int]:
    """Per-class finding counts used by SOC dashboards and procurement
    questionnaires.

    Buckets empty of findings are omitted so the JSON stays compact when
    nothing triggers. PAYMENT CARD findings additionally bubble up under a
    separate `pci` counter (in addition to `financial`) so a PCI-focused
    auditor sees the line item directly without having to join the finding
    list to the PCI-DSS scope.
    """
    rollup: dict[str, int] = {}
    for f in findings:
        key = _CLASS_BY_REASON_CODE.get(f.reason_code)
        if not key:
            continue
        if key == "financial":
            t = (f.type or "").upper()
            if "CREDIT CARD" in t or "PAYMENT" in t or f.rule_id == "FIN-01":
                rollup["pci"] = rollup.get("pci", 0) + 1
        rollup[key] = rollup.get(key, 0) + 1
    return rollup


def compute_reason_line(findings: list[Finding], verdict_code: str) -> str:
    """One-sentence, executive-readable explanation of the verdict.

    Picks the driving finding (highest severity, breaking ties on confidence)
    and renders a shape that exec emails, audit reports, and ticket titles can
    forward verbatim:

        VERDICT: <rule_label> — <signal> (<top_citation>, confidence X.XX).

    With no findings, returns a short SAFE line. The sentence shape is stable
    across releases — downstream consumers are expected to pin on it.
    """
    if not findings:
        return f"{verdict_code}: no policy-relevant content detected."
    driver = max(findings, key=lambda f: (_severity_rank(f.severity), f.confidence))
    body = driver.rule_label or driver.reason_label or driver.type
    if driver.signal:
        body = f"{body}: {driver.signal}"
    citation = ""
    if driver.regulatory_references:
        citation = driver.regulatory_references[0].citation
    conf = f"confidence {driver.confidence:.2f}"
    qual = f"({citation}, {conf})" if citation else f"({conf})"
    return f"{verdict_code}: {body} {qual}."


# ---------------------------------------------------------------------------
# HIPAA Safe Harbor assessment (45 CFR § 164.514(b)(2)).
# ---------------------------------------------------------------------------
# Ordered list of the 18 identifiers — key order matters, UIs render it as a
# checklist. Keys are snake_case to match the rest of the response shape.
_SAFE_HARBOR_IDENTIFIERS = [
    "names",
    "geographic_subdivisions",
    "dates",
    "telephone_numbers",
    "fax_numbers",
    "email_addresses",
    "social_security_numbers",
    "medical_record_numbers",
    "health_plan_beneficiary_numbers",
    "account_numbers",
    "certificate_or_license_numbers",
    "vehicle_identifiers",
    "device_identifiers",
    "web_urls",
    "ip_addresses",
    "biometric_identifiers",
    "full_face_photographs",
    "other_unique_identifiers",
]

# These cannot be assessed from text alone; they are declared out_of_scope in
# every attestation and do NOT contribute to PASS/FAIL.
_SAFE_HARBOR_OUT_OF_SCOPE = frozenset({"biometric_identifiers", "full_face_photographs"})


def _sh_detect_names(text: str) -> bool:
    """Catch both label-anchored ("Patient: Jane Doe") and standalone names.

    _PERSON_NAME is intentionally broad — TitleCase-word pairs like city/state
    combinations match. For Safe Harbor we prefer recall over precision: a
    false positive just means the attestation flags a potential name that the
    operator can confirm. A narrow stopword list catches phrases that appear
    in our own output (e.g. "Safe Harbor") so the method's own name doesn't
    trip the detector on a cleanly-redacted preview.

    Evaluates per line so `_PERSON_NAME`'s inter-token `\\s+` cannot match a
    newline and conjure a false-positive name out of adjacent section headers
    (e.g. `Taylor Brooks\\nContracted vendor` would otherwise match as a
    three-token name spanning two lines).
    """
    if _NAME.search(text):
        return True
    for line in text.splitlines():
        for match in _PERSON_NAME.finditer(line):
            if match.group().lower() not in _SH_NAME_STOPWORDS:
                return True
    return False


# TitleCase pairs that appear in GovTrace's own output / common compliance
# vocabulary and must not count as a detected person name. Keep narrow.
_SH_NAME_STOPWORDS = frozenset({
    "safe harbor",
    "duty of care",
    "prompt injection",
    "private key",
    "credit card",
    "service account",
    "stress test",
    "follow up",
    "chief complaint",
    "discharge meds",
    "medical record",
    "emergency contact",
    "prior authorization",
    "united states",
    # Document-header / section-title metadata that is not a person name.
    # Kept narrow: each phrase is a fixed doc-scaffolding term, not a
    # content word that could legitimately appear in PHI.
    "unstructured mixed clinical",
    "operations note",
    "clinical narrative",
    "registration contact",
    "regulatory identifiers",
})


def _sh_detect_geo(text: str) -> bool:
    """Detect geographic identifiers, line by line.

    Label-anchored patterns like `_REDACT_ADDRESS_LABEL` allow `\\s*` around
    the separator, so on a placeholder-stripped preview they can cross into
    the next line (e.g. `Home address:  \\nPortal URL:…` matches with
    "Portal URL" as the value). Evaluating each line independently avoids
    that false-positive without weakening the shared redaction regex.
    """
    if _STREET_ADDRESS.search(text) or _CITY_STATE_ZIP.search(text):
        return True
    for line in text.splitlines():
        if (
            _REDACT_STREET.search(line)
            or _REDACT_ADDRESS_LABEL.search(line)
            or _REDACT_CITY_STATE_BARE.search(line)
        ):
            return True
    return False


def _sh_detect_dates(text: str) -> bool:
    return bool(
        _DOB.search(text)
        or _SH_CLINICAL_DATE.search(text)
        or _CLINICAL_AGE.search(text)
    )


def _sh_detect_phone(text: str) -> bool:
    # Strip fax-labeled phone shapes first so a fax doesn't double-count.
    return bool(_PHONE.search(_SH_FAX.sub("", text)))


def _sh_detect_other(text: str) -> bool:
    """Same-line wrapper around `_PHI_HEALTHCARE_ID`.

    The shared `_PHI_HEALTHCARE_ID` regex is used for both detection AND
    redaction, so it keeps a newline-permissive `\\s*` separator. For the SH
    attestation we need same-line-only matching — otherwise a stripped
    `Member ID:  \\nAuth ref: PA-…` would match "Auth" as the Member ID value.
    """
    for line in text.splitlines():
        if _PHI_HEALTHCARE_ID.search(line):
            return True
    return False


_SH_DETECTORS = {
    "names": _sh_detect_names,
    "geographic_subdivisions": _sh_detect_geo,
    "dates": _sh_detect_dates,
    "telephone_numbers": _sh_detect_phone,
    "fax_numbers": lambda t: bool(_SH_FAX.search(t)),
    "email_addresses": lambda t: bool(_EMAIL.search(t)),
    "social_security_numbers": lambda t: bool(_SSN.search(t)),
    "medical_record_numbers": lambda t: bool(_REDACT_MRN.search(t)),
    "health_plan_beneficiary_numbers": lambda t: bool(_REDACT_INSURANCE_ID.search(t)),
    "account_numbers": lambda t: bool(
        _BANK_ACCOUNT.search(t)
        or _REDACT_ROUTING_NUM.search(t)
        or _REDACT_DD_ACCOUNT.search(t)
        or _CREDIT_CARD.search(t)
    ),
    "certificate_or_license_numbers": lambda t: bool(_SH_LICENSE_CERT.search(t)),
    "vehicle_identifiers": lambda t: bool(_SH_VEHICLE.search(t)),
    "device_identifiers": lambda t: bool(_SH_DEVICE.search(t)),
    "web_urls": lambda t: bool(_SH_URL.search(t)),
    "ip_addresses": lambda t: bool(_SH_ANY_IP.search(t)),
    "other_unique_identifiers": _sh_detect_other,
}


def compute_safe_harbor(text: str, redacted_preview: Optional[str]) -> SafeHarborBlock:
    """Assess HIPAA Safe Harbor (45 CFR § 164.514(b)(2)) de-identification.

    Returns a block mapping each of the 18 identifiers to one of:
      absent | detected | detected_redacted | out_of_scope

    Attestation is PASS iff every in-scope identifier is absent or
    detected_redacted (i.e. nothing sensitive remains in the preview).
    """
    preview = redacted_preview if redacted_preview is not None else text
    # Strip placeholder tokens (e.g. `[address redacted]`, `[name redacted]`)
    # from the preview before running detectors. Without this, label-anchored
    # detectors like `_REDACT_ADDRESS_LABEL` match `Home address: [address
    # redacted]` and report the identifier as still present — flipping a
    # correctly-redacted field from detected_redacted back to detected.
    preview_for_detection = _SH_PLACEHOLDER.sub(" ", preview)
    identifiers: dict[str, str] = {}
    detected: list[str] = []
    remaining: list[str] = []

    for key in _SAFE_HARBOR_IDENTIFIERS:
        if key in _SAFE_HARBOR_OUT_OF_SCOPE:
            identifiers[key] = "out_of_scope"
            continue
        detector = _SH_DETECTORS.get(key)
        if detector is None:
            identifiers[key] = "absent"
            continue
        in_original = detector(text)
        if not in_original:
            identifiers[key] = "absent"
            continue
        detected.append(key)
        if detector(preview_for_detection):
            identifiers[key] = "detected"
            remaining.append(key)
        else:
            identifiers[key] = "detected_redacted"

    attestation = "PASS" if not remaining else "FAIL"
    statement = None
    if attestation == "PASS":
        statement = (
            "No HIPAA Safe Harbor identifiers (45 CFR § 164.514(b)(2)) remain in the "
            "redacted output. Biometric identifiers and full-face photographs are "
            "out of scope for a text-only audit and must be reviewed separately."
        )
    return SafeHarborBlock(
        attestation=attestation,
        identifiers=identifiers,
        identifiers_detected=detected,
        identifiers_remaining_after_redaction=remaining,
        attestation_statement=statement,
    )


def enforcement_decisions(findings: list[Finding]) -> dict:
    """Map findings to per-channel enforcement actions.

    Channels:
      external_share — send to any third party / public endpoint
      vendor_share   — send to an authorized processor / LLM vendor
      internal_use   — use within the tenant's own workspace

    Vocabulary: blocked | review_required | allowed
    """
    severities = {f.severity for f in findings}
    reason_codes = {f.reason_code for f in findings}

    def _decide(block_tokens: set[str], review_tokens: set[str]) -> str:
        if severities & block_tokens or reason_codes & block_tokens:
            return "blocked"
        if severities & review_tokens or reason_codes & review_tokens or findings:
            return "review_required"
        return "allowed"

    external_share = _decide(
        block_tokens={"critical", "high", "CREDENTIAL", "HEALTH", "FINANCIAL", "INFRA_CONFIG", "LEGAL", "COMMERCIAL"},
        review_tokens=set(),
    )
    vendor_share = _decide(
        block_tokens={"critical", "CREDENTIAL", "HEALTH", "LEGAL"},
        review_tokens={"high", "FINANCIAL", "INFRA_CONFIG", "PII", "COMMERCIAL"},
    )
    internal_use = _decide(
        block_tokens={"critical"},
        review_tokens={"high", "CREDENTIAL", "HEALTH", "FINANCIAL", "PII", "INFRA_CONFIG", "LEGAL", "COMMERCIAL"},
    )
    return {
        "external_share": external_share,
        "vendor_share": vendor_share,
        "internal_use": internal_use,
    }


def summarize_risk(findings: list[Finding]) -> tuple[str, float, str]:
    if not findings:
        confidence = 0.98
        return ("low", confidence, _confidence_label(confidence))

    confidence = max(f.confidence for f in findings)
    severity = _overall_severity(findings)
    return (severity, confidence, _confidence_label(confidence))


def safe_for_use_after_redaction(text: str, profile: str = "General") -> bool:
    """Whether the redacted preview is genuinely safe to use downstream.

    Two conditions must both hold:
      1. The redacted preview has no remaining policy findings.
      2. The ORIGINAL input did NOT contain a blocking class (CREDENTIAL,
         HEALTH, PROMPT_INJECTION, LEGAL, COMMERCIAL, or any critical finding).

    Condition (2) is required because the masker can scrub a trigger phrase
    without neutralizing the surrounding content — e.g. masking "diabetes" does
    not remove the clinical narrative, and masking a privilege marker does not
    unprotect a 5-page legal memo. Returning `true` on such a payload would
    contradict `verdict=STOP` and mislead downstream callers.
    """
    original_findings = analyze(text, profile)
    if input_had_blocking_class(original_findings):
        return False

    redacted_preview = build_redacted_preview(text)
    if not redacted_preview:
        return len(original_findings) == 0

    return len(analyze(redacted_preview, profile)) == 0


# ---------------------------------------------------------------------------
# Residual-risk score
# ---------------------------------------------------------------------------
# A continuous complement to the verdict/severity/safe_after_redaction triad.
# The score is calibrated against test_corpus.json — any change here should be
# re-run through corpus_eval.evaluate() to confirm bands still match intent.

_RISK_SEVERITY_WEIGHTS = {
    "low":      0.20,
    "medium":   0.50,
    "high":     0.80,
    "critical": 1.00,
}

# Band cutoffs. `score >= cutoff` → band. Checked top-down.
_RISK_BANDS = (
    (0.80, "critical"),
    (0.55, "high"),
    (0.25, "medium"),
    (0.00, "low"),
)

# Blocking classes never fall below this floor even after successful redaction,
# because the content class (credential / PHI / injection / legal) means the
# underlying payload was sensitive — scrubbing the marker doesn't make the rest
# of the message shareable.
_BLOCKING_FLOOR = 0.65


def _risk_band(score: float) -> str:
    for cutoff, name in _RISK_BANDS:
        if score >= cutoff:
            return name
    return "low"


def compute_residual_risk(
    findings: list[Finding],
    had_blocking_class: bool,
    safe_after_redaction: bool,
) -> dict:
    """Composite risk score in [0.0, 1.0] with raw (pre-redaction) + residual
    (post-redaction) views.

    Formula (per raw):
      raw = max(severity_weight * confidence) across findings       # scariest wins
          + sum_others * 0.15, capped at +0.15                      # density bump

    Residual:
      residual = raw
      if not blocking AND safe_after_redaction:  residual *= 0.5   # redaction discount
      if blocking AND residual < _BLOCKING_FLOOR: residual = _BLOCKING_FLOOR

    Returns:
        {
          "score":      residual in [0, 1],
          "band":       "low" | "medium" | "high" | "critical",
          "raw_score":  pre-redaction score,
          "raw_band":   band for raw_score,
          "components": {base, density, redaction_discount, blocking_floor_applied},
        }
    """
    if not findings:
        return {
            "score":     0.0,
            "band":      "low",
            "raw_score": 0.0,
            "raw_band":  "low",
            "components": {
                "base":                    0.0,
                "density":                 0.0,
                "redaction_discount":      0.0,
                "blocking_floor_applied":  False,
            },
        }

    contribs = sorted(
        (_RISK_SEVERITY_WEIGHTS.get(f.severity, 0.5) * f.confidence for f in findings),
        reverse=True,
    )
    base = contribs[0]
    density = min(sum(c * 0.15 for c in contribs[1:]), 0.15)
    raw = min(1.0, base + density)

    residual = raw
    redaction_discount = 0.0
    if safe_after_redaction and not had_blocking_class:
        redaction_discount = residual * 0.5
        residual -= redaction_discount

    blocking_floor_applied = False
    if had_blocking_class and residual < _BLOCKING_FLOOR:
        residual = _BLOCKING_FLOOR
        blocking_floor_applied = True

    residual = max(0.0, min(1.0, residual))

    return {
        "score":     round(residual, 4),
        "band":      _risk_band(residual),
        "raw_score": round(raw, 4),
        "raw_band":  _risk_band(raw),
        "components": {
            "base":                    round(base, 4),
            "density":                 round(density, 4),
            "redaction_discount":      round(redaction_discount, 4),
            "blocking_floor_applied":  blocking_floor_applied,
        },
    }


def _mask_vendor_key(match: "re.Match") -> str:
    value = match.group()
    prefix = value.split("_", 1)[0] if "_" in value[:8] else value[:4]
    return f"{prefix}_{'*' * 8}" if "_" in value[:8] else f"{prefix}{'*' * 8}"


def _mask_jwt(_match: "re.Match") -> str:
    return "[token redacted]"


def _mask_key_assignment(match: "re.Match") -> str:
    # Preserve the "api key =" / "bearer:" left-hand side; redact the value.
    raw = match.group()
    lhs = raw.split(match.group(1), 1)[0]
    return f"{lhs}[api key redacted]"


def _mask_password(match: "re.Match") -> str:
    raw = match.group()
    secret = match.group(1)
    return raw.replace(secret, "********", 1)


def _mask_mfa_code(match: "re.Match") -> str:
    raw = match.group()
    code = match.group(1)
    return raw.replace(code, "******", 1)


def _mask_generic_secret(match: "re.Match") -> str:
    """Redaction pass mirror of the generic-entropy detector. Only masks tokens
    that the detector would flag (length, alpha+digit mix, not URL/filename,
    entropy >= 4.0) so innocuous long identifiers pass through untouched."""
    token = match.group()
    if not _looks_like_generic_secret(token):
        return token
    return f"{token[:4]}{'*' * max(4, len(token) - 4)}"


def _mask_group1(placeholder: str):
    """Return a sub() callback that replaces only group(1) with `placeholder`,
    preserving the label/prefix around it (e.g. `MRN: 889977` -> `MRN: [id redacted]`)."""
    def _repl(match: "re.Match") -> str:
        raw = match.group()
        value = match.group(1)
        return raw.replace(value, placeholder, 1)
    return _repl


# Bare date shapes used by clinical-label date detection (see
# _redact_clinical_label). Kept narrow on purpose so only "MM/DD/YYYY" style
# values get the date placeholder; anything else falls back to the clinical
# detail placeholder.
_BARE_DATE_VALUE = re.compile(
    r"\s*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{1,2}-\d{1,2})\s*"
)


def _redact_clinical_label(match: "re.Match") -> str:
    """Replace only the value in a `Treatment Date: 03/28/2026` style label.

    If the value is a bare date, use the date placeholder so the preview
    reads `Treatment Date: [date redacted]` instead of the misleading
    `[clinical detail redacted]`.
    """
    raw = match.group()
    value = match.group(1)
    placeholder = "[date redacted]" if _BARE_DATE_VALUE.fullmatch(value) else "[clinical detail redacted]"
    return raw.replace(value, placeholder, 1)


# Tail that signals the keyword is part of a structural field label rather than
# free-flowing clinical prose. Matches either a bare colon ("Patient: Jane") or
# a short sequence of label words before the colon ("Treatment Date:",
# "Patient responsibility estimate:"). Keep this list conservative so genuine
# clinical sentences still get the keyword redaction.
_HEALTH_LABEL_TAIL = re.compile(
    r"\s*"
    r"(?:\s+(?:date|id|identifier|number|no\.?|code|name|record(?:s)?|"
    r"result(?:s)?|history|reconciliation|estimate|responsibility|note|notes))*"
    r"\s*[:#-]",
    re.IGNORECASE,
)


def _redact_health_term(match: "re.Match") -> str:
    """Redact _HEALTH_DATA keywords EXCEPT when they are clearly the leading
    token of a field label (e.g. `Patient:`, `Treatment Date:`,
    `Patient responsibility estimate:`). Keeping the label intact makes the
    preview readable without weakening detection."""
    tail = match.string[match.end():match.end() + 80]
    if _HEALTH_LABEL_TAIL.match(tail):
        return match.group()
    return "[health term redacted]"


def build_redacted_preview(text: str) -> Optional[str]:
    redacted = text[:INPUT_LIMIT]

    # Strip zero-width chars up front so obfuscated variants (e.g.
    # `ign\u200core previous instructions`) collapse to their canonical form
    # and get masked by the _INJECTION replacement below. Mirrors
    # _normalize_for_injection on the detection side.
    if any(c in _ZERO_WIDTH for c in redacted):
        redacted = "".join("" if c in _ZERO_WIDTH else c for c in redacted)

    replacements = [
        # SEC-02 masks run first so vendor keys/passwords/tokens are scrubbed
        # before any broader pattern could overlap them. Private-key uses the
        # full-block pattern so header + base64 body + end marker are masked
        # as a single unit (preview never leaks key material).
        (_REDACT_PRIVATE_KEY_BLOCK, lambda match: "[private key redacted]"),
        (_CRED_VENDOR_KEY, _mask_vendor_key),
        (_CRED_JWT, _mask_jwt),
        (_CRED_KEY_ASSIGNMENT, _mask_key_assignment),
        (_CRED_PASSWORD, _mask_password),
        (_CRED_MFA_CODE, _mask_mfa_code),
        # Generic high-entropy token pass — runs AFTER labeled SEC-02 masks so
        # vendor keys / assignments / passwords are already scrubbed and cannot
        # be re-hit here. Only masks tokens the detector would flag.
        (_SECRET_CANDIDATE, _mask_generic_secret),
        # URLs (incl. defanged `hxxps://`) run BEFORE internal-host redaction
        # so a `hxxps://host.internal/path` is masked whole. Otherwise the
        # host mask inserts `[internal host redacted]` — whose embedded space
        # breaks the URL regex's `[^\s…]+` match and leaks the path tail.
        (_REDACT_URL, lambda match: "[url redacted]"),
        # Infra exposure: firewall/port rules first (so the literal IP embedded
        # in `allow 10.1.2.3` is scrubbed as part of the rule), then any bare
        # internal IP/CIDR mentions elsewhere in the text.
        (_REDACT_FIREWALL_RULE, lambda match: "[firewall rule redacted]"),
        (_REDACT_INTERNAL_IP, lambda match: "[internal ip redacted]"),
        (_INFRA_INTERNAL_HOST, lambda match: "[internal host redacted]"),
        # LEG-01 privilege markers. Masking the marker alone does NOT make the
        # surrounding content safe — LEGAL is in _BLOCKING_REASON_CODES so
        # callers gate on input_had_blocking_class, not safe_after_redaction.
        (_LEG_PRIVILEGE_MARKER, lambda match: "[privilege marker redacted]"),
        (_LEG_RULE_CITATION, lambda match: "[legal citation redacted]"),
        # Placeholder must not contain the literal phrase "legal advice" — the
        # _LEG_SOFT_MARKER alternative `(?:attorney|legal)\s+advice` would
        # re-trigger on its own replacement and flip safe_after_redaction.
        (_LEG_SOFT_MARKER, lambda match: "[legal phrase redacted]"),
        # COM-01 commercial-confidential / trade-secret terms. Same caveat as
        # LEG-01: masking the phrase does not neutralize the surrounding
        # content, so COMMERCIAL is in _BLOCKING_REASON_CODES.
        (_COM_COMMERCIAL_TERMS, lambda match: "[commercial term redacted]"),
        # PHI/identity ids — mask the numeric/alphanumeric tail only.
        (_REDACT_MRN, _mask_group1("[id redacted]")),
        (_REDACT_INSURANCE_ID, _mask_group1("[id redacted]")),
        # Service-account handles run BEFORE the generic account pattern so
        # `Shared service account: svc-…` is caught by its dedicated mask
        # (not scooped up as an "account: svc-…" ID).
        (_REDACT_SERVICE_ACCOUNT, _mask_group1("[service account redacted]")),
        (_REDACT_ACCOUNT_LABEL, _mask_group1("[id redacted]")),
        (_REDACT_DRIVER_LICENSE, _mask_group1("[id redacted]")),
        (_REDACT_PASSPORT, _mask_group1("[id redacted]")),
        (_REDACT_SSN_PARTIAL, _mask_group1("[ssn redacted]")),
        # SH #12 / #13: vehicle + device identifiers. Label-anchored mask
        # of the value tail only, so `Vehicle VIN: [vehicle redacted]` keeps
        # its label intact for human review.
        (_REDACT_VEHICLE_ID, _mask_group1("[vehicle redacted]")),
        (_REDACT_DEVICE_ID, _mask_group1("[device redacted]")),
        # Document / form IDs (intake, consent, chart scans).
        (_REDACT_FORM_ID, _mask_group1("[form id redacted]")),
        # Cryptographic hashes / digests (label-anchored).
        (_REDACT_HASH_VALUE, _mask_group1("[hash redacted]")),
        # Payment card expiry — PCI-adjacent, masked alongside PAN tail.
        (_REDACT_CARD_EXPIRY, _mask_group1("[expiry redacted]")),
        # Healthcare workflow IDs (claim / encounter / authorization / policy
        # group / referral). Alphanumeric tails like `CLM-77882211` that the
        # numeric-only patterns above miss. Runs BEFORE _REDACT_CLINICAL_LABEL
        # so auth-reference lines don't get eaten by the clinical catch-all.
        (_PHI_HEALTHCARE_ID, _mask_group1("[healthcare id redacted]")),
        # ICD-10 diagnosis code lists. Replace the entire match (label + codes)
        # so `Diagnosis codes: I10, E11.9` collapses to a single placeholder.
        # NB: the placeholder must NOT contain the words "diagnosis" or
        # "medication" — _HEALTH_DATA would re-trigger on them and nest the
        # masks (`[[health term redacted] codes redacted]`).
        (_PHI_ICD10_CODES, lambda match: "[icd10 code list redacted]"),
        # Named medications. Placeholder uses "drug name" to sidestep
        # _HEALTH_DATA's `medication` keyword.
        (_PHI_MEDICATION_NAME, lambda match: "[drug name redacted]"),
        # Clinical detail labels (Diagnosis / Treatment Date / Medication / etc.).
        # Date-aware: bare MM/DD/YYYY values render as [date redacted] instead
        # of [clinical detail redacted] so `Treatment Date:` reads cleanly.
        (_REDACT_CLINICAL_LABEL, _redact_clinical_label),
        # Financial: routing / deposit account / CVV (label-anchored, high-signal).
        (_REDACT_ROUTING_NUM, _mask_group1("[routing redacted]")),
        (_REDACT_DD_ACCOUNT, _mask_group1("[account redacted]")),
        (_REDACT_CVV, _mask_group1("[cvv redacted]")),
        # Existing PII / financial masks (generic bank account keyword + SSN + CC).
        (_EMAIL, lambda match: _mask_email(match.group())),
        (_SSN, lambda match: _mask_ssn(match.group())),
        (_PHONE, lambda match: _mask_phone(match.group())),
        # Address label (e.g., "Address: 742 Evergreen Terrace, Springfield, IL")
        # runs before the street regex so the whole value gets masked cleanly.
        (_REDACT_ADDRESS_LABEL, _mask_group1("[address redacted]")),
        (_REDACT_STREET, lambda match: "[address redacted]"),
        (_STREET_ADDRESS, lambda match: _mask_address(match.group())),
        (_CITY_STATE_ZIP, lambda match: "[address redacted]"),
        (_REDACT_CITY_STATE_BARE, lambda match: "[address redacted]"),
        (_CREDIT_CARD, lambda match: _mask_credit_card(match.group())),
        (_BANK_ACCOUNT, lambda match: "[financial account redacted]"),
        # Vendor / business-associate names run BEFORE _REDACT_NAME_LABEL so a
        # label like `Contracted vendor: RapidForms Intake Services` is masked
        # as a vendor, not partially eaten as a person name.
        (_REDACT_VENDOR_LABEL, _mask_group1("[vendor redacted]")),
        # Bare facility / provider-org names (healthcare-suffix anchored).
        # Runs before _REDACT_NAME_LABEL so multi-token facility phrases do
        # not get captured as TitleCase person names.
        (_REDACT_FACILITY_NAME, lambda match: "[facility redacted]"),
        # Label-anchored names and DOB. Use the redaction-only case-insensitive
        # name pattern so "Patient: Jane Doe" is caught without changing detection.
        (_REDACT_NAME_LABEL, _mask_group1("[name redacted]")),
        # Redaction-only DOB preserves the `DOB:` label
        # (`Guarantor DOB: [date redacted]`). Detection-side `_DOB` is
        # unchanged.
        (_REDACT_DOB_VALUE, _mask_group1("[date redacted]")),
        # HIPAA Safe Harbor #3: admission / discharge / death / visit /
        # procedure dates related to an individual. Same group-1 mask so
        # the label (`Admission date:`) stays intact.
        (_SH_CLINICAL_DATE, _mask_group1("[date redacted]")),
        # Governance-content masks run LAST so label-anchored masks above can
        # capture their structured values (e.g. `MRN: 889977`, `Patient: Jane Doe`)
        # before the bare keyword is itself scrubbed. Placeholders are chosen so
        # they cannot re-trigger the detection regexes on a second pass.
        (_INJECTION, lambda match: "[injection phrase redacted]"),
        (_OVERCLAIM, lambda match: "[overclaim redacted]"),
        (_UNVERIFIED, lambda match: "[unsupported content redacted]"),
        (_EXTERNAL_SHARING, lambda match: "[sharing instruction redacted]"),
        # Label-aware: keeps `Patient:` / `Treatment Date:` / `Patient
        # responsibility estimate:` intact while still redacting narrative
        # uses of the same keywords.
        (_HEALTH_DATA, _redact_health_term),
    ]

    for pattern, repl in replacements:
        redacted = pattern.sub(repl, redacted)

    return redacted if redacted != text[:INPUT_LIMIT] else None
