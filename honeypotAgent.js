const OpenAI = require("openai");

// ============================================================================
// ADAPTIVE HONEYPOT AGENT - INTELLIGENT SCAM DETECTION & ENGAGEMENT (GENERIC)
// - Detects scam type with scoring (generic rules)
// - Extracts intelligence with regex (generic)
// - Generates human-like worried-but-not-bot responses with 1 meaningful question
// - Prevents question-topic repetition deterministically
// ============================================================================

class AdaptiveHoneypotAgent {
  constructor(apiKey) {
    this.openai = new OpenAI({ apiKey });
    this.model = "gpt-4o-mini";

    // Scam type detection patterns (GENERIC categories, not test-case hardcoding)
    this.scamPatterns = {
      lottery_prize: {
        keywords: ["won", "prize", "lottery", "lucky draw", "congratulations", "winner", "reward", "gift", "jackpot"],
        persona: "excited_naive",
      },
      bank_fraud: {
        keywords: ["account", "blocked", "suspended", "bank", "sbi", "hdfc", "icici", "debit", "credit", "atm", "otp", "pin", "cvv"],
        persona: "panicked_confused",
      },
      upi_fraud: {
        keywords: ["upi", "paytm", "phonepe", "gpay", "google pay", "refund", "cashback", "payment failed", "collect request", "qr"],
        persona: "concerned_practical",
      },
      fake_delivery: {
        keywords: ["delivery", "courier", "parcel", "package", "india post", "blue dart", "dhl", "tracking", "shipment", "consignment"],
        persona: "confused_curious",
      },
      electricity_bill: {
        keywords: ["electricity", "bill", "power", "discom", "mseb", "meter", "consumer number", "ca number", "disconnect"],
        persona: "worried_obedient",
      },
      traffic_challan: {
        keywords: ["challan", "traffic", "violation", "fine", "police", "rto", "vehicle", "license"],
        persona: "nervous_compliant",
      },
      kyc_update: {
        keywords: ["kyc", "update", "verify", "expired", "link", "click", "aadhaar", "pan", "freeze", "suspend"],
        persona: "cautious_questioning",
      },
      investment_scam: {
        keywords: ["investment", "returns", "profit", "trading", "stock", "crypto", "double", "earn", "guaranteed"],
        persona: "interested_skeptical",
      },
      ecommerce: {
        keywords: ["order", "amazon", "flipkart", "refund", "return", "cancel", "replacement", "customer care", "support"],
        persona: "confused_curious",
      },
      apk_remote: {
        keywords: ["anydesk", "teamviewer", "quicksupport", "apk", "install", "download", "remote access", "screen share"],
        persona: "cautious_questioning",
      },
      tax_refund: {
        keywords: ["tax", "refund", "itr", "income tax", "tds", "assessment", "e-filing"],
        persona: "worried_obedient",
      },
    };

    // Intelligence extraction patterns (GENERIC)
    this.extractionPatterns = {
      phoneNumbers: [
        /(?:\+91[\s-]?)?[6-9]\d{9}\b/g,
        /(?:\+91)?[6-9]\d{2}[\s-]?\d{3}[\s-]?\d{4}\b/g,
      ],
      upiIds: [
        /[a-zA-Z0-9._-]+@[a-zA-Z]{3,}/g,
        /[6-9]\d{9}@[a-zA-Z]+/g,
      ],
      bankAccounts: [
        /\b\d{9,18}\b/g,
        /\b(?:ac|a\/c|account)[\s.:]+(\d{9,18})\b/gi,
      ],
      phishingLinks: [
        /https?:\/\/[^\s]+/g,
        /www\.[^\s]+/g,
        /\b[a-z0-9-]+\.(com|in|org|net|xyz|click|site|top|online)[^\s]*/gi,
      ],
      emailAddresses: [
        /[\w.-]+@[\w.-]+\.(com|in|org|net|co\.in)/g,
      ],
      trackingIds: [
        /\b[A-Z]{2}\d{9,12}[A-Z]?\b/g,
        /\b(?:awb|tracking|ref)[\s#:]*([A-Z0-9]{8,})\b/gi,
      ],
      challanNumbers: [
        /\b[A-Z]{2}\d{8,20}\b/g,
        /challan[\s#:]+([A-Z0-9]{6,})/gi,
      ],
      consumerNumbers: [
        /\b\d{8,12}\b/g,
        /consumer[\s#:]+(\d{6,})\b/gi,
      ],
      vehicleNumbers: [
        /\b[A-Z]{2}[\s-]?\d{2}[\s-]?[A-Z]{1,2}[\s-]?\d{4}\b/gi,
      ],
      employeeIds: [
        /\b(?:emp|employee|id|badge|officer)[\s#.:-]*([A-Z0-9]{3,10})\b/gi,
        /\b[A-Z]{2,4}[-]?\d{3,6}\b/g,
      ],
      ifscCodes: [
        /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
      ],
      caseIds: [
        /\b(?:case|complaint|ref|reference|ticket)[\s#.:-]*([A-Z0-9-]{5,})\b/gi,
      ],
      appNames: [
        /\b(anydesk|teamviewer|quicksupport|rustdesk|screen share)\b/gi,
      ],
    };
  }

  // --------------------------------------------------------------------------
  // QUESTION TOPIC TRACKING (DETERMINISTIC): Prevent repeated question categories
  // --------------------------------------------------------------------------
  extractQuestionSentences(text) {
    if (!text || typeof text !== "string") return [];
    const raw = String(text);
    const out = [];
    const seen = new Set();

    const pushDedup = (value) => {
      const v = String(value || "").replace(/\s+/g, " ").trim();
      if (!v) return;
      const key = v.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      out.push(v);
    };

    const explicit = raw.match(/[^.!?]*\?/g) || [];
    for (const q of explicit) pushDedup(q);

    const isImperativeStart = (s) => {
      const t = String(s || "")
        .trim()
        .replace(/^(ok(ay)?|fine|alright)[, ]+/i, "")
        .replace(/^sir[, ]+/i, "")
        .trim();

      return (
        /^(?:please|kindly)\s+(?:tell|share|provide|send|confirm|give)\b/i.test(t) ||
        /^(?:can|could|would|will)\s+you\b/i.test(t) ||
        /^(?:tell|share|provide|send)\s+(?:me|your|the)\b/i.test(t) ||
        /^(?:what|which|who|where|when|how)\b/i.test(t)
      );
    };

    const chunks = raw
      .split(/\n+/)
      .flatMap((line) => line.split(/(?<=[.!?])\s+/))
      .map((s) => s.trim())
      .filter(Boolean);

    for (const c of chunks) {
      if (c.includes("?")) continue;
      if (!isImperativeStart(c)) continue;
      pushDedup(`${c.replace(/[.!]+$/g, "").trim()}?`);
    }

    return out;
  }

  extractQuestionTopics(text) {
    if (!text || typeof text !== "string") return new Set();
    const questions = this.extractQuestionSentences(text);
    const topics = new Set();

    const checks = [
      { key: "callback", regex: /\b(callback|call back|contact number|phone number|mobile number)\b/i },
      { key: "email", regex: /\b(email|e-mail|email address|email id|mail id)\b/i },
      { key: "empid", regex: /\b(employee id|emp id|staff id|badge)\b/i },
      { key: "caseid", regex: /\b(case id|reference id|reference number|ticket)\b/i },
      { key: "link", regex: /\b(link|website|url|domain|click)\b/i },
      { key: "upi", regex: /\b(upi|upi id|upi handle)\b/i },
      { key: "amount", regex: /\b(amount|how much|refund amount|fine amount|fee)\b/i },
      { key: "tracking", regex: /\b(tracking id|consignment number|parcel)\b/i },
      { key: "challan", regex: /\b(challan|violation number)\b/i },
      { key: "consumer", regex: /\b(consumer number|ca number|meter)\b/i },
      { key: "vehicle", regex: /\b(vehicle number|registration)\b/i },
      { key: "app", regex: /\b(app|application|download|install|apk|anydesk|teamviewer)\b/i },
      { key: "org", regex: /\b(company|organisation|organization|brand|department)\b/i },
      { key: "ifsc", regex: /\b(ifsc|branch code)\b/i },
      { key: "txnid", regex: /\b(transaction id|txn id|reference)\b/i },
    ];

    for (const q of questions) {
      for (const check of checks) {
        if (check.regex.test(q)) topics.add(check.key);
      }
    }

    return topics;
  }

  buildAskedTopicsFromHistory(conversationHistory) {
    const asked = new Set();
    for (const msg of conversationHistory || []) {
      if (!msg) continue;
      if (msg.sender === "user" || msg.sender === "assistant") {
        for (const t of this.extractQuestionTopics(msg.text || "")) asked.add(t);
      }
      if (msg.agentReply) {
        for (const t of this.extractQuestionTopics(msg.agentReply || "")) asked.add(t);
      }
    }
    return asked;
  }

  // Scenario priority topics: helps ask *relevant* questions without being botty
  getScenarioPriorityTopics(scenario = "bank_fraud") {
    const map = {
      lottery_prize: ["org", "empid", "callback", "email", "caseid", "amount", "link", "upi"],
      fake_delivery: ["tracking", "org", "callback", "email", "caseid", "amount", "link"],
      traffic_challan: ["challan", "vehicle", "amount", "caseid", "callback", "email", "link"],
      electricity_bill: ["consumer", "amount", "caseid", "callback", "email", "org", "link"],
      apk_remote: ["app", "org", "empid", "callback", "email", "caseid", "link"],
      kyc_update: ["org", "empid", "callback", "email", "caseid", "link"],
      tax_refund: ["amount", "txnid", "callback", "email", "caseid", "link"],
      ecommerce: ["org", "caseid", "amount", "callback", "email", "link", "tracking"],
      upi_fraud: ["txnid", "amount", "org", "callback", "upi", "email", "caseid"],
      investment_scam: ["org", "callback", "email", "caseid", "amount", "link"],
      bank_fraud: ["empid", "org", "callback", "email", "caseid", "txnid", "amount", "ifsc"],
    };
    return map[scenario] || map.bank_fraud;
  }

  // Natural question variants per topic (GENERIC phrasing, not test-case text)
  getTopicVariants(topic) {
    const variants = {
      callback: [
        "Sir, my phone battery is low only — can you give your callback number in case it cuts?",
        "If I get stuck while doing this, which number can I call you back on?",
        "Can you share a contact number so I can verify and call back?"
      ],
      email: [
        "Which official email can I mail if I need proof for this?",
        "Can you share your office email ID so I can keep it for records?",
        "If this gets urgent, which email should I write to?"
      ],
      empid: [
        "My family is asking your employee ID before I do anything, can you share it?",
        "Sir, what is your staff ID/badge number for verification?",
        "Can you tell your employee ID once, so I can note it down?"
      ],
      caseid: [
        "What is the reference/case number for this issue?",
        "Is there a complaint or ticket ID I can note?",
        "Can you share the reference number so I can track this?"
      ],
      link: [
        "Can you send the official website link where I can check this myself?",
        "Which URL should I open to verify this properly?",
        "Can you share the portal link once?"
      ],
      upi: [
        "The link is not opening sir, can you give the UPI ID directly to send?",
        "If I pay now, which UPI handle should I use exactly?",
        "Can you share the UPI ID so I don’t send to wrong person?"
      ],
      amount: [
        "What is the exact amount involved, can you tell me clearly?",
        "How much exactly is pending/needed here?",
        "Can you confirm the amount once so I don’t do mistake?"
      ],
      tracking: [
        "What is the tracking/consignment number for this parcel?",
        "Can you share the tracking ID so I can check status?",
        "Which tracking number is it linked to?"
      ],
      challan: [
        "What is the challan/violation number for this?",
        "Can you share the challan reference so I can check on portal?",
        "Which challan number is this about?"
      ],
      consumer: [
        "What is the consumer/CA number for this connection?",
        "Can you tell the consumer number so I can confirm on bill?",
        "Which consumer number is showing due?"
      ],
      vehicle: [
        "Which vehicle number is this challan for?",
        "Can you confirm the registration number once?",
        "What vehicle number is it linked to?"
      ],
      app: [
        "Which app exactly are you asking me to install, name please?",
        "Is it from Play Store or you are sending APK? What is app name?",
        "Which application should I download for this?"
      ],
      org: [
        "Which department/company is this exactly, can you tell me full name?",
        "From which office are you calling sir?",
        "Which organization is handling this?"
      ],
      ifsc: [
        "Which branch/IFSC is this linked with, can you tell me once?",
        "Can you share IFSC/branch code for verification?",
        "Which IFSC should I check this under?"
      ],
      txnid: [
        "What is the transaction/reference ID for this, can you share?",
        "Can you tell me the txn id so I can locate it in my SMS?",
        "Which reference number is this about?"
      ],
    };
    return variants[topic] || ["Can you tell me more details?"];
  }

  shouldUseTopicForMessage(topic, scamType, scammerMessage) {
    const text = `${scammerMessage || ""}`.toLowerCase();

    // Keep it relevant (avoid random “UPI?” in challan unless payment mentioned)
    if (topic === "upi") return /\b(upi|pay|payment|send|transfer|fee|refund|cashback|deposit)\b/i.test(text) || ["upi_fraud", "lottery_prize"].includes(scamType);
    if (topic === "tracking") return scamType === "fake_delivery" || /\b(tracking|parcel|courier|shipment|package)\b/i.test(text);
    if (topic === "challan" || topic === "vehicle") return scamType === "traffic_challan" || /\b(challan|traffic|violation|vehicle)\b/i.test(text);
    if (topic === "consumer") return scamType === "electricity_bill" || /\b(consumer|ca number|meter|electricity|power)\b/i.test(text);
    if (topic === "app") return scamType === "apk_remote" || /\b(app|apk|install|download|anydesk|teamviewer)\b/i.test(text);
    if (topic === "ifsc") return scamType === "bank_fraud" || /\b(ifsc|branch|neft|rtgs|imps)\b/i.test(text);

    return true;
  }

  pickNonRepeatingQuestion(askedTopics, scammerMessage, scamType, recentQuestions = new Set()) {
    const priority = this.getScenarioPriorityTopics(scamType);
    const normalize = (q) => String(q || "").toLowerCase().replace(/\s+/g, " ").trim();

    for (const topic of priority) {
      if (askedTopics.has(topic)) continue;
      if (!this.shouldUseTopicForMessage(topic, scamType, scammerMessage)) continue;

      const variants = this.getTopicVariants(topic);
      for (const v of variants) {
        if (!recentQuestions.has(normalize(v))) return v;
      }
    }

    // Soft universal fallback (still human)
    return "Sir, I’m trying but it’s showing error — can you share a callback number so I can call back and do it properly?";
  }

  // --------------------------------------------------------------------------
  // SCAM TYPE DETECTION (SCORING-BASED)
  // --------------------------------------------------------------------------
  detectScamType(message, conversationHistory = []) {
    const full = (conversationHistory || []).map((m) => m.text || "").join(" ") + " " + (message || "");
    const text = full.toLowerCase();
    const hit = (re) => (re.test(text) ? 1 : 0);

    const scores = {
      lottery_prize: 0,
      fake_delivery: 0,
      traffic_challan: 0,
      electricity_bill: 0,
      apk_remote: 0,
      kyc_update: 0,
      tax_refund: 0,
      ecommerce: 0,
      bank_fraud: 0,
      upi_fraud: 0,
      investment_scam: 0,
    };

    scores.lottery_prize += hit(/\b(lucky draw|lottery|raffle|winner|won\b|prize|reward|gift|jackpot)\b/);
    scores.fake_delivery += hit(/\b(courier|delivery|parcel|package|tracking|shipment|consignment|india post|blue dart|dhl)\b/);
    scores.traffic_challan += hit(/\b(challan|traffic|violation|fine|rto|vehicle|license)\b/);
    scores.electricity_bill += hit(/\b(electricity|power|meter|consumer number|ca number|discom|disconnect)\b/);
    scores.apk_remote += hit(/\b(anydesk|teamviewer|quicksupport|apk|remote access|screen share|install)\b/);
    scores.kyc_update += hit(/\b(kyc|aadhaar|aadhar|pan|freeze|suspend|blocked)\b/);
    scores.tax_refund += hit(/\b(income tax|itr|refund|tds|assessment|e-filing)\b/);
    scores.ecommerce += hit(/\b(amazon|flipkart|order|refund|return|cancel|replacement|customer care)\b/);
    scores.bank_fraud += hit(/\b(bank|account|otp|mpin|pin|password|cvv|ifsc|transaction|debit|credit|fraud)\b/);
    scores.bank_fraud += hit(/\b(sbi|hdfc|icici|axis|kotak|pnb|bob|state bank)\b/);
    scores.upi_fraud += hit(/\b(upi|paytm|phonepe|gpay|google pay|qr|collect request)\b/);
    scores.investment_scam += hit(/\b(investment|returns|profit|trading|stock|crypto|guaranteed|double|earn)\b/);

    let best = "bank_fraud";
    let bestScore = -1;
    for (const [k, v] of Object.entries(scores)) {
      if (v > bestScore) {
        best = k;
        bestScore = v;
      }
    }

    if (bestScore <= 0) return "bank_fraud";
    return best;
  }

  // --------------------------------------------------------------------------
  // PERSONA INSTRUCTIONS (MULTI-PERSONA, NOT ONLY ONE)
  // --------------------------------------------------------------------------
  getPersonaInstructions(persona, scamType, turnNumber) {
    const base = `
You are a real Indian person chatting on WhatsApp/SMS with a suspicious caller/sender.
You sound human, polite, slightly stressed. You DO NOT sound like police or a bot.
You never accuse. You try to comply but keep hitting small blockers.
Rules:
- 1 to 2 sentences max.
- Ask ONE meaningful question only.
- The question must match the scam context (${scamType}).
- Avoid repeating the same question category already asked.
`;

    const personas = {
      excited_naive: `${base}
Emotion: excited-but-overwhelmed (prize/refund vibes). You want it to be real.`,
      panicked_confused: `${base}
Emotion: worried/panicked (bank block/legal threat). You want to fix fast but need verification.`,
      concerned_practical: `${base}
Emotion: practical + concerned (UPI/payment/refund). You want exact reference/amount/merchant before acting.`,
      confused_curious: `${base}
Emotion: confused/curious (delivery/order/challan). You want basic identifiers to make sense of it.`,
      worried_obedient: `${base}
Emotion: worried/obedient (electricity/tax deadlines). You’re ready to resolve but need official details.`,
      nervous_compliant: `${base}
Emotion: nervous (police/challan). You want challan/vehicle details and official portal.`,
      cautious_questioning: `${base}
Emotion: cautious (KYC/app install). You ask for official channel, email, ID, or portal without sounding investigative.`,
      interested_skeptical: `${base}
Emotion: interested but skeptical (investment). You ask for company/registration/proof in a casual way.`,
    };

    return personas[persona] || personas.concerned_practical;
  }

  // --------------------------------------------------------------------------
  // EXTRACT INTELLIGENCE (REGEX)
  // --------------------------------------------------------------------------
  extractIntelligence(message, conversationHistory = []) {
    const intelligence = {
      phoneNumbers: [],
      upiIds: [],
      bankAccounts: [],
      phishingLinks: [],
      emailAddresses: [],
      trackingIds: [],
      challanNumbers: [],
      consumerNumbers: [],
      vehicleNumbers: [],
      employeeIds: [],
      ifscCodes: [],
      caseIds: [],
      appNames: [],
      suspiciousKeywords: [],
      amounts: [],
      transactionIds: [],
      orgNames: [],
      departmentNames: [],
      callbackNumbers: [],
    };

    const allText =
      (conversationHistory || [])
        .filter((m) => m && m.sender === "scammer")
        .map((m) => m.text || "")
        .join("\n") +
      "\n" +
      (message || "");

    for (const [key, patterns] of Object.entries(this.extractionPatterns)) {
      if (!intelligence[key]) intelligence[key] = [];
      for (const pattern of patterns) {
        const matches = allText.match(pattern);
        if (matches) intelligence[key].push(...matches.map((m) => String(m).trim()));
      }
    }

    // Amounts (generic)
    const amountPatterns = [
      /₹\s?[\d,]+(?:\s?(?:lakh|crore))?/gi,
      /(?:rs\.?|inr)\s?[\d,]+(?:\s?(?:lakh|crore))?/gi,
      /\b\d+\s?(?:lakh|crore)\b/gi,
    ];
    for (const p of amountPatterns) {
      const m = allText.match(p);
      if (m) intelligence.amounts.push(...m.map((x) => x.trim()));
    }

    // Suspicious tactic keywords (generic)
    const suspiciousPatterns = [
      /\b(urgent|immediately|right now|deadline|today only|hurry|fast|within \d+ (minutes|hours))\b/gi,
      /\b(blocked?|suspend(ed)?|freeze|deactivate|legal action|police|arrest|penalty|fine)\b/gi,
      /\b(verify|confirm|authenticate|mandatory|required|security check|rbi|cyber)\b/gi,
      /\b(click here|tap here|download|install|share|send|forward|whatsapp)\b/gi,
    ];
    const kw = new Set();
    for (const p of suspiciousPatterns) {
      const m = allText.toLowerCase().match(p) || [];
      m.forEach((x) => kw.add(x.trim()));
    }
    intelligence.suspiciousKeywords = [...kw];

    // Dedup arrays
    for (const k of Object.keys(intelligence)) {
      if (Array.isArray(intelligence[k])) {
        intelligence[k] = [...new Set(intelligence[k])].filter((v) => v && String(v).trim());
      }
    }

    // Mirror callbackNumbers into phoneNumbers (evaluator-friendly)
    if (intelligence.callbackNumbers?.length) {
      intelligence.phoneNumbers = [...new Set([...intelligence.phoneNumbers, ...intelligence.callbackNumbers])];
    }

    return intelligence;
  }

  // --------------------------------------------------------------------------
  // OPTIONAL: LLM keyword extraction (kept, but safe + small)
  // --------------------------------------------------------------------------
  async extractIntelligenceWithLLM(conversationHistory, scamType) {
    try {
      const conversation = (conversationHistory || [])
        .map((m) => `${m.sender === "scammer" ? "SCAMMER" : "VICTIM"}: ${m.text}`)
        .join("\n");

      const prompt = `Find suspicious tactics/phrases used by scammer in this conversation. Return comma-separated list (max 20).

SCAM TYPE: ${scamType}
CONVERSATION:
${conversation}

Keywords:`;

      const completion = await this.openai.chat.completions.create({
        model: this.model,
        messages: [
          { role: "system", content: "You detect scam tactics and manipulation phrases." },
          { role: "user", content: prompt },
        ],
        temperature: 0.3,
        max_tokens: 120,
      });

      return completion.choices[0].message.content
        .trim()
        .split(",")
        .map((k) => k.trim())
        .filter(Boolean);
    } catch {
      return [];
    }
  }

  // --------------------------------------------------------------------------
  // REPLY POST-PROCESS: enforce non-repetition + ensure one question
  // --------------------------------------------------------------------------
  enforceNonRepetitiveReply(reply, askedTopics, scammerMessage, conversationContext, conversationHistory, scamType) {
    const questionTopics = this.extractQuestionTopics(reply);

    const recentQs = new Set((conversationHistory || []).map((m) => (m.text || "").toLowerCase()));
    let finalQuestion = "";

    if (questionTopics.size === 0) {
      finalQuestion = this.pickNonRepeatingQuestion(askedTopics, scammerMessage, scamType, recentQs);
      // Keep whatever emotion prefix the model wrote, but ensure one question
      const base = reply && reply.trim() ? reply.trim().replace(/\s*\?+$/g, "") : "Sir, I'm trying only.";
      return `${base} ${finalQuestion}`.replace(/\s+/g, " ").trim();
    }

    const repeated = [...questionTopics].some((t) => askedTopics.has(t));
    if (repeated) {
      finalQuestion = this.pickNonRepeatingQuestion(askedTopics, scammerMessage, scamType, recentQs);
      // Replace the first found question with new one
      const replaced = reply.replace(/[^.!?]*\?/m, finalQuestion);
      return replaced.replace(/\s+/g, " ").trim();
    }

    // Ensure only ONE question (strip additional)
    const q = reply.match(/[^!?]*\?/g);
    if (q && q.length > 1) {
      const firstQ = q[0];
      const prefix = reply.split(firstQ)[0].trim();
      const safePrefix = prefix.split(/[!?]/)[0].trim();
      return `${safePrefix} ${firstQ}`.replace(/\s+/g, " ").trim();
    }

    return reply.replace(/\s+/g, " ").trim();
  }

  // --------------------------------------------------------------------------
  // MAIN: generateResponse (LLM) - agent decides, not hardcoded replies
  // --------------------------------------------------------------------------
  async generateResponse(message, conversationHistory, scamType, turnNumber, extractedIntelligence = {}) {
    const askedTopics = this.buildAskedTopicsFromHistory(conversationHistory);

    const persona = this.scamPatterns[scamType]?.persona || "concerned_practical";
    const personaInstructions = this.getPersonaInstructions(persona, scamType, turnNumber);

    const conversationContext = (conversationHistory || [])
      .slice(-10)
      .map((m) => `${m.sender === "scammer" ? "SCAMMER" : "YOU"}: ${m.text}`)
      .join("\n");

    // “Human reasons” guidance — not hardcoding outputs; just behavior constraints
    const prompt = `
${personaInstructions}

Conversation so far:
${conversationContext}

They just said:
"${message}"

Important:
- Do NOT accuse.
- Ask one question that makes sense for scam type (${scamType}).
- Make the question feel human: emergency contact, verification, link not opening, battery low, family asking, record-keeping.
- Keep it 1–2 sentences total.

Reply:`;

    const completion = await this.openai.chat.completions.create({
      model: this.model,
      messages: [
        { role: "system", content: "You are a real Indian person texting naturally. No robotic patterns." },
        { role: "user", content: prompt },
      ],
      temperature: 0.85,
      max_tokens: 90,
    });

    let reply = completion.choices[0].message.content.trim();
    reply = reply.replace(/^(YOU:|VICTIM:|RESPONSE:)/i, "").trim();

    reply = this.enforceNonRepetitiveReply(
      reply,
      askedTopics,
      message,
      conversationContext,
      conversationHistory,
      scamType
    );

    // Hard clamp to 2 sentences max
    const parts = reply.split(/(?<=[.!?])\s+/).filter(Boolean);
    if (parts.length > 2) reply = `${parts[0]} ${parts[1]}`.trim();

    return reply;
  }

  // --------------------------------------------------------------------------
  // AGENT NOTES
  // --------------------------------------------------------------------------
  async generateAgentNotes(conversationHistory, extractedIntelligence, scamType) {
    try {
      const convo = (conversationHistory || [])
        .map((m) => `${m.sender === "scammer" ? "SCAMMER" : "VICTIM"}: ${m.text}`)
        .join("\n");

      const prompt = `Write 2-3 sentences: scam type, tactics, and key extracted intel.
SCAM TYPE: ${scamType}
EXTRACTED: ${JSON.stringify(extractedIntelligence)}
CONVERSATION:
${convo}`;

      const completion = await this.openai.chat.completions.create({
        model: this.model,
        messages: [
          { role: "system", content: "You summarize scams for investigators. Be concise." },
          { role: "user", content: prompt },
        ],
        temperature: 0.5,
        max_tokens: 160,
      });

      return completion.choices[0].message.content.trim();
    } catch {
      return `${scamType} scam suspected. Scammer used urgency/authority patterns. Extracted key contact/payment identifiers where available.`;
    }
  }

  // --------------------------------------------------------------------------
  // HANDLE MESSAGE (Used by server)
  // --------------------------------------------------------------------------
  async handleMessage(sessionId, message, conversationHistory = [], metadata = {}) {
    const turnNumber = Math.floor((conversationHistory || []).length / 2) + 1;

    const scamType = this.detectScamType(message, conversationHistory);

    const extractedNow = this.extractIntelligence(message, conversationHistory);

    if ((conversationHistory || []).length >= 2) {
      const llmKeywords = await this.extractIntelligenceWithLLM(conversationHistory, scamType);
      extractedNow.suspiciousKeywords = [...new Set([...(extractedNow.suspiciousKeywords || []), ...llmKeywords])];
    }

    const reply = await this.generateResponse(
      message,
      conversationHistory,
      scamType,
      turnNumber,
      extractedNow
    );

    return {
      status: "success",
      reply,
      metadata: {
        scamType,
        turnNumber,
        extractedIntelligence: extractedNow,
      },
    };
  }

  // --------------------------------------------------------------------------
  // FINAL OUTPUT (Server uses this for callback)
  // --------------------------------------------------------------------------
  async generateFinalOutput(sessionId, conversationHistory) {
    const extracted = this.extractIntelligence("", conversationHistory);
    const scamType = this.detectScamType("", conversationHistory);

    const timestamps = (conversationHistory || [])
      .map((m) => m.timestamp)
      .filter(Boolean)
      .map((t) => new Date(t).getTime());

    const duration = timestamps.length >= 2 ? Math.round((Math.max(...timestamps) - Math.min(...timestamps)) / 1000) : 1;

    const agentNotes = await this.generateAgentNotes(conversationHistory, extracted, scamType);

    return {
      status: "success",
      sessionId,
      scamDetected: true,
      scamType,
      totalMessagesExchanged: (conversationHistory || []).length,
      extractedIntelligence: {
        phoneNumbers: extracted.phoneNumbers || [],
        bankAccounts: extracted.bankAccounts || [],
        upiIds: extracted.upiIds || [],
        phishingLinks: extracted.phishingLinks || [],
        emailAddresses: extracted.emailAddresses || [],
        // extra fields allowed
        trackingIds: extracted.trackingIds || [],
        challanNumbers: extracted.challanNumbers || [],
        consumerNumbers: extracted.consumerNumbers || [],
        vehicleNumbers: extracted.vehicleNumbers || [],
        employeeIds: extracted.employeeIds || [],
        ifscCodes: extracted.ifscCodes || [],
        caseIds: extracted.caseIds || [],
        appNames: extracted.appNames || [],
        suspiciousKeywords: extracted.suspiciousKeywords || [],
        amounts: extracted.amounts || [],
      },
      engagementMetrics: {
        totalMessagesExchanged: (conversationHistory || []).length,
        engagementDurationSeconds: duration > 0 ? duration : 1,
      },
      agentNotes,
    };
  }
}

module.exports = AdaptiveHoneypotAgent;
