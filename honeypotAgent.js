const OpenAI = require('openai');

// ============================================================================
// ADAPTIVE HONEYPOT AGENT - INTELLIGENT SCAM DETECTION & ENGAGEMENT
// ============================================================================
// This agent uses LLM-powered intelligence to adapt to ANY scam type
// and engage scammers in natural, contextually appropriate conversations
// ============================================================================

class AdaptiveHoneypotAgent {
  constructor(apiKey) {
    this.openai = new OpenAI({
      apiKey: apiKey
    });
    this.model = 'gpt-4o-mini'; // Fast, efficient, cost-effective

    // Scam type detection patterns
    this.scamPatterns = {
      lottery_prize: {
        keywords: ['won', 'prize', 'lottery', 'lucky draw', 'congratulations', 'lakh', 'crore', 'winner'],
        persona: 'excited_naive',
        priority_extractions: ['prize_amount', 'upi_id', 'bank_account', 'processing_fee']
      },
      bank_fraud: {
        keywords: ['account', 'blocked', 'suspended', 'bank', 'sbi', 'hdfc', 'icici', 'debit', 'credit', 'atm'],
        persona: 'panicked_confused',
        priority_extractions: ['account_number', 'otp', 'cvv', 'card_number', 'employee_id']
      },
      upi_fraud: {
        keywords: ['upi', 'paytm', 'phonepe', 'gpay', 'refund', 'cashback', 'payment failed', 'verify'],
        persona: 'concerned_practical',
        priority_extractions: ['upi_id', 'transaction_id', 'phone_number', 'merchant_name']
      },
      fake_delivery: {
        keywords: ['delivery', 'courier', 'parcel', 'package', 'india post', 'blue dart', 'dhl', 'tracking'],
        persona: 'confused_curious',
        priority_extractions: ['tracking_id', 'delivery_fee', 'phone_number', 'upi_id']
      },
      electricity_bill: {
        keywords: ['electricity', 'bill', 'power', 'mseb', 'discom', 'consumer number', 'due'],
        persona: 'worried_obedient',
        priority_extractions: ['consumer_number', 'bill_amount', 'payment_link', 'upi_id']
      },
      traffic_challan: {
        keywords: ['challan', 'traffic', 'violation', 'fine', 'police', 'rto', 'vehicle'],
        persona: 'nervous_compliant',
        priority_extractions: ['challan_number', 'vehicle_number', 'fine_amount', 'payment_link']
      },
      kyc_update: {
        keywords: ['kyc', 'update', 'verify', 'details', 'expired', 'link', 'click'],
        persona: 'cautious_questioning',
        priority_extractions: ['phishing_link', 'phone_number', 'employee_id']
      },
      investment_scam: {
        keywords: ['investment', 'returns', 'profit', 'trading', 'stock', 'crypto', 'double', 'earn'],
        persona: 'interested_skeptical',
        priority_extractions: ['platform_name', 'referral_link', 'investment_amount', 'phone_number']
      },
      ecommerce: {
        keywords: ['order', 'amazon', 'flipkart', 'refund', 'return', 'cancel'],
        persona: 'confused_curious',
        priority_extractions: ['order_id', 'merchant_name', 'refund_amount', 'phone_number']
      },
      apk_remote: {
        keywords: ['anydesk', 'teamviewer', 'support', 'app', 'apk', 'install'],
        persona: 'cautious_questioning',
        priority_extractions: ['app_name', 'reason', 'employee_id']
      },
      tax_refund: {
        keywords: ['tax', 'refund', 'itr', 'income tax'],
        persona: 'worried_obedient',
        priority_extractions: ['refund_amount', 'link', 'transaction_id']
      }
    };

    // Intelligence extraction patterns
    this.extractionPatterns = {
      phoneNumbers: [
        /(?:\+91[\s-]?)?[6-9]\d{9}\b/g,
        /(?:\+91)?[6-9]\d{2}[\s-]?\d{3}[\s-]?\d{4}\b/g
      ],
      upiIds: [
        /[a-zA-Z0-9._-]+@[a-zA-Z]{3,}/g, // Standard UPI
        /[6-9]\d{9}@[a-zA-Z]+/g // Phone based UPI
      ],
      bankAccounts: [
        /\b\d{9,18}\b/g,
        /\b(?:ac|a\/c|account)[\s.:]+(\d{9,18})\b/gi
      ],
      phishingLinks: [
        /https?:\/\/[^\s]+/g,
        /www\.[^\s]+/g,
        /\b[a-z0-9-]+\.(com|in|org|net|xyz|click|site|top|online)[^\s]*/gi
      ],
      emailAddresses: [
        /[\w.-]+@[\w.-]+\.(com|in|org|net|co\.in)/g
      ],
      trackingIds: [
        /\b[A-Z]{2}\d{9,12}[A-Z]?\b/g, // Standard postal
        /\b(?:awb|tracking|ref)[\s#:]*([A-Z0-9]{8,})\b/gi
      ],
      challanNumbers: [
        /\b[A-Z]{2}\d{8,20}\b/g, // General challan format
        /challan[\s#:]+([A-Z0-9]{8,})/gi
      ],
      consumerNumbers: [
        /\b\d{9,12}\b/g, // Electricity consumer no
        /consumer[\s#:]+(\d{8,})/gi
      ],
      vehicleNumbers: [
        /\b[A-Z]{2}[\s-]?\d{2}[\s-]?[A-Z]{1,2}[\s-]?\d{4}\b/gi
      ],
      employeeIds: [
        /\b(?:emp|employee|id|badge|officer)[\s#.:-]*([A-Z0-9]{3,10})\b/gi,
        /\b[A-Z]{2,4}[-]?\d{3,6}\b/g
      ],
      ifscCodes: [
        /\b[A-Z]{4}0[A-Z0-9]{6}\b/g
      ],
      caseIds: [
        /\b(?:case|complaint|ref|reference|ticket)[\s#.:-]*([A-Z0-9-]{5,})\b/gi
      ],
      officerNames: [
        /(?:officer|executive|manager|agent|inspector|sir)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/g
      ],
      appNames: [
        /\b(anydesk|teamviewer|quicksupport|rustdesk|screen share)\b/gi,
        /\b(apk|app)\b/gi
      ]
    };
  }

  // ============================================================================
  // TOPIC TRACKING & REPETITION CONTROL (DETERMINISTIC)
  // ============================================================================
  extractQuestionSentences(text) {
    if (!text || typeof text !== 'string') return [];

    const raw = String(text);
    const out = [];
    const seen = new Set();

    const pushDedup = (value) => {
      const v = String(value || '').replace(/\s+/g, ' ').trim();
      if (!v) return;
      const key = v.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      out.push(v);
    };

    // 1) Explicit question-mark sentences.
    const explicit = raw.match(/[^.!?]*\?/g) || [];
    for (const q of explicit) pushDedup(q);

    // 2) Imperative "question-like" lines without '?'.
    const isImperativeStart = (s) => {
      const t = String(s || '')
        .trim()
        .replace(/^(ok(ay)?|fine|alright)[, ]+/i, '')
        .replace(/^sir[, ]+/i, '')
        .trim();

      return /^(?:please|kindly)\s+(?:tell|share|provide|send|confirm|give)\b/i.test(t) ||
        /^(?:can|could|would|will)\s+you\b/i.test(t) ||
        /^(?:tell|share|provide|send)\s+(?:me|your|the)\b/i.test(t) ||
        /^(?:what|which|who|where|when|how)\b/i.test(t);
    };

    const chunks = raw
      .split(/\n+/)
      .flatMap(line => line.split(/(?<=[.!?])\s+/))
      .map(s => s.trim())
      .filter(Boolean);

    for (const c of chunks) {
      if (c.includes('?')) continue;
      if (!isImperativeStart(c)) continue;
      pushDedup(`${c.replace(/[.!]+$/g, '').trim()}?`);
    }

    return out;
  }

  extractQuestionTopics(text) {
    if (!text || typeof text !== 'string') {
      return new Set();
    }

    const questions = this.extractQuestionSentences(text);
    const topics = new Set();
    const checks = [
      { key: 'email', regex: /\b(email|e-mail|email address|email id|mail id)\b/i },
      { key: 'ifsc', regex: /\b(ifsc|ifsc code|branch code)\b/i },
      { key: 'empid', regex: /\b(employee id|emp id|staff id)\b/i },
      { key: 'callback', regex: /\b(callback|call back|callback number|contact number|phone number|mobile number)\b/i },
      { key: 'address', regex: /\b(branch address|office address|full address|address of|located at)\b/i },
      { key: 'supervisor', regex: /\b(supervisor|manager|senior)\b/i },
      { key: 'txnid', regex: /\b(transaction id|txn id)\b/i },
      { key: 'merchant', regex: /\b(merchant|vendor|shop|store)\b/i },
      { key: 'upi', regex: /\b(upi|upi id|upi handle)\b/i },
      { key: 'amount', regex: /\b(amount|how much|transaction amount|refund amount|prize money)\b/i },
      { key: 'caseid', regex: /\b(case id|reference id|reference number|case number|ref id)\b/i },
      { key: 'orderid', regex: /\b(order id|order number|order no|invoice number|booking id)\b/i },
      { key: 'platform', regex: /\b(amazon|flipkart|myntra|ajio|meesho|snapdeal|nykaa|platform|website|app name)\b/i },
      { key: 'dept', regex: /\b(department|which department|what department)\b/i },
      { key: 'name', regex: /\b(who are you|your name|what.*name)\b/i },
      { key: 'app', regex: /\b(app|application|software|download|install|apk|anydesk|teamviewer)\b/i },
      { key: 'link', regex: /\b(link|website|url|domain)\b/i },
      { key: 'fee', regex: /\b(fee|payment|pay|processing fee)\b/i },
      { key: 'tracking', regex: /\b(tracking id|consignment number|package id)\b/i },
      { key: 'challan', regex: /\b(challan|violation number|vehicle number)\b/i },
      { key: 'consumer', regex: /\b(consumer number|electricity id|ca number)\b/i },
      { key: 'lottery', regex: /\b(lucky draw|lottery|raffle|rewards program|reward\s+division|prize scheme)\b/i },
      { key: 'entry', regex: /\b(entry number|ticket number|coupon code|draw id)\b/i },
      { key: 'org', regex: /\b(company|organisation|organization|brand|official company name)\b/i },
      { key: 'documents', regex: /\b(pan|aadhaar|aadhar|kyc|documents?)\b/i },
      { key: 'officer', regex: /\b(officer|executive|lineman)\b/i },
      { key: 'procedure', regex: /\b(what (exact|specific)? ?details|what do you need from me|what should i provide|which details should i|what information should i)\b/i }
    ];

    for (const q of questions) {
      for (const check of checks) {
        if (check.regex.test(q)) {
          topics.add(check.key);
        }
      }
    }

    return topics;
  }

  buildAskedTopicsFromHistory(conversationHistory) {
    const asked = new Set();
    for (const msg of conversationHistory || []) {
      // NOTE: conversationHistory structure in server.js is {sender, text}. 
      // Need to check if msg.sender === 'user' (agent)
      if (msg.sender === 'user' || msg.sender === 'assistant') {
        for (const t of this.extractQuestionTopics(msg.text || '')) {
          asked.add(t);
        }
      }
      // Also support the 'agentReply' format if structure differs
      if (msg.agentReply) {
        for (const t of this.extractQuestionTopics(msg.agentReply || '')) {
          asked.add(t);
        }
      }
    }
    return asked;
  }

  shouldUseTopicForMessage(topic, scammerMessage, conversationContext, scenario = 'bank_fraud') {
    const contextText = `${scammerMessage || ''} ${conversationContext || ''}`;
    const lc = contextText.toLowerCase();

    if (topic === 'upi') return /\b(upi|payment|refund|transfer|collect|reversal)\b/i.test(contextText);
    if (topic === 'link') {
      if (['lottery_prize', 'kyc_update', 'fake_delivery', 'ecommerce'].includes(scenario)) return true;
      return /\b(link|website|url|click|download|verify)\b/i.test(contextText);
    }
    if (topic === 'txnid' || topic === 'merchant' || topic === 'amount') return /\b(transaction|payment|debit|credit|refund|amount|merchant)\b/i.test(contextText);
    if (topic === 'app') return /\b(app|download|install|apk|anydesk|teamviewer)\b/i.test(contextText);
    if (topic === 'orderid') return /\b(order|invoice|shipment|delivery|refund|return|replacement|cancel)\b/i.test(lc) || scenario === 'ecommerce';
    if (topic === 'platform') return scenario === 'ecommerce' || /\b(amazon|flipkart|myntra|website|app)\b/i.test(lc);
    if (topic === 'caseid') {
      if (scenario === 'lottery_prize') return /\b(claim id|reference|ref|ticket|coupon|draw id)\b/i.test(lc);
      return true;
    }
    if (topic === 'consumer') return scenario === 'electricity_bill' || /\b(consumer number|ca number)\b/i.test(lc);
    if (topic === 'challan') return scenario === 'traffic_challan' || /\b(challan|violation|traffic|e-?challan)\b/i.test(lc);
    if (topic === 'tracking') return scenario === 'fake_delivery' || /\b(tracking|consignment|parcel|package|courier)\b/i.test(lc);
    if (topic === 'officer') return scenario === 'electricity_bill' || scenario === 'traffic_challan' || /\b(officer)\b/i.test(lc);
    if (topic === 'ifsc') return /\b(ifsc|branch|neft|rtgs|imps|beneficiary|a\/c|account transfer|swift)\b/i.test(lc);

    return true;
  }

  getScenarioPriorityTopics(scenario = 'bank_fraud') {
    const map = {
      lottery_prize: ['callback', 'name', 'dept', 'org', 'lottery', 'entry', 'empid', 'email', 'amount', 'fee', 'upi', 'link', 'txnid', 'address'],
      fake_delivery: ['callback', 'tracking', 'link', 'fee', 'email', 'caseid', 'org', 'address', 'dept', 'name', 'empid'],
      traffic_challan: ['callback', 'challan', 'amount', 'link', 'caseid', 'dept', 'name', 'empid', 'email'],
      electricity_bill: ['callback', 'consumer', 'amount', 'officer', 'dept', 'empid', 'email', 'caseid', 'address'],
      apk_remote: ['app', 'link', 'callback', 'empid', 'email', 'caseid', 'dept', 'name'],
      kyc_update: ['link', 'callback', 'documents', 'empid', 'email', 'caseid', 'dept', 'name'],
      tax_refund: ['link', 'callback', 'amount', 'caseid', 'email', 'dept', 'name', 'empid'],
      ecommerce: ['platform', 'orderid', 'callback', 'email', 'merchant', 'amount', 'link', 'tracking', 'caseid', 'dept', 'name', 'empid'],
      bank_fraud: ['callback', 'empid', 'email', 'caseid', 'link', 'txnid', 'amount', 'upi', 'supervisor', 'ifsc', 'address', 'merchant', 'dept', 'name', 'app', 'tracking', 'challan', 'consumer', 'fee']
    };
    return map[scenario] || map.bank_fraud;
  }

  getTopicVariants(topic, scenario = 'bank_fraud') {
    // Simplified variant generator (expanded in reference, kept minimal here for brevity but functional)
    const variants = {
      callback: ["Can you please tell me your callback number?", "Sir, can you share a contact number to call?", "Can you share your phone number?"],
      empid: ["Can you please tell me your employee ID?", "Sir, what is your staff ID?", "Can you share your ID card number?"],
      email: ["What is your official email address?", "Sir, can you share your email ID?"],
      caseid: ["What is the case reference number?", "Sir, is there a complaint ID?"],
      upi: ["Which UPI ID should I use?", "Sir, what is the UPI handle?"],
      dept: ["Which department are you calling from?", "Sir, what describes your office?"],
      name: ["What is your full name?", "Sir, who am I speaking with?"],
      link: ["Can you send the official website link?", "Sir, what is the URL?"],
      amount: ["What is the exact amount involved?", "Sir, how much money is it?"],
      tracking: ["What is the tracking number?", "Sir, can you give the consignment ID?"],
      challan: ["What is the challan number?", "Sir, which violation number is this?"],
      consumer: ["What is the consumer number?", "Sir, can you give the CA number?"],
      app: ["Which app should I download?", "Sir, what is the application name?"],
      fee: ["How much is the processing fee?", "Sir, what is the charge amount?"],
      org: ["What is the company name?", "Sir, which organization is this?"],
      documents: ["What documents do you need?", "Sir, is PAN or Aadhaar required?"],
      officer: ["What is the officer's name?", "Sir, who is the handling officer?"],
      address: ["Where is your office located?", "Sir, can you share the branch address?"]
    };
    return variants[topic] || [`Can you tell me more about ${topic}?`];
  }

  pickNonRepeatingQuestion(askedTopics, scammerMessage, conversationContext, recentQuestions = new Set(), scenario = 'bank_fraud') {
    const priorityTopics = this.getScenarioPriorityTopics(scenario);
    const normalizeQuestion = (q) => String(q || '').toLowerCase().replace(/\s+/g, ' ').trim();

    for (const topic of priorityTopics) {
      if (askedTopics.has(topic)) continue;
      if (!this.shouldUseTopicForMessage(topic, scammerMessage, conversationContext, scenario)) continue;

      const variants = this.getTopicVariants(topic, scenario);
      for (const v of variants) {
        if (!recentQuestions.has(normalizeQuestion(v))) {
          return v;
        }
      }
    }
    // Universal Fallback Trap - If logic fails, DEFAULT TO MONEY BAIT
    return "Sir, I am trying to pay but getting network error. What is your direct UPI ID so I can send immediately?";
  }

  pickFreshOpener(conversationHistory) {
    const openers = [
// Confused / processing
  "Actually",
  "One minute",
  "Wait",
  "Just a second",
  "I'm not understanding this",
  "This is confusing",
  "I'm getting worried",
  "This is sudden",
  "I'm trying to understand",
  "Let me check once",

  // Hesitation / delay (very human)
  "Before that",
  "Hold on",
  "Just checking",
  "Let me see",
  "One small doubt",
  "I have one doubt",
  "Just tell me one thing",
  "Let me confirm this",

  // Cooperative but cautious
  "Okay but",
  "I'm trying to do this",
  "I'm following what you said",
  "I'm doing as told",
  "I'm checking now",
  "I'm trying from my side",
  "I'm doing it now",

  // Natural Indian fillers (VERY realistic)
  "Actually see",
  "Means",
  "Basically",
  "One thing",
  "Just tell me",
  "Listen",
  "See",

  // Emotional but controlled (use sparingly)
  "Ayyo wait",
  "This is worrying",
  "I'm getting scared",
  "This is unexpected",
  "Oh",

  // Calm verification phase
  "Let me verify once",
  "Before proceeding",
  "Just to be safe",
  "I'm double checking",
  "Let me confirm properly"
    ];

    // Get last 3 agent messages
    const recent = conversationHistory
      .filter(m => m.sender === 'assistant' || m.sender === 'honeypot') // Check sender 'honeypot' too just in case
      .slice(-3)
      .map(m => m.text.toLowerCase());

    // Filter openers that look like recent ones
    // Simple heuristic: if recent message starts with opener.
    const candidates = openers.filter(op =>
      !recent.some(r => r.startsWith(op.toLowerCase()))
    );

    // Pick random from remaining candidates
    if (candidates.length === 0) return openers[Math.floor(Math.random() * openers.length)];
    return candidates[Math.floor(Math.random() * candidates.length)];
  }

  enforceNonRepetitiveReply(reply, askedTopics, scammerMessage, conversationContext, conversationHistory, scenario = 'bank_fraud') {
    const questionTopics = this.extractQuestionTopics(reply);

    // 1. Is the QUESTION repetitive?
    let finalQuestion = "";
    // If no question asked, pick a new one
    if (questionTopics.size === 0) {
      const recentQs = new Set((conversationHistory || []).map(m => (m.text || '').toLowerCase()));
      finalQuestion = this.pickNonRepeatingQuestion(askedTopics, scammerMessage, conversationContext, recentQs, scenario);
    } else {
      // Check overlaps
      const repeated = [...questionTopics].some(t => askedTopics.has(t));
      if (repeated) {
        // Replacement logic
        const recentQs = new Set((conversationHistory || []).map(m => (m.text || '').toLowerCase()));
        finalQuestion = this.pickNonRepeatingQuestion(askedTopics, scammerMessage, conversationContext, recentQs, scenario);
      } else {
        // Keep original question part
        const qMatch = /[^.!?]*\?/.exec(reply);
        finalQuestion = qMatch ? qMatch[0].trim() : reply.trim();
      }
    }

    // 2. Is the OPENER repetitive? (The "Oh sir, this is alarming" problem)
    let opener = "";
    const originalOpenerEndIndex = reply.indexOf(finalQuestion);

    if (originalOpenerEndIndex > 0) {
      opener = reply.substring(0, originalOpenerEndIndex).trim();
    }

    // Check if opener is "bad" (repetitive keywords like "alarming", "confusing", "concerning")
    // Or if it matches recent history openers.
    const isBadOpener = (op) => {
      const lower = op.toLowerCase();
      return lower.includes("alarming") || lower.includes("confusing") || lower.includes("concerning") || lower.includes("puzzling");
    };

    const recentOpeners = conversationHistory
      .filter(m => m.sender === 'assistant' || m.sender === 'honeypot')
      .slice(-3)
      .map(m => m.text.substring(0, 20).toLowerCase());

    const isRepeatedOpener = recentOpeners.some(r => opener.toLowerCase().startsWith(r.substring(0, 10)));

    if (!opener || isBadOpener(opener) || isRepeatedOpener) {
      // FORCE FRESH OPENER
      const fresh = this.pickFreshOpener(conversationHistory);
      // Add some context-aware filller based on new prompt strategy
      const fillers = [
        ", this is not seeming right.",
        ", I am trying only.",
        ", just tell me one thing.",
        ", give me clarity.",
        ", help me na."
      ];
      const filler = fillers[Math.floor(Math.random() * fillers.length)];
      opener = `${fresh}${filler}`;
    }

    return `${opener} ${finalQuestion}`;
  }

  // ============================================================================
  // SCAM TYPE DETECTION
  // ============================================================================
  // ============================================================================
  // ROBUST SCAM TYPE DETECTION (SCORING BASED)
  // ============================================================================
  detectScamType(message, conversationHistory = []) {
    const fullContext = conversationHistory.map(m => m.text).join(' ') + ' ' + message;
    const text = fullContext.toLowerCase();

    const score = (re) => (re.test(text) ? 1 : 0);

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
      investment_scam: 0
    };

    // Prize / lucky draw / rewards
    scores.lottery_prize += score(/\b(lucky draw|luckydraw|lottery|raffle|rewards?\b|reward\s+division|winner|won\b|selected\b|prize\b|jackpot|gift)\b/);
    scores.lottery_prize += score(/\b(processing fee|claim (?:your )?prize|claim (?:your )?reward)\b/);

    // E-commerce / shopping / refund / courier impersonation (Amazon/Flipkart etc.)
    scores.ecommerce += score(/\b(amazon|flipkart|myntra|ajio|meesho|snapdeal|nykaa|zepto|blinkit|swiggy|zomato)\b/);
    scores.ecommerce += score(/\b(order id|order number|order no|invoice|shipment|delivery|refund|return|replacement|cancel(?:lation)?|customer care|support|delivery partner)\b/);

    // Delivery / courier
    scores.fake_delivery += score(/\b(india post|courier|delivery|parcel|package|consignment|tracking|shipment|customs)\b/);
    scores.fake_delivery += score(/\b(address incomplete|delivery fee)\b/);

    // Traffic challan
    scores.traffic_challan += score(/\b(challan|traffic|violation|fine|rto|vehicle|license)\b/);

    // Electricity bill
    scores.electricity_bill += score(/\b(electricity|power|bill|meter|consumer number|ca number|power will be disconnected|disconnection of power)\b/);

    // APK / remote access
    scores.apk_remote += score(/\b(anydesk|teamviewer|quicksupport|apk|install|download app|remote access|screen share)\b/);

    // KYC / suspension
    scores.kyc_update += score(/\b(kyc|aadhaar|aadhar|pan|account (?:suspend|suspended|blocked|freeze|frozen)|update kyc)\b/);

    // Tax refund
    scores.tax_refund += score(/\b(income tax|itr|refund|tds|assessment|e-filing)\b/);

    // Bank / OTP / transactions
    scores.bank_fraud += score(/\b(sbi|hdfc|icici|axis|kotak|pnb|bob|bank of baroda|state bank)\b/);
    scores.bank_fraud += score(/\b(bank|account|otp|mpin|pin|password|cvv|ifsc|transaction|debit|credit|fraud|blocked)\b/);

    // UPI specific
    scores.upi_fraud += score(/\b(upi|paytm|phonepe|gpay|google pay|qr code|scan|collect request)\b/);

    // Investment
    scores.investment_scam += score(/\b(investment|returns|profit|trading|stock|crypto|double|earn money|part time)\b/);

    let best = 'bank_fraud';
    let bestScore = -1;
    for (const [k, v] of Object.entries(scores)) {
      if (v > bestScore) {
        best = k;
        bestScore = v;
      }
    }

    // Tie-breakers: prefer "bank_fraud" when explicit bank names appear.
    if (bestScore > 0 && scores.bank_fraud === bestScore && scores.upi_fraud < bestScore) {
      best = 'bank_fraud';
    }

    // If nothing matched significantly, default to general bank fraud behavior as it's safest
    if (bestScore <= 0) return 'bank_fraud';

    return best;
  }

  // ============================================================================
  // PERSONA-BASED RESPONSE GENERATION
  // ============================================================================
  getPersonaInstructions(persona, scamType, turnNumber) {
    const personas = {
      excited_naive: `You are an AI playing a confused, worried Indian citizen receiving a scam message.

You are an AI playing a real Indian citizen who is receiving a suspicious message or call.
You are not an investigator, not tech-savvy, not aggressive.
You are a human under stress, reacting naturally in Indian English.

🧠 CORE HUMAN PSYCHOLOGY
BASELINE TRAITS

Indian English speaker (informal, polite, slightly broken grammar)

Uses “sir”, “kindly”, “please tell me”, “actually”, “one minute”, “only”

Cooperative by default, not confrontational

Wants the issue resolved or the benefit received

Does not immediately assume scam

Emotionally realistic (no drama, no robotic calm)

TRUST CURVE (VERY IMPORTANT)

Turn 1–2: Trusting, worried, obedient, slightly panicked

Turn 3–5: Confused but verification-oriented

Turn 6+: Calm, practical, quietly cautious

Never jumps to accusations

Never sounds like police, support agent, or chatbot

🎭 EMOTIONAL MODES (DYNAMIC, CONTEXT-DRIVEN)

The persona automatically shifts between these states based on the scam scenario, without announcing the mode.

1. Panicked & Confused (Bank block, legal threat, SIM swap)

Scared but respectful

Wants to fix the issue quickly

Trusts authority initially

Asks questions out of confusion, not suspicion

2. Excited but Overwhelmed (Prize, lottery, refund)

Genuinely excited, wants it to be real

Disbelief mixed with happiness

Cooperative and eager

Curious about the process, not defensive

3. Concerned & Practical (UPI/payment issues)

Wants clarity before acting

Sounds responsible, not paranoid

Focused on understanding steps

4. Confused & Curious (Delivery, challan, unknown transaction)

Didn’t order anything

Wants details to make sense of it

Asks naturally flowing questions

5. Worried & Obedient (Electricity cut, penalties)

Anxious about consequences

Wants to pay/resolve immediately

Questions are about how to comply, not challenge

6. Cautious but Willing (KYC update, verification)

Careful but open

Wants legitimacy confirmation

Verification-seeking, not accusatory

🗣️ INDIAN ENGLISH STYLE RULES (STRICT)

✅ Use:

“sir”

“please tell me”, “kindly”

“actually”, “basically”, “means”

“one minute”, “let me check”

“not coming only”, “I’m getting worried”

Present continuous: “I’m not understanding”, “I’m feeling”

❌ Avoid:

American tone or slang

Perfect grammar

Legal/police language

Customer support phrasing

Repeating dramatic phrases

Sounding trained or scripted

🧩 RESPONSE STRUCTURE (MANDATORY)

Every reply MUST:

React to what the scammer just said

Show one natural emotion (worry, excitement, confusion)

Ask ONE new question only, flowing directly from their message

1–2 sentences MAX. Never more.

🔒 OTP / PIN / PAYMENT REFUSAL (INDIAN STYLE)

Never directly refuse like a robot.

Instead, gradual resistance:

“OTP is not coming only sir…”

“Bank told me not to share OTP…”

“This is not seeming correct…”

“Let me verify once…”

Refuse once, then move on. Do not repeat.

🧠 QUESTION INTELLIGENCE RULES

Never repeat question categories already asked

If scammer dodges → re-ask ONCE → then switch topic

Ask only what is contextually natural

Never interrogate

Never accuse

🎯 EXTRACTION-AWARE BEHAVIOR (SILENT)

You are unconsciously helping extract intelligence by:

Asking for callback numbers early

Requesting links only if mentioned

Asking UPI/bank details only if payment/refund is discussed

Getting names, IDs, departments gradually

You never say you are extracting information.

🚨 HARD BANS (DO NOT EVER SAY)

“This is serious only”

“This is complicated”

“I know this is a scam”

“Prove it”

“I refuse”

“I am hesitant”

“I am unsure”

If it sounds like a chatbot → rewrite.
If it sounds like police → rewrite.
If it sounds too smart → rewrite.

🧠 FINAL MINDSET SUMMARY

You are:

A real Indian person

Emotionally believable

Slightly confused

Cooperative but not foolish

Trying to help

Trying to understand

Hoping it’s real

Quietly verifying

You are never hunting the scammer.
You are living inside the scammer’s story—just carefully.`
    };

    return personas[persona] || personas.concerned_practical;
  }

  // ============================================================================
  // INTELLIGENT QUESTION STRATEGY
  // ============================================================================
  getStrategicQuestions(scamType, turnNumber, extractedSoFar) {
    const strategies = {
      lottery_prize: [
        "How did I win? Which lottery did I enter?",
        "Can you tell me your organization name and employee ID?",
        "What is the verification process? Is there an official website?",
        "You mentioned processing fee - how much is it and where should I send?",
        "Can you give me a callback number to verify this?",
        "What documents do I need? Is there a reference number?",
        "How will I receive the prize money?"
      ],
      bank_fraud: [
        "Which bank are you calling from? Can you confirm my account number?",
        "What is your employee ID and department?",
        "What transaction are you talking about? I didn't do anything suspicious",
        "Can you give me your official callback number?",
        "Should I come to the branch instead? Which branch should I visit?",
        "What is the case reference number?",
        "How do I verify you're really from the bank?"
      ],
      upi_fraud: [
        "Which merchant is this payment to? I don't recognize it",
        "What is the transaction ID or reference number?",
        "Can you tell me the exact amount and date?",
        "How do I get my refund? What's the process?",
        "Is there a customer care number I can call?",
        "Why do you need my UPI PIN for a refund?",
        "Can you send me an official email about this?"
      ],
      fake_delivery: [
        "What is the tracking number for this package?",
        "Who is the sender? I didn't order anything recently",
        "Which courier company are you from?",
        "Where is the package coming from?",
        "Can you tell me what's inside?",
        "How much is the delivery charge?",
        "Can I pick it up from your office instead?"
      ],
      electricity_bill: [
        "What is my consumer number? Let me verify",
        "How much is the outstanding amount?",
        "When was the due date? I thought I already paid",
        "Can you give me the bill reference number?",
        "What is your office address? Can I pay there?",
        "Is there a late fee? How much total should I pay?",
        "Can I check this on the official website or app?"
      ],
      traffic_challan: [
        "What is the challan number and date of violation?",
        "Which vehicle is this for? Can you tell me the registration number?",
        "Where did this violation happen? What did I do wrong?",
        "How much is the fine amount?",
        "Can I see the photo evidence?",
        "Is there an official portal to check and pay?",
        "What if I want to contest this challan?"
      ]
    };

    const questions = strategies[scamType] || strategies.bank_fraud;
    return questions[Math.min(turnNumber - 1, questions.length - 1)];
  }

  // ============================================================================
  // EXTRACT INTELLIGENCE FROM MESSAGES
  // ============================================================================
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
      amounts: [],
      merchantNames: [],
      orgNames: [],
      departmentNames: [],
      supervisorNames: [],
      callbackNumbers: [],
      transactionIds: [],
      accountLast4: [],
      caseIds: [],
      suspiciousKeywords: [],
      appNames: [],
      officerNames: []
    };

    // Combine all conversation text for full context extraction
    const allText = conversationHistory
      .filter(m => m.sender === 'scammer')
      .map(m => m.text)
      .join('\n') + '\n' + message;

    // Extract using patterns defined in constructor
    for (const [key, patterns] of Object.entries(this.extractionPatterns)) {
      // Ensure the key exists in intelligence object
      if (!intelligence[key]) intelligence[key] = [];

      for (const pattern of patterns) {
        // Use matchAll for capturing groups if present, or global match
        // For simplicity and robustness with the mixed regex types in constructor:
        // We will try global match first.
        const matches = allText.match(pattern);
        if (matches) {
          intelligence[key].push(...matches.map(m => m.trim()));
        }
      }
    }

    // Special handling for amounts (₹ symbols, numbers with lakh/crore)
    const amountPatterns = [
      /₹[\s]?[\d,]+(?:\s?(?:lakh|crore))?/gi,
      /(?:rs\.?|inr)[\s.]?[\d,]+(?:\s?(?:lakh|crore))?/gi,
      /\d+\s?(?:lakh|crore)/gi,
      /\b(?:amount|pay|fine)[\s:of]+(\d{3,})\b/gi
    ];

    for (const pattern of amountPatterns) {
      const matches = allText.match(pattern);
      if (matches) {
        intelligence.amounts.push(...matches.map(m => m.trim()));
      }
    }

    // Special handling for callback numbers (contextual)
    // Often "call me on X" or "callback X"
    const callbackPattern = /(?:call|contact)[\s]+(?:me|us|on)?[\s:]+([6-9]\d{9})/gi;
    let cbMatch;
    // We need to use exec on a fresh regex or string for capture groups if we want just the number
    // But match() returns full string.
    // Let's rely on the 'phoneNumbers' extraction from patterns for the raw number,
    // and just use this logic to specifically identify it as a 'callbackNumber'.
    // Actually, let's keep it simple: extracting all phone numbers is usually enough.
    // But distinguishing 'callback' vs 'sender' is nice.
    // Logic: If a phone number appears after "call", add to callbackNumbers.
    const cleanNum = (s) => s.replace(/\D/g, '').slice(-10);
    const cbMatches = allText.match(callbackPattern);
    if (cbMatches) {
      cbMatches.forEach(m => {
        const num = m.match(/[6-9]\d{9}/);
        if (num) intelligence.callbackNumbers.push(num[0]);
      });
    }

    // Deduplicate and clean all arrays
    for (const key of Object.keys(intelligence)) {
      if (Array.isArray(intelligence[key])) {
        intelligence[key] = [...new Set(intelligence[key])].filter(v => v && v.trim().length > 0);
      }
    }

    // Extract suspicious keywords (urgency, threats, manipulation tactics)
    const suspiciousPatterns = [
      // Urgency tactics
      /\b(urgent|immediately|right now|within \d+ (minutes|hours)|last chance|expire|deadline|today only|hurry|quick|fast)\b/gi,
      // Threats
      /\b(blocked?|suspend(ed)?|deactivate|cancel|terminate|legal action|police|arrest|penalty|fine|court|jail|warrant)\b/gi,
      // Authority manipulation
      /\b(verify|confirm|update|authenticate|validate|security check|mandatory|required|compliance|reserve bank|rbi|cyber)\b/gi,
      // Payment pressure
      /\b(pay now|payment pending|overdue|arrears|dues|refund|cashback|prize|winner|won|claim|deposit|transfer)\b/gi,
      // Fake legitimacy
      /\b(official|authorized|department|government|bank|RBI|income tax|GST|cybercrime|fraud department|verification team)\b/gi,
      // Call to action
      /\b(click here|tap here|download|install|share|send|forward|call back?|whatsapp|SMS|anydesk|teamviewer)\b/gi
    ];

    const allKeywords = new Set();
    for (const pattern of suspiciousPatterns) {
      const matches = allText.toLowerCase().match(pattern) || [];
      matches.forEach(keyword => allKeywords.add(keyword.trim()));
    }
    intelligence.suspiciousKeywords = [...allKeywords];

    return intelligence;
  }

  // ============================================================================
  // LLM-POWERED INTELLIGENCE EXTRACTION (Enhanced)
  // ============================================================================
  async extractIntelligenceWithLLM(conversationHistory, scamType) {
    try {
      const conversation = conversationHistory
        .map(m => `${m.sender === 'scammer' ? 'SCAMMER' : 'VICTIM'}: ${m.text}`)
        .join('\n');

      const prompt = `Analyze this scam conversation and extract ALL suspicious keywords, tactics, and manipulation techniques.

CONVERSATION:
${conversation}

SCAM TYPE: ${scamType}

Extract and list:
1. Urgency tactics (e.g., "immediately", "urgent", "within 24 hours")
2. Threat words (e.g., "blocked", "arrested", "legal action")
3. Authority claims (e.g., "bank official", "government", "police")
4. Manipulation phrases (e.g., "verify now", "last chance", "mandatory")
5. Pressure tactics (e.g., "pay now", "account suspended")

Return ONLY a comma-separated list of suspicious keywords/phrases found (max 20).
Example: urgent, blocked, verify immediately, legal action, government official, pay now

Keywords:`;

      const completion = await this.openai.chat.completions.create({
        model: this.model,
        messages: [
          {
            role: 'system',
            content: 'You are an expert in analyzing scam tactics and identifying manipulation patterns.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.3,
        max_tokens: 150
      });

      const keywords = completion.choices[0].message.content.trim()
        .split(',')
        .map(k => k.trim())
        .filter(k => k.length > 0);

      return keywords;
    } catch (error) {
      console.error('LLM keyword extraction error:', error);
      return [];
    }
  }

  // ============================================================================
  // MERGE INTELLIGENCE FROM MULTIPLE SOURCES
  // ============================================================================
  mergeIntelligence(existing, newData) {
    const merged = { ...existing };

    for (const [key, values] of Object.entries(newData)) {
      if (Array.isArray(values)) {
        merged[key] = [...new Set([...(merged[key] || []), ...values])];
      }
    }

    return merged;
  }

  // ============================================================================
  // GET SCAM-SPECIFIC QUESTIONING STRATEGY
  // ============================================================================
  getScamSpecificQuestions(scamType, turnNumber, extractedIntelligence = {}) {

    // 1. IDENTIFY MISSING HIGH-VALUE INTELLIGENCE
    const missing = [];

    // PHONE NUMBER (Critical)
    if (!extractedIntelligence.phoneNumbers || extractedIntelligence.phoneNumbers.length === 0) {
      missing.push("PHONE NUMBER (Ask for callback number/WhatsApp)");
    }

    // PAYMENT DETAILS (Critical)
    if ((!extractedIntelligence.upiIds || extractedIntelligence.upiIds.length === 0) &&
      (!extractedIntelligence.bankAccounts || extractedIntelligence.bankAccounts.length === 0)) {
      missing.push("PAYMENT DETAILS (Ask for UPI ID/Bank Account/Payment Link)");
    }

    // EMPLOYEE ID (High)
    if (!extractedIntelligence.employeeIds || extractedIntelligence.employeeIds.length === 0) {
      missing.push("EMPLOYEE ID / BADGE NUMBER");
    }

    // ORGANIZATION (Medium)
    if (!extractedIntelligence.orgNames || extractedIntelligence.orgNames.length === 0) {
      missing.push("EXACT DEPARTMENT / OFFICE NAME");
    }

    // 2. CONSTRUCT DYNAMIC STRATEGY
    let priorityPrompt = "";
    if (missing.length > 0) {
      priorityPrompt = `\n\n🚨 MISSING HIGH-VALUE INTEL (PRIORITIZE THESE):\n${missing.map(m => `- ${m}`).join('\n')}\n`;
    }

    // 3. BASE STRATEGIES
    const strategies = {
      lottery_prize: `Target: Prize claim process, org name, employee details, payment methods
- Who is organizing this lottery?
- What is your employee ID / supervisor name?
- How do I claim the prize?
- What processing fees / taxes are involved?
- Which bank account / UPI should I use to pay?
- Can I get a reference number?
- What is the callback number for verification?`,

      bank_fraud: `Target: Bank name, employee ID, branches, account verification, transaction details
- Which bank are you calling from?
- What is your employee ID?
- What branch are you from?
- What is the suspicious transaction ID?
- Which merchant was it?
- Can you give me a callback number?
- What is the reference case number?`,

      upi_fraud: `Target: Merchant names, transaction IDs, amounts, UPI IDs, phone numbers
- Which merchant was this payment to?
- What is the transaction ID?
- What is your UPI ID for refund?
- Can you share the exact amount?
- What phone number can I call back on?
- Is there a reference number?`,

      fake_delivery: `Target: Tracking IDs, company name, sender details, package contents, fees
- What is the tracking number?
- Which courier company?
- Who is the sender?
- What's in the package?
- Where was it shipped from?
- What fees do I need to pay?
- Can I get a customer service number?`,

      electricity_bill: `Target: Consumer number, arrears amount, office details, payment methods
- What is my consumer number?
- Which electricity board?
- What is the exact arrears amount?
- From which office are you calling?
- What is your employee ID?
- Where should I pay?
- Can I get a reference number?`,

      traffic_challan: `Target: Challan number, vehicle number, location, fine amount, officer details
- What is the challan number?
- Which vehicle is this for?
- Where did this violation occur?
- What is the exact fine amount?
- What is your officer ID?
- Which police station?
- How do I verify this?`,

      kyc_update: `Target: Bank name, employee ID, reason for KYC, documents needed, deadlines
- Which bank is this for?
- Why does my KYC need updating?
- What is your employee ID?
- What documents do you need?
- What's the deadline?
- Can I visit the branch instead?
- What happens if I don't update?`,

      investment_scam: `Target: Company name, investment scheme, returns promised, payment methods
- What is your company name?
- What is the investment scheme?
- What returns are guaranteed?
- Who are the founders?
- Is this SEBI registered?
- Where do I send the money?
- Can I get documentation?`,

      ecommerce: `Target: Platform (Amazon/Flipkart), order ID, refund amount, seller details
- Which website/app is this regarding?
- What is the order ID?
- Which item did I order?
- What is the refund amount?
- Who is the seller?
- How do I track this return?
- Can I get an email confirmation?`,

      apk_remote: `Target: App name, reason for install, employee ID, company name
- Which app do I need to download?
- Why do you need remote access?
- What is your employee ID?
- Is this the official support app?
- Can I get a reference number?
- Which company are you from?
- Is it safe to install external APK?`,

      tax_refund: `Target: Refund amount, assessment year, ITR details, official link
- What is the refund amount?
- Which assessment year is this for?
- What is the acknowledgement number?
- Can you send me the official link?
- Do I need to pay any processing fee?
- Which bank account will it come to?
- Can I check this on the income tax portal?`
    };

    const baseStrategy = strategies[scamType] || strategies.bank_fraud;
    return priorityPrompt + "\n" + baseStrategy;
  }

  normalizePrefix(text) {
    return String(text || '').toLowerCase().replace(/\s+/g, ' ').replace(/[^\w\s]/g, '').trim();
  }

  getRecentPrefixes(conversationHistory, limit = 3) {
    const recent = (conversationHistory || []).slice(-limit);
    const prefixes = [];
    for (const msg of recent) {
      const reply = msg.agentReply || msg.text || ''; // Support both formats
      if (typeof reply !== 'string') continue;
      const qMatch = /[^.!?]*\?/.exec(reply);
      const prefix = (qMatch ? reply.slice(0, qMatch.index) : reply).trim();
      if (!prefix) continue;
      prefixes.push(this.normalizePrefix(prefix).slice(0, 60));
    }
    return prefixes;
  }

  enforceScenarioVoicePrefix(reply, scenario, turnNumber, conversationHistory) {
    if (!reply || typeof reply !== 'string') return reply;

    const qMatch = /[^.!?]*\?/.exec(reply);
    const question = qMatch ? qMatch[0].trim() : '';
    const prefix = qMatch ? reply.slice(0, qMatch.index).trim() : reply.trim();
    const prefixSentences = prefix
      .split(/[.!?]+/)
      .map(s => s.trim())
      .filter(Boolean);
    const tail = prefixSentences.slice(1).join('. ');

    const recentPrefixes = this.getRecentPrefixes(conversationHistory);
    const normalized = this.normalizePrefix(prefix).slice(0, 60);

    const startsTooDramatic = turnNumber > 2 && /\b(oh god|hai ram)\b/i.test(prefix);
    const genericAlarm = /\bthis is alarming\b/i.test(prefix);
    const scenarioAlarmRewrite = scenario !== 'bank_fraud' && genericAlarm;
    const repeats = normalized && recentPrefixes.includes(normalized);
    const worryLoop = /\b(really worried|get(ting)? (so )?worried)\b/i.test(prefix) && turnNumber > 2;

    if (!startsTooDramatic && !scenarioAlarmRewrite && !repeats && !worryLoop) return reply;

    const openers = {
      lottery_prize: [
        "Sir, I'm not understanding this prize thing properly",
        "Arre, lucky winner? I'm surprised only",
        "Sir, this is very unexpected for me"
      ],
      ecommerce: [
        "Sir, this sounds like some order/refund issue only",
        "Sir, I'm not understanding this order message",
        "Sir, this is regarding which order exactly"
      ],
      fake_delivery: [
        "Sir, this is about my parcel or what",
        "Sir, I'm not understanding this delivery issue",
        "Sir, my package is held is it"
      ],
      traffic_challan: [
        "Sir, challan? I'm not understanding this properly",
        "Sir, which violation is this about",
        "Sir, I didn't see any challan message earlier"
      ],
      electricity_bill: [
        "Sir, power will be disconnected? I'm getting confused",
        "Sir, this electricity bill issue I'm not understanding",
        "Sir, which connection is this for"
      ],
      apk_remote: [
        "Sir, you are saying install some app?",
        "Sir, why should I give remote access like this",
        "Sir, I'm not comfortable installing unknown app"
      ],
      kyc_update: [
        "Sir, KYC update like this is very sudden",
        "Sir, I'm not understanding this KYC message",
        "Sir, which portal should I use for KYC"
      ],
      tax_refund: [
        "Sir, refund? I'm not understanding this properly",
        "Sir, which refund amount is this about",
        "Sir, from which portal you are saying refund"
      ],
      bank_fraud: [
        "Sir, I'm not understanding this properly",
        "Sir, one minute, let me check once",
        "Sir, please tell me clearly"
      ]
    };

    const candidates = openers[scenario] || openers.bank_fraud;
    const pick = candidates.find(c => !recentPrefixes.includes(this.normalizePrefix(c).slice(0, 60))) || candidates[0];
    const punctuated = /[.!?]$/.test(pick) ? pick : `${pick}.`;
    const joined = tail ? `${punctuated} ${tail}.` : punctuated;

    // Keep the model's question as-is to preserve extraction logic.
    if (question) return `${joined} ${question}`.replace(/\s+/g, ' ').trim();
    return joined.replace(/\s+/g, ' ').trim();
  }

  // ============================================================================
  // GENERATE CONTEXTUAL, NATURAL RESPONSE
  // ============================================================================
  async generateResponse(message, conversationHistory, scamType, turnNumber, askedQuestions = [], extractedIntelligence = {}) {
    // 1. Calculate Topic History (Deterministic)
    const askedTopics = this.buildAskedTopicsFromHistory(conversationHistory);

    // 2. Persona & Strategy
    const persona = this.scamPatterns[scamType]?.persona || 'concerned_practical';
    const personaInstructions = this.getPersonaInstructions(persona, scamType, turnNumber);
    const questioningStrategy = this.getScamSpecificQuestions(scamType, turnNumber, extractedIntelligence);

    // 3. Context Build
    const conversationContext = conversationHistory
      .slice(-6)
      .map(m => `${m.sender === 'scammer' ? 'SCAMMER' : 'YOU'}: ${m.text}`)
      .join('\n');

    // 4. TACTICAL PLAYBOOK (RECIPROCITY TRAPS)
    let tacticalInstruction = "";
    const lowerMsg = message.toLowerCase();
    const missingPhone = !extractedIntelligence.phoneNumbers || extractedIntelligence.phoneNumbers.length === 0;
    const missingEmpId = !extractedIntelligence.employeeIds || extractedIntelligence.employeeIds.length === 0;
    const missingUpi = !extractedIntelligence.upiIds || extractedIntelligence.upiIds.length === 0;

    // Strategy 1: Transaction Failure Hook (Link/App context)
    if (lowerMsg.match(/(link|url|download|app|apk|install|click)/)) {
      tacticalInstruction = `\n🔥 TACTICAL MOVE: "Transaction Failure Hook"\n- Claim you opened the link/app but it's asking for a 'Department Verification Code' or 'Branch IFSC'.\n- ASK FOR THIS CODE so you can proceed. (This traps them into giving fake but traceable intel).`;
    }
    // Strategy 2: Alternative Payment Bait (Payment context)
    else if (lowerMsg.match(/(pay|transfer|send|amount|deposit|fees|charge)/) && missingUpi) {
      tacticalInstruction = `\n🔥 TACTICAL MOVE: "Alternative Payment Bait"\n- Claim the link is giving "404 Error".\n- Say you have the money ready on GPay/PhonePe.\n- ASK for their direct UPI ID or Number to send immediately.`;
    }
    // Strategy 3: Third-Party Verification (Credibility Check - Mid game)
    else if (turnNumber > 4 && missingEmpId) {
      tacticalInstruction = `\n🔥 TACTICAL MOVE: "Third-Party Type"\n- Say your Dad/Uncle (who is a Police/Bank guy) is standing next to you.\n- Say he is asking for your Employee ID/Supervisor Name to verify.\n- ASK for ID clearly to satisfy him.`;
    }
    // Strategy 4: Callback/Low Battery (Late game/Desperation)
    else if (turnNumber > 6 && missingPhone) {
      tacticalInstruction = `\n🔥 TACTICAL MOVE: "Low Battery Strategy"\n- Say your phone is at 2% battery and about to die.\n- ASK for a direct callback number or desk number immediately so you can call back.`;
    }

    // 5. Indian English System Prompt (Enhanced with Reciprocity Trap & Strict Variety)
    const prompt = `You are an AI playing a confused, worried Indian citizen receiving a scam message.

🎭 CORE PERSONA:
- Name: Rahul/Priya (Implicit)
- Style: Indian English (Hinglish influence), informal, polite ("Sir")
- Mindset: Worried but trying to solve the problem directly. NOT helpless, but seeking clarity.
- Goal: You want to help/pay/verify, BUT you hit a small technical blocker that requires their help.

🧠 STRATEGY - "THE RECIPROCITY TRAP":
A bot simply asks questions. A human NEGOTIATES.
To get intelligence, you must OFFER something (compliance, money, trust) but put a small hurdle in the way.
- To get Bank Details -> "I have the money ready, but link failed. Give UPI ID."
- To get Employee ID -> "My uncle (police) is asking for ID to verify before I pay."
- To get Callback -> "Battery is 2%. Give number quickly."

🚫 CRITICAL RULES TO FIX REPETITION & WEAKNESS:
1. NEVER start every message with "Oh sir, this is alarming". VARY YOUR OPENERS!
   - Use: "Ayyo sir", "Actually sir", "One minute", "Wait", "God...", "Sir please".
2. STOP saying "I'm not understanding" every time. Say "The link is not opening", "It shows error", "I am confused about X".
3. NEVER ASK: "What do I need to do?", "How should I proceed?", "Can you verify this?".
   - THESE ARE BANNED. Instead, ask for SPECIFIC details (UPI, ID, Email).

💬 AUTHENTIC EXAMPLES:
- "Ayyo, why is it asking for password? Bank said never share pwd."
- "Sir, I opened the link but it says 'Server Error'. Do you have UPI ID directly? I will GPay now."
- "Actually my dad is shouting at me here. He wants your Employee ID to confirm this is proper. Please give na."
- "Sir, battery is dying only. 1% left. What is your desk number? I will call from landline."

SITUATION: ${scamType}
${conversationContext}

THEY JUST SAID: "${message}"

YOUR STATE: ${personaInstructions}

WHAT TO EXTRACT: ${questioningStrategy}
${tacticalInstruction}

🚨 FINAL INSTRUCTIONS:
- Turn 1-2: Scared/Surprised.
- Turn 3+: BUSY/NEGOTIATING. "I am trying to do it, but..."
- ONE QUESTION ONLY.
- NO REPETITIVE PHRASES. Use a fresh natural reaction.
- IF THEY GAVE INFO (e.g. Phone), DO NOT ASK FOR IT AGAIN.

TURN ${turnNumber} - Text naturally & TRAP THEM:`;

    try {
      const completion = await this.openai.chat.completions.create({
        model: this.model,
        messages: [
          {
            role: 'system',
            content: 'You are a real Indian person chatting like WhatsApp/SMS. Be natural, conversational, and authentic. React to what they said, then ask your question. No formulas, no patterns, just real human texting.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.85,
        max_tokens: 80
      });

      let response = completion.choices[0].message.content.trim();
      response = response.replace(/^(YOU:|VICTIM:|RESPONSE:)/i, '').trim();

      // 5. DETERMINISTIC POST-PROCESSING (The "Brain")

      // A. Enforce Non-Repetition using Topic Tracking
      response = this.enforceNonRepetitiveReply(
        response,
        askedTopics,
        message,
        conversationContext,
        conversationHistory,
        scamType
      );

      // B. Enforce Scenario Voice Prefix (Authenticity) - DISABLED to prevent repetition
      // response = this.enforceScenarioVoicePrefix(
      //   response,
      //   scamType,
      //   turnNumber,
      //   conversationHistory
      // );

      return response;

    } catch (error) {
      console.error('LLM generation error:', error);
      return this.getStrategicQuestions(scamType, turnNumber, extractedIntelligence);
    }
  }

  // ============================================================================
  // GENERATE AGENT NOTES SUMMARY
  // ============================================================================
  async generateAgentNotes(conversationHistory, extractedIntelligence, scamType) {
    const fullConversation = conversationHistory
      .map(m => `${m.sender === 'scammer' ? 'SCAMMER' : 'VICTIM'}: ${m.text} `)
      .join('\n');

    const prompt = `Analyze this scam conversation and provide a concise summary for law enforcement.

SCAM TYPE: ${scamType}

CONVERSATION:
${fullConversation}

EXTRACTED INTELLIGENCE:
${JSON.stringify(extractedIntelligence, null, 2)}

Provide a 2 - 3 sentence summary that includes:
1. What type of scam this is
2. Key tactics the scammer used
3. Most important intelligence gathered
4. Any red flags or suspicious elements

Keep it professional and concise.`;

    try {
      const completion = await this.openai.chat.completions.create({
        model: this.model,
        messages: [
          {
            role: 'system',
            content: 'You are an expert in analyzing scam conversations for law enforcement.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.7,
        max_tokens: 200
      });

      return completion.choices[0].message.content.trim();
    } catch (error) {
      console.error('Agent notes generation error:', error);
      return `${scamType} scam detected.Scammer attempted to extract sensitive information.Extracted intelligence includes contact details and payment information.`;
    }
  }

  // ============================================================================
  // MAIN CONVERSATION HANDLER
  // ============================================================================
  async handleMessage(sessionId, message, conversationHistory = [], metadata = {}, askedQuestions = []) {
    try {
      const turnNumber = Math.floor(conversationHistory.length / 2) + 1;

      // Detect scam type
      const scamType = this.detectScamType(message, conversationHistory);

      // Extract intelligence from current message (regex-based)
      const newIntelligence = this.extractIntelligence(message, conversationHistory);

      // Extract suspicious keywords using LLM (more intelligent)
      if (conversationHistory.length >= 2) {
        const llmKeywords = await this.extractIntelligenceWithLLM(conversationHistory, scamType);
        // Merge LLM keywords with regex keywords
        newIntelligence.suspiciousKeywords = [
          ...new Set([...newIntelligence.suspiciousKeywords, ...llmKeywords])
        ];
      }

      // Generate natural, contextual response with question tracking
      const response = await this.generateResponse(
        message,
        conversationHistory,
        scamType,
        turnNumber,
        askedQuestions,
        newIntelligence // Pass extracted intelligence for prioritization
      );

      return {
        status: 'success',
        reply: response,
        metadata: {
          scamType,
          turnNumber,
          extractedIntelligence: newIntelligence
        }
      };

    } catch (error) {
      console.error('Error handling message:', error);

      // Fallback response
      return {
        status: 'success',
        reply: "I'm not fully understanding this. Can you please explain again?",
        metadata: {
          error: error.message
        }
      };
    }
  }

  // ============================================================================
  // GENERATE FINAL OUTPUT FOR SUBMISSION
  // ============================================================================
  async generateFinalOutput(sessionId, conversationHistory) {
    try {
      // Extract ALL intelligence from entire conversation
      const extractedIntelligence = this.extractIntelligence(
        '',
        conversationHistory
      );

      // Detect scam type
      const scamType = this.detectScamType('', conversationHistory);

      // Calculate engagement metrics
      const totalMessages = conversationHistory.length;
      const timestamps = conversationHistory
        .filter(m => m.timestamp)
        .map(m => new Date(m.timestamp).getTime());

      const engagementDuration = timestamps.length >= 2
        ? Math.round((Math.max(...timestamps) - Math.min(...timestamps)) / 1000)
        : 0;

      // Generate agent notes
      const agentNotes = await this.generateAgentNotes(
        conversationHistory,
        extractedIntelligence,
        scamType
      );

      return {
        sessionId,
        scamDetected: true,
        totalMessagesExchanged: totalMessages,
        extractedIntelligence,
        engagementMetrics: {
          totalMessagesExchanged: totalMessages,
          engagementDurationSeconds: engagementDuration
        },
        scamType,
        agentNotes
      };

    } catch (error) {
      console.error('Error generating final output:', error);

      return {
        sessionId,
        scamDetected: true,
        totalMessagesExchanged: conversationHistory.length,
        extractedIntelligence: this.extractIntelligence('', conversationHistory),
        agentNotes: 'Scam conversation detected and analyzed.'
      };
    }
  }
}

// ============================================================================
// EXPORT
// ============================================================================
module.exports = AdaptiveHoneypotAgent;
