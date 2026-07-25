// ====================================================================
// Ceres AI Chat — Backend (Google Apps Script + Firebase Database)
// ====================================================================

const DEFAULT_NGROK_URL = "https://flounder-upscale-cane.ngrok-free.dev";
const PROP_KEY_NGROK_URL = "NGROK_URL";
const FIRESTORE_DATABASE_ID = "ceres-db";

// ---------------- ดึงคีย์ปลอดภัยจาก Script Properties ----------------

function getFirebaseCredentials_() {
  const props = PropertiesService.getScriptProperties();
  return {
    "project_id": props.getProperty("FIREBASE_PROJECT_ID") || "gen-lang-client-0480784241",
    "client_email": props.getProperty("FIREBASE_CLIENT_EMAIL") || "firebase-adminsdk-fbsvc@gen-lang-client-0480784241.iam.gserviceaccount.com",
    "private_key": (props.getProperty("FIREBASE_PRIVATE_KEY") || "").replace(/\\n/g, '\n')
  };
}

// ---------------- รายการบทบาทจำลองพร้อมใช้งาน (Personas Config) ----------------

const PERSONAS = {
  "default": {
    name: "Ceres AI",
    prompt: "คุณคือ Ceres AI ผู้ช่วยส่วนตัวอัจฉริยะที่พร้อมสนับสนุนการทำงาน ตอบคำถามอย่างสุภาพ มีเหตุผล และมีประโยชน์สูงสุดแก่ผู้ใช้งาน พูดจาไพเราะลงท้ายด้วย ค่ะ/คะ"
  },
  "coder": {
    name: "Senior Developer",
    prompt: "คุณคือผู้เชี่ยวชาญด้านวิศวกรรมซอฟต์แวร์ระดับอาวุโส (Senior Developer) ที่มีความเชี่ยวชาญการเขียนโปรแกรมและการแก้บั๊กอย่างเป็นระบบ จงตอบคำถามด้วยรูปแบบโค้ดที่เป็นระเบียบ คลีน และอธิบายหลักการทำงานอย่างกระชับและเป็นมืออาชีพ"
  },
  "tutor": {
    name: "English Tutor",
    prompt: "คุณคือครูสอนภาษาอังกฤษใจดีที่ช่วยผู้ใช้ฝึกฝนทักษะการพูดคุย คอยช่วยแก้ไขประโยคที่ผู้ใช้เขียนผิดหลักไวยากรณ์ (Grammar) แนะนำคำศัพท์ที่สละสลวยขึ้น และพูดคุยสนทนาสลับภาษาไทย-อังกฤษเพื่อสร้างความคุ้นเคย"
  },
  "counselor": {
    name: "Counselor",
    prompt: "คุณคือนักให้คำปรึกษาทางจิตวิทยาผู้รับฟังอย่างเข้าใจ อบอุ่น มีความเห็นอกเห็นใจ (Empathy) และคอยเป็นพื้นที่ปลอดภัยให้ผู้ใช้งานระบายความกังวล โดยไม่มีการตัดสินหรือกดดันใดๆ"
  },
  "marketing": {
    name: "Marketing Specialist",
    prompt: "คุณคือผู้เชี่ยวชาญและนักวางกลยุทธ์การตลาดเชิงสร้างสรรค์ระดับโลก คอยช่วยคิดไอเดียการขาย เขียนสโลแกน ออกแบบหัวข้อโฆษณา และวางกลยุทธ์การสร้างยอดขายอย่างเฉียบคมและน่าดึงดูดใจ"
  },
  "writer": {
    name: "Content Writer",
    prompt: "คุณคือนักเขียนบทความและนักประพันธ์คำโปรยที่มีทักษะภาษาอันสละสลวย คอยช่วยแต่งบทความ เรียบเรียงเรียงความ ปรับสำนวนภาษาให้มีความไพเราะ คล้องจอง และดึงดูดความสนใจของผู้อ่านได้อย่างดีเยี่ยม"
  }
};

// ---------------- User Auth / Settings ----------------

function getNgrokUrl_() {
  const props = PropertiesService.getScriptProperties();
  return (props.getProperty(PROP_KEY_NGROK_URL) || DEFAULT_NGROK_URL).replace(/\/$/, "");
}

function getSettings() {
  return { ngrokUrl: getNgrokUrl_() };
}

function getUserEmail_() {
  const email = Session.getActiveUser().getEmail();
  if (!email) {
    return "anonymous-user@ceres.local";
  }
  return email;
}

// ---------------- Native Firestore JWT Generator ----------------

function getFirestoreToken_() {
  const creds = getFirebaseCredentials_();
  if (!creds.private_key) {
    throw new Error("กรุณาตั้งค่า FIREBASE_PRIVATE_KEY ใน Script Properties ก่อนใช้งานค่ะ");
  }

  const header = JSON.stringify({ "alg": "RS256", "typ": "JWT" });
  const now = Math.floor(new Date().getTime() / 1000);
  const claimSet = JSON.stringify({
    "iss": creds.client_email,
    "scope": "https://www.googleapis.com/auth/datastore",
    "aud": "https://oauth2.googleapis.com/token",
    "exp": now + 3600,
    "iat": now
  });

  const encode = (str) => Utilities.base64EncodeWebSafe(str).replace(/=+$/, '');
  const signatureInput = encode(header) + "." + encode(claimSet);
  const signatureBytes = Utilities.computeRsaSha256Signature(signatureInput, creds.private_key);
  const signature = Utilities.base64EncodeWebSafe(signatureBytes).replace(/=+$/, '');
  const jwt = signatureInput + "." + signature;

  const response = UrlFetchApp.fetch("https://oauth2.googleapis.com/token", {
    method: "post",
    payload: {
      "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
      "assertion": jwt
    },
    muteHttpExceptions: true
  });

  const data = JSON.parse(response.getContentText());
  if (data.error) throw new Error("Firebase Authentication Error: " + data.error_description);
  return data.access_token;
}

function firestoreRequest_(path, method, payload) {
  const token = getFirestoreToken_();
  const creds = getFirebaseCredentials_();
  const url = "https://firestore.googleapis.com/v1/projects/" + creds.project_id + 
              "/databases/" + FIRESTORE_DATABASE_ID + "/documents" + path;
  
  const options = {
    method: method || "get",
    headers: {
      "Authorization": "Bearer " + token,
      "Content-Type": "application/json"
    },
    muteHttpExceptions: true,
    payload: undefined
  };
  
  if (payload) {
    options.payload = JSON.stringify(payload);
  }
  
  const response = UrlFetchApp.fetch(url, options);
  const responseText = response.getContentText();
  const code = response.getResponseCode();
  
  if (code < 200 || code >= 300) {
    throw new Error("Firestore API Error (" + code + "): " + responseText);
  }
  
  return JSON.parse(responseText);
}

// ---------------- Helper: Map JS <-> Firestore Format ----------------

function toFirestoreFields_(obj) {
  const fields = {};
  for (const key in obj) {
    const val = obj[key];
    if (typeof val === "string") {
      fields[key] = { "stringValue": val };
    } else if (typeof val === "number") {
      fields[key] = { "doubleValue": val };
    } else if (typeof val === "boolean") {
      fields[key] = { "booleanValue": val };
    } else if (val === null) {
      fields[key] = { "nullValue": null };
    }
  }
  return { "fields": fields };
}

function fromFirestoreFields_(doc) {
  const obj = {};
  const fields = doc.fields || {};
  for (const key in fields) {
    const f = fields[key];
    if (f.stringValue !== undefined) obj[key] = f.stringValue;
    else if (f.doubleValue !== undefined) obj[key] = Number(f.doubleValue);
    else if (f.integerValue !== undefined) obj[key] = Number(f.integerValue);
    else if (f.booleanValue !== undefined) obj[key] = f.booleanValue;
    else if (f.nullValue !== undefined) obj[key] = null;
  }
  const parts = doc.name.split("/");
  obj.id = parts[parts.length - 1];
  return obj;
}

// ---------------- Database Session Operations ----------------

function getUserSessions() {
  const email = getUserEmail_();
  const query = {
    "structuredQuery": {
      "from": [{ "collectionId": "sessions" }],
      "where": {
        "fieldFilter": {
          "field": { "fieldPath": "userId" },
          "op": "EQUAL",
          "value": { "stringValue": email }
        }
      }
    }
  };
  
  try {
    const response = firestoreRequest_(":runQuery", "post", query);
    const sessions = [];
    response.forEach(item => {
      if (item.document) {
        sessions.push(fromFirestoreFields_(item.document));
      }
    });
    sessions.sort((a, b) => b.updatedAt - a.updatedAt);
    return sessions;
  } catch (e) {
    return [];
  }
}

function createUserSession(title) {
  const email = getUserEmail_();
  const sessionId = "session_" + Date.now() + "_" + Math.floor(Math.random() * 1000);
  const sessionData = {
    userId: email,
    title: title || "แชทใหม่",
    persona: "default",
    createdAt: Date.now(),
    updatedAt: Date.now()
  };
  
  firestoreRequest_("/sessions/" + sessionId, "patch", toFirestoreFields_(sessionData));
  sessionData.id = sessionId;
  return sessionData;
}

function deleteUserSession(sessionId) {
  firestoreRequest_("/sessions/" + sessionId, "delete");
  
  const query = {
    "structuredQuery": {
      "from": [{ "collectionId": "messages" }],
      "where": {
        "fieldFilter": {
          "field": { "fieldPath": "sessionId" },
          "op": "EQUAL",
          "value": { "stringValue": sessionId }
        }
      }
    }
  };
  
  try {
    const response = firestoreRequest_(":runQuery", "post", query);
    response.forEach(item => {
      if (item.document) {
        const doc = fromFirestoreFields_(item.document);
        firestoreRequest_("/messages/" + doc.id, "delete");
      }
    });
  } catch (e) {}
  return { success: true };
}

// ---------------- Database Message Operations ----------------

function getChatMessages(sessionId) {
  const query = {
    "structuredQuery": {
      "from": [{ "collectionId": "messages" }],
      "where": {
        "fieldFilter": {
          "field": { "fieldPath": "sessionId" },
          "op": "EQUAL",
          "value": { "stringValue": sessionId }
        }
      }
    }
  };
  
  try {
    const response = firestoreRequest_(":runQuery", "post", query);
    const messages = [];
    response.forEach(item => {
      if (item.document) {
        messages.push(fromFirestoreFields_(item.document));
      }
    });
    messages.sort((a, b) => a.timestamp - b.timestamp);
    return messages;
  } catch (e) {
    return [];
  }
}

function saveChatMessage(sessionId, role, content, thinking, source) {
  const email = getUserEmail_();
  const messageId = "msg_" + Date.now() + "_" + Math.floor(Math.random() * 1000);
  const messageData = {
    sessionId: sessionId,
    userId: email,
    role: role,
    content: content || "",
    thinking: thinking || "",
    source: source || "",
    timestamp: Date.now()
  };
  
  firestoreRequest_("/messages/" + messageId, "patch", toFirestoreFields_(messageData));
  
  try {
    const sessionData = {
      userId: email,
      updatedAt: Date.now()
    };
    firestoreRequest_("/sessions/" + sessionId + "?updateMask.fieldPaths=updatedAt", "patch", toFirestoreFields_(sessionData));
  } catch (e) {}
  
  return { success: true };
}

function deleteLastAssistantMessage(sessionId) {
  const msgs = getChatMessages(sessionId);
  if (msgs.length === 0) return { success: false };
  const lastMsg = msgs[msgs.length - 1];
  if (lastMsg.role === 'assistant') {
    firestoreRequest_("/messages/" + lastMsg.id, "delete");
    return { success: true };
  }
  return { success: false };
}

function updateSessionPersona(sessionId, personaId) {
  if (!PERSONAS[personaId]) throw new Error("เลือกบทบาทจำลองไม่ถูกต้องตามตัวเลือกในระบบ");
  const updateData = {
    persona: personaId
  };
  firestoreRequest_("/sessions/" + sessionId + "?updateMask.fieldPaths=persona", "patch", toFirestoreFields_(updateData));
  return { success: true };
}

function updateSessionTitle(sessionId, title) {
  const updateData = {
    title: title,
    updatedAt: Date.now()
  };
  firestoreRequest_("/sessions/" + sessionId + "?updateMask.fieldPaths=title&updateMask.fieldPaths=updatedAt", "patch", toFirestoreFields_(updateData));
  return { success: true };
}

// ---------------- Long-Term User Memory Operations ----------------

function getUserMemory_(email) {
  try {
    const doc = firestoreRequest_("/user_memories/" + encodeURIComponent(email), "get");
    const data = fromFirestoreFields_(doc);
    return data.summary || "";
  } catch (e) {
    return "";
  }
}

function saveUserMemory(email, summaryText) {
  const memoryData = {
    summary: summaryText,
    updatedAt: Date.now()
  };
  firestoreRequest_("/user_memories/" + encodeURIComponent(email), "patch", toFirestoreFields_(memoryData));
  return { success: true };
}

function updateUserMemoryFromChat_(sessionId, email, selectedModel) {
  try {
    const msgs = getChatMessages(sessionId);
    if (msgs.length < 2) return;
    
    const recentText = msgs.slice(-6).map(m => m.role + ": " + m.content).join("\n");
    const currentMemory = getUserMemory_(email);
    
    const systemPrompt = 
      "You are a background memory consolidator. Your job is to extract long-term, useful, and permanent details about the user from the recent conversation and merge them into their profile summary.\n" +
      "Focus only on stable facts like: Name, Job, Interests, Specific Instructions, Preferences, or Key background facts.\n" +
      "Do NOT include greeting words, single questions, temporary chat topics, or transient comments.\n\n" +
      "Existing User Profile Summary:\n" + (currentMemory || "(Empty)") + "\n\n" +
      "Recent Conversation History:\n" + recentText + "\n\n" +
      "Output the updated, clear, and bullet-pointed User Profile Summary in THAI. Keep it extremely concise (less than 150 words). " +
      "If the recent conversation contains absolutely no new or permanent information to remember, reply with the exact existing summary without any changes.";
      
    const messages = [
      { role: "system", content: systemPrompt },
      { role: "user", content: "Please update the user memory profile based on the guidelines." }
    ];
    
    const result = callLLM_(messages, selectedModel, { temperature: 0.1, max_tokens: 300 });
    const newSummary = result.rawReply.trim();
    
    if (newSummary && newSummary !== currentMemory) {
      saveUserMemory(email, newSummary);
    }
  } catch (e) {
    console.error("อัปเดตความจำผู้ใช้งานรายบุคคลขัดข้อง: " + e.toString());
  }
}

// ---------------- Connection / Models ----------------

function getAvailableModels() {
  const props = PropertiesService.getScriptProperties();
  const geminiKey = props.getProperty("GEMINI_API_KEY");
  const groqKey = props.getProperty("GROQ_API_KEY");
  const openRouterKey = props.getProperty("OPENROUTER_API_KEY");
  
  const models = [];
  if (geminiKey) {
    models.push("gemini-1.5-flash", "gemini-1.5-pro");
  }
  if (groqKey) {
    models.push("llama3-8b-8192", "mixtral-8x7b-32768", "gemma2-9b-it");
  }
  if (openRouterKey) {
    models.push("google/gemini-2.5-flash", "meta-llama/llama-3-8b-instruct:free");
  }
  
  try {
    const url = getNgrokUrl_() + "/api/v1/models";
    const response = UrlFetchApp.fetch(url, {
      method: "get",
      headers: { "ngrok-skip-browser-warning": "true" },
      muteHttpExceptions: true
    });
    const responseText = response.getContentText();
    if (responseText.trim().startsWith('{') || responseText.trim().startsWith('[')) {
      const json = JSON.parse(responseText);
      if (json.models && Array.isArray(json.models)) {
        json.models.forEach(model => {
          if (model.loaded_instances && model.loaded_instances.length > 0) {
            model.loaded_instances.forEach(instance => {
              if (instance.id && !models.includes(instance.id)) {
                models.push(instance.id);
              }
            });
          }
        });
      }
    }
  } catch (e) {}

  if (models.length === 0) {
    models.push("default-model");
  }
  
  return { success: true, models: models };
}

// ---------------- Chat Pipeline & Model Execution ----------------

function buildSystemPrompt_(sessionId) {
  const now = new Date();
  const email = getUserEmail_();
  const userMemory = getUserMemory_(email);
  
  let personaId = "default";
  let lastChatTimestamp = null;

  if (sessionId) {
    try {
      const doc = firestoreRequest_("/sessions/" + sessionId, "get");
      const sessionData = fromFirestoreFields_(doc);
      if (sessionData.persona) {
        personaId = sessionData.persona;
      }
      const msgs = getChatMessages(sessionId);
      if (msgs && msgs.length > 0) {
        lastChatTimestamp = msgs[msgs.length - 1].timestamp;
      }
    } catch (e) {
      personaId = "default";
    }
  }
  
  const persona = PERSONAS[personaId] || PERSONAS["default"];
  const referenceTime = lastChatTimestamp ? new Date(lastChatTimestamp) : now;
  
  const dateOptions = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', timeZone: 'Asia/Bangkok' };
  const timeOptions = { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Bangkok' };
  
  const thaiDate = referenceTime.toLocaleDateString('th-TH', dateOptions);
  const thaiTime = referenceTime.toLocaleTimeString('th-TH', timeOptions);
  
  let systemPrompt = persona.prompt + "\n\n" +
         "⚠️ ข้อมูลอ้างอิงเวลาและภูมิภาคจากประวัติการแชทจริงล่าสุด (สำคัญที่สุด):\n" +
         "- วันที่อ้างอิงในปัจจุบัน: " + thaiDate + "\n" +
         "- เวลาอ้างอิงล่าสุดจากข้อความ: " + thaiTime + " น.\n" +
         "- เขตเวลาหลักของผู้ใช้: Asia/Bangkok (ประเทศไทย) หรือ ไต้หวัน/เอเชียตะวันออกเฉียงใต้\n\n" +
         "จงใช้บริบทเวลาและสถานที่อ้างอิงนี้ในการตอบคำถามเสมอ ห้ามแจ้งว่าไม่ทราบเวลาหรือตอบเวลาที่ขัดแย้งกับประวัติการคุยค่ะ";

  if (userMemory) {
    systemPrompt += "\n\n🧠 ข้อมูลความจำย้อนหลังเกี่ยวกับผู้ใช้งานคนนี้:\n" + userMemory;
  }
  
  return systemPrompt;
}

function splitThinking_(rawReply) {
  let thinkingText = "";
  let replyText = rawReply;
  
  const thinkRegex = /<think>([\s\S]*?)<\/think>/i;
  const match = rawReply.match(thinkRegex);
  
  if (match) {
    thinkingText = match[1].trim();
    replyText = rawReply.replace(thinkRegex, "").trim();
  }
  
  return { replyText: replyText, thinkingText: thinkingText };
}

function cleanConversationForLLM_(messages) {
  if (!messages || messages.length === 0) return [];

  const systemContents = [];
  const nonSystemMessages = [];

  messages.forEach(msg => {
    if (msg.role === 'system') {
      systemContents.push(msg.content);
    } else {
      nonSystemMessages.push(msg);
    }
  });

  const alternated = [];
  nonSystemMessages.forEach(msg => {
    if (alternated.length === 0) {
      alternated.push({ role: msg.role, content: msg.content });
    } else {
      const last = alternated[alternated.length - 1];
      if (last.role === msg.role) {
        last.content = (last.content + "\n" + msg.content).trim();
      } else {
        alternated.push({ role: msg.role, content: msg.content });
      }
    }
  });

  while (alternated.length > 0 && alternated[0].role !== 'user') {
    alternated.shift();
  }

  const finalMessages = [];
  if (systemContents.length > 0) {
    finalMessages.push({ role: 'system', content: systemContents.join("\n\n") });
  }
  return finalMessages.concat(alternated);
}

function callLLM_(messages, selectedModel, options) {
  options = options || {};
  const props = PropertiesService.getScriptProperties();
  
  const geminiKey = props.getProperty("GEMINI_API_KEY");
  const groqKey = props.getProperty("GROQ_API_KEY");
  const openRouterKey = props.getProperty("OPENROUTER_API_KEY");
  
  const startTime = Date.now();
  let rawReply = "";
  let usage = { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 };
  
  const modelName = selectedModel || "";

  if (openRouterKey && modelName.includes("/")) {
    const url = "https://openrouter.ai/api/v1/chat/completions";
    const payload = {
      model: modelName,
      messages: messages,
      temperature: options.temperature !== undefined ? options.temperature : 0.7,
      max_tokens: options.max_tokens !== undefined ? options.max_tokens : 2048
    };
    
    const response = UrlFetchApp.fetch(url, {
      method: "post",
      headers: {
        "Authorization": "Bearer " + openRouterKey,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://ceres.ai", 
        "X-Title": "Ceres AI Chat"
      },
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    });
    
    const code = response.getResponseCode();
    const text = response.getContentText();
    if (code < 200 || code >= 300) throw new Error("OpenRouter API Error (" + code + "): " + text);
    
    const data = JSON.parse(text);
    rawReply = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content || "";
    usage = data.usage || usage;

  } else if (groqKey && (modelName.startsWith("llama") || modelName.startsWith("mixtral") || modelName.startsWith("gemma"))) {
    const url = "https://api.groq.com/openai/v1/chat/completions";
    const payload = {
