const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;
const crypto = require('crypto');

// 미들웨어 설정
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// EJS 템플릿 설정
app.set('view engine', 'ejs');

// /: 과제 페이지
app.get('/', (req, res) => {
  const cookieValue = req.get('cookie');

  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 입력 제한 함수
function validateInput(input) {
  // 특수문자 제한
  const specialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/;
  if (specialChars.test(input)) {
    return false;
  }

  // 길이 제한 (5-20자)
  if (input.length < 5 || input.length > 20) {
    return false;
  }

  // 허용된 문자셋 (영문, 숫자만)
  const allowedChars = /^[a-zA-Z0-9]+$/;
  if (!allowedChars.test(input)) {
    return false;
  }

  return true;
}

// 응답 난독화 함수
function obfuscateResponse(data) {
  const encoded = Buffer.from(JSON.stringify(data)).toString('base64');
  const reversed = encoded.split('').reverse().join('');
  return {
    data: reversed,
    timestamp: Date.now()
  };
}

function doLogin(req, res, username, password) {
  if (!username || !password) {
    return res.status(400).json({
      status: 'failure',
      msg: '입력값이 잘못되었습니다.',
    });
  }

  if ((username === 'admin') && (password === 'admin12!')) {
    return res.status(200).json({
      status: 'success',
      msg: '로그인 성공!',
    });
  }

  return res.status(400).json({
    status: 'failure',
    msg: '아이디 또는 비밀번호가 잘못되었습니다.',
  });
}

// Step1
function checkStep1(req, res) {
  const refererValue = req.header('referer');
  const hostValue = req.header('host');

  const isScraping = !refererValue || !refererValue.includes(hostValue);
  if (isScraping) {
    return res.status(400).json({
      status: 'failure',
      msg: '스크래핑 행위가 탐지되었습니다.',
    });
  }

  return isScraping;
}
app.post('/step1', (req, res) => {
  if (!checkStep1(req, res)) {
    const userInput = req.body;
    const username = userInput && userInput.username;
    const password = userInput && userInput.password;
    doLogin(req, res, username, password);
  }
});

// Step2
const {zmc__cQss} = require(path.join(__dirname, 'private', 'js', 'step2-server'));
function checkStep2(req, res) {
  const userInput = req.body;
  try {
    const username = userInput && zmc__cQss(userInput.username);
    const password = userInput && zmc__cQss(userInput.password);
    return {
      username,
      password,
    }
  } catch (e) {
    console.error(e);

    res.status(400).json({
      status: 'failure',
      msg: '스크래핑 행위가 탐지되었습니다.',
    });

    return null;
  }
}
app.post('/step2', (req, res) => {
  const userInputData = checkStep2(req, res);
  if (userInputData != null) {
    doLogin(req, res, userInputData.username, userInputData.password);
  } else {
    res.status(400).json({
      status: 'failure',
      msg: '스크래핑 행위가 탐지되었습니다.',
    });
  }
});

// Step3: 브라우저 특성 검사를 통한 봇 탐지
function checkStep3(req, res) {
  // req.headers에서 'user-agent' 값을 가져옵니다
  // user-agent는 브라우저가 서버에 보내는 자신의 신원 정보입니다
  const userAgent = req.headers['user-agent'];
  
  // user-agent가 없는 경우 (대부분의 봇은 user-agent를 보내지 않음)
  if (!userAgent) {
    return res.status(400).json({
      status: 'failure',
      msg: '정상적인 브라우저가 아닙니다.',
    });
  }

  // req.headers에서 모든 헤더 정보를 가져옵니다
  const headers = req.headers;
  
  // Accept 헤더 검사
  // Accept 헤더는 브라우저가 받을 수 있는 콘텐츠 타입을 나타냅니다
  const accept = headers['accept'];
  // 일반적인 브라우저는 text/html과 application/json을 모두 지원합니다
  if (!accept || !accept.includes('text/html') || !accept.includes('application/json')) {
    return res.status(400).json({
      status: 'failure',
      msg: '브라우저 설정이 비정상적입니다.',
    });
  }

  // Accept-Language 헤더 검사
  // Accept-Language는 브라우저의 언어 설정을 나타냅니다
  const acceptLanguage = headers['accept-language'];
  // 일반적인 브라우저는 반드시 언어 설정을 가집니다
  if (!acceptLanguage) {
    return res.status(400).json({
      status: 'failure',
      msg: '브라우저 언어 설정이 없습니다.',
    });
  }

  // Sec-Fetch-* 헤더 검사
  // Sec-Fetch-* 헤더들은 최신 브라우저의 보안 기능입니다
  const secFetchMode = headers['sec-fetch-mode'];
  const secFetchSite = headers['sec-fetch-site'];
  // 일반적인 브라우저는 이 보안 헤더들을 포함합니다
  if (!secFetchMode || !secFetchSite) {
    return res.status(400).json({
      status: 'failure',
      msg: '브라우저 보안 설정이 비정상적입니다.',
    });
  }

  // 요청 메서드 검사
  // POST 요청만 허용합니다
  if (req.method !== 'POST') {
    return res.status(400).json({
      status: 'failure',
      msg: '잘못된 요청 방식입니다.',
    });
  }

  // Content-Type 헤더 검사
  // 요청의 데이터 형식이 JSON인지 확인합니다
  const contentType = headers['content-type'];
  if (!contentType || !contentType.includes('application/json')) {
    return res.status(400).json({
      status: 'failure',
      msg: '잘못된 요청 형식입니다.',
    });
  }

  // 모든 검사를 통과하면 true를 반환합니다
  return true;
}

// /step3 경로로 POST 요청이 오면 실행되는 함수
app.post('/step3', (req, res) => {
  // checkStep3 함수의 결과가 true이면 로그인 처리를 진행합니다
  if (checkStep3(req, res) === true) {
    // 요청 본문에서 username과 password를 추출합니다
    const userInput = req.body;
    const username = userInput && userInput.username;
    const password = userInput && userInput.password;
    // doLogin 함수를 호출하여 로그인을 처리합니다
    doLogin(req, res, username, password);
  }
});

// Step4: 요청 지문(Fingerprinting) 검사를 통한 봇 탐지
// 클라이언트 요청 기록을 저장할 Map 객체 생성
// Map은 키-값 쌍을 저장하는 데이터 구조입니다
const clientRequests = new Map();

function checkStep4(req, res) {
  // 클라이언트의 IP 주소를 가져옵니다
  // req.ip가 없으면 req.connection.remoteAddress를 사용합니다
  const clientIP = req.ip || req.connection.remoteAddress;
  
  // 해당 IP의 요청 기록이 없으면 새로운 기록을 생성합니다
  if (!clientRequests.has(clientIP)) {
    clientRequests.set(clientIP, {
      count: 0,                    // 요청 횟수
      firstRequest: Date.now(),    // 첫 요청 시간
      lastRequest: Date.now(),     // 마지막 요청 시간
      headers: new Set()           // 헤더 정보를 저장할 Set (중복 방지)
    });
  }
  
  // 클라이언트의 요청 기록을 가져옵니다
  const clientData = clientRequests.get(clientIP);
  const currentTime = Date.now();
  
  // 요청 간격 검사
  // 마지막 요청으로부터의 시간 차이를 계산합니다
  const timeSinceLastRequest = currentTime - clientData.lastRequest;
  // 1초 이내의 연속 요청은 봇일 가능성이 높습니다
  if (timeSinceLastRequest < 1000) {
    return res.status(400).json({
      status: 'failure',
      msg: '요청이 너무 빠릅니다.',
    });
  }
  
  // 요청 횟수 제한 검사
  // 첫 요청으로부터의 시간 차이를 계산합니다
  const timeSinceFirstRequest = currentTime - clientData.firstRequest;
  // 1분 내에 30회 이상의 요청은 봇일 가능성이 높습니다
  if (timeSinceFirstRequest < 60000 && clientData.count > 30) {
    return res.status(400).json({
      status: 'failure',
      msg: '너무 많은 요청이 감지되었습니다.',
    });
  }
  
  // 헤더 일관성 검사
  // 현재 요청의 모든 헤더를 JSON 문자열로 변환합니다
  const currentHeaders = JSON.stringify(req.headers);
  // 이전에 저장된 헤더가 있는데, 현재 헤더와 다르면 봇일 가능성이 높습니다
  if (clientData.headers.size > 0 && !clientData.headers.has(currentHeaders)) {
    return res.status(400).json({
      status: 'failure',
      msg: '요청 패턴이 비정상적입니다.',
    });
  }
  
  // 브라우저 특성 검사
  const headers = req.headers;
  
  // DNT(Do Not Track) 헤더 검사
  // DNT는 사용자의 개인정보 보호 설정을 나타냅니다
  const dnt = headers['dnt'];
  if (dnt === undefined) {
    return res.status(400).json({
      status: 'failure',
      msg: '브라우저 설정이 비정상적입니다.',
    });
  }
  
  // Upgrade-Insecure-Requests 헤더 검사
  // 이 헤더는 보안 연결을 요청하는 설정입니다
  const upgradeInsecure = headers['upgrade-insecure-requests'];
  if (!upgradeInsecure) {
    return res.status(400).json({
      status: 'failure',
      msg: '보안 설정이 비정상적입니다.',
    });
  }
  
  // 요청 데이터 업데이트
  clientData.count++;                    // 요청 횟수 증가
  clientData.lastRequest = currentTime;  // 마지막 요청 시간 업데이트
  clientData.headers.add(currentHeaders); // 현재 헤더 저장
  
  // 오래된 데이터 정리 (1시간 이상 된 데이터)
  if (timeSinceFirstRequest > 3600000) {
    clientRequests.delete(clientIP);
  }
  
  // 모든 검사를 통과하면 true를 반환합니다
  return true;
}

// /step4 경로로 POST 요청이 오면 실행되는 함수
app.post('/step4', (req, res) => {
  // checkStep4 함수의 결과가 true이면 로그인 처리를 진행합니다
  if (checkStep4(req, res) === true) {
    // 요청 본문에서 username과 password를 추출합니다
    const userInput = req.body;
    const username = userInput && userInput.username;
    const password = userInput && userInput.password;
    // doLogin 함수를 호출하여 로그인을 처리합니다
    doLogin(req, res, username, password);
  }
});

// Step5: 동적 콘텐츠 보호와 세션 기반 상태 관리
// 세션 정보를 저장할 Map 객체 생성
// Map은 키-값 쌍을 저장하는 데이터 구조입니다
const sessions = new Map();

// 토큰 생성 함수
// crypto.randomBytes(32)로 32바이트의 랜덤 데이터를 생성하고
// toString('hex')로 16진수 문자열로 변환합니다
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// 세션 생성 함수
// clientIP: 클라이언트의 IP 주소
function createSession(clientIP) {
  // 새로운 세션 ID 생성
  const sessionId = generateToken();
  // 현재 시간을 타임스탬프로 저장
  const timestamp = Date.now();
  
  // 세션 정보를 Map에 저장
  sessions.set(sessionId, {
    clientIP,           // 클라이언트 IP
    createdAt: timestamp,  // 세션 생성 시간
    lastActivity: timestamp, // 마지막 활동 시간
    token: generateToken(),  // 세션 토큰
    requestCount: 0         // 요청 횟수
  });
  
  return sessionId;
}

function checkStep5(req, res) {
  // 클라이언트 IP 주소 가져오기
  const clientIP = req.ip || req.connection.remoteAddress;
  // 요청 헤더에서 세션 ID와 클라이언트 토큰 가져오기
  const sessionId = req.headers['x-session-id'];
  const clientToken = req.headers['x-client-token'];
  
  // 1. 세션 검증
  // 세션 ID가 없거나 유효하지 않은 경우
  if (!sessionId || !sessions.has(sessionId)) {
    // 새로운 세션 생성
    const newSessionId = createSession(clientIP);
    // 응답 헤더에 세션 ID와 토큰 설정
    res.setHeader('x-session-id', newSessionId);
    res.setHeader('x-client-token', sessions.get(newSessionId).token);
    
    return res.status(400).json({
      status: 'failure',
      msg: '세션이 만료되었습니다. 페이지를 새로고침해주세요.',
    });
  }
  
  // 세션 정보 가져오기
  const session = sessions.get(sessionId);
  
  // 2. 세션 만료 검사 (30분)
  const sessionAge = Date.now() - session.createdAt;
  if (sessionAge > 30 * 60 * 1000) { // 30분 = 30 * 60 * 1000 밀리초
    // 세션이 만료되면 삭제
    sessions.delete(sessionId);
    return res.status(400).json({
      status: 'failure',
      msg: '세션이 만료되었습니다. 페이지를 새로고침해주세요.',
    });
  }
  
  // 3. 클라이언트 토큰 검증
  // 토큰이 없거나 서버의 토큰과 일치하지 않는 경우
  if (!clientToken || clientToken !== session.token) {
    return res.status(400).json({
      status: 'failure',
      msg: '잘못된 요청입니다.',
    });
  }
  
  // 4. 요청 횟수 제한 (세션당)
  session.requestCount++;
  if (session.requestCount > 100) { // 세션당 최대 100회 요청
    sessions.delete(sessionId);
    return res.status(400).json({
      status: 'failure',
      msg: '너무 많은 요청이 감지되었습니다.',
    });
  }
  
  // 5. 요청 간격 검사
  const timeSinceLastActivity = Date.now() - session.lastActivity;
  if (timeSinceLastActivity < 500) { // 0.5초 이내의 연속 요청
    return res.status(400).json({
      status: 'failure',
      msg: '요청이 너무 빠릅니다.',
    });
  }
  
  // 6. 세션 데이터 업데이트
  session.lastActivity = Date.now();  // 마지막 활동 시간 업데이트
  session.token = generateToken();    // 새로운 토큰 생성
  
  // 7. 새로운 토큰을 응답 헤더에 포함
  res.setHeader('x-client-token', session.token);
  
  // 모든 검사를 통과하면 true를 반환
  return true;
}

// /step5 경로로 POST 요청이 오면 실행되는 함수
app.post('/step5', (req, res) => {
  // checkStep5 함수의 결과가 true이면 로그인 처리를 진행
  if (checkStep5(req, res) === true) {
    // 요청 본문에서 username과 password를 추출
    const userInput = req.body;
    const username = userInput && userInput.username;
    const password = userInput && userInput.password;
    // doLogin 함수를 호출하여 로그인을 처리
    doLogin(req, res, username, password);
  }
});

// Step6: 허니팟(Honeypot) 기법을 통한 봇 탐지
// 허니팟 트리거 기록을 저장할 Map 객체 생성
// Map은 키-값 쌍을 저장하는 데이터 구조입니다
const honeypotTriggers = new Map();

function checkStep6(req, res) {
  // 클라이언트 IP 주소 가져오기
  const clientIP = req.ip || req.connection.remoteAddress;
  
  // 1. 허니팟 필드 정의
  // 일반 사용자는 절대 채우지 않을 숨겨진 폼 필드들
  const honeypotFields = [
    'website',           // 일반적인 허니팟 필드 (CSS로 숨겨진 웹사이트 입력란)
    'email_confirmation', // 이메일 확인용 허니팟 (중복 이메일 입력란)
    'phone_number',      // 전화번호 허니팟 (숨겨진 전화번호 입력란)
    'timestamp',         // 타임스탬프 허니팟 (자동으로 채워지는 시간 필드)
    'user_type'          // 사용자 타입 허니팟 (숨겨진 사용자 유형 선택란)
  ];
  
  // 2. 요청 본문에서 허니팟 필드 값 확인
  const body = req.body;
  for (const field of honeypotFields) {
    // 허니팟 필드가 존재하고 값이 비어있지 않으면 봇일 가능성이 높음
    if (body[field] !== undefined && body[field] !== '') {
      // 허니팟 트리거 기록
      if (!honeypotTriggers.has(clientIP)) {
        // 새로운 트리거 기록 생성
        honeypotTriggers.set(clientIP, {
          count: 0,                // 트리거 횟수
          firstTrigger: Date.now(), // 첫 트리거 시간
          fields: new Set()        // 트리거된 필드 목록
        });
      }
      
      // 트리거 데이터 가져오기
      const triggerData = honeypotTriggers.get(clientIP);
      triggerData.count++;           // 트리거 횟수 증가
      triggerData.fields.add(field); // 트리거된 필드 기록
      
      // 허니팟 트리거가 3회 이상이면 봇으로 간주
      if (triggerData.count >= 3) {
        return res.status(400).json({
          status: 'failure',
          msg: '비정상적인 접근이 감지되었습니다.',
        });
      }
    }
  }
  
  // 3. 숨겨진 링크 접근 검사
  // 일반 사용자가 접근하지 않을 경로들
  const hiddenPaths = [
    '/admin',           // 관리자 페이지
    '/wp-login.php',    // WordPress 로그인
    '/phpmyadmin',      // phpMyAdmin
    '/.env',           // 환경 설정 파일
    '/config.php'      // 설정 파일
  ];
  
  // 현재 요청 경로 확인
  const path = req.path;
  if (hiddenPaths.includes(path)) {
    // 숨겨진 경로 접근 시 트리거 기록
    if (!honeypotTriggers.has(clientIP)) {
      honeypotTriggers.set(clientIP, {
        count: 0,
        firstTrigger: Date.now(),
        fields: new Set()
      });
    }
    
    const triggerData = honeypotTriggers.get(clientIP);
    triggerData.count++;
    
    // 3회 이상 접근 시 봇으로 간주
    if (triggerData.count >= 3) {
      return res.status(400).json({
        status: 'failure',
        msg: '비정상적인 접근이 감지되었습니다.',
      });
    }
  }
  
  // 4. 요청 헤더의 비정상적인 값 검사
  // IP 주소 형식을 검사할 헤더들
  const suspiciousHeaders = {
    'x-forwarded-for': /^(\d{1,3}\.){3}\d{1,3}$/,    // 프록시 서버 IP
    'x-real-ip': /^(\d{1,3}\.){3}\d{1,3}$/,          // 실제 클라이언트 IP
    'cf-connecting-ip': /^(\d{1,3}\.){3}\d{1,3}$/    // Cloudflare IP
  };
  
  // 각 헤더의 값이 IP 주소 형식과 일치하는지 검사
  for (const [header, pattern] of Object.entries(suspiciousHeaders)) {
    const value = req.headers[header];
    if (value && !pattern.test(value)) {
      // 비정상적인 헤더 값 발견 시 트리거 기록
      if (!honeypotTriggers.has(clientIP)) {
        honeypotTriggers.set(clientIP, {
          count: 0,
          firstTrigger: Date.now(),
          fields: new Set()
        });
      }
      
      const triggerData = honeypotTriggers.get(clientIP);
      triggerData.count++;
      
      // 3회 이상 트리거 시 봇으로 간주
      if (triggerData.count >= 3) {
        return res.status(400).json({
          status: 'failure',
          msg: '비정상적인 접근이 감지되었습니다.',
        });
      }
    }
  }
  
  // 5. 오래된 트리거 데이터 정리 (1시간 이상)
  for (const [ip, data] of honeypotTriggers.entries()) {
    if (Date.now() - data.firstTrigger > 3600000) { // 1시간 = 3600000 밀리초
      honeypotTriggers.delete(ip);
    }
  }
  
  // 모든 검사를 통과하면 true를 반환
  return true;
}

// /step6 경로로 POST 요청이 오면 실행되는 함수
app.post('/step6', (req, res) => {
  // checkStep6 함수의 결과가 true이면 로그인 처리를 진행
  if (checkStep6(req, res) === true) {
    // 요청 본문에서 username과 password를 추출
    const userInput = req.body;
    const username = userInput && userInput.username;
    const password = userInput && userInput.password;
    // doLogin 함수를 호출하여 로그인을 처리
    doLogin(req, res, username, password);
  }
});

// Step7: 요청 제한과 지연을 통한 봇 탐지
// 요청 제한 및 지연 관리를 위한 Map 객체 생성
// Map은 키-값 쌍을 저장하는 데이터 구조입니다
const rateLimits = new Map();

// 지연 시간 계산 함수
// 시도 횟수에 따라 지연 시간을 점진적으로 증가시킵니다
function calculateDelay(attempts) {
  // 1초부터 시작하여 2배씩 증가 (1초, 2초, 4초, 8초, 16초, 30초)
  // Math.pow(2, attempts): 2의 attempts 제곱
  // Math.min(..., 30000): 최대 30초로 제한
  return Math.min(1000 * Math.pow(2, attempts), 30000);
}

// IP 기반 요청 제한 함수
// clientIP: 클라이언트의 IP 주소
async function rateLimit(clientIP) {
  // 해당 IP의 요청 기록이 없으면 새로운 기록 생성
  if (!rateLimits.has(clientIP)) {
    rateLimits.set(clientIP, {
      count: 0,                    // 요청 횟수
      firstRequest: Date.now(),    // 첫 요청 시간
      lastRequest: Date.now(),     // 마지막 요청 시간
      attempts: 0,                 // 연속 시도 횟수
      blocked: false,              // 차단 상태
      blockUntil: 0                // 차단 해제 시간
    });
  }

  // 클라이언트의 요청 기록 가져오기
  const limit = rateLimits.get(clientIP);
  const now = Date.now();

  // 1. 차단 상태 확인
  if (limit.blocked) {
    // 아직 차단 시간이 지나지 않았으면 차단 상태 유지
    if (now < limit.blockUntil) {
      return {
        allowed: false,
        delay: 0,
        message: '너무 많은 요청이 감지되어 일시적으로 차단되었습니다.'
      };
    } else {
      // 차단 시간이 지나면 초기화
      limit.blocked = false;
      limit.attempts = 0;
      limit.count = 0;
    }
  }

  // 2. 요청 간격 검사
  const timeSinceLastRequest = now - limit.lastRequest;
  if (timeSinceLastRequest < 1000) { // 1초 이내의 연속 요청
    limit.attempts++;  // 연속 시도 횟수 증가
    const delay = calculateDelay(limit.attempts);
    
    // 5회 이상 연속으로 빠른 요청이 감지되면 5분 차단
    if (limit.attempts >= 5) {
      limit.blocked = true;
      limit.blockUntil = now + 300000; // 5분 = 300000 밀리초
      return {
        allowed: false,
        delay: 0,
        message: '너무 많은 요청이 감지되어 5분간 차단되었습니다.'
      };
    }
    
    // 지연 시간을 반환하여 클라이언트가 대기하도록 함
    return {
      allowed: false,
      delay,
      message: '요청이 너무 빠릅니다. 잠시 후 다시 시도해주세요.'
    };
  }

  // 3. 시간당 요청 수 제한
  const timeWindow = 3600000;  // 1시간 = 3600000 밀리초
  const maxRequests = 100;     // 1시간당 최대 요청 수
  
  // 시간 창이 지나면 카운터 초기화
  if (now - limit.firstRequest > timeWindow) {
    limit.count = 0;
    limit.firstRequest = now;
  }

  limit.count++;
  // 시간당 요청 한도 초과 시 1시간 차단
  if (limit.count > maxRequests) {
    limit.blocked = true;
    limit.blockUntil = now + 3600000; // 1시간
    return {
      allowed: false,
      delay: 0,
      message: '시간당 요청 한도를 초과했습니다. 1시간 후에 다시 시도해주세요.'
    };
  }

  // 4. 정상 요청 처리
  limit.lastRequest = now;  // 마지막 요청 시간 업데이트
  limit.attempts = 0;       // 연속 시도 횟수 초기화
  
  return {
    allowed: true,
    delay: 0,
    message: null
  };
}

// 요청 검증 함수
async function checkStep7(req, res) {
  // 클라이언트 IP 주소 가져오기
  const clientIP = req.ip || req.connection.remoteAddress;
  
  // 요청 제한 확인
  const limitResult = await rateLimit(clientIP);
  
  // 요청이 허용되지 않은 경우
  if (!limitResult.allowed) {
    // 지연이 필요한 경우 대기
    if (limitResult.delay > 0) {
      await new Promise(resolve => setTimeout(resolve, limitResult.delay));
    }
    
    // 오류 응답 반환
    return res.status(429).json({
      status: 'failure',
      msg: limitResult.message
    });
  }
  
  // 모든 검사를 통과하면 true를 반환
  return true;
}

// /step7 경로로 POST 요청이 오면 실행되는 함수
app.post('/step7', async (req, res) => {
  // checkStep7 함수의 결과가 true이면 로그인 처리를 진행
  if (await checkStep7(req, res) === true) {
    // 요청 본문에서 username과 password를 추출
    const userInput = req.body;
    const username = userInput && userInput.username;
    const password = userInput && userInput.password;
    // doLogin 함수를 호출하여 로그인을 처리
    doLogin(req, res, username, password);
  }
});

// Step8: 미로(Maze) 구조를 통한 스크래핑 방어
const mazeStates = new Map();

function generateMazeHint(clientIP, pattern) {
  const timestamp = Date.now();
  const randomKey = crypto.randomBytes(16).toString('hex');
  return {
    pattern,
    timestamp,
    key: randomKey,
    sequence: [],
    attempts: 0
  };
}

// 브라우저 특성 검증
function checkBrowserBehavior(req, hint) {
  // 필수 헤더 존재 여부만 확인
  const requiredHeaders = ['user-agent', 'accept', 'accept-language'];
  return requiredHeaders.every(header => req.headers[header]);
}

// 자연스러운 시간 간격 검증
function checkNaturalTiming(req, hint) {
  const currentTime = Date.now();
  const timeDiff = currentTime - hint.timestamp;
  
  // 1초 이상의 간격이면 자연스러운 것으로 간주
  return timeDiff >= 1000;
}

// 세션 연속성 검증
function checkSessionContinuity(req, hint) {
  // 쿠키나 세션 ID가 있는지 확인
  return req.headers.cookie || req.headers['x-session-id'];
}

function checkStep8(req, res) {
  const clientIP = req.ip || req.connection.remoteAddress;
  
  let mazeState = mazeStates.get(clientIP);
  
  if (!mazeState) {
    const pattern = Date.now() % 3;
    mazeState = generateMazeHint(clientIP, pattern);
    mazeStates.set(clientIP, mazeState);
    
    return res.status(200).json({
      status: 'maze',
      hint: mazeState.key,
      pattern: pattern
    });
  }
  
  // 시도 횟수 제한
  mazeState.attempts++;
  if (mazeState.attempts > 10) {
    return res.status(400).json({
      status: 'failure',
      msg: '너무 많은 시도가 감지되었습니다. 잠시 후 다시 시도해주세요.'
    });
  }
  
  let isValid = false;
  switch(mazeState.pattern) {
    case 0:
      isValid = checkBrowserBehavior(req, mazeState);
      break;
    case 1:
      isValid = checkNaturalTiming(req, mazeState);
      break;
    case 2:
      isValid = checkSessionContinuity(req, mazeState);
      break;
  }
  
  if (!isValid) {
    const newPattern = (mazeState.pattern + 1) % 3;
    mazeState = generateMazeHint(clientIP, newPattern);
    mazeStates.set(clientIP, mazeState);
    
    return res.status(400).json({
      status: 'failure',
      msg: '검증에 실패했습니다. 다시 시도해주세요.',
      hint: mazeState.key,
      pattern: newPattern
    });
  }
  
  // 검증 성공 시 상태 초기화
  mazeStates.delete(clientIP);
  
  return true;
}

app.post('/step8', (req, res) => {
  if (checkStep8(req, res) === true) {
    const userInput = req.body;
    const username = userInput && userInput.username;
    const password = userInput && userInput.password;
    doLogin(req, res, username, password);
  }
});

// Step9: 요청 퍼즐 시스템
const puzzleStates = new Map();

// 퍼즐 생성 함수
function generatePuzzle(clientIP) {
  // 1. 현재 시간을 기반으로 한 퍼즐 생성
  const timestamp = Date.now();
  const puzzle = {
    // 2. 시간 기반 퍼즐 요소
    timeFactor: timestamp % 1000,
    // 3. IP 기반 퍼즐 요소
    ipFactor: clientIP.split('.').reduce((a, b) => a + parseInt(b), 0) % 100,
    // 4. 랜덤 퍼즐 요소
    randomFactor: Math.floor(Math.random() * 1000),
    // 5. 퍼즐 생성 시간
    createdAt: timestamp
  };

  // 6. 퍼즐 해답 계산
  puzzle.answer = (puzzle.timeFactor + puzzle.ipFactor + puzzle.randomFactor) % 1000;
  
  return puzzle;
}

// 퍼즐 검증 함수
function validatePuzzle(clientIP, userAnswer, puzzle) {
  // 1. 퍼즐 만료 시간 확인 (30초)
  if (Date.now() - puzzle.createdAt > 30000) {
    return false;
  }

  // 2. 사용자 답변이 정확한지 확인
  return parseInt(userAnswer) === puzzle.answer;
}

function checkStep9(req, res) {
  const clientIP = req.ip || req.connection.remoteAddress;
  const userAnswer = req.headers['x-puzzle-answer'];
  
  // 1. 퍼즐 상태 확인
  let puzzleState = puzzleStates.get(clientIP);
  
  // 2. 새로운 퍼즐 생성
  if (!puzzleState || !userAnswer) {
    const puzzle = generatePuzzle(clientIP);
    puzzleStates.set(clientIP, puzzle);
    
    return res.status(200).json({
      status: 'puzzle',
      timeFactor: puzzle.timeFactor,
      ipFactor: puzzle.ipFactor,
      randomFactor: puzzle.randomFactor,
      msg: '퍼즐을 해결해주세요.'
    });
  }
  
  // 3. 퍼즐 검증
  if (!validatePuzzle(clientIP, userAnswer, puzzleState)) {
    // 4. 실패 시 새로운 퍼즐 생성
    const newPuzzle = generatePuzzle(clientIP);
    puzzleStates.set(clientIP, newPuzzle);
    
    return res.status(400).json({
      status: 'failure',
      timeFactor: newPuzzle.timeFactor,
      ipFactor: newPuzzle.ipFactor,
      randomFactor: newPuzzle.randomFactor,
      msg: '퍼즐 해결에 실패했습니다. 다시 시도해주세요.'
    });
  }
  
  // 5. 성공 시 상태 초기화
  puzzleStates.delete(clientIP);
  
  return true;
}

app.post('/step9', (req, res) => {
  if (checkStep9(req, res) === true) {
    const userInput = req.body;
    const username = userInput && userInput.username;
    const password = userInput && userInput.password;
    doLogin(req, res, username, password);
  }
});

// Step10: 요청 DNA 시스템
const requestDNA = new Map();

// DNA 생성 함수
function generateDNA(req) {
  // 1. 요청의 고유한 특성들을 추출
  const dna = {
    // 2. 헤더 DNA
    headers: {
      order: Object.keys(req.headers).join('|'),
      values: Object.values(req.headers).map(v => 
        typeof v === 'string' ? v.length : 0
      ).join('|')
    },
    // 3. 요청 DNA
    request: {
      method: req.method,
      path: req.path,
      query: Object.keys(req.query).join('|'),
      body: Object.keys(req.body).join('|')
    },
    // 4. 시간 DNA
    time: {
      hour: new Date().getHours(),
      minute: new Date().getMinutes(),
      second: new Date().getSeconds()
    },
    // 5. 생성 시간
    createdAt: Date.now()
  };

  // 6. DNA 해시 생성
  dna.hash = crypto
    .createHash('sha256')
    .update(JSON.stringify(dna))
    .digest('hex');

  return dna;
}

// DNA 검증 함수
function validateDNA(req, storedDNA) {
  // 1. DNA 만료 확인 (1분)
  if (Date.now() - storedDNA.createdAt > 60000) {
    return false;
  }

  // 2. 현재 요청의 DNA 생성
  const currentDNA = generateDNA(req);

  // 3. DNA 유사도 계산
  const similarity = calculateDNASimilarity(currentDNA, storedDNA);

  // 4. 유사도가 80% 이상이면 유효한 요청으로 간주
  return similarity >= 0.8;
}

// DNA 유사도 계산 함수
function calculateDNASimilarity(dna1, dna2) {
  let matches = 0;
  let total = 0;

  // 1. 헤더 순서 유사도
  if (dna1.headers.order === dna2.headers.order) matches++;
  total++;

  // 2. 헤더 값 길이 유사도
  if (dna1.headers.values === dna2.headers.values) matches++;
  total++;

  // 3. 요청 메서드 유사도
  if (dna1.request.method === dna2.request.method) matches++;
  total++;

  // 4. 요청 경로 유사도
  if (dna1.request.path === dna2.request.path) matches++;
  total++;

  // 5. 쿼리 파라미터 유사도
  if (dna1.request.query === dna2.request.query) matches++;
  total++;

  // 6. 바디 파라미터 유사도
  if (dna1.request.body === dna2.request.body) matches++;
  total++;

  return matches / total;
}

function checkStep10(req, res) {
  const clientIP = req.ip || req.connection.remoteAddress;
  
  // 1. DNA 상태 확인
  let storedDNA = requestDNA.get(clientIP);
  
  // 2. 새로운 DNA 생성
  if (!storedDNA) {
    const dna = generateDNA(req);
    requestDNA.set(clientIP, dna);
    
    return res.status(200).json({
      status: 'dna',
      msg: '요청 DNA가 생성되었습니다.',
      hash: dna.hash
    });
  }
  
  // 3. DNA 검증
  if (!validateDNA(req, storedDNA)) {
    // 4. 실패 시 새로운 DNA 생성
    const newDNA = generateDNA(req);
    requestDNA.set(clientIP, newDNA);
    
    return res.status(400).json({
      status: 'failure',
      msg: '요청 DNA가 일치하지 않습니다.',
      hash: newDNA.hash
    });
  }
  
  // 5. 성공 시 DNA 업데이트
  const updatedDNA = generateDNA(req);
  requestDNA.set(clientIP, updatedDNA);
  
  return true;
}

app.post('/step10', (req, res) => {
  if (checkStep10(req, res) === true) {
    const userInput = req.body;
    const username = userInput && userInput.username;
    const password = userInput && userInput.password;
    doLogin(req, res, username, password);
  }
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`✅ 서버가 포트 ${PORT}에서 실행 중입니다. http://localhost:${PORT}`);
});