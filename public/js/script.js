function doStep(url, username, password) {
    const data = {
        username: username,
        password: password,
    };

    const xhr = new XMLHttpRequest();
    xhr.open('post', url);
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            try {
                const responseJSON = JSON.parse(xhr.responseText);

                alert(responseJSON.msg);
                if (200 !== xhr.status || 'success' !== responseJSON.status) {
                    usernameInput.value = 'admin';
                    passwordInput.value = 'admin12!';
                    usernameInput.focus();
                }
            } catch(e) {
                console.error(e);
            }
        }
    }
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify(data));
}

function doStep1() {
    const usernameInput = document.querySelector('input#username-input');
    const passwordInput = document.querySelector('input#password-input');

    doStep('./step1', usernameInput.value, passwordInput.value);
}

function doStep2() {
    const usernameInput = document.querySelector('input#username-input');
    const passwordInput = document.querySelector('input#password-input');

    doStep('./step2', _vcdQscmz(usernameInput.value), _vcdQscmz(passwordInput.value));
}

// ================================ 챌린지 영역 ===================================
// Step3: 브라우저 특성 검사를 통한 봇 탐지
function doStep3() {
    const usernameInput = document.querySelector('input#username-input');
    const passwordInput = document.querySelector('input#password-input');

    doStep('./step3', usernameInput.value, passwordInput.value);
}

// Step4: 요청 지문(Fingerprinting) 검사를 통한 봇 탐지
function doStep4() {
    const usernameInput = document.querySelector('input#username-input');
    const passwordInput = document.querySelector('input#password-input');

    doStep('./step4', usernameInput.value, passwordInput.value);
}

// Step5: 요청 시그니처 시스템
function doStep5() {
    const usernameInput = document.querySelector('input#username-input');
    const passwordInput = document.querySelector('input#password-input');

    const xhr = new XMLHttpRequest();
    xhr.open('post', './step5');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            try {
                const responseJSON = JSON.parse(xhr.responseText);
                
                if (responseJSON.status === 'signature') {
                    // 시그니처 생성
                    const timestamp = responseJSON.timestamp;
                    const nonce = responseJSON.nonce;
                    const signature = generateSignature(usernameInput.value, timestamp, nonce);
                    
                    // 시그니처와 함께 다시 요청
                    const retryXhr = new XMLHttpRequest();
                    retryXhr.open('post', './step5');
                    retryXhr.setRequestHeader('Content-Type', 'application/json');
                    retryXhr.setRequestHeader('x-request-signature', signature);
                    retryXhr.setRequestHeader('x-request-timestamp', timestamp);
                    retryXhr.setRequestHeader('x-request-nonce', nonce);
                    retryXhr.onreadystatechange = function() {
                        if (retryXhr.readyState === 4) {
                            try {
                                const retryResponse = JSON.parse(retryXhr.responseText);
                                alert(retryResponse.msg);
                                if (200 !== retryXhr.status || 'success' !== retryResponse.status) {
                                    usernameInput.value = 'admin';
                                    passwordInput.value = 'admin12!';
                                    usernameInput.focus();
                                }
                            } catch(e) {
                                console.error(e);
                            }
                        }
                    };
                    retryXhr.send(JSON.stringify({
                        username: usernameInput.value,
                        password: passwordInput.value
                    }));
                } else {
                    alert(responseJSON.msg);
                    if (200 !== xhr.status || 'success' !== responseJSON.status) {
                        usernameInput.value = 'admin';
                        passwordInput.value = 'admin12!';
                        usernameInput.focus();
                    }
                }
            } catch(e) {
                console.error(e);
            }
        }
    };
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
        username: usernameInput.value,
        password: passwordInput.value
    }));
}

// Step6: 요청 시그니처 시스템 (개선된 버전)
function doStep6() {
    const usernameInput = document.querySelector('input#username-input');
    const passwordInput = document.querySelector('input#password-input');

    const xhr = new XMLHttpRequest();
    xhr.open('post', './step6');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            try {
                const responseJSON = JSON.parse(xhr.responseText);
                
                if (responseJSON.status === 'signature') {
                    // 시그니처 생성
                    const timestamp = responseJSON.timestamp;
                    const nonce = responseJSON.nonce;
                    const challenge = responseJSON.challenge;
                    const signature = generateEnhancedSignature(
                        usernameInput.value,
                        timestamp,
                        nonce,
                        challenge
                    );
                    
                    // 시그니처와 함께 다시 요청
                    const retryXhr = new XMLHttpRequest();
                    retryXhr.open('post', './step6');
                    retryXhr.setRequestHeader('Content-Type', 'application/json');
                    retryXhr.setRequestHeader('x-request-signature', signature);
                    retryXhr.setRequestHeader('x-request-timestamp', timestamp);
                    retryXhr.setRequestHeader('x-request-nonce', nonce);
                    retryXhr.setRequestHeader('x-request-challenge', challenge);
                    retryXhr.onreadystatechange = function() {
                        if (retryXhr.readyState === 4) {
                            try {
                                const retryResponse = JSON.parse(retryXhr.responseText);
                                alert(retryResponse.msg);
                                if (200 !== retryXhr.status || 'success' !== retryResponse.status) {
                                    usernameInput.value = 'admin';
                                    passwordInput.value = 'admin12!';
                                    usernameInput.focus();
                                }
                            } catch(e) {
                                console.error(e);
                            }
                        }
                    };
                    retryXhr.send(JSON.stringify({
                        username: usernameInput.value,
                        password: passwordInput.value
                    }));
                } else {
                    alert(responseJSON.msg);
                    if (200 !== xhr.status || 'success' !== responseJSON.status) {
                        usernameInput.value = 'admin';
                        passwordInput.value = 'admin12!';
                        usernameInput.focus();
                    }
                }
            } catch(e) {
                console.error(e);
            }
        }
    };
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
        username: usernameInput.value,
        password: passwordInput.value
    }));
}

// 시그니처 생성 함수
function generateSignature(username, timestamp, nonce) {
    const data = username + timestamp + nonce;
    return btoa(data); // Base64 인코딩
}

// 개선된 시그니처 생성 함수
function generateEnhancedSignature(username, timestamp, nonce, challenge) {
    const data = username + timestamp + nonce + challenge;
    return btoa(data); // Base64 인코딩
}

// Step7: 요청 제한과 지연을 통한 봇 탐지
function doStep7() {
    const usernameInput = document.querySelector('input#username-input');
    const passwordInput = document.querySelector('input#password-input');

    doStep('./step7', usernameInput.value, passwordInput.value);
}

// Step8: 요청 퍼즐 시스템
function doStep8() {
    const usernameInput = document.querySelector('input#username-input');
    const passwordInput = document.querySelector('input#password-input');

    // 퍼즐 해결 함수
    function solvePuzzle(timeFactor, ipFactor, randomFactor) {
        return (timeFactor + ipFactor + randomFactor) % 1000;
    }

    const xhr = new XMLHttpRequest();
    xhr.open('post', './step8');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            try {
                const responseJSON = JSON.parse(xhr.responseText);
                
                if (responseJSON.status === 'puzzle') {
                    // 퍼즐 해결
                    const answer = solvePuzzle(
                        responseJSON.timeFactor,
                        responseJSON.ipFactor,
                        responseJSON.randomFactor
                    );
                    
                    // 퍼즐 답변과 함께 다시 요청
                    const retryXhr = new XMLHttpRequest();
                    retryXhr.open('post', './step8');
                    retryXhr.setRequestHeader('Content-Type', 'application/json');
                    retryXhr.setRequestHeader('x-puzzle-answer', answer);
                    retryXhr.onreadystatechange = function() {
                        if (retryXhr.readyState === 4) {
                            try {
                                const retryResponse = JSON.parse(retryXhr.responseText);
                                alert(retryResponse.msg);
                                if (200 !== retryXhr.status || 'success' !== retryResponse.status) {
                                    usernameInput.value = 'admin';
                                    passwordInput.value = 'admin12!';
                                    usernameInput.focus();
                                }
                            } catch(e) {
                                console.error(e);
                            }
                        }
                    };
                    retryXhr.send(JSON.stringify({
                        username: usernameInput.value,
                        password: passwordInput.value
                    }));
                } else {
                    alert(responseJSON.msg);
                    if (200 !== xhr.status || 'success' !== responseJSON.status) {
                        usernameInput.value = 'admin';
                        passwordInput.value = 'admin12!';
                        usernameInput.focus();
                    }
                }
            } catch(e) {
                console.error(e);
            }
        }
    };
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
        username: usernameInput.value,
        password: passwordInput.value
    }));
}

// Step9: 요청 DNA 시스템
function doStep9() {
    const usernameInput = document.querySelector('input#username-input');
    const passwordInput = document.querySelector('input#password-input');

    const xhr = new XMLHttpRequest();
    xhr.open('post', './step9');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            try {
                const responseJSON = JSON.parse(xhr.responseText);
                
                if (responseJSON.status === 'dna') {
                    // DNA 해시 저장
                    localStorage.setItem('requestDNA', responseJSON.hash);
                    
                    // DNA 해시와 함께 다시 요청
                    const retryXhr = new XMLHttpRequest();
                    retryXhr.open('post', './step9');
                    retryXhr.setRequestHeader('Content-Type', 'application/json');
                    retryXhr.setRequestHeader('x-dna-hash', responseJSON.hash);
                    retryXhr.onreadystatechange = function() {
                        if (retryXhr.readyState === 4) {
                            try {
                                const retryResponse = JSON.parse(retryXhr.responseText);
                                alert(retryResponse.msg);
                                if (200 !== retryXhr.status || 'success' !== retryResponse.status) {
                                    usernameInput.value = 'admin';
                                    passwordInput.value = 'admin12!';
                                    usernameInput.focus();
                                }
                            } catch(e) {
                                console.error(e);
                            }
                        }
                    };
                    retryXhr.send(JSON.stringify({
                        username: usernameInput.value,
                        password: passwordInput.value
                    }));
                } else {
                    alert(responseJSON.msg);
                    if (200 !== xhr.status || 'success' !== responseJSON.status) {
                        usernameInput.value = 'admin';
                        passwordInput.value = 'admin12!';
                        usernameInput.focus();
                    }
                }
            } catch(e) {
                console.error(e);
            }
        }
    };
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
        username: usernameInput.value,
        password: passwordInput.value
    }));
}

// Step10: 요청 DNA 시스템 (개선된 버전)
function doStep10() {
    const usernameInput = document.querySelector('input#username-input');
    const passwordInput = document.querySelector('input#password-input');

    const xhr = new XMLHttpRequest();
    xhr.open('post', './step10');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            try {
                const responseJSON = JSON.parse(xhr.responseText);
                
                if (responseJSON.status === 'dna') {
                    // DNA 해시 저장
                    localStorage.setItem('requestDNA', responseJSON.hash);
                    
                    // DNA 해시와 함께 다시 요청
                    const retryXhr = new XMLHttpRequest();
                    retryXhr.open('post', './step10');
                    retryXhr.setRequestHeader('Content-Type', 'application/json');
                    retryXhr.setRequestHeader('x-dna-hash', responseJSON.hash);
                    retryXhr.onreadystatechange = function() {
                        if (retryXhr.readyState === 4) {
                            try {
                                const retryResponse = JSON.parse(retryXhr.responseText);
                                alert(retryResponse.msg);
                                if (200 !== retryXhr.status || 'success' !== retryResponse.status) {
                                    usernameInput.value = 'admin';
                                    passwordInput.value = 'admin12!';
                                    usernameInput.focus();
                                }
                            } catch(e) {
                                console.error(e);
                            }
                        }
                    };
                    retryXhr.send(JSON.stringify({
                        username: usernameInput.value,
                        password: passwordInput.value
                    }));
                } else {
                    alert(responseJSON.msg);
                    if (200 !== xhr.status || 'success' !== responseJSON.status) {
                        usernameInput.value = 'admin';
                        passwordInput.value = 'admin12!';
                        usernameInput.focus();
                    }
                }
            } catch(e) {
                console.error(e);
            }
        }
    };
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
        username: usernameInput.value,
        password: passwordInput.value
    }));
}
