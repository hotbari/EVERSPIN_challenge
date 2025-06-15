const axios = require('axios');
const path = require('path');

async function autoLogin() {
    try {
        // 공통 헤더 설정
        const headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Referer': 'http://localhost:3000',
            'Origin': 'http://localhost:3000',
            'Host': 'localhost:3000',
            'Cache-Control': 'no-cache',
            'sec-ch-ua': '"Google Chrome";v="122", "Chromium";v="122", ";Not A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"'
        };

        // Step 1 로그인
        console.log('Step 1 로그인 시도...');
        const step1Response = await axios.post('http://localhost:3000/step1', {
            username: 'admin',
            password: 'admin12!'
        }, { headers });
        console.log('Step 1 결과:', step1Response.data.status === 'success' ? '성공' : '실패');
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Step 2 로그인
        console.log('Step 2 로그인 시도...');
        try {
            const {zmc__cQss} = require(path.join(__dirname, '..', 'private', 'js', 'step2-server'));
            const step2Data = zmc__cQss({
                username: 'admin',
                password: 'admin12!'
            });
            const step2Response = await axios.post('http://localhost:3000/step2', step2Data, { 
                headers,
                validateStatus: status => status < 500
            });
            console.log('Step 2 결과:', step2Response.data.status === 'success' ? '성공' : '실패');
        } catch (step2Error) {
            console.error('Step 2 오류:', step2Error.message);
            if (step2Error.response) {
                console.error('응답 데이터:', step2Error.response.data);
            }
        }
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Step 3 로그인
        console.log('Step 3 로그인 시도...');
        const step3Headers = {
            ...headers,
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1'
        };
        const step3Response = await axios.post('http://localhost:3000/step3', {
            username: 'admin',
            password: 'admin12!'
        }, { headers: step3Headers });
        console.log('Step 3 결과:', step3Response.data.status === 'success' ? '성공' : '실패');
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Step 4 로그인
        console.log('Step 4 로그인 시도...');
        const step4Headers = {
            ...headers,
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1'
        };
        const step4Response = await axios.post('http://localhost:3000/step4', {
            username: 'admin',
            password: 'admin12!'
        }, { headers: step4Headers });
        console.log('Step 4 결과:', step4Response.data.status === 'success' ? '성공' : '실패');
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Step 5 로그인
        console.log('Step 5 로그인 시도...');
        const sessionId = require('crypto').randomBytes(32).toString('hex');
        const clientToken = require('crypto').randomBytes(32).toString('hex');
        const step5Headers = {
            ...headers,
            'x-session-id': sessionId,
            'x-client-token': clientToken
        };
        const step5InitResponse = await axios.post('http://localhost:3000/step5', {
            username: 'admin',
            password: 'admin12!'
        }, { headers: step5Headers });
        
        if (step5InitResponse.headers['x-session-id'] && step5InitResponse.headers['x-client-token']) {
            step5Headers['x-session-id'] = step5InitResponse.headers['x-session-id'];
            step5Headers['x-client-token'] = step5InitResponse.headers['x-client-token'];
        }
        
        await new Promise(resolve => setTimeout(resolve, 2000));
        const step5Response = await axios.post('http://localhost:3000/step5', {
            username: 'admin',
            password: 'admin12!'
        }, { headers: step5Headers });
        console.log('Step 5 결과:', step5Response.data.status === 'success' ? '성공' : '실패');
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Step 6 로그인
        console.log('Step 6 로그인 시도...');
        const step6Response = await axios.post('http://localhost:3000/step6', {
            username: 'admin',
            password: 'admin12!'
        }, { headers });
        console.log('Step 6 결과:', step6Response.data.status === 'success' ? '성공' : '실패');
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Step 7 로그인
        console.log('Step 7 로그인 시도...');
        await new Promise(resolve => setTimeout(resolve, 2000));
        const step7Response = await axios.post('http://localhost:3000/step7', {
            username: 'admin',
            password: 'admin12!'
        }, { headers });
        console.log('Step 7 결과:', step7Response.data.status === 'success' ? '성공' : '실패');

    } catch (error) {
        if (error.response) {
            console.error('자동 로그인 실패:', error.response.data?.msg || error.message);
        } else {
            console.error('자동 로그인 실패:', error.message);
        }
    }
}

autoLogin(); 