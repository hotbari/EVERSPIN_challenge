const axios = require('axios');

async function scrapeStep3() {
    try {
        // 브라우저처럼 보이는 헤더 설정
        const headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': 'application/json',
            'Referer': 'http://localhost:3000',
            'Origin': 'http://localhost:3000',
            'Host': 'localhost:3000',
            'Cache-Control': 'max-age=0',
            'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"'
        };

        // 요청 간격을 두기 위해 대기
        await new Promise(resolve => setTimeout(resolve, 1000));

        const response = await axios.post('http://localhost:3000/step3', {
            username: 'admin',
            password: 'admin12!'
        }, { 
            headers,
            validateStatus: function (status) {
                return status < 500; // 500 미만의 모든 상태 코드를 유효한 응답으로 처리
            }
        });

        if (response.data.status === 'success') {
            console.log('스크래핑 성공!');
        } else {
            console.log('스크래핑 실패:', response.data.msg || '알 수 없는 오류');
        }
    } catch (error) {
        if (error.response) {
            console.error('스크래핑 실패:', error.response.data?.msg || error.message);
        } else {
            console.error('스크래핑 실패:', error.message);
        }
    }
}

scrapeStep3(); 