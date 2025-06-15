const axios = require('axios');

async function scrapeStep6() {
    try {
        // 일반적인 브라우저 헤더 설정
        const headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
            'Content-Type': 'application/json',
            'Referer': 'http://localhost:3000',
            'Origin': 'http://localhost:3000',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Host': 'localhost:3000',
            'Cache-Control': 'no-cache',
            'sec-ch-ua': '"Google Chrome";v="122", "Chromium";v="122", ";Not A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"'
        };

        // 허니팟 필드를 비워두고 요청
        const response = await axios.post('http://localhost:3000/step6', {
            username: 'admin',
            password: 'admin12!'
        }, { headers, validateStatus: status => status < 500 });

        if (response.data.status === 'success') {
            console.log('스크래핑 성공!');
        } else {
            console.log('스크래핑 실패:', response.data.msg);
        }
    } catch (error) {
        console.error('스크래핑 실패:', error.message);
    }
}

scrapeStep6(); 