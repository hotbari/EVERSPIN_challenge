const axios = require('axios');

async function scrapeStep4() {
    try {
        // 일관된 헤더 설정
        const headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',
            'Content-Type': 'application/json',
            'Referer': 'http://localhost:3000',
            'Origin': 'http://localhost:3000'
        };

        // 요청 간격을 두고 여러 번 시도
        for (let i = 0; i < 3; i++) {
            // 요청 간격을 두기 위해 대기
            if (i > 0) {
                await new Promise(resolve => setTimeout(resolve, 2000));
            }

            const response = await axios.post('http://localhost:3000/step4', {
                username: 'admin',
                password: 'admin12!'
            }, { headers });

            if (response.data.status === 'success') {
                console.log('스크래핑 성공!');
                return;
            }
        }

        console.log('스크래핑 실패: 모든 시도 실패');
    } catch (error) {
        console.error('스크래핑 실패:', error.message);
    }
}

scrapeStep4(); 