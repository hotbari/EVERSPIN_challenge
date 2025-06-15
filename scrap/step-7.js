const axios = require('axios');

async function scrapeStep7() {
    try {
        const headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
            'Content-Type': 'application/json',
            'Referer': 'http://localhost:3000',
            'Origin': 'http://localhost:3000'
        };

        // 요청 간격을 두기 위해 대기
        await new Promise(resolve => setTimeout(resolve, 2000));

        const response = await axios.post('http://localhost:3000/step7', {
            username: 'admin',
            password: 'admin12!'
        }, { headers });

        if (response.data.status === 'success') {
            console.log('스크래핑 성공!');
        } else {
            console.log('스크래핑 실패:', response.data.msg);
        }
    } catch (error) {
        console.error('스크래핑 실패:', error.message);
    }
}

scrapeStep7(); 