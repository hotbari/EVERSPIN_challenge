const axios = require('axios');

(async () => {
  const scrap = async () => {
    const data = JSON.stringify({
      username: 'admin',
      password: 'admin12!',
    });
    const options = {
      method: 'POST',
      url: 'http://localhost:3000/step1',
      headers: {
        'Content-Type': 'application/json',
        'Referer': 'http://localhost:3000',
        'Host': 'localhost:3000'
      },
      data,
    };
    try {
      const response = await axios(options);
      if (response.data.status === 'success') {
        console.log('스크래핑 성공!');
      } else {
        console.error('스크래핑 실패:', response.data.msg);
      }
    } catch(e) {
      console.error('스크래핑 실패:', e.message);
    }
  };
  await scrap();
})();