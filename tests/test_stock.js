const http = require('http');

const data = JSON.stringify({
    agriculteur_id: 1,
    stock_id: 1,
    quantite: 600
});

const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/api/distribuer',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length
    }
};

const req = http.request(options, (res) => {
    let responseBody = '';
    res.on('data', (chunk) => responseBody += chunk);
    res.on('end', () => {
        console.log('Status Code:', res.statusCode);
        console.log('Response:', JSON.parse(responseBody));
        if (res.statusCode === 400) {
            console.log('✅ Success: Over-distribution blocked.');
        } else {
            console.log('❌ Failure: Over-distribution NOT blocked.');
        }
        process.exit(0);
    });
});

req.on('error', (error) => {
    console.error(error);
    process.exit(1);
});

req.write(data);
req.end();