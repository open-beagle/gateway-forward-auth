package tfa

const waitingPageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>正在登录 - Beagle Gateway</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }

        .container {
            background: white;
            border-radius: 16px;
            padding: 60px 40px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            text-align: center;
            max-width: 480px;
            width: 90%;
        }

        .spinner {
            width: 80px;
            height: 80px;
            margin: 0 auto 30px;
            position: relative;
        }

        .spinner-ring {
            width: 100%;
            height: 100%;
            border: 6px solid #f3f3f3;
            border-top: 6px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        h1 {
            font-size: 28px;
            font-weight: 600;
            color: #1a1a1a;
            margin-bottom: 16px;
        }

        .subtitle {
            font-size: 16px;
            color: #666;
            margin-bottom: 24px;
            line-height: 1.5;
        }

        .timer {
            font-size: 14px;
            color: #999;
            margin-bottom: 32px;
            font-family: "Courier New", monospace;
        }

        .button {
            display: inline-block;
            padding: 14px 32px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 500;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }

        .button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(102, 126, 234, 0.5);
        }

        .button:active {
            transform: translateY(0);
        }

        .success {
            display: none;
        }

        .success.show {
            display: block;
        }

        .success-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 30px;
            background: #10b981;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: scaleIn 0.3s ease-out;
        }

        @keyframes scaleIn {
            0% {
                transform: scale(0);
            }
            100% {
                transform: scale(1);
            }
        }

        .success-icon::before {
            content: "✓";
            font-size: 48px;
            color: white;
            font-weight: bold;
        }

        .footer {
            margin-top: 32px;
            padding-top: 24px;
            border-top: 1px solid #e5e5e5;
            font-size: 13px;
            color: #999;
        }
    </style>
</head>
<body>
    <div class="container">
        <div id="waiting" class="waiting">
            <div class="spinner">
                <div class="spinner-ring"></div>
            </div>

            <h1>正在登录...</h1>
            <p class="subtitle">
                请在另一个标签页完成登录<br>
                登录成功后将自动跳转
            </p>
            <div class="timer" id="timer">已等待 <span id="seconds">0</span> 秒</div>
            <button class="button" onclick="goToLogin()">等不及了？点击这里自己登录</button>
        </div>

        <div id="success" class="success">
            <div class="success-icon"></div>
            <h1>登录成功</h1>
            <p class="subtitle">正在跳转到您的应用...</p>
        </div>

        <div class="footer">
            Beagle Gateway Forward Auth
        </div>
    </div>

    <script>
        const redirectUrl = "{{.RedirectURL}}";
        const sseUrl = "{{.SSEURL}}";
        const forceLoginUrl = "{{.ForceLoginURL}}";
        
        let seconds = 0;
        let eventSource = null;
        
        // 计时器
        const timerInterval = setInterval(() => {
            seconds++;
            document.getElementById('seconds').textContent = seconds;
            
            // 30分钟超时
            if (seconds >= 1800) {
                clearInterval(timerInterval);
                if (eventSource) {
                    eventSource.close();
                }
                document.querySelector('.subtitle').innerHTML = 
                    '等待超时<br>请点击下方按钮重新登录';
            }
        }, 1000);

        // 连接 SSE
        function connectSSE() {
            eventSource = new EventSource(sseUrl);
            
            eventSource.addEventListener('authenticated', function(e) {
                showSuccess();
                setTimeout(() => {
                    window.location.href = redirectUrl;
                }, 1500);
            });
            
            eventSource.addEventListener('heartbeat', function(e) {
                console.log('Heartbeat received');
            });
            
            eventSource.onerror = function(e) {
                console.error('SSE error:', e);
                // 自动重连由浏览器处理
            };
        }

        function showSuccess() {
            clearInterval(timerInterval);
            if (eventSource) {
                eventSource.close();
            }
            document.getElementById('waiting').style.display = 'none';
            document.getElementById('success').classList.add('show');
        }

        function goToLogin() {
            clearInterval(timerInterval);
            if (eventSource) {
                eventSource.close();
            }
            // 直接跳转到强制登录 URL
            window.location.href = forceLoginUrl;
        }

        // 启动 SSE 连接
        connectSSE();
    </script>
</body>
</html>
`
