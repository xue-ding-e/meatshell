"""Authenticated MCP regression tests. Only ephemeral keys and loopback fixtures.

Requires Python cryptography and paramiko; run with --exe <headless-or-desktop-meatshell>.
Add --caddy <caddy-executable> to repeat the suite through verified loopback HTTPS.
No production OAuth server, SSH server, profile or credential is contacted.
"""
import argparse
import base64
import concurrent.futures
import contextlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', required=True, type=Path)
    parser.add_argument('--caddy', type=Path, help='test through a loopback-only TLS reverse proxy')
    parser.add_argument('--protocol-version', choices=['2025-06-18', '2025-11-25'], default='2025-06-18')
    args = parser.parse_args()
    exe = args.exe.resolve()
    # Synthetic loopback fixtures must not use the caller's outbound proxy.
    child_env = {k:v for k,v in os.environ.items() if k.lower() not in ('all_proxy', 'http_proxy', 'https_proxy')}

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_numbers()
    issuer = 'https://issuer.example.invalid'
    resource = 'https://meatshell.example.invalid/mcp'

    def token(**updates):
        claims = dict(iss=issuer, aud=resource, sub='alice', exp=int(time.time()) + 600,
                      scope='meatshell:mcp', nbf=int(time.time()) - 1)
        claims.update(updates)
        for k in [k for k, v in claims.items() if v is None]:
            del claims[k]
        payload = b64(json.dumps(dict(alg='RS256', kid='fixture')).encode()) + '.' + b64(json.dumps(claims).encode())
        return payload + '.' + b64(key.sign(payload.encode(), padding.PKCS1v15(), hashes.SHA256()))

    with tempfile.TemporaryDirectory(prefix='meatshell-http-fixture-') as temp, contextlib.ExitStack() as stack:
        root = Path(temp)
        profile = root / 'profile'
        profile.mkdir(mode=0o700)
        saved = profile / 'sessions.json'
        config = dict(defaults_rev=3, mcp_enabled=True, mcp_use_saved_credentials=True,
                      mcp_allow_commands=False, mcp_allow_file_transfers=False,
                      sessions=[dict(id='fixture', name='Fixture', host='127.0.0.1', port=1,
                                     user='fixture', auth='password', password='synthetic-not-a-real-secret', kind='ssh')])
        saved.write_text(json.dumps(config))
        jwks = root / 'public-jwks.json'
        jwks.write_text(json.dumps({'keys': [dict(kty='RSA', kid='fixture', alg='RS256', use='sig',
            n=b64(public.n.to_bytes((public.n.bit_length()+7)//8, 'big')),
            e=b64(public.e.to_bytes((public.e.bit_length()+7)//8, 'big')))]}))
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        def connection(timeout):
            return http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
        if args.caddy:
            from tls_proxy_fixture import CaddyTlsFixture
            proxy = stack.enter_context(CaddyTlsFixture(args.caddy.resolve(), root, port, child_env))
            resource = proxy.resource
            connection = proxy.connection
            proxy.check_certificate_validation()
        http_config = root / 'http.json'
        http_settings = dict(bind=f'127.0.0.1:{port}', allowed_origins=['https://client.example.invalid'],
            oauth=dict(issuer=issuer, resource=resource, jwks_file=str(jwks),
                       required_scope='meatshell:mcp', allowed_subjects=['alice', 'bob']))
        http_config.write_text(json.dumps(http_settings))
        # Fail closed at startup: no implicit profile, no insecure resource,
        # no open subject policy, and no private signing material in JWKS.
        start = [str(exe), '--data-dir', str(profile), 'mcp', 'serve', '--http-config', str(http_config)]
        no_profile = subprocess.run([str(exe), 'mcp', 'serve', '--http-config', str(http_config)],
            env={k:v for k,v in os.environ.items() if k != 'MEATSHELL_DATA_DIR'}, capture_output=True, timeout=10)
        assert no_profile.returncode != 0
        for field, invalid in [('issuer', 'http://issuer.example.invalid'), ('resource', 'http://shell.invalid/mcp'), ('allowed_subjects', [])]:
            original = http_settings['oauth'][field]
            http_settings['oauth'][field] = invalid
            http_config.write_text(json.dumps(http_settings))
            assert subprocess.run(start, capture_output=True, timeout=10).returncode != 0
            http_settings['oauth'][field] = original
        http_config.write_text(json.dumps(http_settings))
        public_text = jwks.read_text()
        private_example = json.loads(public_text)
        private_example['keys'][0]['d'] = 'synthetic-invalid-private-component'
        jwks.write_text(json.dumps(private_example))
        assert subprocess.run(start, capture_output=True, timeout=10).returncode != 0
        jwks.write_text(public_text)
        print('PASS: explicit profile, HTTPS issuer/resource, subject allowlist and public-only JWKS startup checks')
        log = root / 'stderr.log'
        with log.open('wb') as output:
            process = subprocess.Popen([str(exe), '--data-dir', str(profile), 'mcp', 'serve', '--http-config', str(http_config)],
                                       stdout=subprocess.DEVNULL, stderr=output, env=child_env)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError('server exited: ' + log.read_text())
                try:
                    with socket.create_connection(('127.0.0.1', port), .1):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise AssertionError('server not ready')

            def request(payload=None, auth=None, session=None, method='POST', path='/mcp', headers=None, raw=None):
                client = connection(timeout=15)
                hdr = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
                       'MCP-Protocol-Version': args.protocol_version}
                if auth is not None:
                    hdr['Authorization'] = 'Bearer ' + auth
                if session is not None:
                    hdr['Mcp-Session-Id'] = session
                hdr.update(headers or {})
                body = raw if raw is not None else (json.dumps(payload) if payload is not None else None)
                client.request(method, path, body=body, headers=hdr)
                response = client.getresponse()
                content = response.read().decode()
                status, response_headers = response.status, dict(response.getheaders())
                client.close()
                value = None
                if content.strip():
                    if content.lstrip().startswith('{'):
                        value = json.loads(content)
                    else:
                        for line in content.splitlines():
                            if line.startswith('data:') and line[5:].strip():
                                candidate = json.loads(line[5:])
                                if isinstance(candidate, dict) and 'jsonrpc' in candidate:
                                    value = candidate
                return status, {k.lower(): v for k, v in response_headers.items()}, value

            init = dict(jsonrpc='2.0', id=1, method='initialize', params=dict(protocolVersion=args.protocol_version,
                capabilities={}, clientInfo=dict(name='synthetic-regression', version='1')))
            alice, bob = token(), token(sub='bob')
            status, headers, _ = request(init)
            assert status == 401 and 'resource_metadata=' in headers['www-authenticate']
            metadata_url = resource.rsplit('/', 1)[0] + '/.well-known/oauth-protected-resource/mcp'
            assert f'resource_metadata="{metadata_url}"' in headers['www-authenticate']
            for path in ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']:
                status, _, value = request(method='GET', path=path)
                assert status == 200 and value['resource'] == resource
                assert value['authorization_servers'] == [issuer] and 'sessions' not in json.dumps(value)
            for invalid in ['bad', alice[:-5]+'AAAAA', token(exp=int(time.time())-1), token(aud='https://other.invalid/mcp'),
                            token(iss='https://other.invalid'), token(exp=None), token(aud=None), token(nbf=int(time.time())+600)]:
                assert request(init, invalid)[0] == 401
            for denied in [token(sub='mallory'), token(scope='other'), token(scope=None)]:
                assert request(init, denied)[0] == 403
            assert request(init, alice, headers={'Origin': 'https://evil.invalid'})[0] == 403
            assert request(init, alice, headers={'Host': 'evil.invalid'})[0] == 403
            assert request(init, alice, headers={'Origin': 'https://client.example.invalid'})[0] == 200
            print('PASS: metadata, signature/expiry/issuer/audience/scope/subject/nbf, origin and Host checks')

            def initialize(auth):
                status, hdr, value = request(init, auth)
                assert status == 200 and value['result']['serverInfo']['name'] == 'meatshell', (status, value)
                assert value['result']['protocolVersion'] == args.protocol_version
                session = hdr['mcp-session-id']
                assert request(dict(jsonrpc='2.0', method='notifications/initialized'), auth, session)[0] == 202
                return session

            a, b = initialize(alice), initialize(bob)
            assert a != b
            listing = dict(jsonrpc='2.0', id=2, method='tools/list')
            assert request(listing, bob, a)[0] == 404
            assert request(listing, alice, b)[0] == 404
            assert request(listing, alice, 'not-a-session')[0] == 404
            assert request(listing, token(sub='mallory'), a)[0] == 403
            assert request(listing, token(exp=int(time.time())-1), a)[0] == 401
            status, _, listed = request(listing, alice, a)
            assert status == 200 and len(listed['result']['tools']) == 8
            assert all(t.get('securitySchemes') == t.get('_meta', {}).get('securitySchemes') and t['securitySchemes'][0]['type'] == 'oauth2' for t in listed['result']['tools'])
            assert request(method='GET', auth=alice, session=a)[0] == 405
            print('PASS: authenticated initialize/list, OAuth tool metadata and principal session isolation')

            def call(name, args, request_id=3, session=a):
                return request(dict(jsonrpc='2.0', id=request_id, method='tools/call', params=dict(name=name, arguments=args)), alice, session)

            status, _, value = call('list_sessions', {})
            assert status == 200 and not value['result'].get('isError')
            text = json.dumps(value)
            assert 'synthetic-not-a-real-secret' not in text and 'Fixture' in text
            _, _, value = call('run_command', dict(session_id='fixture', command='whoami'))
            assert value['result']['isError'] and 'disabled' in json.dumps(value).lower()
            _, _, value = call('upload_file', dict(session_id='fixture', local_path=str(jwks), remote_directory='/tmp'))
            assert value['result']['isError']
            export = root / 'export.json'
            export.write_text(json.dumps({'sessions': []}))
            config['mcp_allow_file_transfers'] = True
            saved.write_text(json.dumps(config))
            _, _, value = call('import_sessions', dict(local_path=str(export), dry_run=False))
            assert value['result']['isError'] and '--allow-config-import' in json.dumps(value)
            config['mcp_use_saved_credentials'] = False
            config['mcp_allow_commands'] = True
            saved.write_text(json.dumps(config))
            _, _, value = call('run_command', dict(session_id='fixture', command='whoami'))
            assert value['result']['isError'] and 'saved' in json.dumps(value).lower()
            print('PASS: redacted read tool; command, file transfer, import and saved-credential gates')

            assert request(auth=alice, session=a, raw='x'*(1024*1024+1))[0] == 413
            assert request(auth=alice, session=a, raw='{bad')[0] == 400
            assert request(listing, alice)[0] == 400
            slow = connection(timeout=10)
            slow.putrequest('POST', '/mcp')
            for k,v in {'Authorization': 'Bearer '+alice, 'Content-Type': 'application/json',
                        'Accept': 'application/json, text/event-stream', 'Mcp-Session-Id': a,
                        'Content-Length': '1000'}.items():
                slow.putheader(k,v)
            slow.endheaders()
            slow.send(b'{')
            started = time.monotonic()
            slow_response = slow.getresponse()
            assert slow_response.status == 408 and 4 <= time.monotonic()-started < 8
            slow_response.read()
            slow.close()
            print('PASS: body cap, slow-body deadline, malformed JSON, initialization requirement')

            # A silent synthetic SSH peer proves cancellation drops network work.
            peer = socket.socket()
            peer.bind(('127.0.0.1', 0))
            peer.listen()
            peer.settimeout(10)
            config['sessions'][0]['port'] = peer.getsockname()[1]
            config['mcp_use_saved_credentials'] = True
            saved.write_text(json.dumps(config))
            accepted = threading.Event()
            closed = threading.Event()
            def silent_peer():
                connection, _ = peer.accept()
                accepted.set()
                connection.settimeout(8)
                try:
                    while connection.recv(8192):
                        pass
                    closed.set()
                except ConnectionResetError:
                    closed.set()
                finally:
                    connection.close()
            thread = threading.Thread(target=silent_peer, daemon=True)
            thread.start()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(call, 'run_command', dict(session_id='fixture', command='true', timeout_seconds=60), 77)
                assert accepted.wait(5), ('SSH fixture never reached', future.result(timeout=1) if future.done() else 'request still pending')
                started = time.monotonic()
                assert request(dict(jsonrpc='2.0', method='notifications/cancelled', params={'requestId': 77}), alice, a)[0] == 202
                result = future.result(timeout=5)
                assert time.monotonic()-started < 5
                assert closed.wait(5), 'cancelled SSH transport did not close'
            print('PASS: MCP cancellation promptly closes synthetic stalled SSH transport')
            accepted.clear()
            closed.clear()
            threading.Thread(target=silent_peer, daemon=True).start()
            short_token = token(exp=int(time.time()) + 2)
            started = time.monotonic()
            request(dict(jsonrpc='2.0', id=79, method='tools/call', params=dict(name='run_command',
                arguments=dict(session_id='fixture', command='true', timeout_seconds=60))), short_token, a)
            assert accepted.is_set() and closed.wait(3), 'expired access token did not close in-flight SSH'
            assert time.monotonic() - started < 4
            print('PASS: token expiry cancels an in-flight operation and bounds its result stream')
            accepted.clear()
            closed.clear()
            threading.Thread(target=silent_peer, daemon=True).start()
            disposable = initialize(alice)
            disconnected = connection(timeout=10)
            disconnected.request('POST', '/mcp', body=json.dumps(dict(jsonrpc='2.0', id=80, method='tools/call',
                params=dict(name='run_command', arguments=dict(session_id='fixture', command='true', timeout_seconds=60)))),
                headers={'Authorization': 'Bearer '+alice, 'Content-Type': 'application/json',
                         'Accept': 'application/json, text/event-stream', 'Mcp-Session-Id': disposable,
                         'MCP-Protocol-Version': args.protocol_version})
            pending_response = disconnected.getresponse()
            assert accepted.wait(5)
            pending_response.close()
            disconnected.close()
            assert request(auth=alice, session=disposable, method='DELETE')[0] in (200,202)
            assert closed.wait(5), 'DELETE after network disconnect did not close SSH'
            assert request(listing, alice, disposable)[0] == 404
            peer.close()
            print('PASS: disconnected request can be explicitly terminated with session DELETE')

            # Reuse the existing synthetic SSH fixture, with a deliberately slow
            # in-memory upload endpoint. Cancelling must stop detached transfers.
            import paramiko
            import ssh_jump_chain_e2e as ssh_fixture
            received = threading.Event()
            writes = []
            class SlowHandle(paramiko.SFTPHandle):
                def write(self, offset, data):
                    writes.append(len(data))
                    received.set()
                    time.sleep(.02)
                    return paramiko.SFTP_OK
            class SlowFiles(ssh_fixture.Files):
                def open(self, path, flags, attr):
                    return SlowHandle(flags)
            original_files = ssh_fixture.Files
            ssh_fixture.Files = SlowFiles
            node = ssh_fixture.Node('http-transfer')
            try:
                config['sessions'][0].update(port=node.port, password=ssh_fixture.PASSWORD)
                saved.write_text(json.dumps(config))
                (profile / 'known_hosts').write_text(f'127.0.0.1:{node.port} {node.key.get_name()} {node.key.get_base64()}\n')
                upload = root / 'synthetic-upload.bin'
                upload.write_bytes(b'x' * (8 * 1024 * 1024))
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(call, 'upload_file', dict(session_id='fixture', local_path=str(upload),
                        remote_directory='/tmp', timeout_seconds=60), 78)
                    assert received.wait(8), 'SFTP upload fixture never received bytes'
                    assert request(dict(jsonrpc='2.0', method='notifications/cancelled', params={'requestId': 78}), alice, a)[0] == 202
                    future.result(timeout=5)
                    deadline = time.monotonic() + 5
                    while any(t.is_active() for t in node.transports) and time.monotonic() < deadline:
                        time.sleep(.05)
                    assert not any(t.is_active() for t in node.transports), 'cancelled SFTP SSH transport is still active'
                    # The server can finish packets already buffered before
                    # disconnect; cancellation cannot roll back remote writes.
                    deadline = time.monotonic() + 4
                    count = len(writes)
                    while time.monotonic() < deadline:
                        time.sleep(.2)
                        if len(writes) == count:
                            break
                        count = len(writes)
                    else:
                        raise AssertionError('SFTP fixture did not drain after transport cancellation')
                    assert sum(writes) < upload.stat().st_size
                print('PASS: cancellation during active upload aborts child transfer and SSH transport')
            finally:
                node.close()
                ssh_fixture.Files = original_files

            assert request(auth=alice, session=a, method='DELETE')[0] in (200, 202)
            assert request(listing, alice, a)[0] == 404
            assert request(listing, bob, b)[0] == 200
            print('PASS: session DELETE invalidates only its owner session')
        finally:
            process.terminate()
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError('service shutdown exceeded 12 seconds')
            output = log.read_text()
            if args.caddy:
                output += proxy.log.read_text()
            assert locals().get('alice', 'not-a-log-value') not in output and locals().get('bob', 'not-a-log-value') not in output
            assert 'synthetic-not-a-real-secret' not in output
        print(f'PASS: clean shutdown; no token/credential logging; negotiated MCP {args.protocol_version}')

        # Keep each admission test on a fresh service. Limits are deliberately
        # independent so a refusal proves the named gate, not an earlier gate.
        limit_names = ('sessions', 'requests', 'calls', 'streams')
        unlimited = dict.fromkeys(limit_names, 0)

        def limits_cli(*arguments, selected=profile, check=True):
            result = subprocess.run([str(exe), '--data-dir', str(selected), 'cli', 'mcp-limits',
                                     *map(str, arguments)], env=child_env, capture_output=True,
                                    text=True, timeout=10)
            if check:
                assert result.returncode == 0, (arguments, result.stdout, result.stderr)
            return result

        def limits_json(*arguments):
            value = json.loads(limits_cli(*arguments, '--json').stdout)
            assert value['zero_means_unlimited'] is True
            assert isinstance(value['saved'], bool) and isinstance(value['restart_required'], bool)
            assert value['saved'] is bool(arguments)
            return value['limits']

        # Reads must not migrate/rewrite the file, and updates must preserve
        # unrelated configuration and untouched individual limits.
        config.pop('mcp_http_limits', None)
        saved.write_text(json.dumps(config))
        before = saved.read_bytes()
        assert limits_json() == unlimited
        assert saved.read_bytes() == before, 'reading defaults rewrote the profile'
        limits_cli('--sessions', 3, '--calls', 2)
        expected = dict(unlimited, sessions=3, calls=2)
        assert limits_json() == expected
        persisted = json.loads(saved.read_text())
        assert persisted['mcp_http_limits'] == expected
        for name, value in config.items():
            if name == 'sessions':
                assert len(persisted[name]) == len(value)
                for original, updated in zip(value, persisted[name]):
                    # ConfigStore intentionally encrypts legacy plaintext secrets
                    # and may serialize default fields during any successful save.
                    for field, field_value in original.items():
                        if field != 'password':
                            assert updated[field] == field_value, ('session setting changed', field)
                    assert updated['password'], 'session credential was lost'
            else:
                assert persisted[name] == value, ('unrelated profile setting changed', name)
        assert limits_json('--streams', 4) == dict(expected, streams=4)
        assert limits_json('--sessions', 0) == dict(expected, sessions=0, streams=4)
        for name in limit_names:
            limits_cli('--' + name, 1_000_000)
            assert limits_json()[name] == 1_000_000
            for invalid in ('-1', '1000001', '18446744073709551616', '1.5', 'abc'):
                before = saved.read_bytes()
                result = limits_cli('--' + name, invalid, check=False)
                assert result.returncode != 0, (name, invalid, result.stdout)
                assert saved.read_bytes() == before, ('invalid CLI changed profile', name, invalid)
        before = saved.read_bytes()
        assert limits_cli('--sessions', 2, '--calls', '1000001', check=False).returncode != 0
        assert saved.read_bytes() == before, 'partial invalid update mutated valid field'
        valid_profile = saved.read_bytes()
        invalid_settings = [None, [], 'invalid', dict(unlimited, unknown=1)]
        for name in limit_names:
            for invalid in (None, -1, 1.5, '2', 1_000_001, 18_446_744_073_709_551_616):
                invalid_settings.append(dict(unlimited, **{name: invalid}))
        for invalid in invalid_settings:
            malformed = dict(config, mcp_http_limits=invalid)
            saved.write_text(json.dumps(malformed))
            before = saved.read_bytes()
            for arguments in (('--json',), ('--sessions', 2, '--json')):
                result = limits_cli(*arguments, check=False)
                assert result.returncode != 0, ('malformed profile accepted', invalid, result.stdout)
                assert saved.read_bytes() == before, ('malformed profile reset or changed', invalid)
        saved.write_bytes(valid_profile)
        other_profile = root / 'other-profile'
        other_profile.mkdir(mode=0o700)
        other_saved = other_profile / 'sessions.json'
        other_saved.write_text(json.dumps(dict(config, mcp_http_limits=dict(unlimited, sessions=1))))
        other_before = other_saved.read_bytes()
        limits_cli('--sessions', 0, '--requests', 0, '--calls', 0, '--streams', 0)
        assert other_saved.read_bytes() == other_before
        print('PASS: limits CLI defaults, partial updates, persistence, bounds, overflow and invalid-input atomicity')

        @contextlib.contextmanager
        def limits_server(limits=None, extra_env=None, preserve_saved=False):
            current = dict(config)
            if limits is not None:
                current['mcp_http_limits'] = limits
            else:
                current.pop('mcp_http_limits', None)
            if not preserve_saved:
                saved.write_text(json.dumps(current))
            with log.open('wb') as output:
                service = subprocess.Popen(start, stdout=subprocess.DEVNULL, stderr=output,
                                           env=dict(child_env, **(extra_env or {})))
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    assert service.poll() is None, 'limits service exited: ' + log.read_text()
                    try:
                        with socket.create_connection(('127.0.0.1', port), .1):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise AssertionError('limits service not ready')
                yield
            finally:
                service.terminate()
                try:
                    service.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    service.kill()
                    service.wait()
                    raise AssertionError('limits service shutdown exceeded 12 seconds')
                output = log.read_text()
                assert alice not in output and bob not in output
                assert 'synthetic-not-a-real-secret' not in output

        @contextlib.contextmanager
        def stalled_calls():
            # Count accepted and closed connections rather than sleeping and
            # guessing whether the concurrent tool bodies actually started.
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(128)
            listener.settimeout(.1)
            state = {'accepted': 0, 'closed': 0}
            condition = threading.Condition()
            stop = threading.Event()
            connections = []
            def serve(client):
                try:
                    while client.recv(8192):
                        pass
                except OSError:
                    pass
                finally:
                    client.close()
                    with condition:
                        state['closed'] += 1
                        condition.notify_all()
            def accept():
                while not stop.is_set():
                    try:
                        client, _ = listener.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    connections.append(client)
                    with condition:
                        state['accepted'] += 1
                        condition.notify_all()
                    threading.Thread(target=serve, args=(client,), daemon=True).start()
            worker = threading.Thread(target=accept, daemon=True)
            worker.start()
            current = json.loads(saved.read_text())
            current['sessions'][0].update(port=listener.getsockname()[1], password='synthetic-not-a-real-secret')
            current['mcp_allow_commands'] = True
            current['mcp_use_saved_credentials'] = True
            saved.write_text(json.dumps(current))
            def wait_count(field, count):
                with condition:
                    assert condition.wait_for(lambda: state[field] >= count, timeout=8), (field, count, state)
            try:
                yield wait_count
            finally:
                stop.set()
                listener.close()
                worker.join(timeout=2)
                for client in connections:
                    try:
                        client.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    client.close()

        def pending_call(session, request_id):
            return call('run_command', dict(session_id='fixture', command='true', timeout_seconds=60),
                        request_id, session)

        def cancel(session, request_id):
            assert request(dict(jsonrpc='2.0', method='notifications/cancelled',
                                params={'requestId': request_id}), alice, session)[0] == 202

        def delete(session):
            assert request(auth=alice, session=session, method='DELETE')[0] in (200, 202)
            assert request(listing, alice, session)[0] == 404

        def incomplete_request(session):
            slow = connection(timeout=10)
            slow.putrequest('POST', '/mcp')
            for name, value in {'Authorization': 'Bearer ' + alice, 'Content-Type': 'application/json',
                                'Accept': 'application/json, text/event-stream', 'Mcp-Session-Id': session,
                                'MCP-Protocol-Version': args.protocol_version, 'Content-Length': '1000'}.items():
                slow.putheader(name, value)
            slow.endheaders()
            slow.send(b'{')
            return slow

        # Missing field means unlimited, including past the historical gates.
        # A conflicting environment profile must not override --data-dir.
        with limits_server(extra_env={'MEATSHELL_DATA_DIR': str(other_profile)}):
            sessions = [initialize(alice) for _ in range(70)]
            with contextlib.ExitStack() as pending:
                slow_clients = [pending.enter_context(contextlib.closing(incomplete_request(sessions[0])))
                                for _ in range(36)]
                assert request(listing, alice, sessions[0])[0] == 200
                for slow in slow_clients:
                    response = slow.getresponse()
                    assert response.status == 408, ('unlimited request admission refused', response.status)
                    response.read()
            with stalled_calls() as wait_count, concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
                futures = [pool.submit(pending_call, sessions[i], 1000+i) for i in range(20)]
                wait_count('accepted', 20)
                assert not any(f.done() for f in futures), 'unlimited concurrent tool/stream admission refused'
                for i in range(20):
                    cancel(sessions[i], 1000+i)
                for future in futures:
                    assert future.result(timeout=5)[0] == 200
                wait_count('closed', 20)
            for session in sessions:
                delete(session)
        print('PASS: missing limits permit 70 sessions, 36 requests and 20 calls/streams; explicit profile wins')

        # Omitted individual values also default to unlimited.
        with limits_server({'sessions': 2}):
            first, second = initialize(alice), initialize(bob)
            assert request(init, alice)[0] == 429
            # Editing the persisted setting does not change a running service.
            limits_cli('--sessions', 0)
            assert request(init, alice)[0] == 429, 'limit changed without restart'
            delete(first)
            replacement = initialize(alice)
            assert request(init, alice)[0] == 429
            delete(replacement)
            assert request(auth=bob, session=second, method='DELETE')[0] in (200, 202)
        with limits_server(preserve_saved=True):
            sessions = [initialize(alice) for _ in range(3)]
            for session in sessions:
                delete(session)
        print('PASS: finite sessions refuse, release on DELETE, recover; changed limits take effect after restart')
        # Lowering a persisted limit cannot evict or change a running service;
        # a restarted service enforces the new, smaller admission capacity.
        with limits_server(dict(unlimited, sessions=3)):
            old_sessions = [initialize(alice) for _ in range(3)]
            limits_cli('--sessions', 1)
            delete(old_sessions.pop())
            replacement = initialize(alice)
            assert request(init, alice)[0] == 429
            for session in [*old_sessions, replacement]:
                delete(session)
        with limits_server(preserve_saved=True):
            session = initialize(alice)
            assert request(init, alice)[0] == 429
            delete(session)
        print('PASS: lowering saved session capacity applies only after restart')


        with limits_server(dict(unlimited, sessions=2)):
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                admissions = list(pool.map(lambda _: request(init, alice), range(8)))
            admitted = [headers['mcp-session-id'] for status, headers, _ in admissions if status == 200]
            assert len(admitted) == 2, [status for status, _, _ in admissions]
            assert all(status in (200, 429) for status, _, _ in admissions)
            for session in admitted:
                delete(session)
            replacement = initialize(alice)
            delete(replacement)
        print('PASS: concurrent initialize never oversubscribes finite session capacity')

        with limits_server(dict(unlimited, requests=1)):
            session = initialize(alice)
            slow = incomplete_request(session)
            try:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    status = request(listing, alice, session)[0]
                    if status == 429:
                        break
                    assert status == 200, status
                    time.sleep(.02)
                else:
                    raise AssertionError('finite request admission never refused')
                response = slow.getresponse()
                assert response.status == 408
                response.read()
            finally:
                slow.close()
            assert request(listing, alice, session)[0] == 200
            # Invalid bodies also release their request permit.
            assert request(auth=alice, session=session, raw='{bad')[0] == 400
            assert request(listing, alice, session)[0] == 200
            delete(session)
        print('PASS: finite request gate refuses during slow body and recovers after timeout/error')

        for gate in ('calls', 'streams'):
            with limits_server(dict(unlimited, **{gate: 1})):
                session = initialize(alice)
                with stalled_calls() as wait_count, concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(pending_call, session, 2000)
                    wait_count('accepted', 1)
                    assert not future.done()
                    status, _, value = call('list_sessions', {}, 2001, session)
                    if gate == 'calls':
                        assert status == 200 and 'error' in value and 'busy' in json.dumps(value).lower(), (status, value)
                        assert request(listing, alice, session)[0] == 200
                    else:
                        assert status == 429, (status, value)
                        assert request(listing, alice, session)[0] == 429
                    # Control messages must remain usable at call/stream capacity.
                    cancel(session, 2000)
                    assert future.result(timeout=5)[0] == 200
                    wait_count('closed', 1)
                    status, _, value = call('list_sessions', {}, 2002, session)
                    assert status == 200 and 'result' in value and not value['result'].get('isError'), (status, value)
                    future = pool.submit(pending_call, session, 2003)
                    wait_count('accepted', 2)
                    delete(session)
                    future.result(timeout=5)
                    wait_count('closed', 2)
                    replacement = initialize(alice)
                    assert call('list_sessions', {}, 2004, replacement)[0] == 200
                    delete(replacement)
            print(f'PASS: finite {gate} refusal, cancellation/DELETE under load, permit recovery')


if __name__ == '__main__':
    main()
