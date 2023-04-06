import boto3
import requests
import json
from requests_aws4auth import AWS4Auth
from datetime import datetime

region = 'us-east-1'
service = 'es'
credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)

# the OpenSearch Service domain, e.g. https://search-mydomain.us-west-1.es.amazonaws.com
opensearch = 'https://my-opensearch.us-east-1.es.amazonaws.com' 
now = datetime.now()
index = 'waf_logs-' + now.strftime("%Y.%m.%d")
datatype = '_doc'
url = opensearch + '/' + index + '/' + datatype

headers = { "Content-Type": "application/json" }

s3 = boto3.client('s3')

# Lambda execution starts here
def handler(event, context):
    for record in event['Records']:

        # Get the bucket name and key for the new file
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        
        # Get, read, and split the file into lines
        obj = s3.get_object(Bucket=bucket, Key=key)
        body = obj['Body'].read()
        lines = body.splitlines()

        # Match the regular expressions to each line and index the JSON
        for line in lines:
            line = line.decode("utf-8")
            message_pattern = json.loads(line)
            time = message_pattern['time']
            client = message_pattern['client']
            session_id = message_pattern['session_id']
            stream = message_pattern['stream']
            host = message_pattern['host']
            request_time = message_pattern['request_time']
            request_method = message_pattern['request_method']
            status = message_pattern['status']
            proxy_status= message_pattern['proxy_status']
            scheme = message_pattern['scheme']
            request_uri = message_pattern['request_uri']
            request_length = message_pattern['request_length']
            bytes_sent = message_pattern['bytes_sent']
            tcpinfo_rtt = message_pattern['tcpinfo_rtt']
            upstream_cache_status = message_pattern['upstream_cache_status']
            upstream_status = message_pattern['upstream_status']
            upstream_bytes_received = message_pattern['upstream_bytes_received']
            upstream_connect_time = message_pattern['upstream_connect_time']
            upstream_header_time = message_pattern['upstream_header_time']
            upstream_response_time = message_pattern['upstream_response_time']
            upstream_addr = message_pattern['upstream_addr']
            upstream_bytes_sent = message_pattern['upstream_bytes_sent']
            sent_http_content_type = message_pattern['sent_http_content_type']
            http_user_agent = message_pattern['http_user_agent']
            http_referer = message_pattern['http_referer']
            sent_http_x_original_image_size = message_pattern['sent_http_x_original_image_size']
            server_protocol = message_pattern['server_protocol']
            server_port = message_pattern['server_port']
            server_addr = message_pattern['server_addr']
            remote_addr = message_pattern['remote_addr']
            remote_port = message_pattern['remote_port']
            waf_attack_family = message_pattern['waf_attack_family']
            waf_attack_action = message_pattern['waf_attack_action']
            waf_learning = message_pattern['waf_learning']
            waf_block = message_pattern['waf_block']
            waf_total_processed = message_pattern['waf_total_processed']
            waf_total_blocked = message_pattern['waf_total_blocked']
            waf_score = message_pattern['waf_score']
            waf_match = message_pattern['waf_match']
            waf_headers = message_pattern['waf_headers']
            country = message_pattern['country']
            state = message_pattern['state']
            asn = message_pattern['asn']
            ssl_protocol = message_pattern['ssl_protocol']
            ssl_cipher = message_pattern['ssl_cipher']
            ssl_session_reused = message_pattern['ssl_session_reused']
            ssl_server_name = message_pattern['ssl_server_name']
            request_id = message_pattern['request_id']
            requestPath = message_pattern['requestPath']
            requestQuery = message_pattern['requestQuery']
            configuration = message_pattern['configuration']
            
            document = { "time": time, "client": client, "session_id": session_id, "stream": stream, "host": host, "request_time": request_time, "request_method": request_method, "status": status, "proxy_status": proxy_status, "scheme": scheme, "request_uri": request_uri, "request_length": request_length, "bytes_sent": bytes_sent, "tcpinfo_rtt": tcpinfo_rtt, "upstream_cache_status": upstream_cache_status, "upstream_status": upstream_status, "upstream_bytes_received": upstream_bytes_received, "upstream_connect_time": upstream_connect_time, "upstream_header_time": upstream_header_time, "upstream_response_time": upstream_response_time, "upstream_addr": upstream_addr, "upstream_bytes_sent": upstream_bytes_sent, "sent_http_content_type": sent_http_content_type, "http_user_agent": http_user_agent, "http_referer": http_referer, "sent_http_x_original_image_size": sent_http_x_original_image_size, "server_protocol": server_protocol, "server_port": server_port, "server_addr": server_addr, "remote_addr": remote_addr, "remote_port": remote_port, "waf_attack_family": waf_attack_family, "waf_attack_action": waf_attack_action, "waf_learning": waf_learning, "waf_block": waf_block, "waf_total_processed": waf_total_processed, "waf_total_blocked": waf_total_blocked, "waf_score": waf_score, "waf_match": waf_match, "waf_headers": waf_headers, "country": country, "state": state, "asn": asn, "ssl_protocol": ssl_protocol, "ssl_cipher": ssl_cipher, "ssl_session_reused": ssl_session_reused, "ssl_server_name": ssl_server_name, "request_id": request_id, "requestPath": requestPath, "requestQuery": requestQuery, "configuration": configuration}
            r = requests.post(url, auth=awsauth, json=document, headers=headers)
