import socket
import sys
import os
import argparse
import re
import time
import email.utils

# 1MB buffer size
BUFFER_SIZE = 1000000

def parse_http(raw_data):
    # Extract into header and body
    header, body = raw_data.split(b"\r\n\r\n", 1)
    # Split header into a list of lines
    header_lines = header.decode("utf-8").split("\r\n")
    # Decompose the header lines into key:value pairs
    headers = {line.split(": ")[0]: line.split(": ")[1] for line in header_lines[1:] if ": " in line}
    return headers, body

def update_date(http_data):
    headers, body = parse_http(http_data)
    
    #Generate new Date header
    headers["Date"] = email.utils.formatdate(time.time(), usegmt=True)
    
    #Reconstruct the header section
    header_lines = [http_data.split(b"\r\n", 1)[0].decode("utf-8")]
    header_lines += [f"{key}: {value}" for key, value in headers.items()]
    
    #Join headers and reassemble the raw HTTP data
    updated_header = "\r\n".join(header_lines).encode("utf-8")
    updated_raw_data = updated_header + b"\r\n\r\n" + body
    
    return updated_raw_data

def fetch_from_server(hostname, resource):
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Connecting to:		' + hostname + '\n')
    try:
        try:
            address = socket.gethostbyname(hostname)
        except Exception as e:
            print(f'Failed to get address: {e}')
            return None
        
        try:
            originServerSocket.connect((address, 80))
        except Exception as e:
            print(f'Failed to connect to origin server: {e}')
            return None
        
        print('Connected to origin Server')
        originServerRequest = f"GET {resource} HTTP/1.1"
        originServerRequestHeader = f"Host: {hostname}\r\nConnection: close"
        request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'
        
        print('Forwarding request to origin server:')
        for line in request.split('\r\n'):
            print('> ' + line)
        
        try:
            originServerSocket.sendall(request.encode())
        except Exception as e:
            print(f'Forward request to origin failed: {e}')
            sys.exit()
        
        print('Request sent to origin server\n')
        responseData = originServerSocket.recv(BUFFER_SIZE)
        headers, body = parse_http(responseData)
        cache_control = headers.get("Cache-Control", "")
        directives = dict(item.split("=") if "=" in item else (item, None) for item in cache_control.split(","))
        
        clientSocket.sendall(responseData)
        
        if "no-store" not in directives:
            cacheDir, file = os.path.split(cacheLocation)
            print('Cached directory ' + cacheDir)
            if not os.path.exists(cacheDir):
                os.makedirs(cacheDir)
            with open(cacheLocation, 'wb') as cacheFile:
                cacheFile.write(responseData)
            print('Cache file closed')
        
        print('Origin response received. Closing sockets')
        originServerSocket.close()
    
    except OSError as err:
        print('Origin server request failed. ' + err.strerror)

    
    return responseData

def check_cache(file_path):
    if not os.path.exists(file_path):
        print("File not found in cache - fetching from origin server...")
        return None
    
    with open(file_path, 'rb') as cache_file:
        cached_data = cache_file.read()
    
    headers, cached_body = parse_http(cached_data)
    cache_control = headers.get("Cache-Control", "")
    directives = dict(item.split("=") if "=" in item else (item, None) for item in cache_control.split(","))
    max_age_seconds = int(directives.get("max-age", 9999999999))
    http_date = headers.get("Date", "")
    dt = email.utils.parsedate_to_datetime(http_date)
    timestamp = dt.timestamp()
    cached_age = time.time() - timestamp
    
    if cached_age > max_age_seconds:
        return None
    
    return cached_data

parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='The IP Address Of Proxy Server')
parser.add_argument('port', help='The port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

try:
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Created socket')
except Exception as e:
    print(f'Failed to create socket: {e}')
    sys.exit()

try:
    serverSocket.bind((proxyHost, proxyPort))
    print('Port is bound')
except Exception as e:
    print(f'Failed to bind to port: {e}')
    sys.exit()

try:
    serverSocket.listen(1)
    print('Listening to socket')
except Exception as e:
    print(f'Failed to listen: {e}')
    sys.exit()

while True:
    print('Waiting for connection...')
    clientSocket = None
    try:
        clientSocket, address = serverSocket.accept()
        print('Received a connection')
    except Exception as e:
        print(f'Failed to accept connection: {e}')
        sys.exit()
    
    message_bytes = clientSocket.recv(BUFFER_SIZE)
    message = message_bytes.decode('utf-8')
    print('Received request:\n< ' + message)
    
    requestParts = message.split()
    method, URI, version = requestParts[:3]
    print(f'Method:		{method}\nURI:		{URI}\nVersion:	{version}\n')
    
    URI = re.sub('^(/?)http(s?)://', '', URI, count=1).replace('/..', '')
    resourceParts = URI.split('/', 1)
    hostname = resourceParts[0]
    resource = '/' + resourceParts[1] if len(resourceParts) == 2 else '/'
    print('Requested Resource:	' + resource)
    
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation += 'default'
    print('Cache location:		' + cacheLocation)
    
    cached_data = check_cache(cacheLocation)
    if cached_data is None:
        cached_data = fetch_from_server(hostname, resource)
    else:
    	cached_data = update_date(cached_data)
    
    try:
        clientSocket.sendall(cached_data)
    except Exception as e:
        print(f'Failed to send cached data: {e}')
        sys.exit()

    clientSocket.shutdown(socket.SHUT_WR)
    print('Client socket shutdown for writing')

    try:
        clientSocket.close()
    except:
        print('Failed to close client socket')
    
    print('Sent to the client')
