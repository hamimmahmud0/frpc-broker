import tunnelmate

conf = {
    "host": "127.0.0.1",
    "port": 5675,
    "protocol": "tcp",
    "scope": "open",
    "service_name": "Yolo Inference Service",
    "service_id": "yolov11-detection",
    "llms": "http://127.0.0.1:5675/llms.txt",
    "attributes": {"version": 11, "size": "n"},
}

with tunnelmate.new("https://broker.example.com", conf) as tunnel:
    tunnel.announce()
    print(tunnel.peer_address)
    tunnel.wait()
