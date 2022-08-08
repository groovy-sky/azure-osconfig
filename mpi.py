
import fire
import json
import shlex
import subprocess

def call(path, payload):
    # print(f"[REQ] {path} {payload}")
    command = f"curl -X POST --unix-socket /run/osconfig/mpid.sock http://osconfig/{path} -H 'Content-Type: application/json' -d '{payload}'"
    args = shlex.split(command)

    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # print(f"[RES] {result.stdout}")
    return result.stdout

def mpi_open(client_name):
    req_payload = {
        "ClientName": client_name,
        "MaxPayloadSizeBytes": 4096
    }
    return call("MpiOpen", json.dumps(req_payload))

def mpi_close(session):
    payload = { "ClientSession": session }
    return call("MpiClose", json.dumps(payload))

def mpi_get(component, object):
    session = mpi_open("TestClient")
    session = session.replace('"', '')

    payload = {
        "ClientSession": session,
        "ComponentName": component,
        "ObjectName": object
    }
    response = call("MpiGet", json.dumps(payload))

    # pretty print the json response
    parsed = json.loads(response)
    print(json.dumps(parsed, indent=4))

    mpi_close(session)

def mpi_set(component, object, payload):
    session = mpi_open("TestClient")
    session = session.replace('"', '')


    req_payload = {
        "ClientSession": session,
        "ComponentName": component,
        "ObjectName": object,
        "Payload": payload
    }
    response = call("MpiSet", json.dumps(req_payload))

    # pretty print the json response
    if response:
        parsed = json.loads(response)
        print(json.dumps(parsed, indent=4))

    mpi_close(session)

if __name__ == '__main__':
    fire.Fire({
        "get": mpi_get,
        "set": mpi_set
    })