import sys

def main():
    try:
        inputs = {
        "hostname": sys.argv[1],
        "username": sys.argv[2],
        "password": sys.argv[3],
        "workflow": sys.argv[4],
        "color_warn": "\033[93m",
        "color_fail": "\033[91m",
        "color_end": "\033[0m"
        }
    except:
        raise Exception("Usage: " + sys.argv[0] + " vroFQDN username password workflowname [severity [executionid]]\nseverity: debug/info/warning/error")

    try:
        inputs["severity"] = sys.argv[5]
    except:
        inputs["severity"] = "info"

    try:
        inputs["executionId"] = sys.argv[6]
    except:
        inputs["executionId"] = ""

    handler(None, inputs)

import json, ssl, time
from urllib import request, parse

def handler(context, inputs):
    
    global color_warn, color_fail, color_end, hostname, access_token

    hostname = inputs["hostname"]
    username = inputs["username"]
    password = inputs["password"]
    foldername = inputs["workflow"].rpartition("/")[0]
    workflowname = inputs["workflow"].rpartition("/")[2]
    severity = inputs["severity"] or "info"
    executionId = inputs["executionId"] or ""
    color_warn = inputs["color_warn"] or ""
    color_fail = inputs["color_fail"] or ""
    color_end = inputs["color_end"] or ""
    workflow = {}
    access_token = getToken(username, password)

    wfLinks = doReq("GET", "/vco/api/catalog/System/Workflow?conditions=name=" + parse.quote(workflowname))["link"]

    for wfLink in wfLinks:
        wf = collectAttributes(wfLink)
        wfCategoryLink = doReq("GET", "/vco/api/catalog/System/WorkflowCategory/" + wf["categoryId"])
        wfCategory = collectAttributes(wfCategoryLink)
        if wfCategory["displayName"] == foldername:
            workflow = wf 
            break

    if workflow:
        print("Workflow '" + workflowname + "' found, id: " + workflow["id"])
    else:
        raise Exception("Workflow '" + workflowname + "' not found.")

    # get last execution if executionId is not defined
    if executionId == "":
        executionLinks = doReq("GET", "/vco/api/catalog/System/WorkflowExecution/?maxResult=1&sortOrders=-startDate&conditions=workflowId=" + workflow["id"])["link"]
        if 0 == len(executionLinks):
            raise Exception("Last workflow token was not found.")

        execution = collectAttributes(executionLinks[0])
        print("Found execution id: " + execution["id"] + ", startDate: " + execution["startDate"])
        executionId = execution["id"]

    state = ""
    timestamp = ""
    lasttimestamp = "0"
    while state == "running" or timestamp != lasttimestamp:
        timestamp = lasttimestamp
        lasttimestamp = getLogs(workflow["id"], executionId, severity, timestamp)
        state = doReq("GET", "/vco/api/workflows/" + workflow["id"] + "/executions/" + executionId)["state"]
        if state == "running" and timestamp == lasttimestamp:
            time.sleep(1)


def getToken(userName, password):
    # ignore certificate errors
    ctx = ssl._create_unverified_context()
    
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    dataDict = {"username": userName, "password": password}
    req = request.Request("https://" + hostname + "/csp/gateway/am/api/login?access_token", headers = headers, data=json.dumps(dataDict).encode("utf-8"));
    resp = json.loads(request.urlopen(req, context=ctx).read().decode("utf-8"))

    dataDict = {"refreshToken": resp["refresh_token"]}
    req = request.Request("https://" + hostname + "/iaas/api/login", headers = headers, data=json.dumps(dataDict).encode("utf-8"));
    resp = json.loads(request.urlopen(req, context=ctx).read().decode("utf-8"))
    return resp["token"]

def doReq(method, path, dataDict = {}):
    # ignore certificate errors
    ctx = ssl._create_unverified_context()
    
    headers = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": "Bearer " + access_token}
    data = json.dumps(dataDict).encode("utf-8")
    req = request.Request("https://" + hostname + path, headers = headers, data=data, method = method)
    if dataDict:
        print("DATA: " + data)
    return json.loads(request.urlopen(req, context=ctx).read().decode("utf-8"))

def collectAttributes(link):
    dict = {}
    for attr in link["attributes"]:
        dict[attr["name"]] = attr.get("value", "")
    return dict

def getLogs(workflowId, executionId, severity, timestamp):
    # ignore certificate errors
    ctx = ssl._create_unverified_context()
    
    logs = doReq("GET", "/vco/api/workflows/" + workflowId + "/executions/" + executionId + "/syslogs?maxResult=100&conditions=severity=" + severity + "&conditions=timestamp%3E" + str(timestamp))["logs"]
    lasttimestamp = timestamp

    for log in logs:
        global item
        try:
            item   # last wf item name
        except:
            item = ""
        entry = log["entry"]
        color = ""
        if entry["short-description"].startswith("__item_stack:/"):     # do not print item numbers, just save them for later
            item = entry["short-description"].partition("/")[2]
        else:
            if "warning" == entry["severity"]:
                color = color_warn
            if "error" == entry["severity"]:
                color = color_fail
            print(entry["time-stamp"] + " " + color + entry["severity"] + color_end + " " + item + " " + entry["short-description"])
        lasttimestamp = entry["time-stamp-val"]
    return lasttimestamp

if __name__ == "__main__":
    main()