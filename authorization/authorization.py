#!/usr/bin/env python
# -*- coding: utf-8 -*-

from operator import truediv
import sys
reload(sys)

if (sys.version_info[0] == 2):
    sys.setdefaultencoding('utf8')

sys.path.append("..")

from helpers.http import get_authorization_header_from_message, get_cookie_header_from_message, isStatusCodesReturned, makeMessage, makeRequest, getResponseBody, IHttpRequestResponseImplementation
from gui.table import LogEntry, UpdateTableEDT
from javax.swing import SwingUtilities
from java.net import URL
import re

def tool_needs_to_be_ignored(self, toolFlag):
    return False # Spider and target requests are not forwarded anyway?
    for i in range(0, self.IFList.getModel().getSize()):
        filterTitle = self.IFList.getModel().getElementAt(i).split(":")[0]
        if filterTitle == "Ignore spider requests":
            if (toolFlag == self._callbacks.TOOL_SPIDER):
                return True
        if filterTitle == "Ignore proxy requests":
            if (toolFlag == self._callbacks.TOOL_PROXY):
                return True
        if filterTitle == "Ignore target requests":
            if (toolFlag == self._callbacks.TOOL_TARGET):
                return True

def capture_last_cookie_header(self, messageInfo):
    cookies = get_cookie_header_from_message(self, messageInfo)
    if cookies:
        self.lastCookiesHeader = cookies
        self.fetchCookiesHeaderButton.setEnabled(True)

def capture_last_authorization_header(self, messageInfo):
    authorization = get_authorization_header_from_message(self, messageInfo)
    if authorization:
        self.lastAuthorizationHeader = authorization
        self.fetchAuthorizationHeaderButton.setEnabled(True)


def valid_tool(self, toolFlag):
    return (toolFlag == self._callbacks.TOOL_PROXY or
            (toolFlag == "AUTORIZE") or # Internal requests, from "retest all" etc
            (toolFlag == self._callbacks.TOOL_REPEATER and self.interceptRequestsfromRepeater.isSelected())
            # TODO: Allow intruder?
            )

def handle_304_status_code_prevention(self, messageInfo):
    if self.prevent304.isSelected():
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        rawHeaders = '\n'.join(requestInfo.getHeaders())

        if not "If-None-Match:" in rawHeaders and not "If-Modified-Since" in rawHeaders:
            return # Nothing to prevent

        requestHeaders = list(requestInfo.getHeaders())
        newHeaders = list()
        for header in requestHeaders:
            if not "If-None-Match:" in header and not "If-Modified-Since:" in header:
                newHeaders.append(header)
        bodyBytes = messageInfo.getRequest()[requestInfo.getBodyOffset():]
        bodyStr = self._helpers.bytesToString(bodyBytes)
        messageInfo.setRequest(self._helpers.buildHttpMessage(newHeaders, bodyStr))

def message_not_from_autorize(self, messageInfo):
    return not self.replaceString.getText() in self._helpers.analyzeRequest(messageInfo).getHeaders() # TODO: set flag on request instead. Maybe setComment?

def message_passed_interception_filters(self, messageInfo):
    if self.IFList.getModel().getSize() == 0:
        return True
   
    reqInfo = self._helpers.analyzeRequest(messageInfo)
    urlString = str(reqInfo.getUrl())
    reqBodyBytes = messageInfo.getRequest()[reqInfo.getBodyOffset():]
    bodyStr = self._helpers.bytesToString(reqBodyBytes)

    resInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
    resBodyBytes = messageInfo.getResponse()[resInfo.getBodyOffset():]
    resStr = self._helpers.bytesToString(resBodyBytes)

    for i in range(0, self.IFList.getModel().getSize()):
        filterTitle = self.IFList.getModel().getElementAt(i).split(":")[0]
        if filterTitle == "Scope items only":
            currentURL = URL(urlString)
            if not self._callbacks.isInScope(currentURL):
                return False

        if filterTitle == "URL Contains (simple string)":
            if self.IFList.getModel().getElementAt(i)[30:] not in urlString:
                return False

        if filterTitle == "URL Contains (regex)":
            regex_string = self.IFList.getModel().getElementAt(i)[22:]
            if re.search(regex_string, urlString, re.IGNORECASE) is None:
                return False

        if filterTitle == "URL Not Contains (simple string)":
            if self.IFList.getModel().getElementAt(i)[34:] in urlString:
                return False

        if filterTitle == "URL Not Contains (regex)":
            regex_string = self.IFList.getModel().getElementAt(i)[26:]
            if not re.search(regex_string, urlString, re.IGNORECASE) is None:
                return False

        if filterTitle == "Request Body contains (simple string)":
            if self.IFList.getModel().getElementAt(i)[40:] not in bodyStr:
                return False

        if filterTitle == "Request Body contains (regex)":
            regex_string = self.IFList.getModel().getElementAt(i)[32:]
            if re.search(regex_string, bodyStr, re.IGNORECASE) is None:
                return False

        if filterTitle == "Request Body NOT contains (simple string)":
            if self.IFList.getModel().getElementAt(i)[44:] in bodyStr:
                return False

        if filterTitle == "Request Body Not contains (regex)":
            regex_string = self.IFList.getModel().getElementAt(i)[36:]
            if not re.search(regex_string, bodyStr, re.IGNORECASE) is None:
                return False

        if filterTitle == "Response Body contains (simple string)":
            if self.IFList.getModel().getElementAt(i)[41:] not in resStr:
                return False

        if filterTitle == "Response Body contains (regex)":
            regex_string = self.IFList.getModel().getElementAt(i)[33:]
            if re.search(regex_string, resStr, re.IGNORECASE) is None:
                return False

        if filterTitle == "Response Body NOT contains (simple string)":
            if self.IFList.getModel().getElementAt(i)[45:] in resStr:
                return False

        if filterTitle == "Response Body Not contains (regex)":
            regex_string = self.IFList.getModel().getElementAt(i)[37:]
            if not re.search(regex_string, resStr, re.IGNORECASE) is None:
                return False

        if filterTitle == "Header contains":
            for header in list(resInfo.getHeaders()):
                if self.IFList.getModel().getElementAt(i)[17:] in header:
                    return False

        if filterTitle == "Header doesn't contain":
            for header in list(resInfo.getHeaders()):
                if not self.IFList.getModel().getElementAt(i)[17:] in header:
                    return False

        if filterTitle == "Only HTTP methods (newline separated)":
            filterMethods = self.IFList.getModel().getElementAt(i)[39:].split("\n")
            filterMethods = [x.lower() for x in filterMethods]
            reqMethod = str(reqInfo.getMethod())
            if reqMethod.lower() not in filterMethods:
                return False

        if filterTitle == "Ignore HTTP methods (newline separated)":
            filterMethods = self.IFList.getModel().getElementAt(i)[41:].split("\n")
            filterMethods = [x.lower() for x in filterMethods]
            reqMethod = str(reqInfo.getMethod())
            if reqMethod.lower() in filterMethods:
                return False

        if filterTitle == "Ignore OPTIONS requests":
            reqMethod = str(reqInfo.getMethod())
            if reqMethod.upper() == "OPTIONS": # If for some reason OpTIONS
                return False

    return True

def handle_message(self, toolFlag, messageIsRequest, messageInfo):
    capture_last_cookie_header(self, messageInfo) # TODO: automatic authentication detection
    capture_last_authorization_header(self, messageInfo)

    if not self.intercept: # Interceptbutton clicked
        return

    if not valid_tool(self, toolFlag): # Whitelist PROXY and REPEATER (if checked)
        return

    #if tool_needs_to_be_ignored(self, toolFlag): # Blacklist SPIDER/PROXY/TARGET. But spider/target not in whitelist anyway?
    #    return


    if messageIsRequest:
        handle_304_status_code_prevention(self, messageInfo)
    else:
        if message_not_from_autorize(self, messageInfo):
            if self.ignore304.isSelected():
                if isStatusCodesReturned(self, messageInfo, ["304", "204"]):
                    return

            if message_passed_interception_filters(self, messageInfo):
                checkAuthorization(self, messageInfo, self._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(), self.doUnauthorizedRequest.isSelected())

def send_request_to_autorize(self, messageInfo):
    if messageInfo.getResponse() is None:
        message = makeMessage(self, messageInfo,False,False)
        requestResponse = makeRequest(self, messageInfo, message)
        checkAuthorization(self, requestResponse,self._helpers.analyzeResponse(requestResponse.getResponse()).getHeaders(),self.doUnauthorizedRequest.isSelected())
    else:
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        httpService = messageInfo.getHttpService()
        newHttpRequestResponse = IHttpRequestResponseImplementation(httpService,request,response)
        newHttpRequestResponsePersisted = self._callbacks.saveBuffersToTempFiles(newHttpRequestResponse)
        checkAuthorization(self, newHttpRequestResponsePersisted,self._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(),self.doUnauthorizedRequest.isSelected())

def auth_enforced_via_enforcement_detectors(self, filters, requestResponse, andOrEnforcement):
    response = requestResponse.getResponse()
    analyzedResponse = self._helpers.analyzeResponse(response)
    auth_enforced = False
    if andOrEnforcement == "And":
        andEnforcementCheck = True
        auth_enforced = True
    else:
        andEnforcementCheck = False
        auth_enforced = False

    for filter in filters:
        filter = self._helpers.bytesToString(bytes(filter))
        inverse = "NOT" in filter
        filter = filter.replace(" NOT", "")

        if filter.startswith("Status code equals: "):
            statusCode = filter[20:]
            filterMatched = inverse ^ isStatusCodesReturned(self, requestResponse, statusCode)

        elif filter.startswith("Headers (simple string): "):
            filterMatched = inverse ^ (filter[25:] in self._helpers.bytesToString(requestResponse.getResponse()[0:analyzedResponse.getBodyOffset()]))

        elif filter.startswith("Headers (regex): "):
            regex_string = filter[17:]
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(p.search(self._helpers.bytesToString(requestResponse.getResponse()[0:analyzedResponse.getBodyOffset()])))

        elif filter.startswith("Body (simple string): "):
            filterMatched = inverse ^ (filter[22:] in self._helpers.bytesToString(requestResponse.getResponse()[analyzedResponse.getBodyOffset():]))

        elif filter.startswith("Body (regex): "):
            regex_string = filter[14:]
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(p.search(self._helpers.bytesToString(requestResponse.getResponse()[analyzedResponse.getBodyOffset():])))

        elif filter.startswith("Full response (simple string): "):
            filterMatched = inverse ^ (filter[31:] in self._helpers.bytesToString(requestResponse.getResponse()))

        elif filter.startswith("Full response (regex): "):
            regex_string = filter[23:]
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(p.search(self._helpers.bytesToString(requestResponse.getResponse())))

        elif filter.startswith("Full response length: "):
            filterMatched = inverse ^ (str(len(response)) == filter[22:].strip())

        if andEnforcementCheck:
            if auth_enforced and not filterMatched:
                auth_enforced = False
        else:
            if not auth_enforced and filterMatched:
                auth_enforced = True

    return auth_enforced

def checkBypass(self, oldStatusCode, newStatusCode, oldContent,
                 newContent, filters, requestResponse, andOrEnforcement):
    if oldStatusCode == newStatusCode:
        auth_enforced = False
        if len(filters) > 0:
            auth_enforced = auth_enforced_via_enforcement_detectors(self, filters, requestResponse, andOrEnforcement)
        if auth_enforced:
            return self.ENFORCED_STR
        elif oldContent == newContent:
            return self.BYPASSSED_STR
        else:
            return self.IS_ENFORCED_STR
    else:
        return self.ENFORCED_STR

def checkAuthorization(self, messageInfo, originalHeaders, checkUnauthorized):
    message = makeMessage(self, messageInfo, True, True) # Applies replacement logic for auth/unauth state
    requestResponse = makeRequest(self, messageInfo, message)
    newResponse = requestResponse.getResponse()
    analyzedResponse = self._helpers.analyzeResponse(newResponse)

    oldStatusCode = originalHeaders[0]
    newStatusCode = analyzedResponse.getHeaders()[0]
    oldContent = getResponseBody(self, messageInfo)
    newContent = getResponseBody(self, requestResponse)

    # Check unauthorized request
    if checkUnauthorized:
        messageUnauthorized = makeMessage(self, messageInfo, True, False)
        requestResponseUnauthorized = makeRequest(self, messageInfo, messageUnauthorized)
        unauthorizedResponse = requestResponseUnauthorized.getResponse()
        analyzedResponseUnauthorized = self._helpers.analyzeResponse(unauthorizedResponse)
        statusCodeUnauthorized = analyzedResponseUnauthorized.getHeaders()[0]
        contentUnauthorized = getResponseBody(self, requestResponseUnauthorized)

    EDFilters = self.EDModel.toArray()

    impression = checkBypass(self, oldStatusCode, newStatusCode, oldContent, newContent, EDFilters, requestResponse, self.AndOrType.getSelectedItem())

    if checkUnauthorized:
        EDFiltersUnauth = self.EDModelUnauth.toArray()
        impressionUnauthorized = checkBypass(self, oldStatusCode, statusCodeUnauthorized, oldContent, contentUnauthorized, EDFiltersUnauth, requestResponseUnauthorized, self.AndOrTypeUnauth.getSelectedItem())

    self._lock.acquire()

    row = self._log.size()
    method = self._helpers.analyzeRequest(messageInfo.getRequest()).getMethod()

    if checkUnauthorized:
        self._log.add(LogEntry(self.currentRequestNumber,self._callbacks.saveBuffersToTempFiles(requestResponse), method, self._helpers.analyzeRequest(requestResponse).getUrl(),messageInfo,impression,self._callbacks.saveBuffersToTempFiles(requestResponseUnauthorized),impressionUnauthorized)) # same requests not include again.
    else:
        self._log.add(LogEntry(self.currentRequestNumber,self._callbacks.saveBuffersToTempFiles(requestResponse), method, self._helpers.analyzeRequest(requestResponse).getUrl(),messageInfo,impression,None,"Disabled")) # same requests not include again.

    SwingUtilities.invokeLater(UpdateTableEDT(self,"insert",row,row))
    self.currentRequestNumber = self.currentRequestNumber + 1
    self._lock.release()

def checkAuthorizationV2(self, messageInfo):
    checkAuthorization(self, messageInfo, self._extender._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(), self._extender.doUnauthorizedRequest.isSelected())

def retestAllRequests(self):
    self.logTable.setAutoCreateRowSorter(True)
    for i in range(self.tableModel.getRowCount()):
        logEntry = self._log.get(self.logTable.convertRowIndexToModel(i))
        handle_message(self, "AUTORIZE", False, logEntry._originalrequestResponse)
