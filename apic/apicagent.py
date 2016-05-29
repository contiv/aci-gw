#Copyright 2015 Cisco Systems Inc. All rights reserved.

#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

import os
import sys
from cobra.mit.access import MoDirectory
from cobra.mit.session import LoginSession
from cobra.mit.session import CertSession
from cobra.mit.request import ConfigRequest
from cobra.model.fv import Tenant
from cobra.model.fv import Ctx
from cobra.model.fv import BD
from cobra.model.fv import RsCtx
from cobra.model.fv import Subnet
from cobra.model.fv import Ap
from cobra.model.fv import AEPg
from cobra.model.fv import RsBd
from cobra.model.fv import RsDomAtt, RsNodeAtt
from cobra.model.fv import RsProv, RsCons
from cobra.model.vz import Filter, Entry, BrCP, Subj, RsSubjFiltAtt
from flask import Flask
from flask import json, request, Response

DefACIKeyFile = "/aciconfig/aci.key"
contivDefTenant = 'ContivTenant'
# Node used by contiv
contivDefNode = 'topology/pod-1/node-102'

class SafeDict(dict):
    'Provide a default value for missing keys'
    def __missing__(self, key):
        return 'missing'

class ObjDict(dict):
    'Provide a default value for missing keys'
    def __missing__(self, key):
        return None

class OperDict(dict):
    'Gracefully handle missing operation'
    def __missing__(self, key):
        return printSupport

def createTenant(moDir):
    uniMo = moDir.lookupByDn('uni')
    fvTenantMo = Tenant(uniMo, 'ContivTenant')
    cR = ConfigRequest()
    cR.addMo(fvTenantMo)
    moDir.commit(cR)

def createPvtNw(moDir, tenantDn):
    ctxMo = Ctx(tenantDn, 'ContivPvtVrf')
    cR = ConfigRequest()
    cR.addMo(ctxMo)
    moDir.commit(cR)

def createPvtNwWrapper(moDir):
    createPvtNw(moDir, 'uni/tn-ContivTenant')

def createBdSubnet(moDir):
    if len(sys.argv) < 4:
        print "Pls specify a subnet a.b.c.d/n"
        sys.exit(2)

    ip = sys.argv[3]
    netmask = ip.split('/')
    if len(netmask) != 2:
        print "Pls specify a subnet a.b.c.d/n"
        sys.exit(2)

    bdName = 'ContivBD' + netmask[0]
    fvBDMo = BD('uni/tn-ContivTenant', name=bdName)
    # associate to nw context
    RsCtx(fvBDMo, tnFvCtxName='ContivPvtVrf')
    # create subnet
    Subnet(fvBDMo, ip)
    cR = ConfigRequest()
    cR.addMo(fvBDMo)
    moDir.commit(cR)

def createAppProf(moDir):
    if len(sys.argv) < 5:
        print "Pls specify a subnet a.b.c.d/n and app"
        sys.exit(2)

    ip = sys.argv[3]
    netmask = ip.split('/')
    if len(netmask) != 2:
        print "Pls specify a subnet a.b.c.d/n"
        sys.exit(2)

    bdName = 'ContivBD' + netmask[0]
    appName = sys.argv[4]
    fvApMo = Ap('uni/tn-ContivTenant', appName)
    cR = ConfigRequest()
    cR.addMo(fvApMo)
    moDir.commit(cR)

def createEpg(moDir):
    if len(sys.argv) < 6:
        print "Pls specify a subnet a.b.c.d/n, app and epg"
        sys.exit(2)

    ip = sys.argv[3]
    netmask = ip.split('/')
    if len(netmask) != 2:
        print "Pls specify a subnet a.b.c.d/n"
        sys.exit(2)

    bdName = 'ContivBD' + netmask[0]
    appName = sys.argv[4]
    appDn = 'uni/tn-' + contivDefTenant + '/ap-' + appName
    epgName = sys.argv[5]
    fvEpg = AEPg(appDn, epgName)

    # associate to BD
    RsBd(fvEpg, tnFvBDName=bdName)
    # associate to phy domain
    physDom = os.getenv('APIC_PHYS_DOMAIN', 'not_specified')
    if physDom == "not_specified":
        print "Pls specify a physical domain"
        sys.exit(2)    

    contivClusterDom = 'uni/phys-' + physDom
    RsDomAtt(fvEpg, contivClusterDom)
    # TODO: add static binding
    cR = ConfigRequest()
    cR.addMo(fvEpg)
    moDir.commit(cR)

def createServiceContract(moDir):
    if len(sys.argv) < 5:
        print "Pls specify a label and dPort"
        sys.exit(2)

    serviceName = sys.argv[3]
    dPort = sys.argv[4]

    tenMo = moDir.lookupByDn('uni/tn-ContivTenant')
    # filter container
    filterName = 'filter-' + serviceName
    filterMo = Filter(tenMo, filterName)

    # filter entry for the given port
    entryName = 'entryPort-' + dPort
    entryMo = Entry(filterMo, entryName)
    entryMo.dFromPort = int(dPort)
    entryMo.dToPort = int(dPort)
    entryMo.prot = 6  # tcp
    entryMo.etherT = 'ip'

    # contract container
    ccName = 'contr-' + serviceName
    ccMo = BrCP(tenMo, ccName)
    
    # subject for associating filter to contract
    subjName = 'subj-' + serviceName
    subjMo = Subj(ccMo, subjName)
    RsSubjFiltAtt(subjMo, tnVzFilterName=filterMo.name)

    cR = ConfigRequest()
    cR.addMo(tenMo)
    moDir.commit(cR)

def setupServiceProvider(moDir):
    if len(sys.argv) < 6:
        print "Pls specify an app, epg and contract"
        sys.exit(2)

    appName = sys.argv[3]
    epgName = sys.argv[4]
    serviceName = sys.argv[5]
    contrDn = 'uni/tn-' + contivDefTenant + '/brc-' + 'contr-' + serviceName
    contrMo = moDir.lookupByDn(contrDn)
    epgDn = 'uni/tn-' + contivDefTenant + '/ap-' + appName + '/epg-' + epgName
    # RsProv does not like Dn need to look up parent
    epgMo = moDir.lookupByDn(epgDn)
    provMo = RsProv(epgMo, tnVzBrCPName=contrMo.name)

    cR = ConfigRequest()
    cR.addMo(epgMo)
    moDir.commit(cR)

def addServiceConsumer(moDir):
    if len(sys.argv) < 6:
        print "Pls specify an app, epg and contract"
        sys.exit(2)

    appName = sys.argv[3]
    epgName = sys.argv[4]
    serviceName = sys.argv[5]
    contrDn = 'uni/tn-' + contivDefTenant + '/brc-' + 'contr-' + serviceName
    contrMo = moDir.lookupByDn(contrDn)
    epgDn = 'uni/tn-' + contivDefTenant + '/ap-' + appName + '/epg-' + epgName
    # RsProv does not like Dn need to look up parent
    epgMo = moDir.lookupByDn(epgDn)
    consMo = RsCons(epgMo, tnVzBrCPName=contrMo.name)

    cR = ConfigRequest()
    cR.addMo(epgMo)
    moDir.commit(cR)

# need to add delete contracts and BDs
def deleteAppProf(moDir):
    if len(sys.argv) < 4:
        print "Pls specify an app"
        sys.exit(2)

    appName = sys.argv[3]
    appDn = 'uni/tn-' + contivDefTenant + '/ap-' + appName
    fvApMo = moDir.lookupByDn(appDn)

    fvApMo.delete()
    cR = ConfigRequest()
    cR.addMo(fvApMo)
    moDir.commit(cR)

def printSupport(moDir):
    print "Supported operations:"
    for oper in operDict:
        if oper != 'default':
            print oper

# Dict of tenants we currently have
tenantDict = ObjDict()
subnetDict = ObjDict()
appDict = ObjDict()
appResourceDict = SafeDict()

app = Flask(__name__)
apicUrl = 'notset'

# create a DN string for tenant
def formTenantDn(tenantName):
    tenantDn = 'uni/tn-' + tenantName
    return tenantDn

# form a name for a tenant VRF
def formTenantVRFName(tenantName):
    tenVrfName = tenantName + '-Vrf'
    return tenVrfName

# create a DN string for the bridge domain
def formBDDn(tenantName, bdName):
    bdDn = 'uni/tn-' + tenantName + '/BD-' + bdName
    return bdDn

# form a name for the bridge domain
def formBDName(tenantName, subnet):
    bdName = tenantName + '-' + subnet
    return bdName

# create a DN string for the application profile
def formAppProfDn(tenantName, appProfName):
    appProfDn = 'uni/tn-' + tenantName + '/ap-' + appProfName
    return appProfDn

# Wrapper to check if an DN already exists
def checkDnExists(apicMoDir, dnStr):
    mo = apicMoDir.lookupByDn(dnStr)
    if mo is None:
        return (False, None)
    else:
        return (True, mo)
    
# create a tenant if it does not exist.
def setupTenant(spec, apicMoDir):
    tenant = spec['tenant']
    # Check if the APIC already knows about this tenant
    tenantDn = formTenantDn(tenant)
    exists, fvTenantMo = checkDnExists(apicMoDir, tenantDn)
    if exists:
        # The tenant already exists in the APIC. Stash what we got.
        print "Tenant %s already exists." % (tenant)
        tenantDict[tenant] = fvTenantMo
    else:
        print "Creating tenant ", tenant
        uniMo = apicMoDir.lookupByDn('uni')
        fvTenantMo = Tenant(uniMo, tenant)
        # create a vrf for the tenant
        ctxMo = Ctx(fvTenantMo, tenant + '-Vrf')
        cR = ConfigRequest()
        cR.addMo(fvTenantMo)
        apicMoDir.commit(cR)
        tenantDict[tenant] = fvTenantMo

    return ['success', 'ok']

# create a bd and subnet if it does not exist
def setupSubnet(spec, apicMoDir):
    # Check if we are going to be using the provided bridge domain.
    # In that case, we don't need to create a subnet/BD.
    bridgeDomain = os.getenv('APIC_EPG_BRIDGE_DOMAIN', 'not_specified')
    if bridgeDomain != "not_specified":
	    # Use what has been provided.
        return ['success', 'ok']
         
    gw = spec['subnet']

    netmask = gw.split('/')
    if len(netmask) != 2:
    	return ['failed', 'invalid subnet']
    
    tenant = spec['tenant']
    bdName = formBDName(tenant, netmask[0])
    bdDn = formBDDn(tenant, bdName)
    # Check if this BD already exists within this tenant context.
    exists, fvBDMo = checkDnExists(apicMoDir, bdDn)
    if exists:
        print "BD %s exists under tenant %s" % (bdName, tenant)
        subnetDict[gw] = fvBDMo
    else:
        print "Creating BD %s under tenant %s" % (bdName, tenant)
        tenMo = tenantDict[tenant]
        fvBDMo = BD(tenMo, name=bdName)
        # associate to nw context
        tenVrf = formTenantVRFName(tenant)
        RsCtx(fvBDMo, tnFvCtxName=tenVrf)
        # create subnet
        Subnet(fvBDMo, gw)
        cR = ConfigRequest()
        cR.addMo(fvBDMo)
        apicMoDir.commit(cR)
        subnetDict[gw] = fvBDMo

    return ['success', 'ok']

def ipProtoNametoNumber(protoString):
    if protoString == 'icmp':
        return 1
    elif protoString == 'tcp':
        return 6
    elif protoString == 'udp':
        return 17
    else:
        return -1

def addProvidedContracts(spec, apicMoDir):

    tenant = spec['tenant']
    tenMo = tenantDict[tenant]
    appName = spec['app']
    epgList = spec['epgs']
    resrcList = []

    cR = ConfigRequest()
    cR.addMo(tenMo)

    for e in epgList:
        epg = SafeDict(e)
        serviceName = epg['name']
        filters = epg['filterinfo']
        if filters is 'missing':
            print "No provider in ", serviceName
            continue

        print ">>Provider ", filters, serviceName
        epgcR = ConfigRequest()
        # filter container
        filterName = 'filt-' + appName + serviceName
        filterMo = Filter(tenMo, filterName)
        # save the filter dn to this app's resource list
        resrcList.append(filterMo) 
    
	for eachEntry in filters:
	    filterEntry = SafeDict(eachEntry)
            ipProtocol = filterEntry['protocol']
            servPort = filterEntry['servport']
	   
            etherType = 'ip'
            filterProto = 0
            filterPort = 0
            if ipProtocol is not 'missing':
                filterProto = ipProtoNametoNumber(ipProtocol)
	    if servPort is not 'missing':
                filterPort = int(servPort)

            # Form the entry name
            entryName = 'entry-' + etherType
            if filterProto > 0:
                entryName = entryName + '-' + ipProtocol
            if filterPort > 0:
                entryName = entryName + '-' + servPort          

            print "creating filter entry %s", entryName
            entryMo = Entry(filterMo, entryName)
            entryMo.etherT = etherType
            if filterProto > 0:
                entryMo.prot = filterProto
            # Set port information only if TCP or UDP
            if entryMo.prot == 6 or entryMo.prot == 17:
                if filterPort > 0:
                    entryMo.dFromPort = filterPort
                    entryMo.dToPort = filterPort
    
        # contract container
        ccName = 'contr-' + appName + serviceName
        print '==>contract name:', ccName 
        ccMo = BrCP(tenMo, ccName)
        # save the contract dn to this app's resource list
        resrcList.append(ccMo) 
        
        # subject for associating filter to contract
        subjName = 'subj-' + serviceName
        subjMo = Subj(ccMo, subjName)
        RsSubjFiltAtt(subjMo, tnVzFilterName=filterMo.name)
        epgDn = 'uni/tn-' + tenant + '/ap-' + appName + '/epg-' + serviceName
        # RsProv does not like Dn need to look up parent
        epgMo = apicMoDir.lookupByDn(epgDn)
        provMo = RsProv(epgMo, tnVzBrCPName=ccMo.name)
        epgcR.addMo(epgMo)
        apicMoDir.commit(epgcR)
    
    cR = ConfigRequest()
    cR.addMo(tenMo)
    apicMoDir.commit(cR)
    # save the resource list
    appKey = tenant + '-' + appName
    appResourceDict[appKey] = resrcList

def setupUnenforcedMode(spec, apicMoDir):
    epgList = spec['epgs']
    tenant = spec['tenant']
    appName = spec['app']

    for e in epgList:
        epg = SafeDict(e)
        epgName = epg['name']
        epgDn = 'uni/tn-' + tenant + '/ap-' + appName + '/epg-' + epgName
        epgMo = apicMoDir.lookupByDn(epgDn)

        epgcR = ConfigRequest()
        contrDn = 'uni/tn-common/brc-default'
        contrMo = apicMoDir.lookupByDn(contrDn)
        consMo = RsCons(epgMo, tnVzBrCPName=contrMo.name)
        epgcR.addMo(epgMo)
        apicMoDir.commit(epgcR)

def setupPerEpgProvConsContracts(spec, apicMoDir):
    epgList = spec['epgs']
    tenant = spec['tenant']
    appName = spec['app']

    for e in epgList:
        epg = SafeDict(e)
        epgName = epg['name']
        if epg['conscontracts'] is 'missing' and epg['provcontracts'] is 'missing':
            print "No external contracts/policies for this EPG %s" % (epgName)
            continue

        print "Setting up external contracts for %s" % (epgName)
        epgDn = 'uni/tn-' + tenant + '/ap-' + appName + '/epg-' + epgName
        epgMo = apicMoDir.lookupByDn(epgDn)
		
        # If the EPG mo does not exist, nothing can be
        # done. Typically, should not happen.
        if epgMo is None:
            continue
			
        epgcR = ConfigRequest()

        if epg['conscontracts'] is not 'missing':
            for oneContractDn in epg['conscontracts']:
                contrMo = apicMoDir.lookupByDn(oneContractDn)
                if contrMo is None:
                    # The specified contract is not present.
                    # Move on with the next contract.
                    continue                        
                consMo = RsCons(epgMo, tnVzBrCPName=contrMo.name)

        if epg['provcontracts'] is not 'missing':
            for oneContractDn in epg['provcontracts']:
                contrMo = apicMoDir.lookupByDn(oneContractDn)
                if contrMo is None:
                    # The specified contract is not present.
                    # Move on with the next contract.
                    continue                        
                consMo = RsProv(epgMo, tnVzBrCPName=contrMo.name)

        epgcR.addMo(epgMo)
        apicMoDir.commit(epgcR)

def setupConsumers(spec, apicMoDir):

    tenant = spec['tenant']
    tenMo = tenantDict[tenant]
    appName = spec['app']
    epgList = spec['epgs']

    for e in epgList:
        epg = SafeDict(e)
        epgName = epg['name']
        epgDn = 'uni/tn-' + tenant + '/ap-' + appName + '/epg-' + epgName
        epgMo = apicMoDir.lookupByDn(epgDn)
        consumeList = epg['uses']
        if epg['uses'] is 'missing':
            continue

        epgcR = ConfigRequest()
        for service in consumeList:
            ccName = 'contr-' + appName + service
            contrDn = 'uni/tn-' + tenant + '/brc-' + ccName
            contrMo = apicMoDir.lookupByDn(contrDn)
            # RsCons does not like Dn need to look up parent
            consMo = RsCons(epgMo, tnVzBrCPName=contrMo.name)
            print '<<', epgName, 'consumes', service

        epgcR.addMo(epgMo)
        apicMoDir.commit(epgcR)

def getBridgeDomainName(spec):
    bridgeDomain = os.getenv('APIC_EPG_BRIDGE_DOMAIN', 'not_specified')
    if bridgeDomain != "not_specified":
	# Use what has been provided.
        return bridgeDomain

    tenant = spec['tenant']
    gateway = spec['subnet']
    netmask = gateway.split('/')
    bridgeDomain = tenant + '-' + netmask[0]

    return bridgeDomain


# create EPGs and contracts per the app spec
def setupApp(spec, apicMoDir):
    # create an app prof if it does not exist.
    appName = spec['app']
    tenant = spec['tenant']
    tenMo = tenantDict[tenant]
    epgList = spec['epgs']

    physDom = os.getenv('APIC_PHYS_DOMAIN', 'not_specified')
    if physDom == "not_specified":
        return ['failed', 'Physical domain not specified']

    # Check if the APIC already knows about this application profile
    # within this tenant context
    appProfDn = formAppProfDn(tenant, appName)
    exists, fvApMo = checkDnExists(apicMoDir, appProfDn)
    if exists:
        # The appProfile already exists in the APIC. Stash what we got.
        print "App-prof %s,%s already exists." % (tenant, appName)
        appDict[appName] = fvApMo
    else:
        print "Creating application profile %s in tenant %s" % (appName, tenant)
        fvApMo = Ap(tenMo, appName)
        appDict[appName] = fvApMo

    cR = ConfigRequest()
    cR.addMo(fvApMo)

    # Get the bridge domain
    bdName = getBridgeDomainName(spec)

    #if nodeid is passed, use that
    leafNodes = os.getenv('APIC_LEAF_NODE', contivDefNode)
    leafList = leafNodes.split(",")

    # Walk the EPG list and create them.
    for epg in epgList:
        epgName = epg['name']
        fvEpg = AEPg(fvApMo, epgName)
        # associate to BD
        RsBd(fvEpg, tnFvBDName=bdName)
        # associate to phy domain
        contivClusterDom = 'uni/phys-' + physDom
        RsDomAtt(fvEpg, contivClusterDom)
        # TODO: add static binding
        vlan = epg['vlantag']
        encapid = 'vlan-' + vlan
        for leaf in leafList:
            RsNodeAtt(fvEpg, tDn=leaf, encap=encapid)
        
    apicMoDir.commit(cR)

    unenforcedMode = os.getenv('APIC_CONTRACTS_UNRESTRICTED_MODE', 'no')
    if unenforcedMode.lower() == "yes":
        print "Setting up EPG in un-enforced mode."
        setupUnenforcedMode(spec, apicMoDir)
    else:
        print "Establishing provided contracts."
        addProvidedContracts(spec, apicMoDir)
        print "Establishing consumed contracts."
        setupConsumers(spec, apicMoDir)
        print "Establishing pre-defined contracts."
        setupPerEpgProvConsContracts(spec, apicMoDir)

    return ['success', 'ok']

# delete App profile and any contracts/filter allocated for it
def deleteApp(spec, apicMoDir):
    # create an app prof if it does not exist.
    appName = spec['app']
    tenant = spec['tenant']

    tenMo = tenantDict[tenant]
    if tenMo is None:
        return ['failed', 'tenant not found']

    fvApMo = appDict[appName]
    if fvApMo is None:
        return ['failed', 'app not found']
    
    # delete the app profile
    fvApMo.delete()
    cR = ConfigRequest()
    cR.addMo(fvApMo)
    apicMoDir.commit(cR)
    appDict.pop(appName)

    # delete resources
    appKey = tenant + '-' + appName
    resrcList = appResourceDict[appKey]
    if resrcList is 'None':
        return ['ok', 'no contracts in app']

    for rMo in resrcList:
        rMo.delete()
        cR1 = ConfigRequest()
        cR1.addMo(rMo)
        apicMoDir.commit(cR1)
        print "Deleted", rMo.dn

    appResourceDict.pop(appKey)
    return ['success', 'ok']


#response for POST request
def getResp(result, info):
    data = {
         'result' : result,
         'info'   : info
    }
    js = json.dumps(data)
    
    resp = Response(js, status=200, mimetype='application/json')
    return resp

################################################################################
@app.route("/deleteAppProf", methods=['POST'])
def delete_api():
    if request.headers['Content-Type'] != 'application/json':
        resp = getResp('unchanged', 'invalid-args')
        return resp
 
    print request
    jsData = request.get_json()
    print jsData
    # make sure input is well-formed
    topData = SafeDict(jsData)
    if topData['tenant'] is 'missing':
        print "tenant name is missing"
        resp = getResp('unchanged', 'tenant name missing')
        return resp

    if topData['app'] is 'missing':
        print "app name is missing"
        resp = getResp('unchanged', 'app name missing')
        return resp

    apicUrl = os.environ.get('APIC_URL') 
    if apicUrl == 'SANITY':
        resp = getResp("success", "LGTM")
        return resp

    apicMoDir = apicSession.getMoDir()
    if apicMoDir is None:
        resp = getResp('failed', "Invalid APIC session")
        return resp

    apicMoDir.login()
    ret = deleteApp(jsData, apicMoDir)
    apicMoDir.logout()
    resp = getResp(ret[0], ret[1])
    return resp

################################################################################
@app.route("/createAppProf", methods=['POST'])
def create_api():
    if request.headers['Content-Type'] != 'application/json':
        resp = getResp('unchanged', 'invalid-args')
        return resp
 
    print request
    jsData = request.get_json()
    print jsData
    # make sure input is well-formed
    valid = validateData(jsData)
    if not valid[0] is 'success':
        resp = getResp('invalid-args', valid[1])
        return resp

    if apicUrl == 'SANITY':
        resp = getResp(valid[0], valid[1])
        return resp

    apicMoDir = apicSession.getMoDir()
    if apicMoDir is None:
        resp = getResp('failed', "Invalid APIC session")
        return resp

    apicMoDir.login()
    setupTenant(jsData, apicMoDir)
    ret = setupSubnet(jsData, apicMoDir)
    if ret[0] != 'success':
        resp = getResp(ret[0], ret[1])
        apicMoDir.logout()
        return resp

    ret = setupApp(jsData, apicMoDir)
    apicMoDir.logout()
    resp = getResp(ret[0], ret[1])
    return resp

################################################################################
def validateData(jsData):
    topData = SafeDict(jsData)
    # make sure we have tenant, subnet and app at top level
    if topData['tenant'] is 'missing':
        print "tenant: name is missing"
        return ['failed', 'tenant name missing']

    if topData['subnet'] is 'missing':
        print "subnet is missing"
        return ['failed', 'subnet missing']

    gw = jsData['subnet']
    netmask = gw.split('/')
    if len(netmask) != 2:
        return ['failed', 'invalid subnet']

    if topData['app'] is 'missing':
        return ['failed', 'appname missing']

    if not 'epgs' in jsData:
        return ['failed', 'epg list missing']

    epgList = jsData['epgs']

    if len(epgList) == 0:
        return ['failed', 'empty/missing epglist']

    consumeSet = set()
    provideSet = set()
    for e in epgList:
        if not isinstance(e, dict):
            ss = 'epg must be a dict, is' + str(type(e))
            return ['failed', ss]

        epg = SafeDict(e)
        if epg['name'] is 'missing':
            return ['failed', 'epg must have a name']

        if epg['vlantag'] is 'missing':
            return ['failed', 'epg must have a vlantag']

        # build set of provided services
        if not epg['filterinfo'] is 'missing':
            provideSet.add(epg['name'])

        if epg['uses'] is 'missing':
            print 'no consume specified for', epg['name']
            continue

        consumeList = epg['uses']

        # build the set of consumed services
        for c in consumeList:
            consumeSet.add(c)

    if not consumeSet.issubset(provideSet):
            diff = consumeSet - provideSet
            s1 = 'no provider for: '
            for item in diff:
                s1 += item
                s1 += ', '
            print s1
            return ['failed', s1]

    return ['success', 'LGTM']

################################################################################
@app.route("/validateAppProf", methods=['POST'])
def validate_api():
    if request.headers['Content-Type'] != 'application/json':
        resp = getResp('failed', 'not JSON')
        return resp

    print request
    jsData = request.get_json()
    print jsData
    ret = validateData(jsData)
    resp = getResp(ret[0], ret[1])
    return resp

################################################################################
def readFile(fileName=None, mode="r"):
    if fileName is None:
        return ""

    fileData = ""
    try:
      aFile = open(fileName, mode)
      fileData = aFile.read()
    except:
      print "Could not read {}".format(fileName)

    return fileData

################################################################################
def VerifyEnv():
    mandatoryEnvVars = ['APIC_URL',
                        'APIC_USERNAME',
                        'APIC_LEAF_NODE',
                        'APIC_PHYS_DOMAIN']

    for envVar in mandatoryEnvVars:
        val = os.getenv(envVar, 'None')
        if val == 'None':
            print "WARNING: {} is not set - GW cannot function".format(envVar)

################################################################################
class ApicSession():
    def __init__(self):
        self.sessionType = "INVALID"
        self.apicUrl = os.getenv('APIC_URL', 'None')
        self.apicUser = os.getenv('APIC_USERNAME', 'None')
        if self.apicUrl == 'None' or self.apicUser == 'None':
            print "Cannot set up session -- missing config"
            return

        self.certDN = os.getenv('APIC_CERT_DN', 'None') 
        self.pKey = ""
        aciKeyFile = os.getenv('APIC_LOCAL_KEY_FILE', DefACIKeyFile) 
        if self.certDN != 'None':
            self.pKey = readFile(aciKeyFile)
        else:
            print "APIC_CERT_DN is not set, keys disabled"

        if self.pKey != "":
            self.sessionType = "KEY"
            print "Key based auth selected"
            return

        self.apicPassword = os.getenv('APIC_PASSWORD', 'None')
        if self.apicPassword == 'None':
            print "ERROR: No valid auth type available"
        else:
            print "Login based auth selected"
            self.sessionType = "PASSWORD"

    def getMoDir(self):
        if self.sessionType == "KEY":
            certSession = CertSession(self.apicUrl, self.certDN, self.pKey)
            return MoDirectory(certSession)

        if self.sessionType == "PASSWORD":
            loginSession = LoginSession(self.apicUrl, self.apicUser,
                                        self.apicPassword)
            return MoDirectory(loginSession)

        if self.sessionType == "INVALID":
            return None

    def getSessionType(self):
        return self.sessionType

################################################################################
if __name__ == "__main__":

    # Verify basic environment settings we expect
    VerifyEnv()

    # Setup auth type for apic sessions
    apicSession = ApicSession()
        
    app.run(host='0.0.0.0', debug=True)

