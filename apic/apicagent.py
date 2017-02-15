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
import logging
from cobra.mit.access import MoDirectory
from cobra.mit.session import LoginSession
from cobra.mit.session import CertSession
from cobra.mit.request import ConfigRequest, DnQuery
from cobra.model.fv import Tenant
from cobra.model.fv import Ctx
from cobra.model.fv import BD
from cobra.model.fv import RsCtx
from cobra.model.fv import Subnet
from cobra.model.fv import Ap
from cobra.model.fv import AEPg
from cobra.model.fv import RsBd
from cobra.model.fv import RsDomAtt, RsNodeAtt, RsPathAtt
from cobra.model.fv import RsProv, RsCons, CEp
from cobra.model.vmm import SecP
from cobra.model.vz import Filter, Entry, BrCP, Subj, RsSubjFiltAtt
from flask import Flask
from flask import json, request, Response

##############################################################################
supportedLogLevels = ['INFO', 'DEBUG', 'ERROR']
logLevel = os.getenv('LOG_LEVEL', 'INFO')
print 'Loglevel is set to : %s' % logLevel
if logLevel not in supportedLogLevels:
    print 'Supported log levels are: %s , defaulting to INFO' % (supportedLogLevels)
    logLevel = 'INFO'
logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', level=logLevel)

##############################################################################
aciGwApiVer = "v1.2"
DefACIKeyFile = "/aciconfig/aci.key"
contivDefTenant = 'ContivTenant'
# Node used by contiv
contivDefNode = 'topology/pod-1/node-102'

class SafeDict(dict):
    'Provide a default value for missing keys'
    def __missing__(self, key):
        return 'missing'
    'Verify presence of mandatory and optional keys'
    def Validate(self, mandatory, optional, prefix):
        present = set()
        for key in self:
            present.add(key)

        diff = mandatory.symmetric_difference(present)
        absent = mandatory.intersection(diff)
        if len(absent) != 0:
            errMsg = "{}:Missing mandatory fields: {}".format(prefix, absent)
            return ['failed', errMsg]

        if not diff.issubset(optional):
            unknown = diff - optional
            errMsg = "{}:Unknown fields: {}".format(prefix, unknown)
            return ['failed', errMsg]

        return ['ok', ""]


class ObjDict(dict):
    'Provide a default value for missing keys'
    def __missing__(self, key):
        return None

class OperDict(dict):
    'Gracefully handle missing operation'
    def __missing__(self, key):
        return printSupport

def printSupport(moDir):
    logging.debug('Supported operations:')
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
    logging.debug('Inside formTenantDn function')
    tenantDn = 'uni/tn-' + tenantName
    return tenantDn

# form a name for a tenant VRF
def formTenantVRFName(tenantName):
    logging.debug('Inside formTenantVRFName function')
    tenVrfName = tenantName + '-Vrf'
    return tenVrfName

# create a DN string for the bridge domain
def formBDDn(tenantName, bdName):
    logging.debug('Inside formBDDn function')
    bdDn = 'uni/tn-' + tenantName + '/BD-' + bdName
    return bdDn

# create a DN string for the application profile
def formAppProfDn(tenantName, appProfName):
    logging.debug('Inside formAppProfDn function')
    appProfDn = 'uni/tn-' + tenantName + '/ap-' + appProfName
    return appProfDn

# Wrapper to check if an DN already exists
def checkDnExists(apicMoDir, dnStr):
    logging.debug('Inside checkDnExists function')
    mo = apicMoDir.lookupByDn(dnStr)
    if mo is None:
        return (False, None)
    else:
        return (True, mo)
    
# create a tenant if it does not exist.
def setupTenant(spec, apicMoDir):
    logging.debug('Inside setupTenant function')
    tenant = spec['tenant']
    # Check if the APIC already knows about this tenant
    tenantDn = formTenantDn(tenant)
    exists, fvTenantMo = checkDnExists(apicMoDir, tenantDn)
    if exists:
        # The tenant already exists in the APIC. Stash what we got.
        logging.info('Tenant %s already exists.' % tenant)
        tenantDict[tenant] = fvTenantMo
    else:
        logging.info('Creating tenant %s' % tenant)
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
def findTenantVrfContexts(tenant, apicMoDir):
    logging.debug('Inside findTenantVrfContexts function')
    tenantDn = formTenantDn(tenant)
    dnQuery = DnQuery(tenantDn)
    dnQuery.subtree = 'children'
    tenantMo = apicMoDir.query(dnQuery)
    if len(tenantMo) > 0:
        # We expect only 1 tenant with that name
        return tenantMo[0].ctx
    else:
        return []
    
def createBridgeDomain(tenant, epgSpec, apicMoDir):
    logging.debug('Inside createBridgeDomain function')
    gw = epgSpec['gw-cidr']

    netmask = gw.split('/')
    if len(netmask) != 2:
        return ['failed', 'invalid subnet']
    # Check if gw ip is correct
    bdIsL3 = True
    if netmask[0] == '':
        logging.info('Missing gateway in contiv network. Creating BD without Subnet (L2 only).')
        bdIsL3 = False
    
    bdName = epgSpec['nw-name']
    bdDn = formBDDn(tenant, bdName)

    logging.info('Creating BD %s under tenant %s' % (bdName, tenant))
    # Check if there is a VRF to tie the BD. If not, create one.
    tenMo = tenantDict[tenant]
    ctxMos = findTenantVrfContexts(tenant, apicMoDir)
    logging.debug('Fetched context mos:')
    logging.debug(ctxMos)
    if len(ctxMos) == 0:
        # No VRFs found. Need to create one.
        tenVrfName = formTenantVRFName(tenant)
        ctxMo = Ctx(tenMo, tenVrfName)
        cR = ConfigRequest()
        cR.addMo(ctxMo)
        apicMoDir.commit(cR)
    elif len(ctxMos) > 1:
        logging.error('Multi VRF scenario requires pre-created BDs')
        return ['failed', 'Multiple VRFs under tenant not supported yet']
    else:
        for ctxMo in ctxMos:
            tenVrfName = ctxMo.name

    fvBDMo = BD(tenMo, name=bdName)
    RsCtx(fvBDMo, tnFvCtxName=tenVrfName)
    if bdIsL3:
        # create subnet
        Subnet(fvBDMo, gw)
    cR = ConfigRequest()
    cR.addMo(fvBDMo)
    apicMoDir.commit(cR)
    if bdIsL3:
        subnetDict[gw] = fvBDMo
    logging.info('Created BD {}'.format(bdName))

    return ['success', 'ok']

def ipProtoNametoNumber(protoString):
    logging.debug('Inside ipProtoNametoNumber function ')
    if protoString == 'icmp':
        return 1
    elif protoString == 'tcp':
        return 6
    elif protoString == 'udp':
        return 17
    else:
        return -1

def addDefinedContracts(spec, apicMoDir):
    logging.debug('Inside addDefinedContracts function')
    tenant = spec['tenant']
    tenMo = tenantDict[tenant]
    appName = spec['app-prof']
    resrcList = []

    contracts = spec['contract-defs']
    if contracts is 'missing':
        logging.info('No defined contracts in {}'.format(appName))
        return

    cR = ConfigRequest()
    cR.addMo(tenMo)

    for cc in contracts:
        c = SafeDict(cc)
        logging.debug('>> Adding contract {}'.format(c['name']))
        contractCR = ConfigRequest()
        # filter container
        filterName = 'filt-' + c['name']
        filterMo = Filter(tenMo, filterName)
        # save the filter dn to this app's resource list
        resrcList.append(filterMo) 
    
        filters = c['filter-info']
        logging.debug(filters)
        if filters is 'missing':
            logging.error('ERROR no filters in contract')
            continue
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

            logging.info('creating filter entry {}'.format(entryName))
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
        ccName = c['name']
        logging.info('==>contract name:%s' % ccName)
        ccMo = BrCP(tenMo, ccName)
        # save the contract dn to this app's resource list
        resrcList.append(ccMo) 
        
        # subject for associating filter to contract
        subjName = 'subj-' + ccName
        subjMo = Subj(ccMo, subjName)
        RsSubjFiltAtt(subjMo, tnVzFilterName=filterMo.name)
        contractCR.addMo(ccMo)
        apicMoDir.commit(contractCR)

    cR = ConfigRequest()
    cR.addMo(tenMo)
    apicMoDir.commit(cR)
    # save the resource list
    appKey = tenant + '-' + appName
    appResourceDict[appKey] = resrcList

def setupUnenforcedMode(spec, apicMoDir):
    logging.debug('Inside setupUnenforcedMode function')
    epgList = spec['epgs']
    tenant = spec['tenant']
    appName = spec['app-prof']

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

def addContractLinks(spec, apicMoDir):
    logging.debug('Inside addContractLinks function')
    epgList = spec['epgs']
    tenant = spec['tenant']
    appName = spec['app-prof']
    tenMo = tenantDict[tenant]

    for e in epgList:
        epg = SafeDict(e)
        epgName = epg['name']
        links = epg['contract-links']
        if links is 'missing':
            logging.debug('No contract links specified for epg {}'.format(epgName))
            continue

        epgDn = 'uni/tn-' + tenant + '/ap-' + appName + '/epg-' + epgName
        epgMo = apicMoDir.lookupByDn(epgDn)
		
        # If the EPG mo does not exist, nothing can be
        # done. Typically, should not happen.
        if epgMo is None:
            logging.error('Could not locate epg %s within tenant %s' % (epgName, tenant))
            return ['ERROR', "Could not locate epg {}".format(epgName)]

        epgcR = ConfigRequest()
        for l in links:
            link = SafeDict(l)

            cKind = link['contract-kind']
            if cKind != "EXTERNAL" and cKind != "INTERNAL":
                logging.error('Unknown contract-kind')
                return ['ERROR', "Unknown contract-kind {}".format(cKind)]

            if cKind == "EXTERNAL":
                contrMo = apicMoDir.lookupByDn(link['contract-dn'])
                if contrMo is None:
                    logging.error('ERROR external contract {} not found'.format(link['contract-dn']))
                    return ['ERROR', "No ext contract {}".format(link['contract-dn'])]

            if cKind == "INTERNAL":
                ccName = link['contract-name']
                contractDN = 'uni/tn-' + tenant + '/brc-' + ccName
                contrMo = apicMoDir.lookupByDn(contractDN)
                if contrMo is None:
                    #add the cc Mo, so we can setup the link
                    contrMo = BrCP(tenMo, ccName)
                    ccCR = ConfigRequest()
                    ccCR.addMo(contrMo)
                    apicMoDir.commit(ccCR)

            # at this point, we are ready to add cons/prov link
            if link['link-kind'] == "CONSUME":
                linkMo = RsCons(epgMo, tnVzBrCPName=contrMo.name)
                logging.debug('epg {} consumes {}'.format(epgName, contrMo.name))
            else:
                linkMo = RsProv(epgMo, tnVzBrCPName=contrMo.name)
                logging.debug('epg {} provides {}'.format(epgName, contrMo.name))

        epgcR.addMo(epgMo)
        apicMoDir.commit(epgcR)

    return ['success', 'ok']

def getBridgeDomain(tenant, epgSpec, apicMoDir, commonTenant):
    logging.debug('Inside getBridgeDomain function')
    bdName = os.getenv('APIC_EPG_BRIDGE_DOMAIN', 'not_specified')
    if bdName != "not_specified":
    # Use what has been provided.
        return bdName

    bdName = epgSpec['nw-name']
    bdDn = formBDDn(tenant, bdName)

    # Check if this BD already exists within this tenant context.
    exists, fvBDMo = checkDnExists(apicMoDir, bdDn)
    if exists:
        logging.info('epg {} will use existing BD {}'.format(epgSpec['name'], bdName))
        return bdName

    # if common tenant is specified, check for BD there as well
    if commonTenant == 'yes':
        bdDn = formBDDn('common', bdName)
        exists, fvBDMo = checkDnExists(apicMoDir, bdDn)
        if exists:
            logging.info('epg {} will use existing BD/tn-common {}'.format(epgSpec['name'], bdName))
            return bdName

    createBridgeDomain(tenant, epgSpec, apicMoDir)
    return bdName


# create EPGs and contracts per the app spec
def setupApp(spec, apicMoDir, gwConfig):
    logging.debug('Inside setupApp function')
    # create an app prof if it does not exist.
    appName = spec['app-prof']
    tenant = spec['tenant']
    tenMo = tenantDict[tenant]
    epgList = spec['epgs']

    logging.debug('Nodes : %s' % gwConfig.nodes)
    logging.debug('Paths : %s' % gwConfig.paths)

    physDom = gwConfig.physDom
    vmmDom = gwConfig.vmmDom
    if physDom == "not_specified" and vmmDom == "not_specified":
        return ['failed', 'Physical and VMM domain not specified']

    # Check if the APIC already knows about this application profile
    # within this tenant context
    appProfDn = formAppProfDn(tenant, appName)
    exists, fvApMo = checkDnExists(apicMoDir, appProfDn)
    if exists:
        # The appProfile already exists in the APIC. Stash what we got.
        logging.info('App-prof %s,%s already exists.' % (tenant, appName))
        appDict[appName] = fvApMo
    else:
        logging.info('Creating application profile %s in tenant %s' % (appName, tenant))
        fvApMo = Ap(tenMo, appName)
        appDict[appName] = fvApMo

    cR = ConfigRequest()
    cR.addMo(fvApMo)

    # Walk the EPG list and create them.
    for epg in epgList:
        # Get the bridge domain for this epg, will create if needed
        comTen = gwConfig.includeCommonTenant
        bdName = getBridgeDomain(tenant, epg, apicMoDir, comTen)
        epgName = epg['name']
        fvEpg = AEPg(fvApMo, epgName)
        # associate to BD
        RsBd(fvEpg, tnFvBDName=bdName)
        vlan = epg['vlan-tag']
        encapid = 'vlan-' + vlan
        
        if vmmDom != "not_specified":
            # associate to vmm domain
            logging.info("VMM Domain: {}".format(vmmDom))
            contivClusterDom = 'uni/vmmp-VMware/dom-' + vmmDom
            logging.debug("Bind VMM : {} on {}".format(vmmDom, encapid))
            rsDomAtt = RsDomAtt(fvEpg, tDn=contivClusterDom, instrImedcy='immediate', encap=encapid, resImedcy='immediate')
            SecP(rsDomAtt, forgedTransmits='accept', allowPromiscuous='accept', macChanges='accept')
        
        if physDom != "not_specified":
            # associate to phy domain
            contivClusterDom = 'uni/phys-' + physDom
            RsDomAtt(fvEpg, contivClusterDom)
            # TODO: add static binding
            logging.info('Nodes : %s' % gwConfig.nodes)
            for leaf in gwConfig.nodes:
                logging.debug('Bind Leaf : %s' % leaf)
                RsNodeAtt(fvEpg, tDn=leaf, encap=encapid)

            logging.info('Paths : %s' % gwConfig.paths)
            for path in gwConfig.paths:
                logging.debug('Path = %s' % path)
                RsPathAtt(fvEpg, tDn=path, instrImedcy='immediate', encap=encapid)

    apicMoDir.commit(cR)

    enforce = gwConfig.enforcePolicies
    if enforce.lower() == "no":
        logging.info('Setting up EPG in un-enforced mode.')
        setupUnenforcedMode(spec, apicMoDir)
    else:
        logging.debug('Establishing policy contracts.')
        addDefinedContracts(spec, apicMoDir)
        logging.debug('Establishing consumer/provider links.')
        ret = addContractLinks(spec, apicMoDir)
        if ret[0] != 'success':
            return ret

    return ['success', 'ok']

# delete App profile and any contracts/filter allocated for it
def deleteApp(spec, apicMoDir):
    logging.debug('Inside deleteApp function')
    # create an app prof if it does not exist.
    appName = spec['app-prof']
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

#response for GET request
def getEPResp(result, msg="ok", ip="None", vlan="None"):
    data = {
         'result' : result,
         'ip'   : ip,
         'vlan'   : vlan,
         'msg'   : msg
    }
    js = json.dumps(data)
    
    resp = Response(js, status=200, mimetype='application/json')
    return resp

################################################################################
@app.route("/deleteAppProf", methods=['POST'])
def delete_api():
    logging.debug('Inside delete_api function')
    if request.headers['Content-Type'] != 'application/json':
        resp = getResp('unchanged', 'invalid-args')
        return resp
 
    print request
    jsData = request.get_json()
    print jsData
    # make sure input is well-formed
    topData = SafeDict(jsData)
    if topData['tenant'] is 'missing':
        logging.error('tenant name is missing')
        resp = getResp('unchanged', 'tenant name missing')
        return resp

    if topData['app-prof'] is 'missing':
        logging.error('app name is missing')
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
def validateExternalContracts(jsData, apicMoDir):
    logging.debug('Inside validateExternalContracts function')

    epgList = jsData['epgs']

    logging.debug('Validating pre-defined contracts')
    for e in epgList:
        epg = SafeDict(e)
        epgName = epg['name']
        if epg['contract-links'] is 'missing':
            # No external contracts to validate.
            logging.info('epg {} -- no links to validate'.format(epgName))
            continue

        links = epg['contract-links']
        for l in links:
            link = SafeDict(l)
            if link['contract-kind'] != "EXTERNAL":
                continue

            contractDN = link['contract-dn']
            if contractDN is 'missing':
                    return ['failed', "Missing DN for external contract - epg {}".format(epgName)]
      
            contrMo = apicMoDir.lookupByDn(contractDN)
            if contrMo is None:
                    return ['failed', "External contract {} not found in APIC.".format(contractDN)]
	
    return ['success', 'LGTM']

################################################################################
@app.route("/createAppProf", methods=['POST'])
def create_api():
    logging.debug('Inside create_api function')
    if request.headers['Content-Type'] != 'application/json':
        resp = getResp('unchanged', 'invalid-args')
        return resp
 
    print request
    reqData = request.get_json()
    print reqData
    jsData = SafeDict(reqData)
    # make sure input is well-formed
    valid = validateData(jsData)
    if not valid[0] is 'success':
        resp = getResp('invalid-args', valid[1])
        return resp

    gwConfig = AciGwConfig(jsData)
    valid = gwConfig.Validate()
    if not valid[0] is 'success':
        resp = getResp('error-gw-config', valid[1])
        return resp

    apicUrl = os.environ.get('APIC_URL') 
    if apicUrl == 'SANITY':
        resp = getResp(valid[0], valid[1])
        return resp

    apicMoDir = apicSession.getMoDir()
    if apicMoDir is None:
        resp = getResp('failed', "Invalid APIC session")
        return resp

    apicMoDir.login()

    valid = validateExternalContracts(jsData, apicMoDir)
    if not valid[0] is 'success':
        resp = getResp('invalid-args', valid[1])
        return resp

    setupTenant(jsData, apicMoDir)

    ret = setupApp(jsData, apicMoDir, gwConfig)
    apicMoDir.logout()
    resp = getResp(ret[0], ret[1])
    return resp

################################################################################
def validateData(topData):
    logging.debug('Inside validateData function')
    # validate top level
    topMandatory = set(['aci-gw-api-version', 'tenant', 'app-prof', 'epgs'])
    topOpt = set(['contract-defs', 'gw-config'])
    res = topData.Validate(topMandatory, topOpt, "Top level")
    if res[0] != 'ok':
        return res

    needVer = topData['aci-gw-api-version']
    gotVer = aciGwApiVer
    if needVer != gotVer:
        err = "GW Version mismatch. Need: {} Found: {}".format(needVer, gotVer)
        logging.error(err)
        return ['failed', err]
        
    epgList = topData['epgs']
    if len(epgList) == 0:
        return ['failed', 'empty/missing epglist']

    epgMustFields = set(['name', 'nw-name', 'gw-cidr', 'vlan-tag'])
    epgOptFields = set(['contract-links'])
    for e in epgList:
        if not isinstance(e, dict):
            ss = 'epg must be a dict, is' + str(type(e))
            return ['failed', ss]

        epg = SafeDict(e)
        res = epg.Validate(epgMustFields, epgOptFields, "EPG")
        if res[0] != 'ok':
            return res

    return ['success', 'LGTM']

################################################################################
@app.route("/validateAppProf", methods=['POST'])
def validate_api():
    logging.debug('Inside validate_api function')
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
@app.route("/getEndpoint", methods=['POST'])
def endpoint_api():
    logging.debug('Inside endpoint_api function')
    if request.headers['Content-Type'] != 'application/json':
        resp = getEPResp('error', 'invalid-args')
        return resp

    print request
    jsData = request.get_json()
    print jsData
    # make sure input is well-formed
    topData = SafeDict(jsData)
    if topData['tenant'] is 'missing':
        logging.error('tenant name is missing')
        resp = getEPResp('error', 'tenant name missing')
        print resp
        return resp

    if topData['app-prof'] is 'missing':
        logging.error('app name is missing')
        resp = getEPResp('error', 'app name missing')
        print resp
        return resp

    if topData['epg'] is 'missing':
        logging.error('epg name is missing')
        resp = getEPResp('error', 'epg name missing')
        print resp
        return resp

    if topData['epmac'] is 'missing':
        logging.error('ep mac is missing')
        resp = getEPResp('error', 'ep mac missing')
        print resp
        return resp

    apicMoDir = apicSession.getMoDir()
    if apicMoDir is None:
        resp = getEPResp('failed', "Invalid APIC session")
        print resp
        return resp

    apicMoDir.login()
    epDN = "uni/tn-" + topData['tenant'] + "/ap-" + topData['app-prof'] + \
           "/epg-" + topData['epg'] + "/cep-" + topData['epmac']
    epMo = apicMoDir.lookupByDn(epDN)
    if epMo is None:
        logging.error('ERR {} not found'.format(epDN))
        result = "None"
        ip = "None"
        vlan = "None"
        msg = "Not found in APIC"
    else:
        logging.debug('{} found!'.format(epDN))
        result = "success"
        ip = epMo.ip
        encap = epMo.encap.split('-')
        if len(encap) == 2:
            vlan = encap[1]
        else:
            vlan = "None"

        msg = "ok"
    apicMoDir.logout()
    resp = getEPResp(result, msg, ip, vlan)
    print resp
    return resp

################################################################################
def readFile(fileName=None, mode="r"):
    logging.debug('Inside readFile function')
    if fileName is None:
        return ""

    fileData = ""
    with open(fileName) as f:
        fileData = f.read()

    return fileData

################################################################################
def VerifyEnv():
    logging.debug('Inside VerifyEnv function')
    mandatoryEnvVars = ['APIC_URL',
                        'APIC_USERNAME']

    for envVar in mandatoryEnvVars:
        val = os.getenv(envVar, 'None')
        if val == 'None':
            logging.error('WARNING: {} is not set - GW cannot function'.format(envVar))

################################################################################

class AciGwConfig():
    def __init__(self, spec):
        logging.debug('Inside AciGwConfig:__init__ function')
        self.nodes = []
        self.paths = []
        self.physDom = 'not_specified'
        self.vmmDom = 'not_specified'
        self.enforcePolicies = 'yes'
        self.includeCommonTenant = 'no'
        gc = spec['gw-config']
        if gc is 'missing':
            self.setupFromEnv()
        else:
            safeGc = SafeDict(gc)
            nodes = safeGc['nodeBindings']
            if not nodes is 'missing':
                self.nodes = nodes.split(",")
            paths = safeGc['pathBindings']
            if not paths is 'missing':
                self.paths = paths.split(",")
            physDom = safeGc['physicalDomain']
            if not physDom is 'missing':
                self.physDom = physDom
            vmmDom = safeGc['vmmDomain']
            if not vmmDom is 'missing':
                self.vmmDom = vmmDom
            enforcePolicies = safeGc['enforcePolicies']
            if not enforcePolicies is 'missing':
                self.enforcePolicies = enforcePolicies
            includeCommonTenant = safeGc['includeCommonTenant']
            if not includeCommonTenant is 'missing':
                self.includeCommonTenant = includeCommonTenant

    def setupFromEnv(self):
        logging.debug('Inside AciTopology:setupFromEnv function')
        self.physDom = os.getenv('APIC_PHYS_DOMAIN', 'not_specified')
        self.vmmDom = os.getenv('APIC_VMM_DOMAIN', 'not_specified')
        self.enforcePolicies = 'yes'
        # if unrestricted mode is yes, do not enforce policies
        unrMode = os.getenv('APIC_CONTRACTS_UNRESTRICTED_MODE', 'no')
        if unrMode == 'yes':
            self.enforcePolicies = 'no'

        self.includeCommonTenant = os.getenv('APIC_INC_COMMON_TENANT', 'no')
        leafNodes = os.getenv('APIC_LEAF_NODE', 'not_specified')
        logging.debug('APIC_LEAF_NODE = %s' % leafNodes)
        if leafNodes != 'not_specified':
            if leafNodes.find('pathep') == -1:
                self.isPath = False
                self.nodes = leafNodes.split(",")
                logging.debug('ACI leaves are %s' % self.nodes)
            else:
                self.isPath = True
                self.paths = leafNodes.split(",")
                logging.debug('ACI paths are %s' % self.paths)

    def Validate(self):
        if self.physDom == 'not_specified' and self.vmmDom == 'not_specified':
            return ['failed', 'No physDom or vmmDom specified']
        elif self.physDom != 'not_specified':
            if len(self.nodes) == 0 and len(self.paths) == 0:
                return ['failed', 'No bindings specified']

        return ['success', 'LGTM']

################################################################################
class ApicSession():
    def __init__(self):
        logging.debug('Inside ApicSession:__init__ function')
        self.sessionType = "INVALID"
        self.apicUrl = os.getenv('APIC_URL', 'None')
        self.apicUser = os.getenv('APIC_USERNAME', 'None')
        if self.apicUrl == 'None' or self.apicUser == 'None':
            logging.error('Cannot set up session -- missing config')
            return

        self.certDN = os.getenv('APIC_CERT_DN', 'None') 
        self.pKey = ""
        aciKeyFile = os.getenv('APIC_LOCAL_KEY_FILE', DefACIKeyFile) 
        if self.certDN != 'None':
            self.pKey = readFile(aciKeyFile)
        else:
            logging.info('APIC_CERT_DN is not set, keys disabled')

        if self.pKey != "":
            self.sessionType = "KEY"
            logging.debug('Key based auth selected')
            return

        self.apicPassword = os.getenv('APIC_PASSWORD', 'None')
        if self.apicPassword == 'None':
            logging.debug('ERROR: No valid auth type available')
        else:
            logging.debug('Login based auth selected')
            self.sessionType = "PASSWORD"

    def getMoDir(self):
        logging.debug('Inside ApicSession:getMoDir function')
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
        logging.debug('Inside ApicSession:getSessionType function')
        return self.sessionType

################################################################################
if __name__ == "__main__":

    # Verify basic environment settings we expect
    logging.debug('Starting aci-gw container')
    VerifyEnv()

    # Setup auth type for apic sessions
    apicSession = ApicSession()
        
    app.run(host='0.0.0.0', debug=True)

