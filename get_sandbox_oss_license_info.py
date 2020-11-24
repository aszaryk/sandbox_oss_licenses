import sys
import csv
import requests
import xml.etree.ElementTree as ET
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from veracode_api_py import VeracodeAPI



def getBuilds():

    application_input = open(sys.argv[1], "r")
    applications = application_input.read().splitlines()

    for app in applications:
        rest_app_guid= VeracodeAPI().get_app_by_name(app)
        
        app_name = rest_app_guid[0]['profile']['name']
        legacy_id = rest_app_guid[0]['id']
        
        print ('Processing App: ' + app_name + ', app_id: ' + str(legacy_id))
        
        sandbox_list = VeracodeAPI().get_sandbox_list(legacy_id)
        
        sandbox_tree = ET.fromstring(sandbox_list)
        for sanbox_ids in sandbox_tree.iter('{https://analysiscenter.veracode.com/schema/4.0/sandboxlist}sandbox'):
            sandbox_id = sanbox_ids.attrib['sandbox_id']

            sandbox_build_list = VeracodeAPI().get_build_info(legacy_id, None ,sandbox_id)

            sandbox_build_tree = ET.fromstring(sandbox_build_list)
            for sandbox_build_ids in sandbox_build_tree.iter('{https://analysiscenter.veracode.com/schema/4.0/buildinfo}buildinfo'):
                sandbox_build_id = sandbox_build_ids.attrib['build_id']

                parseSCA(VeracodeAPI().get_detailed_report(sandbox_build_id))


def parseSCA(xmlFile):
    
    tree = ET.fromstring(xmlFile)

    for appdetail in tree.iter('{https://www.veracode.com/schema/reports/export/1.0}detailedreport'):
        appdata = appdetail.attrib['app_name'] + " | " + appdetail.attrib['sandbox_name'] + " | " + appdetail.attrib['version']  + " | "

    for sca in tree.findall('{https://www.veracode.com/schema/reports/export/1.0}software_composition_analysis'):
        for vulns in sca.findall('{https://www.veracode.com/schema/reports/export/1.0}vulnerable_components'):
            for components in vulns.findall('{https://www.veracode.com/schema/reports/export/1.0}component'):
                csvdata = components.get("component_id") + " | " + components.get("file_name") + " | " + components.get("version") + " | " + components.get("library") + " | " + components.get("vendor") + " | " + components.get("vulnerabilities") + " | "
                
                license_exists = components.findall('{https://www.veracode.com/schema/reports/export/1.0}licenses')
                if not license_exists:
                    cvslic = "UNRECOGNIZED"
                    f = open("cvs-lic.csv", "a", newline='')
                    f.write(appdata+csvdata+cvslic+"\n")
                    f.close()
                else:
                    for licenses in components.findall('{https://www.veracode.com/schema/reports/export/1.0}licenses'):
                
                        for lic in licenses.findall('{https://www.veracode.com/schema/reports/export/1.0}license'):
                            cvslic = lic.get("name")
                            f = open("cvs-lic.csv", "a", newline='')
                            f.write(appdata+csvdata+cvslic+"\n")
                            f.close()

def main():

    with open('cvs-lic.csv', mode='w', newline='') as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=['Application Name | Sandbox Name | Scan Name | Component ID | Component Name | Version | Library | Vendor | Vulnerabilities | License Name'])
        csv_writer.writeheader()
    getBuilds()


if __name__ == "__main__":
    main()