# glsa_parser/glsa_to_oval.py
import os
import lxml.etree as ET
from git import Repo

def sync_glsa():
    """Logic to pull from Codeberg"""
    # ... (Your GitPython code) ...
    print("Sync complete.")

def generate_oval():
    """Logic to build the enriched XML"""
    # ... (Your lxml/nvdlib code) ...
    return "gentoo-enriched-oval.xml"

def main():
    """The entry point for the 'glsa-oval' command"""
    sync_glsa()
    generate_oval()

if __name__ == "__main__":
    main()


import os
import time
import lxml.etree as ET
from git import Repo
from datetime import datetime
import nvdlib

# --- CONFIGURATION ---
CODEBERG_URL = "https://codeberg.org/gentoo/glsa-content.git"
LOCAL_DATA = "./glsa-storage"
NVD_API_KEY = "YOUR_NVD_API_KEY" # Strongly recommended
# Rate limit: 50 requests / 30 seconds with key; 5 / 30 seconds without.
SLEEP_TIME = 0.6 if NVD_API_KEY else 6.0 

def sync_glsa():
    """Syncs Gentoo GLSA XMLs from the Codeberg mirror."""
    if not os.path.exists(LOCAL_DATA):
        print(f"Cloning from Codeberg...")
        Repo.clone_from(CODEBERG_URL, LOCAL_DATA)
    else:
        print(f"Pulling latest updates...")
        Repo(LOCAL_DATA).remotes.origin.pull()

def get_nvd_scores(cve_id):
    """Enriches GLSA with CVSS scores from NVD."""
    try:
        # Search for the specific CVE
        r = nvdlib.searchCVE(cveId=cve_id, key=NVD_API_KEY)
        if r:
            cve = r[0]
            v3 = getattr(cve, 'v31score', getattr(cve, 'v30score', 0.0))
            v2 = getattr(cve, 'v2score', 0.0)
            return v3, v2
    except Exception as e:
        print(f"  [!] NVD Lookup failed for {cve_id}: {e}")
    return 0.0, 0.0

def generate_oval():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    output_file = f"gentoo-{timestamp}-oval.xml"
    
    # OVAL Namespaces
    NS = {None: "http://oval.mitre.org/XMLSchema/oval-definitions-5"}
    root = ET.Element("oval_definitions", nsmap=NS)
    definitions = ET.SubElement(root, "definitions")
    
    print(f"Processing GLSA files...")
    for filename in os.listdir(LOCAL_DATA):
        if filename.endswith(".xml") and "glsa-" in filename:
            tree = ET.parse(os.path.join(LOCAL_DATA, filename))
            glsa = tree.getroot()
            glsa_id = glsa.get("id")
            
            # Create OVAL Definition
            defn = ET.SubElement(definitions, "definition", 
                                  id=f"oval:org.gentoo.glsa:def:{glsa_id.replace('-', '')}", 
                                  version="1", class_="vulnerability")
            
            metadata = ET.SubElement(defn, "metadata")
            title_text = glsa.findtext("title")
            
            # ENRICHMENT: Find CVEs and fetch scores
            cves = [uri.text.split("=")[-1] for uri in glsa.findall(".//uri") if "cve.mitre.org" in uri.text]
            
            max_v3 = 0.0
            for cve in cves:
                print(f"  Enriching {glsa_id} with {cve}...")
                v3, v2 = get_nvd_scores(cve)
                max_v3 = max(max_v3, v3)
                ET.SubElement(metadata, "reference", source="NVD", ref_id=cve, 
                              comment=f"CVSS v3: {v3} / v2: {v2}")
                time.sleep(SLEEP_TIME) # Respect NVD API limits

            # Add Severity to title for SIEM visibility
            ET.SubElement(metadata, "title").text = f"[{max_v3}] {title_text}"
            ET.SubElement(metadata, "description").text = glsa.findtext("synopsis")

    # Save output
    with open(output_file, "wb") as f:
        f.write(ET.tostring(root, pretty_print=True, xml_declaration=True, encoding="UTF-8"))
    
    print(f"\nDONE: {output_file} created with NVD enrichment.")

if __name__ == "__main__":
    sync_glsa()
    generate_oval()
