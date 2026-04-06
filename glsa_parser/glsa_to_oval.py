import os
import time
import lxml.etree as ET
from git import Repo
from datetime import datetime
import nvdlib

# --- CONFIGURATION ---
CODEBERG_URL = "https://codeberg.org/gentoo/glsa-content.git"
LOCAL_DATA = "./glsa-storage"
NVD_API_KEY = "YOUR_NVD_API_KEY"  # Get one at nvd.nist.gov
SLEEP_TIME = 0.6 if NVD_API_KEY else 6.0 

def sync_glsa():
    """Syncs Gentoo GLSA XMLs from the Codeberg mirror."""
    if not os.path.exists(LOCAL_DATA):
        print(f"[*] Cloning GLSA content from Codeberg...")
        Repo.clone_from(CODEBERG_URL, LOCAL_DATA)
    else:
        print(f"[*] Pulling latest GLSA updates...")
        repo = Repo(LOCAL_DATA)
        repo.remotes.origin.pull()
    print("[+] Sync complete.")

def get_nvd_scores(cve_id):
    """Enriches GLSA with CVSS scores from NVD."""
    try:
        # Search for the specific CVE
        r = nvdlib.searchCVE(cveId=cve_id, key=NVD_API_KEY)
        if r:
            cve = r[0]
            # Prioritize v3.1, then v3.0, else 0.0
            v3 = getattr(cve, 'v31score', getattr(cve, 'v30score', 0.0))
            v2 = getattr(cve, 'v2score', 0.0)
            return v3, v2
    except Exception as e:
        print(f"  [!] NVD Lookup failed for {cve_id}: {e}")
    return 0.0, 0.0

def generate_oval():
    """Builds the enriched OVAL XML with a timestamped filename."""
    # Create the timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    output_file = f"gentoo-{timestamp}-oval.xml"
    
    # OVAL XML Boilerplate
    NS = {None: "http://oval.mitre.org/XMLSchema/oval-definitions-5"}
    root = ET.Element("oval_definitions", nsmap=NS)
    definitions = ET.SubElement(root, "definitions")
    
    print(f"[*] Processing GLSA files into {output_file}...")
    
    glsa_files = [f for f in os.listdir(LOCAL_DATA) if f.endswith(".xml") and "glsa-" in f]
    
    for filename in glsa_files:
        try:
            tree = ET.parse(os.path.join(LOCAL_DATA, filename))
            glsa = tree.getroot()
            glsa_id = glsa.get("id")
            
            # Create OVAL Definition block
            defn = ET.SubElement(definitions, "definition", 
                                  id=f"oval:org.gentoo.glsa:def:{glsa_id.replace('-', '')}", 
                                  version="1", class_="vulnerability")
            
            metadata = ET.SubElement(defn, "metadata")
            title_text = glsa.findtext("title")
            
            # Find CVE IDs within the GLSA
            cves = [uri.text.split("=")[-1] for uri in glsa.findall(".//uri") if "cve.mitre.org" in uri.text]
            
            max_v3 = 0.0
            for cve in cves:
                print(f"  [+] Enriching {glsa_id} with {cve} intelligence...")
                v3, v2 = get_nvd_scores(cve)
                max_v3 = max(max_v3, v3)
                
                # Add NVD Reference to OVAL Metadata
                ref = ET.SubElement(metadata, "reference", source="NVD", ref_id=cve)
                ref.set("comment", f"CVSS v3: {v3} / v2: {v2}")
                
                # Respect NVD Rate Limits
                time.sleep(SLEEP_TIME)

            # Finalize Metadata with CVSS-boosted Title
            ET.SubElement(metadata, "title").text = f"[{max_v3}] {title_text}"
            ET.SubElement(metadata, "description").text = glsa.findtext("synopsis")
            
        except Exception as e:
            print(f"  [!] Error parsing {filename}: {e}")

    # Write the datestamped OVAL file
    with open(output_file, "wb") as f:
        f.write(ET.tostring(root, pretty_print=True, xml_declaration=True, encoding="UTF-8"))
    
    print(f"\n[SUCCESS] OVAL feed created: {output_file}")
    return output_file

def main():
    """SecOps Entry Point"""
    sync_glsa()
    generate_oval()

if __name__ == "__main__":
    main()
