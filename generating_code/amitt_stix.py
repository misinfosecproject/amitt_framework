from datetime import datetime
import pandas as pd
import os
import json
import uuid
import xlrd

class Amitt:
    ''' Manage AMITT metadata

    Create MISP galaxy and cluster JSON files from the AMITT metadata xlsx.

    '''

    def __init__(self, infile = 'amitt_metadata_v3.xlsx'):
        
        # Load metadata from file
        metadata = {}
        xlsx = pd.ExcelFile(infile)
        for sheetname in xlsx.sheet_names:
            metadata[sheetname] = xlsx.parse(sheetname)

        # Create individual tables and dictionaries
        self.phases = metadata['phases']
        self.techniques = metadata['techniques']
        self.tasks = metadata['tasks']
        self.incidents = metadata['incidents']

        tactechs = self.techniques.groupby('tactic')['id'].apply(list).reset_index().rename({'id':'techniques'}, axis=1)
        self.tactics = metadata['tactics'].merge(tactechs, left_on='id', right_on='tactic', how='left').fillna('').drop('tactic', axis=1)

        self.phasedict = self.make_object_dict(self.phases)
        self.tacdict   = self.make_object_dict(self.tactics)
        self.techdict  = self.make_object_dict(self.techniques)

        self.stix_bundle = {}
        self.stix_created_by = str(uuid.uuid4())
        self.stix_marking_definition = str(uuid.uuid4())
        self.stix_creation_timestamp = datetime.now().isoformat()
        self.stix_tactic_uuid = {}
        self.stix_technique_uuid = {}

    def make_object_dict(self, df):
        return(pd.Series(df.name.values,index=df.id).to_dict())

    def write_amitt_file(self, fname, file_data):
        with open(fname, 'w') as f:
            json.dump(file_data, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.write('\n')

    def make_stix_bundle(self):
        """
        Create an empty STIX 2.0 bundle to populate with objects.
        :return:
        """
        bundle = {
            'type': 'bundle',
            'id': f'bundle--{str(uuid.uuid4())}',
            'spec_version': '2.0',
            'objects': []
        }

        self.stix_bundle = bundle

    def make_amitt_tactic(self):
        """
        {
            "created": "2018-10-17T00:14:20.652Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "The adversary is trying to move through your environment.\n\nLateral Movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it. Reaching their objective often involves pivoting through multiple systems and accounts to gain. Adversaries might install their own remote access tools to accomplish Lateral Movement or use legitimate credentials with native network and operating system tools, which may be stealthier. ",
            "external_references": [
                {
                    "external_id": "TA0008",
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/tactics/TA0008"
                }
            ],
            "id": "x-mitre-tactic--7141578b-e50b-4dcc-bfa4-08a8dd689e9e",
            "modified": "2019-07-19T17:44:36.953Z",
            "name": "Lateral Movement",
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "type": "x-mitre-tactic",
            "x_mitre_shortname": "lateral-movement"
        }
        :return:
        """
        # Tactics format:
        # [['TA01', 'Strategic Planning', 'P01', 1, 'Defining the desired end state...', ...]]
        tactics = self.tactics.values.tolist()

        for tac in tactics:
            tactic = {}
            tactic['created'] = f'{self.stix_creation_timestamp}'
            tactic['created_by_ref'] = f'identity--{self.stix_created_by}'
            tactic['description'] = f'{tac[4]}'
            tactic['external_references'] = [
                {
                    'external_id': f'{tac[0]}',
                    'source_name': 'mitre-attack',
                    'url': f'https://github.com/misinfosecproject/amitt_framework/blob/master/tactics/{tac[0]}.md'
                }
            ]
            tactic['id'] = f'x-mitre-tactic--{str(uuid.uuid4())}'
            tactic['modified'] = f'{self.stix_creation_timestamp}'
            tactic['name'] = f'{tac[1]}'
            tactic['object_marking_refs'] = [
                f'marking-definition--{self.stix_marking_definition}'
            ]
            tactic['type'] = 'x-mitre-tactic'
            tactic['x_mitre_shortname'] = f'{tac[1]}'.replace(' ', '-').lower()

            # Add the tactic to the STIX bundle.
            self.stix_bundle['objects'].append(tactic)

            # Map the tactic external ID to the x-mitre-tactic uuid for use in x-mitre-matrix.
            self.stix_tactic_uuid[tac[0]] = tactic['id']

    def make_amitt_technique(self):
        """
        {
            "created": "2017-05-31T21:30:22.096Z",
            "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
            "description": "Some security tools inspect files with static signatures to determine if they are known malicious. Adversaries may add data to files to increase the size beyond what security tools are capable of handling or to change the file hash to avoid hash-based blacklists.",
            "external_references": [
                {
                    "external_id": "T1009",
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1009"
                },
                {
                    "external_id": "CAPEC-572",
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/572.html"
                }
            ],
            "id": "attack-pattern--519630c5-f03f-4882-825c-3af924935817",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "defense-evasion"
                }
            ],
            "modified": "2019-01-31T19:18:29.228Z",
            "name": "Binary Padding",
            "object_marking_refs": [
                "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
            ],
            "type": "attack-pattern",
            "x_mitre_data_sources": [
                "Binary file metadata",
                "File monitoring",
                "Malware reverse engineering"
            ],
            "x_mitre_defense_bypassed": [
                "Signature-based detection",
                "Anti-virus"
            ],
            "x_mitre_detection": "Depending on the method used to pad files, a file-based signature may be capable of detecting padding using a scanning or on-access based tool. \n\nWhen executed, the resulting process from padded files may also exhibit other behavior characteristics of being used to conduct an intrusion such as system and network information Discovery or Lateral Movement, which could be used as event indicators that point to the source file.",
            "x_mitre_platforms": [
                "Linux",
                "macOS",
                "Windows"
            ],
            "x_mitre_version": "1.0"
        }
        :return:
        """
        # Techniques format:
        # ['T0001', '5Ds (dismiss, distort, distract, dismay, divide)', 'TA01', '4Ds of propaganda ...'], ...]
        techniques = self.techniques.values.tolist()

        for tech in techniques:
            if tech[1] != tech[1]:
                tech[1] = ''

            if tech[2] != tech[2]:
                tech[2] = ''

            if tech[3] != tech[3]:
                tech[3] = ''

            if tech[1] == tech[2] == tech[3] == '':
                continue

            technique = {}
            technique['created'] = f'{self.stix_creation_timestamp}'
            technique['created_by_ref'] = f'identity--{self.stix_created_by}'
            technique['description'] = f'{tech[3]}'
            technique['external_references'] = [
                {
                    'external_id': f'{tech[0]}',
                    'source_name': 'mitre-attack',
                    'url': f'https://github.com/misinfosecproject/amitt_framework/blob/master/techniques/{tech[0]}.md'
                }
            ]
            technique['id'] = f'attack-pattern--{str(uuid.uuid4())}'
            # technique['kill_chain_phases'] = [
            #     {
            #         'phase_name': self.tacdict[tech[2]].replace(' ', '-').lower(),
            #         'kill_chain_name': 'mitre-attack'
            #     }
            # ]
            technique['kill_chain_phases'] = [
                {
                    'phase_name': self.tacdict[tech[2]].replace(' ', '-').lower(),
                    'kill_chain_name': 'mitre-attack'
                }
            ]
            technique['modified'] = f'{self.stix_creation_timestamp}'
            technique['name'] = f'{tech[1]}'

            technique['object_marking_refs'] = [
                f'marking-definition--{self.stix_marking_definition}'
            ]
            technique['type'] = 'attack-pattern'
            technique['x_mitre_platforms'] = [
                "Linux",
                "macOS",
                "Windows"
            ],
            technique['x_mitre_version'] = '1.0'

            # Add the technique to the STIX bundle.
            self.stix_bundle['objects'].append(technique)

    def make_amitt_matrix(self):
        """
                {
          "created": "2018-10-17T00:14:20.652Z",
          "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
          "description": "The full ATT&CK Matrix includes techniques spanning Windows, Mac, and Linux platforms and can be used to navigate through the knowledge base.",
          "external_references": [
            {
              "external_id": "enterprise-attack",
              "source_name": "mitre-attack",
              "url": "https://attack.mitre.org/matrices/enterprise"
            }
          ],
          "id": "x-mitre-matrix--eafc1b4c-5e56-4965-bd4e-66a6a89c88cc",
          "modified": "2019-04-16T21:39:18.247Z",
          "name": "Enterprise ATT&CK",
          "object_marking_refs": [
            "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
          ],
          "tactic_refs": [
            "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
            "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
            "x-mitre-tactic--5bc1d813-693e-4823-9961-abf9af4b0e92",
            "x-mitre-tactic--5e29b093-294e-49e9-a803-dab3d73b77dd",
            "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a",
            "x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263",
            "x-mitre-tactic--c17c5845-175e-4421-9713-829d0573dbc9",
            "x-mitre-tactic--7141578b-e50b-4dcc-bfa4-08a8dd689e9e",
            "x-mitre-tactic--d108ce10-2419-4cf9-a774-46161d6c6cfe",
            "x-mitre-tactic--f72804c5-f15a-449e-a5da-2eecd181f813",
            "x-mitre-tactic--9a4e74ab-5008-408c-84bf-a10dfbc53462",
            "x-mitre-tactic--5569339b-94c2-49ee-afb3-2222936582c8"
          ],
          "type": "x-mitre-matrix"
        },
        :return:
        """
        matrix = {}
        matrix['created'] = self.stix_creation_timestamp
        matrix['created_by_ref'] = self.stix_created_by
        matrix['description'] = 'Adversarial Misinformation and Influence Tactics and Techniques'
        matrix['external_references'] = [
            {
                "external_id": "amitt-attack",
                "source_name": "amitt-attack",
                "url": "https://github.com/misinfosecproject/amitt_framework"
            }
        ]
        matrix['id'] = f'x-mitre-matrix--{str(uuid.uuid4())}'
        matrix['modified'] = self.stix_creation_timestamp
        matrix['name'] = 'AMITT Misinformation Framework'
        matrix['object_marking_refs'] = [
            f'marking-definition--{self.stix_marking_definition}'
          ],
        matrix['tactic_refs'] = [
            v for k, v in self.stix_tactic_uuid.items()
        ]
        matrix['type'] = 'x-mitre-matrix'

        self.stix_bundle['objects'].append(matrix)





def main():
    amitt = Amitt()

    # print(amitt.tactics)
    # print(amitt.tactics.values.tolist())
    # print(amitt.techniques.values.tolist())

    amitt.make_stix_bundle()
    amitt.make_amitt_tactic()
    amitt.make_amitt_technique()
    amitt.make_amitt_matrix()

    amitt.write_amitt_file('amitt-attack.json', amitt.stix_bundle)



if __name__ == '__main__':
    main()
